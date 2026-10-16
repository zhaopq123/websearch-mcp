# -*- coding: utf-8 -*-
"""一键登录票据与访问信息的安全测试。

票据机制解决的是「安装体验」问题：不让用户去 grep 口令再手工粘贴。
但它是新增的鉴权入口，必须钉住安全边界。
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from starlette.testclient import TestClient

from websearch.proxy.manager import ProxyManager
from websearch.proxy.panel import build_panel_app
from websearch.proxy.store import Store

FAKE_PANEL_TOKEN = "panel-token-for-test-only-0123456789"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / ".env")
    s.set_many({"WS_PANEL_TOKEN": FAKE_PANEL_TOKEN})
    return s


@pytest.fixture
def client(store):
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    return TestClient(build_panel_app(store, mgr))


# ══════════════════ 票据签发与校验 ══════════════════


def test_ticket_is_one_time(store):
    """票据用过即废 —— 防重放。"""
    t = store.issue_login_ticket()
    assert store.consume_login_ticket(t) is True
    assert store.consume_login_ticket(t) is False, "票据被重复使用"


def test_ticket_stored_as_hash_not_plaintext(store):
    """票据存哈希 —— 即使 .env 泄露也拿不到可用票据。"""
    t = store.issue_login_ticket()
    content = store.path.read_text(encoding="utf-8")
    assert t not in content, "票据明文落盘了"
    assert "WS_LOGIN_TICKET_HASH=" in content


def test_ticket_expires(store):
    """过期票据失效。"""
    t = store.issue_login_ticket(ttl_sec=-1)   # 立刻过期
    assert store.consume_login_ticket(t) is False


def test_wrong_ticket_rejected(store):
    store.issue_login_ticket()
    assert store.consume_login_ticket("not-the-ticket") is False


def test_empty_ticket_rejected(store):
    assert store.consume_login_ticket("") is False
    assert store.consume_login_ticket(None) is False  # type: ignore[arg-type]


def test_wrong_ticket_does_not_invalidate_valid_one(store):
    """用错票据来试，不能把有效票据搞失效。

    这是踩过的坑：原实现「失败即作废」看起来更安全，但会导致
    拿旧票据试一下就把刚签发的新票据删掉 —— 用户点链接进不去。
    票据是 32 字节随机数 + 5 分钟时效，暴力猜测不现实，
    不需要靠「失败即废」兜底。
    """
    t = store.issue_login_ticket()
    assert store.consume_login_ticket("wrong") is False
    assert store.consume_login_ticket(t) is True, "错误尝试误伤了有效票据"


def test_second_ticket_replaces_first(store):
    """签发新票据应使旧票据失效（同一时间只允许一个待用票据）。"""
    t1 = store.issue_login_ticket()
    t2 = store.issue_login_ticket()
    assert store.consume_login_ticket(t1) is False
    assert store.consume_login_ticket(t2) is True


# ══════════════════ 一键登录路由 ══════════════════


def test_magic_login_sets_session(client, store):
    """带有效票据访问 /_open → 建立会话。"""
    t = store.issue_login_ticket()
    r = client.get(f"/_open?t={t}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers.get("location") == "/"
    # 会话建立后能读配置
    assert client.get("/api/config").status_code == 200


def test_magic_login_bad_ticket_redirects_to_login(client):
    r = client.get("/_open?t=bogus", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers.get("location", "")


def test_magic_login_without_ticket(client):
    r = client.get("/_open", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers.get("location", "")


def test_magic_login_does_not_leak_ticket_in_location(client, store):
    """跳转目标不能带上票据（否则票据会留在浏览器历史）。"""
    t = store.issue_login_ticket()
    r = client.get(f"/_open?t={t}", follow_redirects=False)
    assert t not in r.headers.get("location", "")


def test_magic_login_ticket_not_in_cookie(client, store):
    """Cookie 里是会话 id，不是票据。"""
    t = store.issue_login_ticket()
    r = client.get(f"/_open?t={t}", follow_redirects=False)
    cookie = r.headers.get("set-cookie", "")
    assert t not in cookie
    assert FAKE_PANEL_TOKEN not in cookie


def test_magic_login_unauthenticated_access_still_blocked(client, store):
    """一键登录不影响其他接口的鉴权。"""
    t = store.issue_login_ticket()
    client.get(f"/_open?t={t}", follow_redirects=False)
    client.post("/api/logout")
    assert client.get("/api/config").status_code == 401


def test_cookie_samesite_is_lax_not_strict(client, store):
    """Cookie 必须 SameSite=lax，不能用 strict。

    这是真 bug 的回归（用户视角测试才抓到）：
    用 strict 时，**从外部链接点进来的首次跳转不携带 Cookie** ——
    而「从面板日志/聊天里点链接进面板」正是本功能的核心场景。
    表现是：链接能点、303 正常、但下一跳就掉登录，
    用户看到「刚进去又让我登录」，完全不知道哪里错了。

    lax 仍阻止跨站 POST（CSRF 防护），对本场景足够安全。
    """
    t = store.issue_login_ticket()
    r = client.get(f"/_open?t={t}", follow_redirects=False)
    cookie = r.headers.get("set-cookie", "").lower()
    assert "samesite=lax" in cookie, f"Cookie 不是 lax：{cookie}"
    assert "samesite=strict" not in cookie, "strict 会让点链接进来的人掉登录"


def test_login_cookie_also_lax(client):
    """口令登录的 Cookie 也要 lax（与 /_open 保持一致）。"""
    r = client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    cookie = r.headers.get("set-cookie", "").lower()
    assert "samesite=lax" in cookie


def test_cookie_is_httponly(client, store):
    """Cookie 必须 HttpOnly（防 XSS 窃取会话）。"""
    t = store.issue_login_ticket()
    r = client.get(f"/_open?t={t}", follow_redirects=False)
    assert "httponly" in r.headers.get("set-cookie", "").lower()


# ══════════════════ 访问信息打印 ══════════════════


def test_lan_ip_detection_returns_something_or_empty():
    """LAN IP 探测不能抛异常（容器/无网络环境要能降级）。"""
    from websearch.proxy.panel_server import _detect_lan_ip

    ip = _detect_lan_ip()
    assert isinstance(ip, str)
    # 不允许返回回环（那是探测失败的表现，调用方据此跳过局域网地址）
    assert not ip.startswith("127.")


def test_access_info_prints_magic_link(capsys, store, tmp_path):
    """打印内容里必须含可点击的一键登录链接。"""
    from websearch.proxy.panel_server import _print_access_info

    _print_access_info(store, "127.0.0.1", 8500)
    out = capsys.readouterr().out
    assert "/_open?t=" in out, "没有打印一键登录链接"
    assert "8500" in out
    # 不能把口令本身打出来
    assert FAKE_PANEL_TOKEN not in out, "打印内容泄露了面板口令"


def test_access_info_mentions_tunnel_for_loopback(capsys, store):
    """绑回环时必须告诉用户怎么从外部访问（否则用户就卡在这里）。"""
    from websearch.proxy.panel_server import _print_access_info

    _print_access_info(store, "127.0.0.1", 8500)
    out = capsys.readouterr().out
    assert "-L" in out, "没给出 SSH 隧道方式"
    assert "WS_PANEL_HOST" in out, "没给出改监听地址的方式"


def test_access_info_lan_mode_shows_direct_url(capsys, store):
    """绑非回环时给出局域网直连地址。"""
    from websearch.proxy.panel_server import _print_access_info

    _print_access_info(store, "0.0.0.0", 8500)
    out = capsys.readouterr().out
    assert "访问地址" in out
    assert FAKE_PANEL_TOKEN not in out
