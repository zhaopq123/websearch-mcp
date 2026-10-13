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


def test_failed_consume_also_invalidates(store):
    """校验失败也要作废 —— 否则给了暴力尝试的窗口。"""
    t = store.issue_login_ticket()
    store.consume_login_ticket("wrong")          # 用错票据
    assert store.consume_login_ticket(t) is False, "失败尝试后原票据仍可用"


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
