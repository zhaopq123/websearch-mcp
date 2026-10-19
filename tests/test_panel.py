# -*- coding: utf-8 -*-
"""配置存储与面板的安全测试。

这是「用户资产不泄露」这条底线的回归测试。每条断言都对应一个
真实的泄露场景 —— 改代码时如果打破了，这里必须红。

⚠️ 测试用的全是**假凭据**（FAKE_SUB 里的 token 是编的）。
"""
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from starlette.testclient import TestClient

from websearch.nodes.pool import fingerprint
from websearch.proxy.manager import ProxyManager
from websearch.proxy.panel import build_panel_app
from websearch.proxy.store import ConfigError, Store

# 假订阅链接：域名真实存在但 token 是编的，用于验证「不回显」逻辑
FAKE_SUB = "https://sub.example-airport.com/api/v1/client/subscribe?token=FAKEtoken1234567890"
FAKE_PANEL_TOKEN = "panel-token-for-test-only-0123456789"


@pytest.fixture
def store():
    d = tempfile.mkdtemp()
    s = Store(Path(d) / ".env")
    s.set_many({
        "WS_SUBSCRIPTION_URL": FAKE_SUB,
        "WS_PANEL_TOKEN": FAKE_PANEL_TOKEN,
    })
    return s


@pytest.fixture
def client(store):
    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    app = build_panel_app(store, mgr)
    return TestClient(app)


# ══════════════════ 文件权限（红线） ══════════════════
#
# ⚠️ 这些断言只在 POSIX 上有意义（2026-10-19 实测）：Windows 的 os.chmod
# 只能切只读位，stat 恒报 0o666/0o777，把「600」写成硬断言等于在 Windows
# 上恒红。产品侧仍按 POSIX 收紧（Linux/Termux/容器是目标平台），
# 所以是**跳过**而不是放宽断言 —— 放宽就把这条泄露红线废了。
# 沿用 test_nodes.py 的 IS_WIN 口径，别再造一套。
IS_WIN = sys.platform == "win32"
posix_only = pytest.mark.skipif(IS_WIN, reason="Windows 无 POSIX 权限语义")


@posix_only
def test_env_file_is_600(store):
    """凭据文件必须 600 —— 同机其他用户不能读到订阅链接。"""
    mode = stat.S_IMODE(os.stat(store.path).st_mode)
    assert mode == 0o600, f"权限 {oct(mode)}，应为 600"


@posix_only
def test_parent_dir_is_700(store):
    mode = stat.S_IMODE(os.stat(store.path.parent).st_mode)
    assert mode == 0o700, f"目录权限 {oct(mode)}，应为 700"


@posix_only
def test_permissions_rechecked_after_rewrite(store):
    """每次写入都要重新收紧权限（防止外部 chmod 后没恢复）。"""
    os.chmod(store.path, 0o644)
    assert store.check_permissions()[0] is False
    store.set_many({"WS_PROXY_ENABLED": "1"})
    mode = stat.S_IMODE(os.stat(store.path).st_mode)
    assert mode == 0o600, "写入后未恢复 600"


def test_atomic_write_leaves_no_tmp(store):
    store.set_many({"WS_PROXY_ENABLED": "1"})
    assert not store.path.with_suffix(".tmp").exists()


# ══════════════════ 凭据不回显（红线） ══════════════════


def test_read_public_never_returns_subscription(store):
    """面板视图绝不能含订阅原文或 token。"""
    pub = json.dumps(store.read_public(), ensure_ascii=False)
    assert "FAKEtoken1234567890" not in pub, "泄露了订阅 token"
    assert FAKE_SUB not in pub, "泄露了完整订阅链接"
    assert FAKE_PANEL_TOKEN not in pub, "泄露了面板口令"


def test_read_public_returns_mask_and_host(store):
    """但要给出足够信息让用户确认配的是哪个机场。"""
    pub = store.read_public()
    assert pub["subscription"]["configured"] is True
    assert pub["subscription"]["host"] == "sub.example-airport.com"
    assert "●" in pub["subscription"]["masked"]
    assert "FAKEtoken" not in pub["subscription"]["masked"]


def test_mask_short_values_fully_hidden():
    """太短的值要全遮，不能靠首尾字符反推。"""
    from websearch.proxy.store import _mask

    assert set(_mask("abc")) == {"●"}
    assert "a" not in _mask("abc")
    assert _mask("") == ""


def test_safe_host_strips_path_and_query(store):
    """host 提取必须去掉 path/query —— token 通常在 query 里。"""
    from websearch.proxy.store import _safe_host

    assert _safe_host(FAKE_SUB) == "sub.example-airport.com"
    assert "token" not in _safe_host(FAKE_SUB)
    assert _safe_host("") == ""
    assert _safe_host("not a url") == ""


# ══════════════════ 写入白名单 ══════════════════


def test_write_rejects_unknown_key(store):
    """不能借面板注入任意环境变量。"""
    with pytest.raises(ConfigError):
        store.set_many({"PATH": "/evil"})
    with pytest.raises(ConfigError):
        store.set_many({"WS_ALLOW_PRIVATE_NET": "1"})   # 这个不在白名单


def test_write_rejects_newline_injection(store):
    """值里不能塞换行来伪造额外配置行。"""
    with pytest.raises(ConfigError):
        store.set_many({"WS_SUBSCRIPTION_URL": "https://a.com/\nWS_PROXY_ENABLED=1"})


def test_delete_removes_key(store):
    store.delete(["WS_SUBSCRIPTION_URL"])
    assert store.get("WS_SUBSCRIPTION_URL", "") == ""
    assert "WS_SUBSCRIPTION_URL" not in store.path.read_text(encoding="utf-8")


# ══════════════════ gitignore 自检 ══════════════════


def test_check_gitignored_detects_missing(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    s = Store(d / ".env")
    ok, note = s.check_gitignored(d)
    assert ok is False and ".gitignore" in note


def test_check_gitignored_passes_when_present(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    (d / ".gitignore").write_text("venv/\n.env\n", encoding="utf-8")
    s = Store(d / ".env")
    ok, _ = s.check_gitignored(d)
    assert ok is True


# ══════════════════ 面板鉴权 ══════════════════


def test_api_requires_auth(client):
    """未登录访问任何 API 都是 401。"""
    for path in ("/api/config", "/api/proxy/nodes", "/api/pool"):
        r = client.get(path)
        assert r.status_code == 401, f"{path} 未鉴权！"
    for path in ("/api/save", "/api/proxy/start", "/api/proxy/stop",
                 "/api/proxy/check", "/api/subscription/clear"):
        r = client.post(path, json={})
        assert r.status_code == 401, f"{path} 未鉴权！"


def test_root_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert "/login" in r.headers.get("location", "")


def test_healthz_is_public_and_bare(client):
    """探活端点免鉴权，但只回 {ok:true}，不泄露任何状态。"""
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_login_wrong_token_rejected(client):
    r = client.post("/api/login", json={"token": "wrong"})
    assert r.status_code == 401
    assert "FAKE" not in r.text


def test_login_then_access(client):
    r = client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    assert r.status_code == 200 and r.json()["ok"] is True
    # Cookie 里不能是口令明文
    cookie = r.headers.get("set-cookie", "")
    assert FAKE_PANEL_TOKEN not in cookie, "口令明文进了 Cookie"
    # 登录后能读配置
    r2 = client.get("/api/config")
    assert r2.status_code == 200
    assert "FAKEtoken" not in r2.text, "配置接口泄露了订阅 token"


def test_login_lockout_after_repeated_failures(client):
    """暴力破解要被挡住。"""
    for _ in range(5):
        client.post("/api/login", json={"token": "wrong"})
    r = client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    assert r.status_code == 429, "连续失败后未锁定"


def test_logout_invalidates_session(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    assert client.get("/api/config").status_code == 200
    client.post("/api/logout")
    assert client.get("/api/config").status_code == 401


# ══════════════════ 保存接口校验 ══════════════════


def test_save_rejects_non_http_subscription(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.post("/api/save", json={"subscription_url": "file:///etc/passwd"})
    assert r.status_code == 400
    assert "http" in r.json()["error"]


def test_save_rejects_bad_port(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.post("/api/save", json={"http_port": "not-a-number"})
    assert r.status_code == 400


def test_save_response_has_no_secret(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.post("/api/save", json={
        "subscription_url": "https://sub.another-airport.net/api?token=NEWsecret9999"
    })
    assert r.status_code == 200
    assert "NEWsecret9999" not in r.text, "保存响应回显了订阅 token"


def test_save_updates_config(client, store):
    """保存要真的写进配置键。

    曾经的 bug：面板把前端字段名（proxy_enabled）当成配置键写进去，
    结果 set_many 抛 ConfigError → 面板返回 400，而测试只断言配置值，
    表现为「保存失败但没人发现」。所以这里**必须同时断言返回码**。
    """
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.post("/api/save", json={"proxy_enabled": True, "http_port": 17900})
    assert r.status_code == 200, f"保存失败: {r.text}"
    assert store.get_bool("WS_PROXY_ENABLED") is True
    assert store.get_int("WS_HTTP_PROXY_PORT") == 17900


def test_save_never_writes_unknown_keys(client, store):
    """保存后配置文件里不能出现白名单外的键。

    这是上面那个 bug 的直接回归：前端字段名绝不能落到文件里。
    """
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    client.post("/api/save", json={
        "proxy_enabled": True, "auto_start": True,
        "http_port": 17901, "socks_port": 17902, "health_interval": 600,
    })
    content = store.path.read_text(encoding="utf-8")
    for bogus in ("proxy_enabled", "auto_start", "http_port",
                  "socks_port", "health_interval"):
        # 不能出现 "proxy_enabled=" 这种前端字段名做键的行
        assert f"\n{bogus}=" not in content, f"写入了非法键 {bogus}"
    # 正确的键要在
    for good in ("WS_PROXY_ENABLED", "WS_HTTP_PROXY_PORT",
                 "WS_SOCKS_PROXY_PORT", "WS_PROXY_HEALTH_INTERVAL"):
        assert good in content, f"缺少配置键 {good}"


def test_save_all_fields_roundtrip(client, store):
    """所有可保存字段都要能读回来（防止漏改某个字段的键名）。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.post("/api/save", json={
        "proxy_enabled": True, "auto_start": False,
        "http_port": 17911, "socks_port": 17912, "health_interval": 900,
    })
    assert r.status_code == 200, r.text
    assert store.get_bool("WS_PROXY_ENABLED") is True
    assert store.get_bool("WS_PROXY_AUTO_START") is False
    assert store.get_int("WS_HTTP_PROXY_PORT") == 17911
    assert store.get_int("WS_SOCKS_PROXY_PORT") == 17912
    assert store.get_int("WS_PROXY_HEALTH_INTERVAL") == 900


def test_proxy_start_without_subscription_fails_cleanly(client):
    """没配订阅时启动代理 → 明确报错，不崩。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    client.post("/api/subscription/clear")
    r = client.post("/api/proxy/start")
    assert r.status_code == 400
    assert "订阅" in r.json()["error"]


def test_proxy_nodes_empty_when_not_started(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.get("/api/proxy/nodes")
    assert r.status_code == 200
    assert r.json()["nodes"] == []


# ══════════════════ 节点池卡片（只读） ══════════════════
#
# 权限模型（用户定的）：自养池是程序自己跑的，用户**只能看**，不能碰。
# 所以这里钉死两件事：① 有灯（哪个通/哪个不通）② 绝不给写入口。


def _pool_app(tmp_path, n_alive=1, n_dead=1):
    """造一个带节点库的面板 —— 模拟「面板进程读服务端正在用的库」。"""
    from websearch.nodes.pool import NodePool
    store = Store(tmp_path / ".env")
    store.set_many({"WS_PANEL_TOKEN": FAKE_PANEL_TOKEN})
    db = tmp_path / "cache" / "nodes.sqlite3"
    db.parent.mkdir(parents=True, exist_ok=True)
    pool = NodePool(db)
    nodes = [("alive%d.example.com" % i, "ss",
              {"server": "alive%d.example.com" % i, "server_port": 443,
               "method": "aes-256-gcm", "password": "pw"})
             for i in range(n_alive)]
    nodes += [("dead%d.example.com" % i, "ss",
               {"server": "dead%d.example.com" % i, "server_port": 443,
                "method": "aes-256-gcm", "password": "pw"})
              for i in range(n_dead)]
    pool.upsert_nodes(nodes, "s1", pool="free")
    for i in range(n_alive):
        host = "alive%d.example.com" % i
        pool.record_probe(fingerprint("ss", {
            "server": host, "server_port": 443,
            "method": "aes-256-gcm", "password": "pw"}), True, 80 + i)
    pool.close()
    mgr = ProxyManager(tmp_path / "proxy-run", singbox_bin="/nonexistent/sing-box")
    return build_panel_app(store, mgr, pool_db=db)


def test_pool_card_shows_lights(tmp_path):
    client = TestClient(_pool_app(tmp_path, n_alive=2, n_dead=1))
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.get("/api/pool")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] is True and d["available"] is True
    assert d["stats"]["total"] == 3 and d["stats"]["alive"] == 2
    assert sum(1 for n in d["nodes"] if n["alive"]) == 2
    # 活的排前面
    assert d["nodes"][0]["alive"] is True
    # 不给凭据
    assert "password" not in json.dumps(d)


def test_pool_card_missing_db_is_graceful(client):
    """库没生成也要给个人话说明，不能 500。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.get("/api/pool")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] is True and d["available"] is False
    assert d.get("note")


def test_pool_api_is_readonly(client):
    """用户不能碰自养池：没有 POST/PUT/DELETE，只有 GET。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    for method in ("post", "put", "delete", "patch"):
        fn = getattr(client, method)
        # TestClient.delete 不吃 json=，单独走一次
        r = fn("/api/pool") if method == "delete" else fn("/api/pool", json={})
        assert r.status_code in (405, 404), f"{method.upper()} /api/pool 竟然被接受"


def test_pool_card_only_alive_filter(tmp_path):
    client = TestClient(_pool_app(tmp_path, n_alive=2, n_dead=3))
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    d = client.get("/api/pool?only_alive=1").json()
    assert len(d["nodes"]) == 2 and all(n["alive"] for n in d["nodes"])


# ══════════════════ 订阅：能增也能删 ══════════════════


def test_clear_subscription_actually_removes_it(store, client):
    """「只能写不能删」的反向回归：删完必须真的没了。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    assert store.read_public()["subscription"]["configured"] is True

    r = client.post("/api/subscription/clear")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert store.read_public()["subscription"]["configured"] is False
    # 面板再读也不能把它读回来
    assert client.get("/api/config").json()["config"]["subscription"]["configured"] is False


def test_save_then_clear_roundtrip(client, store):
    """保存 → 覆盖 → 删除 三步都通，且全程不回显原文。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    new_sub = "https://sub.another-airport.net/api?token=SECONDsecret"
    r = client.post("/api/save", json={"subscription_url": new_sub})
    assert r.status_code == 200 and r.json()["ok"] is True
    body = r.text
    assert "SECONDsecret" not in body, "保存接口回显了订阅 token"
    assert store.get("WS_SUBSCRIPTION_URL") == new_sub

    assert client.post("/api/subscription/clear").json()["ok"] is True
    assert store.get("WS_SUBSCRIPTION_URL", "") == ""


def test_page_renders_pool_card_and_sub_toggle(client):
    """页面模板别写坏：节点池卡片、显示开关、删除订阅按钮都得在。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    for marker in ('id="poolCard"', 'id="poolStats"', 'btnPoolAlive',
                   'id="btnShowSub"', 'id="btnClear"', 'loadPool()'):
        assert marker in body, f"页面缺少 {marker}"
    # 删除按钮的文案必须是「删除订阅」，不能再说「清除订阅」这种含糊话
    assert "删除订阅" in body
    # 池子卡片必须明说「只读 / 程序维护」
    assert "只读" in body


def test_health_reports_pool_when_no_subscription(tmp_path):
    """只用自养池时，别再说「没配代理、只搜国内网站」。

    这是线上实测到的真缺陷：池子里有可用的节点、墙外搜索是通的，
    健康卡片却报「只搜国内网站」并让用户去填订阅链接 —— 结论错、
    指引也错，还跟新加的池子卡片自相矛盾。
    """
    client = TestClient(_pool_app(tmp_path, n_alive=3, n_dead=1))
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    d = client.get("/api/health-summary").json()
    proxy = [i for i in d["items"] if "代理" in i["title"]]
    assert proxy, "没有代理状态条目"
    top = proxy[0]
    assert top["level"] == "ok", f"池子可用却报了 {top['level']}：{top['title']}"
    assert "节点池" in top["title"]
    assert "只搜国内" not in top["title"]
    assert "只搜国内" not in top["detail"]


def test_health_still_warns_when_pool_empty(client):
    """池子空 + 没订阅 → 仍然如实报 warn，且必须说「还能用」。"""
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    d = client.get("/api/health-summary").json()
    proxy = [i for i in d["items"] if "代理" in i["title"]]
    assert proxy[0]["level"] == "warn"
