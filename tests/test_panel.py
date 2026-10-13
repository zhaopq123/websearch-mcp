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


def test_env_file_is_600(store):
    """凭据文件必须 600 —— 同机其他用户不能读到订阅链接。"""
    mode = stat.S_IMODE(os.stat(store.path).st_mode)
    assert mode == 0o600, f"权限 {oct(mode)}，应为 600"


def test_parent_dir_is_700(store):
    mode = stat.S_IMODE(os.stat(store.path.parent).st_mode)
    assert mode == 0o700, f"目录权限 {oct(mode)}，应为 700"


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
    for path in ("/api/config", "/api/proxy/nodes"):
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
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    client.post("/api/save", json={"proxy_enabled": True, "http_port": 17900})
    assert store.get_bool("WS_PROXY_ENABLED") is True
    assert store.get_int("WS_HTTP_PROXY_PORT") == 17900


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
