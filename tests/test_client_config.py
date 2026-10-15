# -*- coding: utf-8 -*-
"""「最后一公里」测试：接入 AI 客户端的配置片段。

这是产品最关键的一环 —— 服务跑起来了，用户却不知道怎么接到自己的
AI 客户端，那前面所有工作都白做。这个接口负责把 MCP 协议细节
（transport / headers / endpoint）翻译成「复制粘贴就能用」的片段。

安全边界：这个响应**必须含 token**（客户端需要它才能连），
所以只在已登录会话里返回 —— 未登录必须 401。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from starlette.testclient import TestClient

from websearch.proxy.manager import ProxyManager
from websearch.proxy.panel import build_panel_app
from websearch.proxy.store import Store

FAKE_PANEL_TOKEN = "panel-token-for-test-only-0123456789"
FAKE_MCP_TOKEN = "fake-mcp-token-for-test-abcdef123456"


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / ".env")
    # 注意：WS_PORT 是**只读**配置（面板不该能改服务端口），
    # 所以只能写面板口令；端口靠 DEFAULTS / 环境变量提供。
    s.set_many({"WS_PANEL_TOKEN": FAKE_PANEL_TOKEN})
    return s


@pytest.fixture
def client(store):
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    return TestClient(build_panel_app(store, mgr))


@pytest.fixture
def authed(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    return client


# ══════════════════ 鉴权边界（最重要） ══════════════════


def test_client_config_requires_auth(client):
    """未登录不能取配置片段 —— 它含 MCP token。"""
    r = client.get("/api/client-config")
    assert r.status_code == 401, "未鉴权就能拿到含 token 的配置片段！"


def test_client_config_after_logout_denied(client):
    client.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    assert client.get("/api/client-config").status_code in (200, 400)
    client.post("/api/logout")
    assert client.get("/api/client-config").status_code == 401


# ══════════════════ 内容正确性 ══════════════════


def test_client_config_returns_all_formats(authed, monkeypatch):
    """四种格式都要有（覆盖主流客户端）。"""
    monkeypatch.setattr(
        "websearch.proxy.panel._read_mcp_token", lambda: FAKE_MCP_TOKEN
    )
    r = authed.get("/api/client-config")
    assert r.status_code == 200
    d = r.json()
    if not d.get("ok"):
        pytest.skip(f"环境无 .tokens 文件：{d.get('error')}")
    for fmt in ("generic_json", "claude_desktop", "dsh", "curl"):
        assert fmt in d["snippets"], f"缺少格式 {fmt}"
        assert d["snippets"][fmt].strip(), f"格式 {fmt} 是空的"


def test_generic_json_is_valid_mcp_config(authed, monkeypatch):
    """通用 JSON 必须是合法 JSON 且结构符合 mcpServers 约定。"""
    monkeypatch.setattr(
        "websearch.proxy.panel._read_mcp_token", lambda: FAKE_MCP_TOKEN
    )
    d = authed.get("/api/client-config").json()
    if not d.get("ok"):
        pytest.skip("环境无 token")
    cfg = json.loads(d["snippets"]["generic_json"])
    assert "mcpServers" in cfg
    srv = cfg["mcpServers"]["websearch"]
    assert srv["url"].endswith("/mcp")
    assert srv["headers"]["Authorization"] == f"Bearer {FAKE_MCP_TOKEN}"


def test_dsh_snippet_matches_manager_format(authed, monkeypatch):
    """DSH 片段必须符合 dsh-mcp-manager 的字段约定。"""
    monkeypatch.setattr(
        "websearch.proxy.panel._read_mcp_token", lambda: FAKE_MCP_TOKEN
    )
    d = authed.get("/api/client-config").json()
    if not d.get("ok"):
        pytest.skip("环境无 token")
    cfg = json.loads(d["snippets"]["dsh"])
    for field in ("name", "transport", "enabled", "url", "headers"):
        assert field in cfg, f"DSH 片段缺字段 {field}"
    assert cfg["transport"] == "streamable-http"
    assert cfg["enabled"] is True


def test_url_uses_request_host(authed, monkeypatch):
    """URL 要用用户实际访问的地址 —— 那才是可达的。

    用户从局域网 IP 访问面板，生成的配置就该是那个 IP，
    而不是 127.0.0.1（后者在用户机器上指向用户自己，连不通）。
    """
    monkeypatch.setattr(
        "websearch.proxy.panel._read_mcp_token", lambda: FAKE_MCP_TOKEN
    )
    r = authed.get("/api/client-config", headers={"host": "192.168.1.100:8500"})
    d = r.json()
    if not d.get("ok"):
        pytest.skip("环境无 token")
    assert "192.168.1.100" in d["url"], f"URL 没用请求 Host：{d['url']}"
    assert "8500" not in d["url"], "URL 误用了面板端口（应为 MCP 服务端口 8300）"


def test_url_falls_back_when_localhost(authed, monkeypatch):
    """从 127.0.0.1 访问时，应替换成局域网 IP（否则用户拿去用不了）。"""
    monkeypatch.setattr(
        "websearch.proxy.panel._read_mcp_token", lambda: FAKE_MCP_TOKEN
    )
    monkeypatch.setattr(
        "websearch.proxy.panel._detect_lan_ip_safe", lambda: "10.0.0.5"
    )
    r = authed.get("/api/client-config", headers={"host": "127.0.0.1:8500"})
    d = r.json()
    if not d.get("ok"):
        pytest.skip("环境无 token")
    assert "10.0.0.5" in d["url"], f"回环地址没被替换：{d['url']}"


def test_token_missing_gives_actionable_error(authed, monkeypatch):
    """读不到 token 时要给人话提示，不是抛异常。"""
    monkeypatch.setattr("websearch.proxy.panel._read_mcp_token", lambda: "")
    r = authed.get("/api/client-config")
    assert r.status_code == 400
    d = r.json()
    assert d["ok"] is False
    assert ".tokens" in d["error"], "错误信息没说清楚去哪找 token"


def test_curl_snippet_has_auth_header(authed, monkeypatch):
    monkeypatch.setattr(
        "websearch.proxy.panel._read_mcp_token", lambda: FAKE_MCP_TOKEN
    )
    d = authed.get("/api/client-config").json()
    if not d.get("ok"):
        pytest.skip("环境无 token")
    curl = d["snippets"]["curl"]
    assert "Authorization: Bearer" in curl
    assert "initialize" in curl, "自检命令应包含 initialize 握手"
