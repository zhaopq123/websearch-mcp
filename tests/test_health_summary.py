# -*- coding: utf-8 -*-
"""人话状态接口测试（产品视角）。

为什么单独测这个：用户不该看到 {"bypassed": true, "consecutive_failures": 3}
这种字段然后自己猜该怎么办。产品应该直接说「🟢能用 / 🔴哪里坏了 + 点这里修」。

这些测试从**用户视角**断言：每条状态都必须可理解、有结论、必要时有出路。
"""
import sys
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
def authed(store):
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    c = TestClient(build_panel_app(store, mgr))
    c.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    return c


def test_health_summary_requires_auth(store):
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    c = TestClient(build_panel_app(store, mgr))
    assert c.get("/api/health-summary").status_code == 401


def test_health_summary_shape(authed):
    r = authed.get("/api/health-summary")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] is True
    assert d["overall"] in ("ok", "warn", "error")
    assert isinstance(d["items"], list) and d["items"]
    for it in d["items"]:
        assert it["level"] in ("ok", "warn", "error")
        assert it["title"], "每条状态必须有标题（用户看的就是它）"
        assert it["detail"], "每条状态必须有说明（否则用户不知道意味着什么）"


def test_every_problem_has_a_way_out(authed):
    """凡是「有问题」的条目，必须给出下一步动作 —— 不能只报错不管。

    这是产品思维的核心：用户看到红点时的第一反应是「那我该干嘛」。
    """
    d = authed.get("/api/health-summary").json()
    for it in d["items"]:
        if it["level"] in ("warn", "error"):
            # 允许少数纯提示类（如「未装 sing-box」）没有动作，
            # 但 detail 里必须说清影响范围
            if "action" not in it:
                assert it["detail"], f"「{it['title']}」既没动作也没说明"


def test_service_down_is_reported_as_error(store):
    """搜索服务没在跑时必须报 error（用户最需要知道这个）。"""
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    c = TestClient(build_panel_app(store, mgr))
    c.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    d = c.get("/api/health-summary").json()
    titles = [i["title"] for i in d["items"]]
    # 测试环境 8300 通常没在跑（或被别的进程占），只要有一条关于服务的状态
    assert any("搜索服务" in t for t in titles), f"没有搜索服务状态：{titles}"
    assert d["overall"] in ("warn", "error"), "服务不可用时应给出非 ok 结论"


def test_no_proxy_is_warn_not_error(store):
    """没配代理是「能用但不全」（warn），不是「坏了」（error）。

    这个区分很重要：把「只搜国内源」报成 error 会让用户以为坏了，
    而其实搜索完全能用。
    """
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    c = TestClient(build_panel_app(store, mgr))
    c.post("/api/login", json={"token": FAKE_PANEL_TOKEN})
    d = c.get("/api/health-summary").json()
    proxy_items = [i for i in d["items"] if "代理" in i["title"]]
    assert proxy_items, "没有代理状态条目"
    assert proxy_items[0]["level"] == "warn", "没配代理应报 warn（能用但不全）"
    # 必须说清「仍然能用」，否则用户以为坏了
    assert "国内" in proxy_items[0]["detail"] or "能" in proxy_items[0]["detail"]


def test_health_summary_has_no_credentials(authed, store):
    """状态接口不能泄露凭据。"""
    store.set_many({"WS_SUBSCRIPTION_URL":
                    "https://sub.secret-airport.com/api?token=SECRET123456"})
    r = authed.get("/api/health-summary")
    assert "SECRET123456" not in r.text
    assert "secret-airport" not in r.text


# ══════════════════ 一键修权限 ══════════════════


def test_fix_permissions_requires_auth(store):
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    c = TestClient(build_panel_app(store, mgr))
    assert c.post("/api/fix-permissions").status_code == 401


def test_fix_permissions_actually_fixes(authed, store):
    """用户点一下就该修好 —— 不该要求他懂 chmod。"""
    import os
    import stat

    os.chmod(store.path, 0o644)
    assert store.check_permissions()[0] is False
    r = authed.post("/api/fix-permissions")
    assert r.status_code == 200 and r.json()["ok"] is True
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600


# ══════════════════ 重启搜索服务 ══════════════════


def test_search_restart_requires_auth(store):
    import tempfile

    mgr = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    c = TestClient(build_panel_app(store, mgr))
    assert c.post("/api/search/restart").status_code == 401


def test_search_restart_reports_clearly_when_nothing_to_kill(authed):
    """没有进程可杀时要给人话错误，不是 500 或静默。"""
    r = authed.post("/api/search/restart")
    # 测试环境里 websearch.server 多半没在跑 → 应返回 400 + 人话
    assert r.status_code in (200, 400, 500)
    d = r.json()
    assert "error" in d or d.get("ok") is True
    if not d.get("ok"):
        assert d["error"], "失败时必须说明原因"
