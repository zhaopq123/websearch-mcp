# -*- coding: utf-8 -*-
"""节点有效性校验与自动探测测试。

背景（2026-10-13 实测踩坑）：
用户配了机场订阅、19 个节点、代理进程也起来了，但上不了网。
根因是订阅里第一个节点的 server 是 0.0.0.0（占位条目），
而它恰好被选成 selector 的 default —— 所有流量发往 0.0.0.0:443，
报 "connect: connection refused"。表面看像「节点全不通」，
实际是**坏节点污染了整个代理**。

教训：解析阶段必须过滤无效地址；启动时必须探测选节点。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.subparse import (
    NodeParseError,
    build_singbox_config,
    parse_node,
    parse_subscription_text,
)


# ══════════════════ 坏节点必须在解析阶段被拦下 ══════════════════


@pytest.mark.parametrize("bad_server", [
    "0.0.0.0",       # 最常见的占位地址（实测踩坑的就是它）
    "::",
    "127.0.0.1",     # 指向本机没意义
    "localhost",
    "::1",
])
def test_reject_invalid_server_address(bad_server):
    """占位/回环地址必须被拒 —— 否则会污染 selector 的 default。"""
    uri = f"trojan://testpass@{bad_server}:443?sni=x.com#坏节点"
    with pytest.raises(NodeParseError) as ei:
        parse_node(uri, 0)
    assert "无效" in str(ei.value)


def test_reject_missing_server():
    uri = "trojan://testpass@:443#空地址"
    with pytest.raises(NodeParseError):
        parse_node(uri, 0)


@pytest.mark.parametrize("bad_port", ["0", "99999", "-1"])
def test_reject_invalid_port(bad_port):
    uri = f"trojan://testpass@example.com:{bad_port}#坏端口"
    with pytest.raises(NodeParseError):
        parse_node(uri, 0)


def test_bad_node_excluded_from_subscription_report():
    """坏节点进 skipped，好节点进 nodes —— 不静默丢弃也不污染。"""
    good = "trojan://testpass@example.com:443?sni=x.com#好节点"
    bad = "trojan://testpass@0.0.0.0:443#占位节点"
    report = parse_subscription_text(f"{bad}\n{good}")
    assert len(report.nodes) == 1
    assert report.nodes[0].tag == "好节点"
    assert len(report.skipped) == 1
    assert "无效" in report.skipped[0]["reason"]


def test_bad_node_does_not_become_selector_default():
    """关键回归：坏节点绝不能成为 default。

    这是实测 bug 的直接复现 —— 坏节点在列表第一位，
    原实现把 tags[0] 当 default，于是全部流量走它。
    """
    bad = "trojan://testpass@0.0.0.0:443#占位节点"
    good = "trojan://testpass@example.com:443?sni=x.com#好节点"
    report = parse_subscription_text(f"{bad}\n{good}")
    cfg = build_singbox_config(report)
    sel = [o for o in cfg["outbounds"] if o["type"] == "selector"][0]
    assert sel["default"] == "好节点", f"default 是坏节点：{sel['default']}"
    assert "占位节点" not in sel["outbounds"], "坏节点不该出现在 selector 里"


def test_all_nodes_bad_degrades_to_direct():
    """全是坏节点 → 退化成 direct，而不是生成一个必然失败的配置。"""
    report = parse_subscription_text(
        "trojan://testpass@0.0.0.0:443#坏1\ntrojan://testpass@127.0.0.1:443#坏2"
    )
    cfg = build_singbox_config(report)
    assert cfg["route"]["final"] == "direct"
    assert not [o for o in cfg["outbounds"] if o["type"] == "selector"]


# ══════════════════ 显式指定默认节点（探测后切换用） ══════════════════


def test_default_tag_respected():
    """探测出最快节点后，配置里的 default 要能换成它。"""
    a = "trojan://pw@a.example.com:443#节点A"
    b = "trojan://pw@b.example.com:443#节点B"
    report = parse_subscription_text(f"{a}\n{b}")
    cfg = build_singbox_config(report, default_tag="节点B")
    sel = [o for o in cfg["outbounds"] if o["type"] == "selector"][0]
    assert sel["default"] == "节点B"


def test_unknown_default_tag_falls_back():
    """给了不存在的 tag 时退回第一个（不能让配置非法）。"""
    report = parse_subscription_text("trojan://pw@a.example.com:443#节点A")
    cfg = build_singbox_config(report, default_tag="不存在的节点")
    sel = [o for o in cfg["outbounds"] if o["type"] == "selector"][0]
    assert sel["default"] == "节点A"


# ══════════════════ 探测结果结构（不打真网络） ══════════════════


def test_probe_result_shape_in_summary(tmp_path):
    """summary() 要带 probe 字段（面板据此展示「几个节点可用」）。"""
    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tmp_path, singbox_bin="/nonexistent/sing-box")
    s = pm.summary()
    assert "probe" in s
    assert isinstance(s["probe"], dict)


def test_probe_without_nodes_is_clear(tmp_path):
    """没有节点时探测要给可读错误，不抛异常。"""
    import asyncio

    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tmp_path, singbox_bin="/nonexistent/sing-box")
    r = asyncio.run(pm.probe_nodes())
    assert r["ok"] is False
    assert "节点" in r["error"]


def test_probe_result_has_no_credentials(tmp_path):
    """探测结果会展示在面板上，绝不能含凭据。"""
    import json as _json

    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tmp_path, singbox_bin="/nonexistent/sing-box")
    # 手工塞一个探测结果（含节点名，但不该有 server/password/uuid）
    pm.probe_result = {
        "tested": 2, "alive_count": 1, "dead_count": 1,
        "best": "香港01", "best_ms": 120,
        "alive": [{"tag": "香港01", "ms": 120}],
        "at": 0,
    }
    blob = _json.dumps(pm.summary(), ensure_ascii=False)
    assert "香港01" in blob
    for secret in ("password", "uuid", "server", "0b6e8bb4"):
        assert secret not in blob.lower(), f"探测结果泄露了 {secret}"
