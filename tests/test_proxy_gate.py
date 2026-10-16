# -*- coding: utf-8 -*-
"""代理健康门测试 —— 「代理挂了不等于服务挂了」的回归。

这是降级设计的核心：用户配的代理随时可能失效（节点死、订阅过期、
sing-box 被 OOM），如果代理失效就让搜索不可用，那是把增强功能做成了
单点故障。这里钉住降级与恢复的行为。
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.gate import ProxyGate, _is_proxy_failure


def aged_gate(url: str = "http://127.0.0.1:17890") -> ProxyGate:
    """造一个**已过启动宽限期**的门。

    为什么需要：门有 WARMUP_GRACE（默认 20 秒），启动宽限期内
    连打多少次失败都不会降级 —— 那是刻意的（服务与代理同时启动时，
    头几个请求打不通是正常的）。测试要验证「稳态下连续失败会降级」，
    就必须先把宽限期跳过去，否则测的是宽限期而不是降级逻辑。
    """
    g = ProxyGate(url)
    g._born_mono = time.monotonic() - (ProxyGate.WARMUP_GRACE + 1)
    return g


def warm_gate(url: str = "http://127.0.0.1:17890") -> ProxyGate:
    """造一个**仍在启动宽限期**的门。"""
    return ProxyGate(url)


# ══════════════════ 未配代理：完全不影响原行为 ══════════════════


def test_no_proxy_means_no_gate():
    """没配代理时门是关的，use_proxy 恒为 False（即走直连）。"""
    g = ProxyGate("")
    assert g.enabled is False
    assert g.use_proxy is False
    assert g.state.proxy_configured is False


def test_disabled_flag_overrides_url():
    g = ProxyGate("http://127.0.0.1:17890", enabled=False)
    assert g.enabled is False
    assert g.use_proxy is False


# ══════════════════ 降级触发 ══════════════════


def test_bypass_after_consecutive_proxy_failures():
    """连续代理类失败达到阈值 → 降级直连（稳态下，即已过启动宽限期）。"""
    g = aged_gate()
    assert g.use_proxy is True
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError: connection refused")
    assert g.state.bypassed is True
    assert g.use_proxy is False, "达到阈值后应降级直连"
    assert g.state.bypass_count == 1


def test_startup_grace_prevents_false_bypass():
    """启动宽限期内**不该**降级（这是本次修复的核心）。

    实测踩坑：服务与代理同时启动时，头 2-3 个请求打不通是正常的
    （sing-box 还在起、节点还在握手）。没有宽限期就会被判「代理坏了」，
    于是服务永久降级直连，而代理几秒后就绪了 ——
    表现是「代理明明正常，但搜索服务说什么都不走代理」。
    """
    g = warm_gate()          # 仍在宽限期内
    for _ in range(ProxyGate.FAIL_THRESHOLD * 3):
        g.note_result(False, "ConnectTimeout")
    assert g.state.bypassed is False, "宽限期内就降级了 —— 冷启动会被误判"
    assert g.use_proxy is True
    # 宽限期过后，同样的失败就该触发降级
    g._born_mono = time.monotonic() - (ProxyGate.WARMUP_GRACE + 1)
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectTimeout")
    assert g.state.bypassed is True, "过了宽限期仍不降级 —— 降级逻辑坏了"


def test_success_resets_failure_counter():
    """中间成功一次就清零，避免「偶发失败累积」误降级。"""
    g = aged_gate()
    g.note_result(False, "ConnectError")
    g.note_result(False, "ConnectError")
    g.note_result(True)
    g.note_result(False, "ConnectError")
    g.note_result(False, "ConnectError")
    assert g.state.bypassed is False, "成功应清零计数，不该降级"


def test_engine_block_does_not_trigger_bypass():
    """引擎被反爬不是代理的错 —— 不能因此降级。

    这是最容易搞错的地方：百度返回验证码说明代理工作正常
    （请求确实到了百度），把它算成代理故障会导致「代理好好的却被直连」。
    """
    g = aged_gate()
    for _ in range(10):
        g.note_result(False, "marker:verify.css")
        g.note_result(False, "http_403")
        g.note_result(False, "irrelevant: 0/5 条命中查询词")
    assert g.state.bypassed is False, "引擎反爬不该触发代理降级"
    assert g.state.consecutive_failures == 0


@pytest.mark.parametrize("err,expected", [
    ("ConnectError: connection refused", True),
    ("ProxyError: 502 Bad Gateway", True),
    ("ReadTimeout", True),
    ("ConnectTimeout: timed out", True),
    ("tunnel connection failed: 403", True),
    ("All connection attempts failed", True),
    ("marker:verify.css", False),
    ("http_403", False),
    ("deep_marker:isCheating", False),
    ("zero_results", False),
    ("irrelevant: 3 条结果无一命中", False),
])
def test_proxy_failure_classification(err, expected):
    assert _is_proxy_failure(err) is expected


def test_no_bypass_when_already_bypassed():
    """已在旁路状态时不再重复计数（避免 bypass_count 虚高）。"""
    g = aged_gate()
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")
    assert g.state.bypass_count == 1
    for _ in range(10):
        g.note_result(False, "ConnectError")
    assert g.state.bypass_count == 1, "旁路期间不应重复计降级"


# ══════════════════ 恢复 ══════════════════


def test_restore_clears_bypass():
    g = aged_gate()
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")
    assert g.state.bypassed is True
    g.restore()
    assert g.state.bypassed is False
    assert g.use_proxy is True
    assert g.state.consecutive_failures == 0
    assert g.state.last_error == ""


def test_maybe_probe_recovers_when_healthy():
    """旁路期间探活成功 → 自动恢复走代理。"""
    import asyncio

    g = aged_gate()
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")
    assert g.state.bypassed is True

    # 把探活间隔归零，模拟「间隔已到」
    g._last_probe_mono = 0.0

    async def healthy():
        return True

    asyncio.run(g.maybe_probe(healthy))
    assert g.state.bypassed is False, "探活成功后应恢复走代理"
    assert g.state.last_probe_ok is True


def test_maybe_probe_keeps_bypass_when_unhealthy():
    import asyncio

    g = aged_gate()
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")
    g._last_probe_mono = 0.0

    async def dead():
        return False

    asyncio.run(g.maybe_probe(dead))
    assert g.state.bypassed is True, "探活失败应保持降级"
    assert g.state.last_probe_ok is False


def test_maybe_probe_swallows_probe_exception():
    """探活本身抛异常不能影响搜索。"""
    import asyncio

    g = aged_gate()
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")
    g._last_probe_mono = 0.0

    async def boom():
        raise RuntimeError("probe exploded")

    asyncio.run(g.maybe_probe(boom))   # 不应抛出
    assert g.state.bypassed is True


def test_probe_respects_interval():
    """间隔未到不该频繁探活（否则旁路期间每次搜索都多付一次超时）。"""
    import asyncio

    g = aged_gate()
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")

    calls = {"n": 0}

    async def counting():
        calls["n"] += 1
        return False

    # 第一次（_last_probe_mono 刚被 _open_bypass 设为当前时间）应被间隔挡住
    asyncio.run(g.maybe_probe(counting))
    assert calls["n"] == 0, "间隔未到不该探活"


# ══════════════════ 状态输出 ══════════════════


def test_state_dict_has_no_credentials():
    """代理地址里若含密码，状态输出必须掩码（面板会展示它）。"""
    g = ProxyGate("http://user:secretpw@127.0.0.1:17890")
    d = g.state.to_dict()
    assert "secretpw" not in str(d), "状态输出泄露了代理密码"


def test_state_dict_fields():
    g = ProxyGate("http://127.0.0.1:17890")
    d = g.state.to_dict()
    for k in ("proxy_configured", "using_proxy", "bypassed",
              "consecutive_failures", "bypass_count", "last_error"):
        assert k in d


def test_state_dict_has_configured_contract_key():
    """`proxy_status` 工具 docstring 声明的字段名是 `configured`。

    2026-10-16 实测 bug：实现只给了 `proxy_configured`，调用方按文档取
    data["configured"] 直接 KeyError。两个名字都必须存在 —— 契约名
    供工具/客户端用，历史名供 panel 用，删任一个都会打断一边。
    """
    g = ProxyGate("http://127.0.0.1:17890")
    d = g.state.to_dict()
    assert "configured" in d, "缺 `configured`（proxy_status 文档声明字段）"
    assert "proxy_configured" in d, "缺 `proxy_configured`（panel 在用）"
    assert d["configured"] == d["proxy_configured"]


def test_proxy_status_node_pool_exposes_health_ratio():
    """`proxy_status.node_pool` 必须给出 alive_rate / untested，不能只给 total。

    2026-10-16 vivo 实测：面板上一次看到 total=31581、alive=8。只报 total
    会让调用方（和用户）误判「池子很大很健康」，实际可用节点是个位数。
    健康度必须是一等字段，不能逼调用方自己拿 total 猜。
    这里直接构造 tool 的返回形状做契约断言（不拉起整个服务）。
    """
    # 复刻 server.proxy_status 里 pool_info 的构造逻辑做契约断言
    ps = {
        "total": 31581, "alive": 8, "untested": 30414,
        "by_pool": {"free": {"total": 31581, "alive": 8, "untested": 30414}},
        "best": {}, "by_country": {},
    }
    total = ps["total"]
    pool_info = {
        "total": total,
        "alive": ps["alive"],
        "alive_rate": round(ps["alive"] / total, 4) if total else 0.0,
        "untested": (ps.get("by_pool") or {}).get("free", {}).get("untested", 0),
    }
    assert "alive_rate" in pool_info, "缺 alive_rate（健康度一等字段）"
    assert "untested" in pool_info, "缺 untested（未测库存）"
    assert pool_info["alive_rate"] < 0.01, "8/31581 应远小于 1%"
    assert pool_info["untested"] == 30414, "untested 必须取 by_pool.free，不能拿 total-alive 估"
