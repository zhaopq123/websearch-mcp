# -*- coding: utf-8 -*-
"""代理健康门测试 —— 「代理挂了不等于服务挂了」的回归。

这是降级设计的核心：用户配的代理随时可能失效（节点死、订阅过期、
sing-box 被 OOM），如果代理失效就让搜索不可用，那是把增强功能做成了
单点故障。这里钉住降级与恢复的行为。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.gate import ProxyGate, _is_proxy_failure


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
    """连续代理类失败达到阈值 → 降级直连。"""
    g = ProxyGate("http://127.0.0.1:17890")
    assert g.use_proxy is True
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError: connection refused")
    assert g.state.bypassed is True
    assert g.use_proxy is False, "达到阈值后应降级直连"
    assert g.state.bypass_count == 1


def test_success_resets_failure_counter():
    """中间成功一次就清零，避免「偶发失败累积」误降级。"""
    g = ProxyGate("http://127.0.0.1:17890")
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
    g = ProxyGate("http://127.0.0.1:17890")
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
    g = ProxyGate("http://127.0.0.1:17890")
    for _ in range(ProxyGate.FAIL_THRESHOLD):
        g.note_result(False, "ConnectError")
    assert g.state.bypass_count == 1
    for _ in range(10):
        g.note_result(False, "ConnectError")
    assert g.state.bypass_count == 1, "旁路期间不应重复计降级"


# ══════════════════ 恢复 ══════════════════


def test_restore_clears_bypass():
    g = ProxyGate("http://127.0.0.1:17890")
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

    g = ProxyGate("http://127.0.0.1:17890")
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

    g = ProxyGate("http://127.0.0.1:17890")
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

    g = ProxyGate("http://127.0.0.1:17890")
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

    g = ProxyGate("http://127.0.0.1:17890")
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
