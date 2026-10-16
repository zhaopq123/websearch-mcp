# -*- coding: utf-8 -*-
"""治理层测试：限流 / 熔断 / 健康度。

这些是「系统不把自己作死」的保证，必须单测覆盖：
熔断写错会让早停慢性杀死慢引擎，限流写错会让请求卡到全局超时。
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.config import Config
from websearch.governor import Governor, RateLimiter


@pytest.fixture
def cfg():
    c = Config.from_env()
    c.cb_failure_threshold = 3
    c.cb_cooldown_sec = 1
    c.cb_cooldown_max_sec = 4
    c.rate_per_sec = 10
    c.rate_burst = 3
    return c


def test_rate_limiter_burst(cfg):
    async def run():
        rl = RateLimiter(rate=100, burst=3)
        for _ in range(3):
            assert await rl.acquire(timeout=1.0) is True
        # 第 4 个要等令牌补充；给足超时应该能拿到
        assert await rl.acquire(timeout=1.0) is True
    asyncio.run(run())


def test_rate_limiter_timeout_returns_false(cfg):
    """限流拿不到令牌必须返回 False 而不是死等 —— 否则会把请求卡到全局超时。"""
    async def run():
        rl = RateLimiter(rate=0.01, burst=1)  # 极慢
        assert await rl.acquire(timeout=0.05) is True
        t0 = time.monotonic()
        assert await rl.acquire(timeout=0.2) is False
        assert time.monotonic() - t0 < 1.0
    asyncio.run(run())


def test_circuit_opens_after_threshold(cfg):
    g = Governor(cfg)
    for _ in range(cfg.cb_failure_threshold):
        g.record("x", False, 100, "boom")
    assert g.health("x").state == "open"
    assert g.allow_now("x")[0] is False


def test_circuit_half_open_after_cooldown(cfg):
    g = Governor(cfg)
    for _ in range(cfg.cb_failure_threshold):
        g.record("x", False, 10, "boom")
    assert g.health("x").state == "open"
    # 冷却（1s）过后应进入 half_open 放行一次探测
    g.health("x").open_until = time.monotonic() - 0.01
    ok, reason = g.allow_now("x")
    assert ok is True and reason == "half_open"


def test_circuit_closes_on_success(cfg):
    g = Governor(cfg)
    for _ in range(cfg.cb_failure_threshold):
        g.record("x", False, 10, "boom")
    g.health("x").state = "half_open"
    g.record("x", True, 10)
    assert g.health("x").state == "closed"
    assert g.health("x").consecutive_fail == 0


def test_ready_count_counts_expired_cooldown(cfg):
    """冷却已过的 open 引擎必须算就绪——否则准入门和半开探测互相等死。

    2026-10-14 实测死锁：冷启动预热全失败 → 14 引擎全 open，300s 冷却
    过后 remaining=0 但状态还是 open，ready_count 全跳过 → 容量门永远
    不放行 → allow_now 永不被调用 → half_open 永不发生 → 搜索永久
    server_busy，只有重启能解。open→half_open 的转换只发生在
    allow_now，放行入口必须先把这些引擎算进来。
    """
    g = Governor(cfg)
    for name in ("a", "b"):
        for _ in range(cfg.cb_failure_threshold):
            g.record(name, False, 10, "boom")
    # 冷却中：不算就绪
    g.health("a").open_until = time.monotonic() + 100
    g.health("b").open_until = time.monotonic() + 100
    assert g.ready_count() == 0
    # 冷却结束：算就绪（放它去吃半开探测那一枪）
    g.health("a").open_until = time.monotonic() - 0.01
    assert g.ready_count() == 1
    g.health("b").open_until = time.monotonic() - 0.01
    assert g.ready_count() == 2
    # 且 allow_now 此时确实放行并翻 half_open
    ok, reason = g.allow_now("a")
    assert ok is True and reason == "half_open"


def test_ready_count_skips_active_cooldown_even_with_tokens(cfg):
    """真在冷却中的引擎，就算桶里有令牌也不算就绪。"""
    g = Governor(cfg)
    for _ in range(cfg.cb_failure_threshold):
        g.record("x", False, 10, "boom")
    g.health("x").open_until = time.monotonic() + 100
    assert g.health("x").limiter.peek() >= 1.0  # 桶是满的
    assert g.ready_count() == 0


def test_cooldown_grows_exponentially(cfg):
    """重复触发熔断时冷却应该翻倍，避免刚恢复又被打。"""
    g = Governor(cfg)
    # 不 reset，连续失败：每超过阈值一次就应延长冷却
    for _ in range(3):
        g.record("x", False, 10, "boom")
    c1 = g.health("x").cooldown
    for _ in range(2):
        g.record("x", False, 10, "boom")
    c2 = g.health("x").cooldown
    assert c2 > c1, f"冷却没有增长: {c1} -> {c2}"


def test_cancelled_not_counted_as_failure(cfg):
    """被早停取消的请求绝不能计入失败。

    否则「早停」这个优化会变成慢性自杀：每次搜索都取消慢引擎，
    慢引擎的连续失败数一路涨，最后被永久熔断，等于自断一臂。
    """
    g = Governor(cfg)
    for _ in range(10):
        g.record("slow", False, 5000, "cancelled", cancelled=True)
    assert g.health("slow").state == "closed"
    assert g.health("slow").consecutive_fail == 0


def test_success_ema_moves(cfg):
    g = Governor(cfg)
    assert g.health("x").ema_success == 1.0
    for _ in range(5):
        g.record("x", False, 10, "boom")
    g.reset("x")
    assert g.health("x").ema_success < 1.0


def test_weight_degrades_not_zero(cfg):
    """差的引擎降权而不是归零：健康源不够时，半死的源也比没有强。"""
    g = Governor(cfg)
    assert g.weight("x", 1.0) == 1.0
    for _ in range(10):
        g.record("x", False, 10, "boom")
    g.reset("x")
    w = g.weight("x", 1.0)
    assert 0 < w < 1.0


def test_force_open_for_warmup(cfg):
    g = Governor(cfg)
    g.force_open("dead", cooldown=300, reason="warmup failed")
    assert g.health("dead").state == "open"
    assert g.allow_now("dead")[0] is False


def test_reset_all(cfg):
    g = Governor(cfg)
    for name in ("a", "b"):
        for _ in range(3):
            g.record(name, False, 10, "boom")
    g.reset()
    assert all(h.state == "closed" for h in g._h.values())


# ══════════════ 2026-10-15 压测复盘：soft fail 熔断 ══════════════


def test_soft_fail_does_not_trip_below_threshold(cfg):
    """偶发 soft fail（<9 次）不熔断 —— 小众查询/抖动的误杀防护。"""
    g = Governor(cfg)
    for _ in range(cfg.cb_soft_failure_threshold - 1):
        g.record("weixin", False, 10, "zero_results", soft=True)
    assert g.health("weixin").state == "closed"
    assert g.health("weixin").consecutive_soft == cfg.cb_soft_failure_threshold - 1


def test_soft_fail_trips_at_threshold(cfg):
    """连续 soft fail 达阈值 → 熔断。

    实测背景：DDG 被免费池出口 IP 全量拉黑，sr=0.065 但永远 closed，
    每轮搜索白跑一次 8s 超时。
    """
    g = Governor(cfg)
    for _ in range(cfg.cb_soft_failure_threshold):
        g.record("ddg", False, 10, "zero_results", soft=True)
    assert g.health("ddg").state == "open"
    assert g.allow_now("ddg")[0] is False


def test_success_resets_soft_streak(cfg):
    """一次成功即清零 soft 连击 —— 恢复后不带着旧账。"""
    g = Governor(cfg)
    for _ in range(cfg.cb_soft_failure_threshold - 2):
        g.record("ddg", False, 10, "zero_results", soft=True)
    g.record("ddg", True, 100)
    assert g.health("ddg").consecutive_soft == 0
    # 再积累到阈值才熔断（证明清零生效）
    for _ in range(cfg.cb_soft_failure_threshold - 1):
        g.record("ddg", False, 10, "zero_results", soft=True)
    assert g.health("ddg").state == "closed"
    g.record("ddg", False, 10, "zero_results", soft=True)
    assert g.health("ddg").state == "open"
