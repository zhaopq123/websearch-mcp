"""治理层 —— 限流（令牌桶）+ 熔断（状态机）+ 健康度（EMA）。

为什么三个放一起：它们都是「per-engine 的一次调用能不能放行 / 结果怎么记」，
共享同一份 per-engine 状态。拆成三个类再互相引用，反而多一层间接。
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .config import Config

log = logging.getLogger("websearch.gov")


class RateLimiter:
    """令牌桶（惰性填充，无后台线程）。

    惰性填充：不跑 asyncio.sleep 循环，按「当前时间 - 上次时间」补令牌。
    vivo 上省掉 N 个常驻 task，这点开销在手机 CPU 上是能感觉到的。
    """

    __slots__ = ("rate", "burst", "_tokens", "_last", "_lock", "waiter_count")

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()
        self.waiter_count = 0

    def peek(self) -> float:
        """当前可用令牌（惰性结算的只读版，不消费、不加锁）。

        令牌桶是惰性填充：_tokens 只在 acquire() 时结算。直接读 _tokens
        在没人请求时永远是旧值（干涸后看起来永远没恢复）——
        容量感知判断必须走 peek，否则排队者全部饿死在假枯竭上。
        """
        now = time.monotonic()
        return min(self.burst, self._tokens + (now - self._last) * self.rate)

    async def acquire(self, timeout: float | None = None) -> bool:
        """拿一个令牌。返回 False = 超时没拿到（调用方应跳过该引擎，不是死等）。

        关键设计：**超时后返回 False 而不是无限等待**。
        限流是为了不被封 IP，但如果限流把请求卡到全局超时，
        那这次搜索就废了——宁可少一个源，也不能拖垮整体。
        """
        self.waiter_count += 1
        try:
            loop = time.monotonic()
            deadline = loop + timeout if timeout else None
            while True:
                async with self._lock:
                    now = time.monotonic()
                    self._tokens = min(
                        self.burst, self._tokens + (now - self._last) * self.rate
                    )
                    self._last = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return True
                    # 还要等多久才有下一个令牌
                    need = (1.0 - self._tokens) / self.rate if self.rate > 0 else 0.05
                if deadline is not None and time.monotonic() + need > deadline:
                    return False
                await asyncio.sleep(min(need, 0.5))
        finally:
            self.waiter_count -= 1


@dataclass
class Health:
    """单个引擎的健康画像。"""

    ema_success: float = 1.0        # 成功率 EMA
    latency_ema_ms: float = 0.0     # 延迟 EMA
    consecutive_fail: int = 0
    consecutive_ok: int = 0
    # 连续 soft fail 次数（zero_results/timeout：引擎「没坏但没产出」）。
    # 2026-10-15 压测新增字段：DDG 被免费池出口 IP 全量拉黑后连续
    # zero_results，soft 不计熔断 → 每轮搜索都白跑一次（服务日志
    # sr=0.065 仍 closed）。达 soft 阈值（hard 的 3 倍）才熔断，
    # 偶发不杀（weixin 误熔断 600s 的教训）。
    consecutive_soft: int = 0
    total_calls: int = 0
    total_ok: int = 0
    total_blocked: int = 0
    last_error: str = ""
    last_ok_at: float = 0.0
    # ── 熔断 ──
    state: str = "closed"           # closed | open | half_open
    open_until: float = 0.0
    cooldown: float = 0.0
    # ── 限流 ──
    limiter: RateLimiter = field(default_factory=lambda: RateLimiter(0.5, 3))

    def to_dict(self) -> dict[str, Any]:
        import time as _t

        return {
            "state": self.state,
            "ema_success": round(self.ema_success, 3),
            "latency_ema_ms": round(self.latency_ema_ms, 1),
            "consecutive_fail": self.consecutive_fail,
            "total_calls": self.total_calls,
            "total_ok": self.total_ok,
            "total_blocked": self.total_blocked,
            "success_rate": round(self.total_ok / self.total_calls, 3) if self.total_calls else 1.0,
            "last_error": self.last_error,
            "circuit_open_remaining_sec": (
                round(max(0.0, self.open_until - _t.monotonic()), 1)
                if self.state == "open"
                else 0.0
            ),
            "tokens_available": round(self.limiter._tokens, 2),
        }


class Governor:
    """per-engine 的放行/记账中心。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._h: dict[str, Health] = {}
        self._lock = asyncio.Lock()
        self.skipped_by_circuit = 0
        self.skipped_by_ratelimit = 0

    def health(self, engine: str) -> Health:
        h = self._h.get(engine)
        if h is None:
            rate, burst = self.cfg.engine_rates.get(
                engine, (self.cfg.rate_per_sec, self.cfg.rate_burst)
            )
            h = Health(limiter=RateLimiter(rate, burst))
            self._h[engine] = h
        return h

    def allow_now(self, engine: str) -> tuple[bool, str]:
        """熔断状态判定（不含限流，限流是异步的）。"""
        h = self.health(engine)
        now = time.monotonic()
        if h.state == "open":
            if now >= h.open_until:
                h.state = "half_open"
                log.info("引擎 %s 冷却结束 → half_open（放行一次探测）", engine)
                return True, "half_open"
            return False, "circuit_open"
        return True, h.state

    def ready_count(self) -> int:
        """非熔断且桶里有令牌的引擎数。

        用于准入层的容量感知：全枯竭时扇出必然空手而归。
        _h 为空（刚启动、预热还没建健康档案）时按"全部就绪"处理，
        避免启动期卡死。

        ⚠️ 2026-10-14 修死锁：冷却已结束（open_until 已过）但状态还是
        "open"的引擎**必须算就绪**。open→half_open 的转换只发生在
        allow_now() 里，而 allow_now 只在真正扇出时被调用——容量门若把
        这些引擎全跳过，就成了「门等引擎就绪、引擎等门放行」的互相等，
        搜索永久 server_busy（冷启动预热失败时实测复现：14 引擎全
        open，remaining=0 却谁都过不来，直到重启）。冷却结束即放行，
        让 acquire→allow_now 自己去翻 half_open，成败由探测说话。
        """
        if not self._h:
            return 99
        n = 0
        now = time.monotonic()
        for h in self._h.values():
            if h.state == "open" and now < h.open_until:
                continue  # 真在冷却中，不算
            if h.limiter.peek() >= 1.0:
                n += 1
        return n

    async def acquire(self, engine: str, timeout: float) -> tuple[bool, str]:
        """完整放行判定：熔断 + 令牌桶。"""
        ok, reason = self.allow_now(engine)
        if not ok:
            self.skipped_by_circuit += 1
            return False, reason
        got = await self.health(engine).limiter.acquire(timeout=timeout)
        if not got:
            self.skipped_by_ratelimit += 1
            return False, "rate_limited"
        return True, "ok"

    def record(
        self,
        engine: str,
        ok: bool,
        elapsed_ms: int = 0,
        error: str = "",
        blocked: bool = False,
        cancelled: bool = False,
        soft: bool = False,
    ) -> None:
        """记账。

        最重要的规则：**超时和被早停取消不计入失败**。
        否则「早停」这个优化会变成慢性自杀——每次搜索都取消慢引擎，
        慢引擎的连续失败数一路涨，最后被永久熔断，等于自断一臂。
        """
        if cancelled:
            # 只更新延迟，不动成败
            h = self.health(engine)
            h.latency_ema_ms = 0.7 * h.latency_ema_ms + 0.3 * elapsed_ms
            return

        h = self.health(engine)
        h.total_calls += 1
        a = self.cfg.cb_ema_alpha
        h.ema_success = (1 - a) * h.ema_success + a * (1.0 if ok else 0.0)
        if elapsed_ms:
            h.latency_ema_ms = (
                elapsed_ms if h.latency_ema_ms == 0
                else 0.7 * h.latency_ema_ms + 0.3 * elapsed_ms
            )

        if ok:
            h.total_ok += 1
            h.consecutive_fail = 0
            h.consecutive_ok += 1
            h.consecutive_soft = 0
            h.last_ok_at = time.monotonic()
            # 探测成功 → 闭合，冷却重置
            if h.state != "closed":
                log.info("引擎 %s 探测成功 → closed", engine)
                h.state = "closed"
                h.cooldown = 0.0
                h.open_until = 0.0
        else:
            h.consecutive_ok = 0
            h.last_error = error[:200]
            if blocked:
                h.total_blocked += 1
            if soft:
                # 软失败：引擎正常响应（或只是慢）但没产出。
                # 两种来源：
                #   · zero_results —— 可能查询本身无匹配，也可能是页面结构变更前兆
                #   · timeout —— 引擎在预算内没回（真实坏信号，但仍可能是网络抖动）
                # 共同点：都只降 EMA 权重（降权优于除名），不喂熔断计数。
                # 区别于 cancelled=True：**计入 total_calls**，
                # 否则健康面板会显示 success_rate=1.0 而引擎实际在连续超时
                # （实测 bing 连超 2 次、返回 0 结果，面板仍报 4/4 全成功）。
                # 不喂熔断是为了避免小众查询/偶发抖动误杀引擎
                # （实测 weixin 被误熔断 600s）。
                #
                # 2026-10-15 补充：连续 soft fail 达 soft 阈值（hard 的
                # 3 倍，见 cfg.cb_soft_failure_threshold）**也熔断**。
                # 实测 DDG 被免费池出口 IP 全量拉黑：sr=0.065、连续
                # zero_results 但永远 closed，每轮搜索白跑一次 8s 超时。
                # 「偶发不杀 + 持续死透杀」两条都要 —— 阈值拉开档次即可。
                h.consecutive_soft += 1
                if (h.consecutive_soft
                        >= self.cfg.cb_soft_failure_threshold):
                    log.info(
                        "引擎 %s 连续 %d 次无产出（soft fail）→ 熔断",
                        engine, h.consecutive_soft)
                    self._trip(h, engine)
                return
            h.consecutive_fail += 1
            if h.consecutive_fail >= self.cfg.cb_failure_threshold:
                self._trip(h, engine)

    def _trip(self, h: Health, engine: str) -> None:
        """跳闸。冷却时间指数增长，避免刚恢复又被打。"""
        base = self.cfg.cb_cooldown_sec
        h.cooldown = min(
            self.cfg.cb_cooldown_max_sec,
            (h.cooldown * 2) if h.cooldown else base,
        )
        h.state = "open"
        h.open_until = time.monotonic() + h.cooldown
        log.warning(
            "引擎 %s 连续失败 %d 次 → 熔断 %ss（last: %s）",
            engine, h.consecutive_fail, h.cooldown, h.last_error,
        )

    def force_open(self, engine: str, cooldown: float | None = None,
                   reason: str = "forced") -> None:
        """立即熔断（用于启动预热）。

        启动时不探测的话，每个不可达的引擎都要在**每一次搜索**里白等一个
        连接超时（实测 2.5s×4 = 10s，直接吃光全局预算）。
        预热一次，后面全部秒跳过。
        """
        h = self.health(engine)
        h.consecutive_fail = max(h.consecutive_fail, self.cfg.cb_failure_threshold)
        h.cooldown = min(
            self.cfg.cb_cooldown_max_sec, cooldown or self.cfg.cb_cooldown_sec
        )
        h.state = "open"
        h.open_until = time.monotonic() + h.cooldown
        h.last_error = reason[:200]
        log.info("引擎 %s 预热判定不可用 → 熔断 %ss（%s）", engine, h.cooldown, reason)

    def weight(self, engine: str, base: float) -> float:
        """有效权重 = 基础权重 × 健康度。

        用 0.3 的下限而不是直接归零：健康的源不够时，
        一个半死的源也比没有强——「降权」优于「除名」。
        """
        h = self.health(engine)
        return base * (0.3 + 0.7 * h.ema_success)

    def all_health(self) -> dict[str, dict[str, Any]]:
        return {k: v.to_dict() for k, v in self._h.items()}

    def reset(self, engine: str | None = None) -> None:
        if engine:
            h = self._h.get(engine)
            if h:
                h.state = "closed"
                h.open_until = 0.0
                h.consecutive_fail = 0
                h.cooldown = 0.0
        else:
            for h in self._h.values():
                h.state = "closed"
                h.open_until = 0.0
                h.consecutive_fail = 0
                h.cooldown = 0.0
