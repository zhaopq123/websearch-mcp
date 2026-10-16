"""代理健康门 —— 让「代理挂了」不等于「服务挂了」。

核心问题：用户配了代理（可能指向本地 sing-box），但代理随时可能挂
（节点失效、订阅过期、sing-box 被 OOM 杀掉）。如果代理挂了就让整个
搜索服务不可用，那是把「增强功能」做成了「单点故障」。

设计（职责划分）：
  · **本模块只管决策**：当前该走代理还是直连、什么时候降级、什么时候恢复。
    不持有 httpx client —— client 由 HttpPool 统一管理，避免两处各建一份
    连接池（那会让连接复用失效，在手机 ARM 上代价很高）。
  · HttpPool 提供两个 client：走代理的与直连的，按本模块的判定选择。
  · 代理连续失败 N 次 → 打开「旁路」(bypass)，暂时直连。
  · 旁路期间定期探活，恢复了自动切回代理。
  · 探活用「墙外可达性」判定：能连上 google generate_204 才算好。
    只看 TCP 端口通不算 —— sing-box 活着但节点死了也会监听端口。

为什么不用「请求失败就重试直连」：
  那会让每次失败都多付一次超时（12s），用户体感是「时快时慢」。
  宁可提前探活，也不要事后补救。
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

log = logging.getLogger("websearch.proxy.gate")


@dataclass
class GateState:
    """代理门状态（给工具/面板读）。"""

    proxy_configured: bool = False
    proxy_url: str = ""
    using_proxy: bool = False
    bypassed: bool = False         # 是否处于旁路（降级直连）
    consecutive_failures: int = 0
    last_probe_ok: bool = False
    last_probe_ms: int = 0
    last_probe_at: float = 0.0
    last_error: str = ""
    bypass_count: int = 0          # 累计降级次数（可观测性）

    def to_dict(self) -> dict[str, Any]:
        return {
            # ⚠️ 2026-10-16：`configured` 是 `proxy_status` 工具 docstring
            # 一直声明的字段名，实现里却只给了 `proxy_configured` ——
            # 调用方按文档取 data["configured"] 直接 KeyError。
            # 两个都发：`configured` 是契约名，`proxy_configured` 是历史名
            # （panel 在用），删任一个都会打断一边，所以并存。
            "configured": self.proxy_configured,
            "proxy_configured": self.proxy_configured,
            # 掩码后再输出 —— 代理地址常写成 http://user:pass@host:port，
            # 原样返回会让面板/日志/工具输出泄露代理密码。
            "proxy_url": _mask_proxy(self.proxy_url) if self.proxy_configured else "",
            "using_proxy": self.using_proxy,
            "bypassed": self.bypassed,
            "consecutive_failures": self.consecutive_failures,
            "last_probe_ok": self.last_probe_ok,
            "last_probe_ms": self.last_probe_ms,
            "last_error": self.last_error,
            "bypass_count": self.bypass_count,
        }


def _mask_proxy(url: str) -> str:
    """掩码代理地址里的用户名密码。

    http://user:secret@host:17890 -> http://user:***@host:17890
    没有凭据时原样返回（大部分场景就是 127.0.0.1:port，无需掩码）。
    """
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit, urlunsplit

        p = urlsplit(url)
        if not (p.username or p.password):
            return url
        user = p.username or ""
        host = p.hostname or ""
        port = f":{p.port}" if p.port else ""
        return urlunsplit((p.scheme, f"{user}:***@{host}{port}", p.path, "", ""))
    except Exception:
        # 解析失败就别冒险输出原文
        return "***"


class ProxyGate:
    """代理健康门（纯决策，不持有连接）。"""

    # ⚠️ 阈值 5 而非 3：实测冷启动竞态下 3 次就够降级了。
    # 典型场景：服务重启时代理（sing-box）还在启动，头 2-3 个请求
    # 打不通就被判「代理坏了」，于是搜索服务降级直连，
    # 而代理其实几秒后就绪了 —— 表现为「代理明明正常，
    # 但搜索服务说什么都不走代理」。
    # 代价是：真坏时代理要多失败 2 次才降级（约 2 个请求周期，可接受）。
    FAIL_THRESHOLD = 5
    # 旁路后多久探活一次。30s 而非 60s：恢复要更快，
    # 因为「代理好了但搜索还直连」是最容易被误判成「服务坏了」的状态。
    PROBE_INTERVAL = 30.0
    # 探活宽限期：启动后这段时间内不判代理故障（给代理留启动时间）
    WARMUP_GRACE = 20.0
    PROBE_URL = "https://www.google.com/generate_204"

    def __init__(self, proxy_url: str, *, enabled: bool = True):
        self.proxy_url = (proxy_url or "").strip()
        self.enabled = bool(enabled and self.proxy_url)
        self.state = GateState(
            proxy_configured=bool(self.proxy_url),
            proxy_url=self.proxy_url,
            using_proxy=self.enabled,
        )
        self._last_probe_mono = 0.0
        self._lock = asyncio.Lock()
        # 启动时刻：宽限期内不判代理故障（见 note_result）
        self._born_mono = time.monotonic()

    # ── 决策 ──

    @property
    def use_proxy(self) -> bool:
        """当前该不该走代理。"""
        return self.enabled and not self.state.bypassed

    @property
    def in_warmup(self) -> bool:
        """是否还在启动宽限期内。"""
        return (time.monotonic() - self._born_mono) < self.WARMUP_GRACE

    # ── 结果反馈 ──

    def note_result(self, ok: bool, error: str = "") -> None:
        """报告一次请求结果，用于判断代理是否健康。

        两条规则：
        1. **只有指向代理自身的失败才算数**。引擎被反爬（403、
           验证码、marker）是目标站的行为，不是代理的问题 —— 把它算成
           代理故障会导致误降级（明明代理好好的，却因为百度封了就直连）。
        2. **启动宽限期内不判故障**。服务与代理同时启动时，头几个请求
           打不通是正常的（代理进程还在初始化、节点还在握手）。
           实测踩坑：宽限期不存在时，服务重启后 2-3 个请求就够降级，
           而代理几秒后就绪了 —— 表现是「代理明明正常，
           但搜索服务说什么都不走代理」，且**永远不会自己恢复**。
        """
        if not self.enabled or self.state.bypassed:
            return
        if ok:
            self.state.consecutive_failures = 0
            return
        if self.in_warmup:
            # 宽限期内只记录不降级
            self.state.last_error = f"启动宽限期内（{error or '连接失败'}）"
            return
        if error and not _is_proxy_failure(error):
            return
        self.state.consecutive_failures += 1
        if self.state.consecutive_failures >= self.FAIL_THRESHOLD:
            self._open_bypass(error)

    def _open_bypass(self, error: str) -> None:
        self.state.bypassed = True
        self.state.using_proxy = False
        self.state.bypass_count += 1
        self.state.last_error = error or "连续失败"
        self._last_probe_mono = time.monotonic()
        log.warning("代理连续失败 %d 次，降级为直连（原因：%s）",
                    self.state.consecutive_failures, self.state.last_error[:80])

    def restore(self) -> None:
        """恢复走代理。"""
        self.state.bypassed = False
        self.state.using_proxy = self.enabled
        self.state.consecutive_failures = 0
        self.state.last_error = ""
        log.info("代理已恢复，请求重新走代理")

    # ── 探活 ──

    async def maybe_probe(self, probe: Callable[[], Awaitable[bool]]) -> None:
        """旁路状态下定期探活；通了就恢复。

        probe 由调用方提供（它持有 client），本模块不碰网络。
        """
        if not self.enabled or not self.state.bypassed:
            return
        if time.monotonic() - self._last_probe_mono < self.PROBE_INTERVAL:
            return
        async with self._lock:
            # 双检：等锁期间可能已被别的协程探过
            if not self.state.bypassed:
                return
            if time.monotonic() - self._last_probe_mono < self.PROBE_INTERVAL:
                return
            self._last_probe_mono = time.monotonic()
            t0 = time.monotonic()
            try:
                ok = await probe()
            except Exception as e:
                ok = False
                self.state.last_error = f"探活异常：{type(e).__name__}"
            self.state.last_probe_ok = ok
            self.state.last_probe_ms = int((time.monotonic() - t0) * 1000)
            self.state.last_probe_at = time.time()
            if ok:
                self.restore()

    def note_probe(self, ok: bool, error: str = "") -> None:
        """记录一次探活结果（供 initial_probe 使用）。"""
        self.state.last_probe_ok = ok
        self.state.last_probe_at = time.time()
        if not ok:
            self.state.last_error = error or "探活失败"
            self._open_bypass(self.state.last_error)


def _is_proxy_failure(error: str) -> bool:
    """判断错误是否指向「代理本身有问题」。

    只有这些才算：
      · 连不上代理（ProxyError/ConnectError）
      · 超时（代理转发慢或死）
      · 隧道失败（CONNECT 被拒）
    引擎被反爬（marker:/403/验证码）不算 —— 那是目标站的事。
    """
    e = (error or "").lower()
    markers = (
        "proxyerror", "connecterror", "connecttimeout", "readtimeout",
        "timeout", "connection refused", "network is unreachable",
        "tunnel connection failed", "502 bad gateway",
        "all connection attempts failed",
    )
    return any(m in e for m in markers)
