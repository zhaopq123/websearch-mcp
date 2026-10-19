# -*- coding: utf-8 -*-
"""web_fetch 的「代理失败 → 直连兜底」回归。

背景（2026-10-16 vivo 实测）：自养节点池里的免费节点延迟能到 9 秒，
而 `web_fetch` 过去无条件走代理。结果是一条极隐蔽的故障链：

  1. 代理活着但慢 → 抓取读超时
  2. `fetch_many` 的 `wait_for` 超时 → cancel 掉 `fetch_one`
  3. `CancelledError` 是 `BaseException`，绕过 `except Exception`
     → 代理门收不到失败反馈，`consecutive_failures` 永远 0
  4. gate 永远不降级 → 所有 web_fetch 永远超时

面板上一点异常都看不出来（`bypassed=False`、`consecutive_failures=0`），
但整个抓正文功能已经瘫了。这个测试钉住修复后的行为：
**代理类失败必须自动直连重试一次。**

不跑真实网络：用假 pool 精确控制「第一次超时、第二次成功」。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx
import pytest

from websearch.cache import Cache
from websearch.config import Config
from websearch.governor import Governor
from websearch.http_pool import HttpPool
from websearch.orchestrator import (
    Orchestrator,
    _proxy_might_be_at_fault,
    _retry_timeout_ms,
)


# ── 辅助判定函数的单测 ──────────────────────────────────────

def test_proxy_fault_detector_accepts_network_errors():
    """网络层失败 → 认为「值得换直连重试」。"""
    for e in (httpx.ConnectTimeout("x"), httpx.ReadTimeout("x"),
              httpx.ConnectError("x"), httpx.ProxyError("x")):
        assert _proxy_might_be_at_fault(e), f"{type(e).__name__} 应判为代理类故障"


def test_proxy_fault_detector_rejects_site_answers():
    """站点答复（4xx/5xx、被反爬）→ 不该重试（换条路照样被拒）。"""
    for e in (httpx.HTTPStatusError("403", request=None, response=None),
              ValueError("empty_extraction")):
        assert not _proxy_might_be_at_fault(e), f"{type(e).__name__} 不该重试"


def test_proxy_fault_detector_reads_error_text():
    """异常文本里带超时/隧道失败字样也要认（有的错误被包装过）。"""
    assert _proxy_might_be_at_fault(RuntimeError("tunnel connection failed: 502"))
    assert _proxy_might_be_at_fault(RuntimeError("alL ConNection attempts failed"))


# ── fetch_one 的兜底行为 ────────────────────────────────────

class _FakePool:
    """假 HttpPool：第一次（走代理）抛超时，第二次（direct=True）成功。"""

    class _Gate:
        def note_result(self, ok, error=""):
            pass

    def __init__(self, *, first_exc, ok_direct: bool = True):
        self.first_exc = first_exc
        self.ok_direct = ok_direct
        self.calls: list[bool] = []
        self.gate = self._Gate()

    async def fetch(self, url, *, direct=False, **_kw):
        self.calls.append(direct)
        if not direct:
            raise self.first_exc
        if not self.ok_direct:
            raise httpx.ConnectTimeout("direct also failed")
        req = httpx.Request("GET", url)
        return httpx.Response(
            200, request=req,
            headers={"content-type": "text/html; charset=utf-8"},
            content=("<html><head><title>标题</title></head><body>"
                     "<p>正文内容，足够长以便抽取器认为有效。</p>"
                     "</body></html>").encode("utf-8"),
        )

    async def aclose(self):
        pass


def _orch_with(pool) -> Orchestrator:
    cfg = Config.from_env()
    cfg.cache_enabled = False
    o = Orchestrator(cfg, HttpPool(cfg), Cache(cfg), Governor(cfg))
    o.pool = pool  # type: ignore[assignment]
    return o


def test_fetch_falls_back_to_direct_when_proxy_times_out():
    """代理读超时 → 自动直连重试 → 拿到正文。"""
    pool = _FakePool(first_exc=httpx.ReadTimeout("proxy too slow"))
    o = _orch_with(pool)
    loop = asyncio.new_event_loop()
    try:
        fr = loop.run_until_complete(o.fetch_one("https://www.baidu.com"))
    finally:
        loop.close()

    assert pool.calls == [False, True], f"应先走代理再直连，实际 {pool.calls}"
    assert fr.ok, f"直连兜底应成功，实际 error={fr.error!r}"
    assert "正文内容" in (fr.text or ""), "应抽到正文"


def test_fetch_does_not_retry_on_site_rejection():
    """403 这类站点答复不该触发重试（白等一次超时）。"""
    pool = _FakePool(first_exc=httpx.HTTPStatusError(
        "403", request=None, response=None))
    o = _orch_with(pool)
    loop = asyncio.new_event_loop()
    try:
        fr = loop.run_until_complete(o.fetch_one("https://www.baidu.com"))
    finally:
        loop.close()

    assert pool.calls == [False], f"站点答复不该重试，实际 {pool.calls}"
    assert not fr.ok


def test_fetch_reports_error_when_both_paths_fail():
    """代理挂 + 直连也挂 → 老老实实报错，不假装成功。"""
    pool = _FakePool(first_exc=httpx.ConnectTimeout("proxy dead"), ok_direct=False)
    o = _orch_with(pool)
    loop = asyncio.new_event_loop()
    try:
        fr = loop.run_until_complete(o.fetch_one("https://www.baidu.com"))
    finally:
        loop.close()

    assert pool.calls == [False, True], "两条路都该试过"
    assert not fr.ok
    assert fr.error, "失败必须有 error 说明，不能静默"


# ── 重试预算（2026-10-19：两次各用满 6s 会吃光 12s 总预算） ──

def _cfg(budget_ms=12000, fetch_ms=6000):
    c = Config.from_env()
    c.total_budget_ms = budget_ms
    c.fetch_timeout_ms = fetch_ms
    return c


def test_retry_budget_shrinks_to_remaining():
    """第一次用掉 6s，总预算 12s → 重试只剩 12-6-1.5=4.5s。"""
    assert _retry_timeout_ms(6000, _cfg()) == 4500


def test_retry_budget_never_exceeds_fetch_timeout():
    """刚开始就失败 → 重试仍不超过单次抓取超时。"""
    assert _retry_timeout_ms(200, _cfg()) == 6000


def test_retry_skipped_when_budget_exhausted():
    """预算已耗尽 → 返回 None，别白等第二次超时。"""
    assert _retry_timeout_ms(11000, _cfg()) is None
    assert _retry_timeout_ms(12000, _cfg()) is None


def test_retry_skipped_when_remaining_below_minimum():
    """剩余不足 1s 也不重试（重试必然超时，纯浪费）。"""
    assert _retry_timeout_ms(10500, _cfg()) is None


# ── 失败原因不能是空白（2026-10-19 vivo 实测） ──

def test_empty_exception_message_falls_back_to_class_name():
    """httpx 的超时异常常常没有 message —— 返回空白 error 等于静默失败。"""
    from websearch.orchestrator import _err_text

    assert _err_text(httpx.ReadTimeout("")) == "ReadTimeout"
    assert _err_text(httpx.ConnectError("")) == "ConnectError"
    # 有 message 时保留类名 + 内容
    assert "ConnectTimeout" in _err_text(httpx.ConnectTimeout("proxy dead"))
    assert "proxy dead" in _err_text(httpx.ConnectTimeout("proxy dead"))


def test_fetch_failure_never_returns_empty_error():
    """两条路都挂且异常无 message → error 仍必须可读。"""
    pool = _FakePool(first_exc=httpx.ReadTimeout(""), ok_direct=False)
    o = _orch_with(pool)
    loop = asyncio.new_event_loop()
    try:
        fr = loop.run_until_complete(o.fetch_one("https://example.com/"))
    finally:
        loop.close()

    assert not fr.ok
    assert fr.error and fr.error.strip(), "失败必须带原因，不能空白"
