# -*- coding: utf-8 -*-
"""搜索准入预算：排队 + 等令牌 必须共用同一个截止时间，且必须被报出来。

背景（2026-10-14 全量测试）：最坏情况下一次调用要 21 秒才返回，而
`meta.elapsed_ms` 只有几百毫秒 —— 因为 `search_queue_timeout` 被
**两段串起来各用一次**：先等准入（最多 12s），再等引擎令牌（又最多 12s）。
这段耗时还发生在 `_search_impl_gate` 的 t0 之前，所以既不在 elapsed 里、
也看不出它花在哪。这里把两条都钉死。
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.orchestrator import Orchestrator


class _Pool:
    """只提供准入包装会碰到的那一个方法。"""

    async def maybe_recover_proxy(self) -> None:
        return None


class _Gov:
    """可切换的就绪数：ready=0 用来卡住容量等待。"""

    def __init__(self, ready: int = 99):
        self._ready = ready

    def ready_count(self) -> int:
        return self._ready

    def allow_now(self, name):          # pragma: no cover - 本文件不走到
        return True, ""

    def record(self, *a, **k):          # pragma: no cover
        pass


def _orch(cfg: Config, gov) -> Orchestrator:
    return Orchestrator(cfg, _Pool(), None, gov)


@pytest.mark.asyncio
async def test_queue_and_capacity_wait_share_one_budget():
    """准入排队花掉的时间要从容量等待里扣掉，总等待不超过一个 timeout。"""
    cfg = Config()
    cfg.search_queue_timeout = 2.0
    cfg.max_search_concurrency = 1
    orch = _orch(cfg, _Gov(ready=0))

    await orch._adm.acquire()          # 占住唯一名额，逼后面这次排队

    async def _release_later():
        await asyncio.sleep(0.9)       # 必须 < timeout，否则只是准入超时
        orch._adm.release()

    holder = asyncio.create_task(_release_later())
    started = time.monotonic()
    res = await orch.search("排队预算测试", engine_names=[], fresh=True)
    wall = time.monotonic() - started
    await holder

    assert res["meta"]["error"] == "server_busy"
    # 旧实现：0.9s 排队 + 2.0s 容量等待 ≈ 2.9s
    # 新实现：两段共用一个截止时间 ≈ 2.0s（0.25s 轮询粒度 => 上限 ~2.25s）
    assert wall < 2.5, f"两段等待没有共用预算，总耗时 {wall:.2f}s"
    assert res["meta"]["queue_wait_ms"] >= 900


@pytest.mark.asyncio
async def test_busy_result_reports_queue_wait():
    """被拒（server_busy）也要给出排队耗时，不能只报 0。"""
    cfg = Config()
    cfg.search_queue_timeout = 0.5
    cfg.max_search_concurrency = 1
    orch = _orch(cfg, _Gov(ready=99))
    await orch._adm.acquire()
    res = await orch.search("忙碌路径", engine_names=[], fresh=True)
    orch._adm.release()
    assert res["meta"]["error"] == "server_busy"
    assert "queue_wait_ms" in res["meta"]
    assert res["meta"]["queue_wait_ms"] >= 400


@pytest.mark.asyncio
async def test_queue_wait_folded_into_elapsed():
    """成功路径：排队耗时单列 + 计入 elapsed_ms，口径是墙钟时间。"""
    cfg = Config()
    cfg.search_queue_timeout = 5.0
    cfg.max_search_concurrency = 2
    orch = _orch(cfg, _Gov(ready=99))

    async def _fake_gate(*a, **k):
        return {"query": a[0], "results": [], "meta": {"elapsed_ms": 30}}

    orch._search_impl_gate = _fake_gate                # type: ignore[assignment]
    res = await orch._search_impl("排队折算测试", engine_names=[])
    meta = res["meta"]
    assert "queue_wait_ms" in meta
    assert meta["elapsed_ms"] == 30 + meta["queue_wait_ms"]
