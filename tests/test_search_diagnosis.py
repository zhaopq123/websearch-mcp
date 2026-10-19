# -*- coding: utf-8 -*-
"""结果可观测性回归：空结果/低覆盖必须自带人话诊断。

背景（2026-10-16 实测）：vivo 生产上全引擎熔断时 `web_search` 返回
`results=[]` + `coverage=0.0`，`meta` 里只有 `succeeded=[]` —— 调用方
分不清「该查询确实无匹配」还是「服务整体退化了」。**静默的空结果是最坏
的结果**，必须由服务自己说清是哪一种。

不跑真实网络：把引擎放行层换成「全部熔断」，断言 `meta.diagnosis`
给出可操作的解释。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.cache import Cache
from websearch.config import Config
from websearch.governor import Governor
from websearch.http_pool import HttpPool
from websearch.orchestrator import Orchestrator


def _make() -> tuple[Orchestrator, Config]:
    cfg = Config.from_env()
    cfg.cache_enabled = False
    orch = Orchestrator(cfg, HttpPool(cfg), Cache(cfg), Governor(cfg))
    return orch, cfg


def test_diagnosis_present_and_explains_engine_blackout():
    """全部引擎熔断 → 诊断必须说是「服务退化」而非「查询无结果」。"""
    o, cfg = _make()
    engines = cfg.active_engines()

    async def _deny(engine, timeout):
        return False, "circuit_open"

    o.gov.acquire = _deny  # type: ignore[assignment]

    async def _trip_all():
        for e in engines:
            h = o.gov.health(e)
            h.state = "open"
            h.open_until = time_monotonic_huge()

    def time_monotonic_huge():
        import time
        return time.monotonic() + 10 ** 9

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_trip_all())
        res = loop.run_until_complete(o.search("asdfghjkl 无关词", fresh=True))
        loop.run_until_complete(o.pool.aclose())
    finally:
        loop.close()

    meta = res["meta"]
    assert res["results"] == []
    assert "diagnosis" in meta, "空结果必须带 meta.diagnosis"
    d = meta["diagnosis"]
    assert d, "空结果的 diagnosis 不能是空串"
    assert any(w in d for w in ("引擎", "熔断", "服务")), d


def test_busy_meta_also_has_diagnosis():
    """server_busy 走的是另一条 return，同样要有 diagnosis（形状一致）。"""
    o, cfg = _make()
    cfg.search_queue_timeout = 0.0
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(o.search("x", fresh=True))
        loop.run_until_complete(o.pool.aclose())
    finally:
        loop.close()
    meta = res["meta"]
    if meta.get("error") == "server_busy":
        assert "diagnosis" in meta, "server_busy 分支也要有 diagnosis"
        assert meta["diagnosis"], "diagnosis 不能为空"
