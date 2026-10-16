# -*- coding: utf-8 -*-
"""联网端到端测试。默认跳过，跑法：

    pytest -m online -v

需要真实网络。国内网络下部分国际引擎不可达属正常，
测试只断言「至少有可用引擎」和「结果相关性」。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.config import Config
from websearch.server import Service

QUERY = "无人零售 咖啡机 市场"
HITS = ("咖啡", "零售", "无人")


@pytest.fixture(scope="module")
def svc():
    """整个模块共用一个 Service 和一个事件循环。

    httpx 的连接池绑在创建它的事件循环上。如果每个用例各自
    run()（= 新建循环），第二个用例就会报 "Event loop is closed"。
    生产环境是单 loop 常驻，不存在这个问题 —— 这是测试写法的问题，
    不是服务的缺陷，所以测试这边改。
    """
    cfg = Config.from_env()
    cfg.cache_enabled = False  # E2E 要测真实链路，不走缓存
    service = Service(cfg)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    service._test_loop = loop
    yield service
    loop.run_until_complete(service.aclose())
    loop.close()


def run(coro):
    """在共享循环上跑协程。"""
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.mark.online
def test_warmup_finds_usable_engines(svc):
    info = run(svc.warmup())
    assert info is not None
    assert len(info.get("available", [])) >= 1, (
        f"一个引擎都不可用，网络或解析器有问题: {info.get('unavailable')}"
    )


@pytest.mark.online
def test_search_returns_relevant_results(svc):
    async def _body():
        return await svc.orch.search(QUERY, max_results=8)
    r = run(_body())

    assert r["results"], f"没有结果：{r['meta']['engines']}"
    # 至少一半结果要和查询相关（防止投毒结果混入）
    hit = sum(1 for x in r["results"]
              if any(h in (x["title"] + x["snippet"]) for h in HITS))
    assert hit >= max(1, len(r["results"]) // 2), (
        f"结果相关性过低 {hit}/{len(r['results'])}: "
        f"{[x['title'][:30] for x in r['results'][:5]]}"
    )


@pytest.mark.online
def test_meta_is_complete(svc):
    async def _body():
        return await svc.orch.search(QUERY, max_results=5)
    r = run(_body())
    m = r["meta"]
    for key in ("elapsed_ms", "engines", "coverage", "total_unique", "returned",
                "early_stopped", "cache_hits"):
        assert key in m, f"meta 缺字段 {key}"
    assert isinstance(m["engines"]["attempted"], list)
    assert isinstance(m["engines"]["succeeded"], list)
    assert isinstance(m["engines"]["failed"], list)


@pytest.mark.online
def test_search_respects_budget(svc):
    """总耗时不能超过全局预算太多（预算失控是现有方案的通病）。"""
    async def _body():
        return await svc.orch.search("人工智能", max_results=10)
    r = run(_body())
    budget = svc.cfg.total_budget_ms
    assert r["meta"]["elapsed_ms"] < budget * 1.6, (
        f"耗时 {r['meta']['elapsed_ms']}ms 超出预算 {budget}ms 太多"
    )


@pytest.mark.online
def test_fetch_extracts_content(svc):
    """抓一个稳定可抓的页面。"""
    async def _body():
        return await svc.orch.fetch_one(
            "https://docs.python.org/3/library/asyncio.html", max_chars=3000
        )
    fr = run(_body())
    assert fr.ok, f"抓取失败: {fr.error}"
    assert len(fr.text) > 500, f"正文太短: {len(fr.text)}"
    assert "asyncio" in fr.text


@pytest.mark.online
def test_fetch_blocks_private_url(svc):
    async def _body():
        return await svc.orch.fetch_one("http://127.0.0.1:22/")
    fr = run(_body())
    assert not fr.ok
    assert fr.error_kind == "blocked_url"


@pytest.mark.online
def test_deep_research_runs(svc):
    async def _body():
        return await svc.orch.research(
            ["咖啡机 市场 规模", "无人零售 趋势"],
            max_results_per_query=5, fetch_top=1, max_chars=1500,
        )
    rr = run(_body())
    assert rr["meta"]["queries_count"] == 2
    assert "sources" in rr


@pytest.mark.online
def test_concurrent_searches(svc):
    """并发安全：10 个查询同时打，不能互相干扰、不能崩。"""
    async def _body():
        queries = [f"测试查询{i} 咖啡" for i in range(10)]
        return await asyncio.gather(*[
            svc.orch.search(q, max_results=5) for q in queries
        ])
    rs = run(_body())
    assert len(rs) == 10
    assert all("meta" in r for r in rs)


@pytest.mark.online
def test_cache_works_and_fresh_bypasses(svc):
    """缓存要能用，但 fresh=True 必须完全绕过（实时性是硬要求）。"""
    svc.cfg.cache_enabled = True
    # 前面的用例已经把若干引擎打到熔断了（模块级 fixture 共享 Governor），
    # 这里先复位，否则首查可能一个引擎都成功不了、也就没有缓存可写。
    async def _body():
        # 前面的用例会把若干引擎打到熔断（模块级 fixture 共享状态），
        # 不先复位+warmup 的话，首查可能一个引擎都成功不了、也就无缓存可写。
        svc.gov.reset()
        await svc.orch.warmup()
        q = "咖啡机 市场规模"
        await svc.orch.search(q, max_results=5)
        await asyncio.sleep(0.6)
        cached = await svc.orch.search(q, max_results=5)
        fresh = await svc.orch.search(q, max_results=5, fresh=True)
        return cached, fresh
    cached, fresh = run(_body())
    assert cached["meta"]["cache_hits"] >= 1, (
        f"第二次查询没命中缓存 hits={cached['meta']['cache_hits']} "
        f"ok={cached['meta']['engines']['succeeded']} "
        f"skipped={cached['meta']['engines']['skipped']} "
        f"results={len(cached['results'])}"
    )
    assert fresh["meta"]["realtime"] is True
    assert fresh["meta"]["cache_hits"] == 0, "fresh=True 却走了缓存"


@pytest.mark.online
def test_time_range_forces_realtime(svc):
    """传了时间过滤就必须走实时 —— 给三天前的缓存等于没答。"""
    svc.cfg.cache_enabled = True
    async def _body():
        svc.gov.reset()
        await svc.orch.warmup()
        r = await svc.orch.search("咖啡机", max_results=5, time_range="w")
        return r
    r = run(_body())
    assert r["meta"]["realtime"] is True
    assert r["meta"]["cache_hits"] == 0
