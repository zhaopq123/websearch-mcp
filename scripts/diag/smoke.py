#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端冒烟：预热 → 搜索 → 缓存 → 批量抓取 → 深度检索 → 健康度。

在 vivo 上直接跑（服务代码目录的上级）：cd /opt/websearch-mcp && PYTHONPATH=src ...
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from websearch.config import Config
from websearch.server import Service


def show(t):
    print("\n" + "═" * 68)
    print(f" {t}")
    print("═" * 68)


async def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "无人零售 咖啡机 市场"
    cfg = Config.from_env()
    cfg.cache_enabled = True
    svc = Service(cfg)

    show("0. 启动预热")
    t0 = time.monotonic()
    info = await svc.warmup()
    print(f"耗时 {int((time.monotonic()-t0)*1000)}ms")
    print("  可用:", info.get("available"))
    for b in info.get("unavailable", []):
        print(f"  不可用: {b['engine']:<12} {b['error'][:44]}")

    show(f"1. 实时搜索: {query}")
    r = await svc.orch.search(query, max_results=8, fresh=True)
    m = r["meta"]
    print(f"耗时 {m['elapsed_ms']}ms  结果 {len(r['results'])} 条  覆盖 {m['coverage']}  "
          f"抓取时刻 {m['fetched_at']}  实时={m['realtime']}")
    print(f"引擎成功: {m['engines']['succeeded']}")
    if m["engines"]["failed"]:
        print(f"引擎失败: {[(x['engine'], x['error'][:26]) for x in m['engines']['failed']]}")
    for i, x in enumerate(r["results"][:6], 1):
        print(f"  {i}. [{x['score']:.2f}] {x['title'][:46]}")
        print(f"     {x['url'][:76]}")
        if x.get("snippet"):
            print(f"     ↳ {x['snippet'][:64]}")

    show("2. 相关性校验（防投毒）")
    hits = sum(1 for x in r["results"]
               if any(k in (x["title"] + x["snippet"]) for k in ("咖啡", "零售", "无人")))
    print(f"结果相关性: {hits}/{len(r['results'])} 条命中查询词  "
          f"{'OK' if hits >= max(1, len(r['results'])//2) else 'WARN 偏低'}")

    show("3. 缓存命中")
    await asyncio.sleep(0.5)
    r2 = await svc.orch.search(query, max_results=8)
    print(f"第二次耗时 {r2['meta']['elapsed_ms']}ms  cache_hits={r2['meta']['cache_hits']}  "
          f"(实时第一次 {m['elapsed_ms']}ms)")
    print(f"realtime={r2['meta']['realtime']}")

    show("4. 批量抓正文")
    urls = [x["url"] for x in r["results"][:3]]
    if urls:
        t1 = time.monotonic()
        frs = await svc.orch.fetch_many(urls, max_chars=1200)
        print(f"{len(urls)} 个 URL 并发抓取，墙钟 {int((time.monotonic()-t1)*1000)}ms")
        for f in frs:
            print(f"  {'OK  ' if f.ok else 'FAIL'} [{f.extractor:<11}] {f.elapsed_ms:>5}ms "
                  f"{f.bytes_read:>7}B  {f.url[:50]}")
            if f.ok:
                print(f"       {f.text[:100].replace(chr(10),' ')}...")

    show("5. 深度检索（3 查询并发）")
    t2 = time.monotonic()
    rr = await svc.orch.research(
        ["咖啡机 市场规模 2026", "无人零售 行业趋势", "智能咖啡机 投资"],
        max_results_per_query=6, fetch_top=1, max_chars=1000)
    print(f"耗时 {rr['meta']['elapsed_ms']}ms  抓到 {rr['meta']['sources_fetched']} 篇  "
          f"失败 {rr['meta']['sources_failed']} 篇")
    for q in rr["per_query"]:
        print(f"  {q['query']:<24} {q['count']} 条  覆盖 {q['coverage']}")

    show("6. 引擎健康度")
    for name, h in svc.gov.all_health().items():
        if h["total_calls"]:
            print(f"  {name:<12} {h['state']:<9} 成功 {h['total_ok']}/{h['total_calls']}  "
                  f"{h['latency_ema_ms']:.0f}ms  熔断 {h['total_blocked']}")

    show("7. 缓存与资源")
    print(" 缓存:", svc.cache.stats())
    print(" 连接池:", svc.pool.stats())

    await svc.aclose()
    print("\n冒烟完成。")


if __name__ == "__main__":
    asyncio.run(main())
