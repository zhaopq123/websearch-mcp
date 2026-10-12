#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""压力测试：并发搜索 / 批量抓取 / 长跑稳定性 / 内存。

用法：
  ./venv/bin/python scripts/stress.py              # 全套
  ./venv/bin/python scripts/stress.py --quick      # 快速
"""
import argparse
import asyncio
import gc
import random
import resource
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.server import Service

QUERIES = [
    "无人零售 咖啡机 市场", "Python 异步编程", "2026 人工智能 趋势",
    "跨境电商 独立站", "小红书 运营 技巧", "抖音 算法 推荐机制",
    "供应链管理 数字化", "智能制造 工业4.0", "SaaS 定价策略",
    "微信 公众号 涨粉",
]


def rss_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except Exception:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def pct(vals, p):
    if not vals:
        return 0
    s = sorted(vals)
    i = min(len(s) - 1, int(len(s) * p / 100))
    return s[i]


async def bench_search(svc, concurrency, rounds, label):
    print(f"\n── {label}：并发 {concurrency} × {rounds} 轮 ──")
    all_ms, fails, empty = [], 0, 0
    sem = asyncio.Semaphore(concurrency)
    base_rss = rss_mb()

    async def one(q):
        async with sem:
            t0 = time.monotonic()
            try:
                r = await svc.orch.search(q, max_results=8)
            except Exception as e:
                return None, (time.monotonic() - t0) * 1000, f"{type(e).__name__}: {e}"
            ms = (time.monotonic() - t0) * 1000
            return r, ms, None

    for rd in range(rounds):
        qs = [(QUERIES[(i + rd) % len(QUERIES)]) for i in range(concurrency)]
        t0 = time.monotonic()
        results = await asyncio.gather(*[one(q) for q in qs])
        wall = (time.monotonic() - t0) * 1000
        for r, ms, err in results:
            if err:
                fails += 1
                continue
            all_ms.append(ms)
            if not r["results"]:
                empty += 1
        print(f"   第{rd+1}轮: 墙钟 {wall:>7.0f}ms  平均 {sum(all_ms[-concurrency:])/concurrency:>6.0f}ms")

    all_ms.sort()
    n = len(all_ms)
    print(f"  样本 {n}  失败 {fails}  空结果 {empty}")
    if all_ms:
        print(f"  延迟 P50 {pct(all_ms,50):>6.0f}ms  P90 {pct(all_ms,90):>6.0f}ms  "
              f"P99 {pct(all_ms,99):>6.0f}ms  max {all_ms[-1]:>6.0f}ms")
        print(f"  吞吐 {n/ (sum(all_ms)/1000) if all_ms else 0:>6.2f} req/s（按总耗时算）")
    print(f"  内存 RSS {base_rss:.0f}MB → {rss_mb():.0f}MB")
    return {"n": n, "fails": fails, "empty": empty, "p90": pct(all_ms, 90)}


async def bench_fetch(svc, urls, concurrency):
    print(f"\n── 批量抓取：{len(urls)} 个 URL，并发 {concurrency} ──")
    t0 = time.monotonic()
    frs = await svc.orch.fetch_many(urls, max_chars=3000, concurrency=concurrency)
    wall = (time.monotonic() - t0) * 1000
    ok = [f for f in frs if f.ok]
    chars = sum(len(f.text) for f in ok)
    print(f"  墙钟 {wall:.0f}ms  成功 {len(ok)}/{len(frs)}  总字符 {chars}")
    if ok:
        lat = sorted(f.elapsed_ms for f in ok)
        print(f"  延迟 P50 {pct(lat,50)}ms  P90 {pct(lat,90)}ms  max {lat[-1]}ms")
    return {"ok": len(ok), "total": len(frs), "wall_ms": wall}


async def bench_sustained(svc, seconds, qps):
    """长跑：按固定 QPS 持续打，看有没有退化/泄漏。"""
    print(f"\n── 长跑：{seconds}s，目标 {qps} QPS ──")
    start = time.monotonic()
    done, fails = 0, 0
    lat_batch = []
    base_rss = rss_mb()
    peak_rss = base_rss
    idx = 0
    while time.monotonic() - start < seconds:
        batch_start = time.monotonic()
        tasks = [
            svc.orch.search(QUERIES[(idx + i) % len(QUERIES)], max_results=5)
            for i in range(qps)
        ]
        idx += qps
        rs = await asyncio.gather(*tasks, return_exceptions=True)
        for r in rs:
            if isinstance(r, Exception):
                fails += 1
            else:
                done += 1
        peak_rss = max(peak_rss, rss_mb())
        # 维持目标 QPS
        elapsed = time.monotonic() - batch_start
        if elapsed < 1.0:
            await asyncio.sleep(1.0 - elapsed)
        if done % 20 < qps:
            gc.collect()
    total = time.monotonic() - start
    print(f"  完成 {done} 次，失败 {fails}  实际 {done/total:.2f} QPS")
    print(f"  内存 RSS {base_rss:.0f}MB → {rss_mb():.0f}MB（峰值 {peak_rss:.0f}MB）")
    print(f"  引擎健康：")
    for name, h in svc.gov.all_health().items():
        if h["total_calls"]:
            print(f"    {name:<12} {h['state']:<9} 成功 {h['total_ok']}/{h['total_calls']} "
                  f"平均 {h['latency_ema_ms']:.0f}ms 熔断 {h['total_blocked']}")
    print(f"  缓存: {svc.cache.stats()['hit_rate']:.0%} 命中")
    return {"done": done, "fails": fails, "qps": done / total,
            "rss_growth": rss_mb() - base_rss}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()

    cfg = Config.from_env()
    cfg.cache_enabled = True
    svc = Service(cfg)

    print("═" * 62)
    print(" websearch-mcp 压力测试")
    print(f" 引擎: {', '.join(cfg.active_engines())}")
    print(f" 预算: 总 {cfg.total_budget_ms}ms / 单引擎 {cfg.engine_timeout_ms}ms")
    print(f" 并发上限: {cfg.max_concurrency}  限流: {cfg.rate_per_sec}/s burst {cfg.rate_burst}")
    print("═" * 62)

    print("\n[1/5] 预热")
    t0 = time.monotonic()
    info = await svc.warmup()
    print(f"  {int((time.monotonic()-t0)*1000)}ms  可用: {info.get('available')}")

    r1 = await bench_search(svc, 5, 2, "低并发" if not args.quick else "并发搜索")

    if not args.quick:
        await bench_search(svc, 20, 2, "中并发")
        await bench_search(svc, 50, 1, "高并发")

    print("\n[3/5] 批量抓取")
    urls = [
        "https://docs.python.org/3/library/asyncio.html",
        "https://docs.python.org/3/library/json.html",
        "https://www.python.org/",
        "https://httpbin.org/html",
        "https://example.com/",
        "https://www.iana.org/domains/reserved",
    ]
    await bench_fetch(svc, urls, cfg.fetch_concurrency)

    if not args.quick:
        print("\n[4/5] 长跑稳定性")
        await bench_sustained(svc, seconds=30, qps=3)

    print("\n[5/5] 收尾")
    print(f"  连接池: {svc.pool.stats()}")
    print(f"  缓存:   {svc.cache.stats()}")
    print(f"  早停次数: {svc.orch.early_stops}")
    print(f"  熔断器跳过: {svc.gov.skipped_by_circuit}  限流跳过: {svc.gov.skipped_by_ratelimit}")
    await svc.aclose()
    print("\n完成。")


if __name__ == "__main__":
    asyncio.run(main())
