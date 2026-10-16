#!/usr/bin/env python3
"""引擎探针：逐个引擎发一次真实请求，看能不能解析出结果。

用途：改版检测 + 首次部署时的可用性摸底。
每个引擎的解析器都依赖对方的 HTML 结构，这个脚本是唯一能证明它们还活着的手段。
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import REGISTRY
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool, detect_block


async def probe_one(pool, name, engine, query, cfg):
    spec = engine.build(query, count=10)
    t0 = time.monotonic()
    try:
        if spec.method == "POST":
            resp = await pool.fetch(spec.url, method="POST", data=spec.data,
                                    params=spec.params, timeout_ms=8000,
                                    referer=spec.referer, headers=spec.extra_headers)
        else:
            resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=8000,
                                    referer=spec.referer, headers=spec.extra_headers)
    except Exception as e:
        return name, False, f"REQ_FAIL {type(e).__name__}: {str(e)[:90]}", 0, 0

    ms = int((time.monotonic() - t0) * 1000)
    html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
    blocked, reason = detect_block(resp.status_code, html)
    if blocked:
        return name, False, f"BLOCKED {reason} (http {resp.status_code})", 0, ms
    try:
        results = engine.parse(html, limit=10)
    except Exception as e:
        return name, False, f"PARSE_FAIL {type(e).__name__}: {str(e)[:90]}", 0, ms
    if not results:
        return name, False, f"ZERO_RESULTS (http {resp.status_code}, {len(html)}B)", 0, ms
    return name, True, f"http {resp.status_code}, {len(html)}B", len(results), ms


async def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "无人零售 咖啡机 2026"
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    print(f"探针查询: {query!r}\n")
    print(f"{'引擎':<12} {'状态':<6} {'结果数':<6} {'耗时ms':<7} 详情")
    print("-" * 90)

    tasks = [probe_one(pool, n, e, query, cfg) for n, e in REGISTRY.items()]
    results = await asyncio.gather(*tasks)

    ok_engines = []
    for name, ok, detail, count, ms in results:
        flag = "OK" if ok else "FAIL"
        print(f"{name:<12} {flag:<6} {count:<6} {ms:<7} {detail}")
        if ok:
            ok_engines.append(name)

    print("-" * 90)
    print(f"可用引擎 ({len(ok_engines)}/{len(results)}): {', '.join(ok_engines)}")

    # 打印每个可用引擎的第一条结果，肉眼确认解析质量
    print("\n各引擎首条结果抽样：")
    for name, ok, detail, count, ms in results:
        if not ok:
            continue
        e = REGISTRY[name]
        spec = e.build(query, count=5)
        try:
            if spec.method == "POST":
                resp = await pool.fetch(spec.url, method="POST", data=spec.data,
                                        params=spec.params, timeout_ms=8000,
                                        referer=spec.referer)
            else:
                resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=8000,
                                        referer=spec.referer)
            html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
            rs = e.parse(html, limit=3)
            for r in rs[:2]:
                print(f"  [{name}] {r.title[:44]:<46} | {r.snippet[:40]}")
        except Exception as ex:
            print(f"  [{name}] 抽样失败: {ex}")

    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
