#!/usr/bin/env python3
"""把各引擎的原始 HTML 存到磁盘，用于离线分析和改解析器。

在线调解析器是灾难：每次改一行正则都要重新发请求，还可能触发反爬。
存下来离线分析，一次抓取能调十轮正则。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import REGISTRY
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool

OUT = Path("/tmp/wsprobe")
OUT.mkdir(parents=True, exist_ok=True)


async def dump(name, engine, query, pool):
    spec = engine.build(query, count=10)
    try:
        if spec.method == "POST":
            resp = await pool.fetch(spec.url, method="POST", data=spec.data,
                                    params=spec.params, timeout_ms=10000,
                                    referer=spec.referer, headers=spec.extra_headers)
        else:
            resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=10000,
                                    referer=spec.referer, headers=spec.extra_headers)
    except Exception as e:
        print(f"{name}: FAIL {type(e).__name__}: {str(e)[:80]}")
        return
    html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
    p = OUT / f"{name}.html"
    p.write_text(html, encoding="utf-8")
    print(f"{name}: http {resp.status_code}, {len(html)} chars -> {p}")


async def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "Python 异步编程"
    only = sys.argv[2].split(",") if len(sys.argv) > 2 else None
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    tasks = []
    for n, e in REGISTRY.items():
        if only and n not in only:
            continue
        tasks.append(dump(n, e, query, pool))
    await asyncio.gather(*tasks)
    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
