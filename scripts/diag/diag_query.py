#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断：查询词编码 + 单引擎结果正确性 + 正文提取器。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import REGISTRY
from websearch.extract import decode_bytes, extract
from websearch.http_pool import HttpPool

Q = "无人零售 咖啡机 市场"   # 硬编码，绕开 shell 传参


async def main():
    print("query repr:", repr(Q), "len:", len(Q))
    cfg = Config.from_env()
    pool = HttpPool(cfg)

    for name in ("bing", "so360"):
        e = REGISTRY[name]
        spec = e.build(Q, count=8)
        print(f"\n--- {name} ---")
        print("url:", spec.url)
        print("params:", {k: (repr(v)[:40]) for k, v in spec.params.items()})
        try:
            if spec.method == "POST":
                resp = await pool.fetch(spec.url, method="POST", data=spec.data,
                                        params=spec.params, timeout_ms=8000, referer=spec.referer)
            else:
                resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=8000,
                                        referer=spec.referer)
        except Exception as ex:
            print("  REQ FAIL:", type(ex).__name__, ex)
            continue
        print("  实际请求URL:", str(resp.url)[:120])
        html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
        rs = e.parse(html, limit=5)
        print(f"  解析 {len(rs)} 条")
        for r in rs[:4]:
            print(f"   - {r.title[:50]} | {r.url[:60]}")

    # 正文提取器诊断
    print("\n=== 正文提取诊断 ===")
    test_urls = [
        "https://baike.baidu.com/item/%E5%92%96%E5%95%A1%E6%9C%BA",
        "https://www.ruanyifeng.com/blog/2019/11/python-mock.html",
    ]
    for u in test_urls:
        try:
            resp = await pool.fetch(u, timeout_ms=10000)
            html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
            Path(f"/tmp/wsprobe/fetch_{u.split('/')[-1][:20]}.html").write_text(html, encoding="utf-8")
            text, title, extractor = extract(html, url=u, limit=800)
            print(f"  {u[:60]}")
            print(f"    {len(html)}B -> {len(text)} chars [{extractor}] title={title[:30]!r}")
            print(f"    {text[:120]!r}")
        except Exception as ex:
            print(f"  {u[:60]} FAIL {type(ex).__name__}: {str(ex)[:80]}")

    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
