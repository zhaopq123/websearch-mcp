#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""诊断必应对中文查询的响应。"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import REGISTRY
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool
from websearch.text import canonicalize_url, domain_of

Q = "无人零售 咖啡机 市场"


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    for name in ("bing", "toutiao", "bing_intl"):
        e = REGISTRY[name]
        spec = e.build(Q, count=8)
        try:
            if spec.method == "POST":
                resp = await pool.fetch(spec.url, method="POST", data=spec.data,
                                        params=spec.params, timeout_ms=9000, referer=spec.referer)
            else:
                resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=9000,
                                        referer=spec.referer)
        except Exception as ex:
            print(f"{name}: FAIL {type(ex).__name__} {ex}")
            continue
        html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
        p = Path(f"/tmp/wsprobe/{name}_cn.html")
        p.write_text(html, encoding="utf-8")
        t = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        print(f"{name}: http {resp.status_code} {len(html)}B title={t.group(1)[:60] if t else '?'}")
        print(f"   final_url: {str(resp.url)[:100]}")
        print(f"   b_algo 次数: {html.count('b_algo')}, 结果链接域名 top5:")
        doms = {}
        for m in re.finditer(r'<a\b[^>]*href="(https?://[^"]+)"', html):
            d = domain_of(m.group(1))
            doms[d] = doms.get(d, 0) + 1
        for d, c in sorted(doms.items(), key=lambda x: -x[1])[:5]:
            print(f"     {d}: {c}")
    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
