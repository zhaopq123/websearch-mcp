#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对照实验：先访问引擎首页拿 cookie 再搜索，是否改善结果质量/反爬。

假设：百度/搜狗/必应对「没有 cookie 的冷请求」返回降级结果或验证页。
先访问一次首页拿到会话 cookie，很多反爬就能过。
"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import REGISTRY
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool

Q = "无人零售 咖啡机 市场"
HITS = ("咖啡", "零售", "无人")

PATTERNS = {
    "bing": (r'<li\b[^>]*class="[^"]*b_algo[^"]*".*?</li>',
             r'<h2\b[^>]*>\s*<a\b[^>]*href="[^"]+"[^>]*>(.*?)</a>'),
    "baidu": (r'<div\b[^>]*class="[^"]*(?:result|c-container)[^"]*"[^>]*>.*?(?=<div|</body>)',
              r'<h3\b[^>]*>\s*<a\b[^>]*href="[^"]+"[^>]*>(.*?)</a>'),
    "sogou": (r'<div\b[^>]*class="[^"]*(?:vrwrap|rb)[^"]*"[^>]*>.*?</div>\s*</div>',
              r'<h3\b[^>]*>\s*<a\b[^>]*href="[^"]+"[^>]*>(.*?)</a>'),
    "so360": (r'<li\b[^>]*class="[^"]*res-list[^"]*"[^>]*>.*?</li>',
              r'<h3\b[^>]*>\s*<a\b[^>]*href="[^"]+"[^>]*>(.*?)</a>'),
}


def titles_of(name, html):
    if name not in PATTERNS:
        return []
    blk, tit = PATTERNS[name]
    out = []
    for m in re.finditer(blk, html, re.I | re.S):
        am = re.search(tit, m.group(0), re.I | re.S)
        if am:
            out.append(re.sub(r"<[^>]+>", "", am.group(1)).strip())
    return out


async def run(pool, name, warm):
    e = REGISTRY[name]
    if warm:
        try:
            await pool.fetch(e.homepage, timeout_ms=8000, referer="")
            await asyncio.sleep(0.3)
        except Exception as ex:
            print(f"  {name} 首页预热失败: {type(ex).__name__}")
    spec = e.build(Q, count=8)
    try:
        if spec.method == "POST":
            resp = await pool.fetch(spec.url, method="POST", data=spec.data,
                                    params=spec.params, timeout_ms=9000, referer=spec.referer)
        else:
            resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=9000,
                                    referer=spec.referer)
    except Exception as ex:
        return f"REQ_FAIL {type(ex).__name__}"
    html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
    ts = titles_of(name, html)
    good = sum(1 for t in ts if any(h in t for h in HITS))
    return f"{len(ts):>2} 条, 命中 {good:>2}, 样例: {ts[0][:36] if ts else '(无)'}"


async def main():
    cfg = Config.from_env()
    for warm in (False, True):
        pool = HttpPool(cfg)
        print(f"\n=== cookie 预热 = {warm} ===")
        for name in ("bing", "baidu", "sogou", "so360"):
            r = await run(pool, name, warm)
            print(f"  {name:<10} {r}")
        await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
