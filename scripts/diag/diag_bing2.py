#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""必应参数对照实验：找出中文查询下结果质量最高的参数组合。

评估指标：标题里出现「咖啡」或「零售」的比例 —— 查询是「无人零售 咖啡机 市场」，
正常结果里这两个词应该大量出现。全是「无」的字典页 = 查询被 Bing 改写了。
"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import BingEngine
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool

Q = "无人零售 咖啡机 市场"
HITS = ("咖啡", "零售", "无人")


def score(titles):
    if not titles:
        return 0.0, 0
    good = sum(1 for t in titles if any(h in t for h in HITS))
    return good / len(titles), good


async def try_variant(pool, label, url, params, extra_headers=None):
    try:
        resp = await pool.fetch(url, params=params, timeout_ms=9000,
                                referer="https://cn.bing.com/", headers=extra_headers)
    except Exception as ex:
        print(f"{label:<28} REQ_FAIL {type(ex).__name__}")
        return
    html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
    titles = []
    for m in re.finditer(r'<li\b[^>]*class="[^"]*b_algo[^"]*".*?</li>', html, re.I | re.S):
        am = re.search(r'<h2\b[^>]*>\s*<a\b[^>]*href="[^"]+"[^>]*>(.*?)</a>', m.group(0), re.I | re.S)
        if am:
            titles.append(re.sub(r"<[^>]+>", "", am.group(1)).strip())
    ratio, good = score(titles)
    print(f"{label:<28} {len(titles):>2} 条, 命中 {good:>2}, 质量 {ratio:.0%}")
    for t in titles[:3]:
        print(f"{'':<28}   - {t[:44]}")


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    print(f"查询: {Q!r}\n")

    variants = [
        ("A cn +默认参数", "https://cn.bing.com/search",
         {"q": Q, "count": 16, "first": 1}),
        ("B cn +mkt=zh-CN", "https://cn.bing.com/search",
         {"q": Q, "count": 16, "first": 1, "mkt": "zh-CN", "setlang": "zh-CN"}),
        ("C cn +mkt+ensearch=0", "https://cn.bing.com/search",
         {"q": Q, "count": 16, "first": 1, "mkt": "zh-CN", "setlang": "zh-CN", "ensearch": 0}),
        ("D www +mkt=zh-CN", "https://www.bing.com/search",
         {"q": Q, "count": 16, "first": 1, "mkt": "zh-CN", "setlang": "zh-CN"}),
        ("E www +form=QBLH", "https://www.bing.com/search",
         {"q": Q, "count": 16, "first": 1, "form": "QBLH", "mkt": "zh-CN"}),
        ("F cn +form=QBLH", "https://cn.bing.com/search",
         {"q": Q, "count": 16, "first": 1, "form": "QBLH", "mkt": "zh-CN", "setlang": "zh-CN"}),
        ("G cn 无 count/first", "https://cn.bing.com/search",
         {"q": Q}),
        ("H cn +mkt +完整浏览器头", "https://cn.bing.com/search",
         {"q": Q, "count": 16, "first": 1, "mkt": "zh-CN", "setlang": "zh-CN"}),
    ]
    for label, url, params in variants:
        await try_variant(pool, label, url, params)
        print()
    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
