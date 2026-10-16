#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定位百度的 TypeError + 测试 %20 空格编码对必应的影响。"""
import asyncio
import re
import sys
import traceback
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.engines import REGISTRY, BingEngine
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool

Q = "无人零售 咖啡机 市场"
HITS = ("咖啡", "零售", "无人")


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)

    print("=== 1. 百度 TypeError 定位 ===")
    e = REGISTRY["baidu"]
    try:
        spec = e.build(Q, count=8)
        print("  build OK:", spec.url, spec.params)
        resp = await pool.fetch(spec.url, params=spec.params, timeout_ms=9000,
                                referer=spec.referer, headers=spec.extra_headers)
        html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
        print("  http", resp.status_code, len(html), "B")
        try:
            rs = e.parse(html, limit=5)
            print("  parse:", len(rs), "条")
            for r in rs[:3]:
                print("   -", r.title[:40])
        except Exception:
            traceback.print_exc()
    except Exception:
        traceback.print_exc()

    print("\n=== 2. 必应空格编码对照（+ vs %20）===")
    for label, enc in (("plus(+) ", urllib.parse.quote_plus(Q)),
                       ("pct20   ", urllib.parse.quote(Q)),
                       ("gbk     ", urllib.parse.quote(Q.encode("gbk", "ignore")))):
        url = f"https://cn.bing.com/search?q={enc}&count=16"
        try:
            resp = await pool.fetch(url, timeout_ms=9000, referer="https://cn.bing.com/")
            html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
            ts = []
            for m in re.finditer(r'<li\b[^>]*class="[^"]*b_algo[^"]*".*?</li>', html, re.I | re.S):
                am = re.search(r'<h2[^>]*>\s*<a[^>]*href="[^"]+"[^>]*>(.*?)</a>', m.group(0), re.I | re.S)
                if am:
                    ts.append(re.sub(r"<[^>]+>", "", am.group(1)).strip())
            good = sum(1 for t in ts if any(h in t for h in HITS))
            print(f"  {label} {len(ts):>2}条 命中{good:>2} | {ts[0][:44] if ts else '(无)'}")
        except Exception as ex:
            print(f"  {label} FAIL {type(ex).__name__}: {str(ex)[:60]}")

    print("\n=== 3. 其它候选引擎探测 ===")
    cands = [
        ("夸克/神马", "https://m.sm.cn/search?q={q}"),
        ("中国搜索", "https://www.chinaso.com/newssearch/all?q={q}"),
        ("Yandex", "https://yandex.com/search/?text={q}"),
        ("搜狗微信", "https://weixin.sogou.com/weixin?type=2&query={q}"),
        ("Startpage", "https://www.startpage.com/sp/search?query={q}"),
        ("Ecosia", "https://www.ecosia.org/search?q={q}"),
        ("Lukol", "https://www.lukol.com/search?q={q}"),
    ]
    for label, tpl in cands:
        url = tpl.format(q=urllib.parse.quote_plus(Q))
        try:
            resp = await pool.fetch(url, timeout_ms=8000, referer="")
            html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
            hits = sum(1 for h in HITS if h in html)
            print(f"  {label:<10} http {resp.status_code} {len(html):>7}B 命中关键词 {hits}")
        except Exception as ex:
            print(f"  {label:<10} FAIL {type(ex).__name__}: {str(ex)[:50]}")

    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
