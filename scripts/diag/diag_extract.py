#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""正文提取器专项测试：抓真实页面，看提取质量。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.extract import decode_bytes, extract, extract_builtin, HAVE_TRAFILATURA
from websearch.http_pool import HttpPool

URLS = [
    "https://www.ruanyifeng.com/blog/2019/11/python-mock.html",
    "https://zh.wikipedia.org/wiki/%E5%92%96%E5%95%A1%E6%9C%BA",
    "https://baike.baidu.com/item/%E6%97%A0%E4%BA%BA%E9%9B%B6%E5%94%AE",
    "https://www.sohu.com/a/772588309_121455468",
    "https://s.weibo.com/top/summary",
    "https://news.sina.com.cn/",
    "https://www.zhihu.com/question/26541458",
    "https://docs.python.org/3/library/asyncio.html",
]


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    print(f"trafilatura 可用: {HAVE_TRAFILATURA}\n")
    print(f"{'URL':<58} {'状态':<5} {'HTML':>8} {'提取':>7} {'引擎':<12} 标题")
    print("-" * 110)
    for u in URLS:
        try:
            resp = await pool.fetch(u, timeout_ms=12000)
            html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
        except Exception as ex:
            print(f"{u[:56]:<58} FAIL  {'':>8} {'':>7} {'':<12} {type(ex).__name__}: {str(ex)[:30]}")
            continue
        text, title, eng = extract(html, url=u, limit=4000)
        tb, tb_title = extract_builtin(html, 4000)
        flag = "OK" if text else "EMPTY"
        print(f"{u[:56]:<58} {flag:<5} {len(html):>8} {len(text):>7} {eng:<12} {title[:26]}")
        print(f"{'':<58} 内置提取器单独跑: {len(tb):>6} 字符")
        if text:
            print(f"{'':<58} 开头: {text[:90].replace(chr(10), ' ')!r}")
    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
