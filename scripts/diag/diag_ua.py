#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证：移动 UA + PC 端点，现有解析器能不能出正确结果。

如果可以，就只需要换 UA，不用重写所有解析器（工作量差一个数量级）。
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

MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1")
DESKTOP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

TESTS = [
    ("bing", "https://cn.bing.com/search", {"q": Q, "count": 16}),
    ("baidu", "https://www.baidu.com/s", {"wd": Q, "rn": 16, "ie": "utf-8"}),
    ("sogou", "https://www.sogou.com/web", {"query": Q, "ie": "utf8"}),
    ("so360", "https://www.so.com/s", {"q": Q, "pn": 1, "src": "srp"}),
]


async def one(pool, name, url, params, ua, referer):
    try:
        resp = await pool.fetch(url, params=params, timeout_ms=9000,
                                referer=referer, headers={"User-Agent": ua})
    except Exception as ex:
        return f"FAIL {type(ex).__name__}: {str(ex)[:40]}"
    html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
    Path(f"/tmp/wsprobe/ua_{name}_{'m' if 'iPhone' in ua else 'd'}.html").write_text(
        html, encoding="utf-8")
    try:
        rs = REGISTRY[name].parse(html, limit=10)
    except Exception as ex:
        return f"PARSE_FAIL {type(ex).__name__}"
    good = sum(1 for r in rs if any(h in (r.title + r.snippet) for h in HITS))
    sample = rs[0].title[:36] if rs else "(无)"
    return f"{len(rs):>2}条 相关{good:>2} | {sample}"


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    print(f"查询: {Q!r}\n")
    print(f"{'引擎':<8} {'桌面UA':<46} {'移动UA':<46}")
    print("-" * 100)
    for name, url, params in TESTS:
        d = await one(pool, name, url, params, DESKTOP_UA, REGISTRY[name].homepage)
        m = await one(pool, name, url, params, MOBILE_UA, REGISTRY[name].homepage)
        print(f"{name:<8} {d:<46} {m:<46}")
    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
