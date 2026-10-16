#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump 移动端页面并统计结构，用于写解析器。"""
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool

Q = "无人零售 咖啡机 市场"
MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1")

TARGETS = {
    "baidu_m": ("https://m.baidu.com/s", {"word": Q}, MOBILE_UA),
    "sogou_m": ("https://m.sogou.com/web/searchList.jsp", {"keyword": Q}, MOBILE_UA),
    "so360_m": ("https://m.so.com/s", {"q": Q}, MOBILE_UA),
    "weixin": ("https://weixin.sogou.com/weixin", {"type": 2, "query": Q}, None),
}


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    for name, (url, params, ua) in TARGETS.items():
        headers = {"User-Agent": ua} if ua else None
        try:
            resp = await pool.fetch(url, params=params, timeout_ms=10000,
                                    referer="", headers=headers,
                                    max_bytes=cfg.search_max_bytes)
        except Exception as ex:
            print(f"{name}: FAIL {type(ex).__name__}: {str(ex)[:60]}")
            continue
        html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
        Path(f"/tmp/wsprobe/{name}.html").write_text(html, encoding="utf-8")
        print(f"\n=== {name}: http {resp.status_code}, {len(html)}B ===")
        # class 频次（找结果容器）
        classes = re.findall(r'class="([a-zA-Z0-9_\- ]{2,40})"', html)
        from collections import Counter
        for c, n in Counter(classes).most_common(14):
            print(f"   {n:>4}  .{c}")
    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
