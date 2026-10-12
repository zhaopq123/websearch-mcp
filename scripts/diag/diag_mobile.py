#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""移动端站点 + 更多候选源探测。

思路：移动版搜索页的反爬通常比 PC 版弱一个量级（百度/搜狗尤其明显），
而且 HTML 更干净、更好解析、流量更小（手机服务器省流量是刚需）。
"""
import asyncio
import json
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.config import Config
from websearch.extract import decode_bytes
from websearch.http_pool import HttpPool

Q = "无人零售 咖啡机 市场"
HITS = ("咖啡", "零售", "无人")

MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1")

CANDS = [
    ("百度移动", f"https://m.baidu.com/s?word={{q}}", MOBILE_UA),
    ("搜狗移动", f"https://m.sogou.com/web/searchList.jsp?keyword={{q}}", MOBILE_UA),
    ("360移动", f"https://m.so.com/s?q={{q}}", MOBILE_UA),
    ("必应移动", f"https://cn.bing.com/search?q={{q}}", MOBILE_UA),
    ("头条搜索", f"https://so.toutiao.com/search?keyword={{q}}", None),
    ("搜狗微信", f"https://weixin.sogou.com/weixin?type=2&query={{q}}", None),
    ("B站API", "https://api.bilibili.com/x/web-interface/search/type?search_type=video&keyword={q}", None),
    ("知乎", f"https://www.zhihu.com/search?q={{q}}", None),
    ("微博", f"https://s.weibo.com/weibo?q={{q}}", None),
    ("中国搜索", f"https://www.chinaso.com/newssearch/all?q={{q}}", None),
    ("Yandex", f"https://yandex.com/search/?text={{q}}", None),
    ("Ecosia", f"https://www.ecosia.org/search?q={{q}}", None),
    ("Mojeek", f"https://www.mojeek.com/search?q={{q}}", None),
    ("Marginalia", f"https://search.marginalia.nu/search?query={{q}}", None),
]


async def main():
    cfg = Config.from_env()
    pool = HttpPool(cfg)
    print(f"查询: {Q!r}\n")
    print(f"{'源':<10} {'状态':<6} {'大小':>8} {'命中':>4}  详情")
    print("-" * 78)

    for label, tpl, ua in CANDS:
        url = tpl.format(q=urllib.parse.quote_plus(Q))
        headers = {"User-Agent": ua} if ua else None
        try:
            resp = await pool.fetch(url, timeout_ms=9000, referer="", headers=headers)
        except Exception as ex:
            print(f"{label:<10} FAIL   {'':>8} {'':>4}  {type(ex).__name__}: {str(ex)[:40]}")
            continue
        try:
            html = decode_bytes(resp.content, resp.headers.get("content-type", ""))
        except Exception:
            html = resp.text
        hits = sum(1 for h in HITS if h in html)
        Path(f"/tmp/wsprobe/{label}.html").write_text(html, encoding="utf-8")
        # 数一下外部链接数量（判断是不是真结果页）
        ext = len(re.findall(r'https?://(?!\w*\.?(?:baidu|sogou|so\.com|toutiao|bilibili|zhihu|weibo)\.)', html))
        print(f"{label:<10} {resp.status_code:<6} {len(html):>8} {hits:>4}  外链~{ext}")

    # 头条：看看有没有内嵌 JSON
    print("\n=== 头条内嵌数据探测 ===")
    try:
        p = Path("/tmp/wsprobe/头条搜索.html")
        html = p.read_text(encoding="utf-8")
        for key in ("_SSR_HYDRATED_DATA", "__INITIAL_STATE__", "window._", "hydration"):
            if key in html:
                print(f"  发现 {key}")
        m = re.search(r'<script[^>]*>\s*window\._SSR_HYDRATED_DATA\s*=\s*(\{.*?\})</script>', html, re.S)
        if m:
            try:
                d = json.loads(m.group(1))
                print("  JSON keys:", list(d.keys())[:10])
            except Exception as e:
                print("  解析失败:", str(e)[:60], "样本:", m.group(1)[:120])
    except Exception as e:
        print("  读取失败", e)

    await pool.aclose()


if __name__ == "__main__":
    asyncio.run(main())
