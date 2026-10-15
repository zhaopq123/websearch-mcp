"""搜索引擎适配器。

设计原则：
  1. **零第三方解析依赖** —— 全用正则。lxml/bs4 在 aarch64 上编译成本高，
     而搜索结果页的结构足够规整，正则完全够用。
  2. **每个引擎都有专用解析器 + 通用兜底** —— 专用解析器 0 结果时自动回落到
     通用解析器（抓页面里所有「像结果」的链接）。网站改版不至于让整个源当天报废。
  3. **解析出 0 条也算失败** —— 不静默返回空列表，编排层要据此记账。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote_plus, unquote, parse_qs, urlsplit

from .models import SearchResult
from .text import clean_snippet, domain_of

log = logging.getLogger("websearch.engines")


@dataclass
class RequestSpec:
    url: str
    method: str = "GET"
    params: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] | None = None
    referer: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    # 是否走直连（跳过本地代理）。2026-10-15：国内引擎（百度/360/搜狗/
    # 微信/头条/cn.bing）在国内直连更快更稳，走海外代理出口反而被
    # 目标站拒绝（实测香港节点经代理请求百度恒 ConnectError）；
    # 国外引擎（DDG/bing_intl）必须走代理。由 Engine.needs_proxy 决定，
    # orchestrator 在 build 后填充。
    direct: bool = False


# ────────────────────────── 通用兜底解析器 ──────────────────────────

# 这些路径几乎不可能是搜索结果
_JUNK_PATH = re.compile(
    r"/(?:login|signin|signup|register|about|contact|privacy|terms|help|"
    r"settings|download|app|mobile|faq|sitemap|search|advanced)\b", re.I
)
_JUNK_EXT = re.compile(r"\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|pdf)$", re.I)

# 搜索引擎自己的域名。兜底解析器很容易把「百度首页/登录页/热搜榜」上的链接
# 当成搜索结果（实测抓到过 passport.baidu.com、top.baidu.com）。
# 但引擎的跳转壳（/link?url=、/link?m=）是**真实结果**，必须保留。
_SELF_HOSTS = {
    "baidu.com", "bdstatic.com", "sogou.com", "sogoucdn.com", "so.com",
    "360.cn", "bing.com", "microsoft.com", "msn.com", "toutiao.com",
    "toutiaoimg.com", "mojeek.com", "duckduckgo.com", "brave.com",
    "zhihu.com", "weibo.com",
}
_LINK_PATH = re.compile(r"^/(?:link|jump|url)\b", re.I)

# ── 结果后过滤（2026-10-14 全量测试复盘，实测噪声形态）──
# 1) 登录/验证/挑战页：baidu 搜 ChatGPT 时前 2 条曾是 passport.baidu.com
#    与 top.baidu.com；so360 返回过 cloudflare 验证页；这些「通了但
#    不是内容」的条目比没有结果更坏 —— 用户以为搜到了。
# 2) 已知仿冒站（域名黑名单）：实测搜 ChatGPT 返回 chatgpt-ai.com
#    仿冒官网。只列**实测抓到过**的，不做通用品牌仿冒猜测（误伤真站）。
_CHALLENGE_HOSTS = {
    "challenges.cloudflare.com",
}
# ── 游戏/小说/泛娱乐聚合站（2026-10-15 实测加入）──
# 搜「免费vpn节点」时 bing 返回 10 条里 9 条是游戏站（Poki/4399/7k7k/
# Playhop/小猪秒玩/Yandex Games）+ 小说站（17K）+ Steam——「免费」
# 一词命中混过了相关性校验。这类站对**任何信息检索查询**都是噪声
#（websearch 是查资料的服务，不是找游戏），域名级拉黑。
# 注意与 nodes/sources.py 的 _NOISE_DOMAINS 区分：那是节点源场景
#（github 在名单里），通用搜索里 github 是好结果，两份名单不共用。
_SEARCH_NOISE_HOSTS = {
    # 网页游戏平台
    "4399.com", "7k7k.com", "poki.com", "playhop.com", "pigame.cc",
    "yandex.com", "yandex.net", "4399dj.com", "3839.com", "2144.com",
    "337.com", "kaopu.com",
    # 免费小说站
    "17k.com", "qidian.com", "zongheng.com", "hongxiu.com",
    # 游戏商店（信息检索场景的泛娱乐噪声）
    "steampowered.com", "epicgames.com",
}
# ⚠️ 不拉黑正经媒体（澎湃/搜狐/网易等）——它们偶尔是搜索query的
# 正经结果（如「免费vpn节点」返回的校园 VPN 指南）。黑名单只收
# 「对任何信息检索查询都不可能相关」的纯娱乐聚合站。
_CHALLENGE_PATH = re.compile(r"/_cdn-cgi/|/cdn-cgi/", re.I)
_IMPERSONATION_HOSTS = {
    "chatgpt-ai.com",
}


def _is_self_noise(url: str) -> bool:
    """是不是引擎自身站点上的非结果链接。"""
    try:
        host = (urlsplit(url).hostname or "").lower().lstrip("www.")
    except ValueError:
        return False
    if not any(host == h or host.endswith("." + h) for h in _SELF_HOSTS):
        return False
    path = urlsplit(url).path or "/"
    return not _LINK_PATH.match(path)


def _is_noise_result(url: str) -> bool:
    """统一结果噪声判定：self 噪声 / 验证挑战页 / 已知仿冒站。"""
    if _is_self_noise(url):
        return True
    try:
        host = (urlsplit(url).hostname or "").lower().lstrip("www.")
        path = urlsplit(url).path or ""
    except ValueError:
        return False
    if host in _CHALLENGE_HOSTS or _CHALLENGE_PATH.search(path):
        return True
    if any(host == h or host.endswith("." + h)
           for h in _SEARCH_NOISE_HOSTS):
        return True
    return host in _IMPERSONATION_HOSTS


def generic_parse(html: str, engine: str, limit: int) -> list[SearchResult]:
    """通用兜底：抓所有「看起来像结果」的 <a>。

    启发式：链接文字长度 ≥ 8（中文 ≥ 4 字），目标不是本站的导航/登录页。
    这是最后一道防线，质量不如专用解析器，但有总比该源完全失效强。
    """
    # 可见文本门槛：反爬验证页通常只有几十个字的可见文本，
    # 但页面里的 <a> 不少（"关于搜狗""企业推广"之类）。
    # 不设这个门槛，兜底解析器会把验证页的导航链接当成搜索结果返回 ——
    # 那是最坏的一类错误：**看起来成功了的失败**。
    visible = _strip_tags(re.sub(r"<(?:head)\b.*?</head>", " ", html, flags=re.I | re.S))
    if len(visible) < 500:
        return []

    out: list[SearchResult] = []
    seen: set[str] = set()
    # 只取带 href 的 a 标签，捕获其可见文字
    for m in re.finditer(
        r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.I | re.S
    ):
        href = m.group(1).strip()
        text = re.sub(r"<[^>]+>", "", m.group(2))
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) < 4:
            continue
        if not href.startswith("http"):
            continue
        if _JUNK_EXT.search(href) or _JUNK_PATH.search(href):
            continue
        if _is_self_noise(href):
            continue
        key = href
        if key in seen:
            continue
        seen.add(key)
        out.append(
            SearchResult(
                title=text[:200], url=href, snippet="", engine=engine,
                rank=len(out), site=domain_of(href),
            )
        )
        if len(out) >= limit:
            break
    return out


def _strip_tags(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s or "")
    return re.sub(r"\s+", " ", s).strip()


# ────────────────────────── 基类 ──────────────────────────


class Engine:
    name = "base"
    label = "Base"
    weight = 1.0
    homepage = ""
    supports_time = False
    # 是否需要翻墙（走本地代理）。国内引擎置 False → 直连：
    # 实测国内站经海外代理出口恒被拒（百度 ConnectError），
    # 而直连百度仅 1.1s。默认 True 保持原行为（国外引擎）。
    needs_proxy = True

    def build(self, query: str, *, count: int = 10, lang: str = "",
              region: str = "", time_range: str = "", page: int = 1) -> RequestSpec:
        raise NotImplementedError

    def parse(self, html: str, limit: int = 10) -> list[SearchResult]:
        raise NotImplementedError

    def _fallback(self, html: str, limit: int) -> list[SearchResult]:
        return generic_parse(html, self.name, limit)


# ────────────────────────── Bing ──────────────────────────


class BingEngine(Engine):
    """cn.bing.com。国内可用，质量高，反爬中等。"""

    name = "bing"
    label = "必应（中国）"
    weight = 1.0
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://cn.bing.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        params: dict[str, Any] = {
            "q": query,
            "count": min(count * 2, 50),
            "first": (page - 1) * count + 1,
        }
        if lang:
            params["setlang"] = lang
            params["mkt"] = region or ("zh-CN" if lang.startswith("zh") else "en-US")
        # Bing 的时间过滤：ex1:"ez5"=24h ez4=一周 ez3=一月 ez2=一年
        if time_range:
            params["filters"] = {
                "d": 'ex1:"ez5"', "w": 'ex1:"ez4"',
                "m": 'ex1:"ez3"', "y": 'ex1:"ez2"',
            }.get(time_range, "")
        return RequestSpec(
            url="https://cn.bing.com/search", params=params, referer=self.homepage
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        # Bing 的每条结果块
        for m in re.finditer(
            r'<li\b[^>]*class="[^"]*b_algo[^"]*".*?</li>', html, re.I | re.S
        ):
            block = m.group(0)
            am = re.search(r'<h2\b[^>]*>\s*<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                           block, re.I | re.S)
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if not url.startswith("http") or not title:
                continue
            snippet = ""
            # 摘要可能在 <p> 或 class="b_caption"/b_lineclamp*
            sm = re.search(
                r'<p\b[^>]*>(.*?)</p>|<div\b[^>]*class="[^"]*b_caption[^"]*"[^>]*>.*?'
                r'<p\b[^>]*>(.*?)</p>',
                block, re.I | re.S,
            )
            if sm:
                snippet = _strip_tags(sm.group(1) or sm.group(2) or "")
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


class BingIntlEngine(BingEngine):
    needs_proxy = True    # 国际版必须走代理（覆盖基类）
    """www.bing.com。国际版，作为国内版的互补（索引略有差异）。"""

    name = "bing_intl"
    label = "必应（国际）"
    weight = 0.9
    homepage = "https://www.bing.com/"

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        spec = super().build(query, count=count, lang=lang, region=region,
                             time_range=time_range, page=page)
        spec.url = "https://www.bing.com/search"
        spec.referer = self.homepage
        spec.params["setlang"] = lang or "en"
        spec.params["mkt"] = region or "en-US"
        # 国际版加 cc 有时更稳
        spec.params["form"] = "QBLH"
        return spec


# ────────────────────────── 百度 ──────────────────────────


class BaiduEngine(Engine):
    """百度。中文覆盖最强，反爬最凶 —— 熔断机制主要就是为它准备的。"""

    name = "baidu"
    label = "百度"
    weight = 1.0
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://www.baidu.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        params: dict[str, Any] = {
            "wd": query,
            "rn": min(count * 2, 50),
            "pn": (page - 1) * count,
            "ie": "utf-8",
        }
        # 百度的 rtt：1=一天 2=一周 3=一月 4=一年
        if time_range:
            params["rtt"] = {"d": 1, "w": 2, "m": 3, "y": 4}.get(time_range, "")
            params["bsft"] = 1
        return RequestSpec(
            url="https://www.baidu.com/s", params=params, referer=self.homepage,
            extra_headers={"Accept-Language": "zh-CN,zh;q=0.9"},
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        # 百度结果块：class 里含 result / c-container
        for m in re.finditer(
            r'<div\b[^>]*class="[^"]*(?:result|c-container)[^"]*"[^>]*>.*?(?=<div\b[^>]*'
            r'class="[^"]*(?:result|c-container)[^"]*"|</body>)',
            html, re.I | re.S,
        ):
            block = m.group(0)
            am = re.search(
                r'<h3\b[^>]*class="[^"]*t[^"]*"[^>]*>\s*<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                block, re.I | re.S,
            )
            if not am:
                am = re.search(r'<a\b[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                               block, re.I | re.S)
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if not url.startswith("http") or not title:
                continue
            snippet = ""
            for pat in (
                r'<div\b[^>]*class="[^"]*c-abstract[^"]*"[^>]*>(.*?)</div>',
                r'<span\b[^>]*class="[^"]*content-right[^"]*"[^>]*>(.*?)</span>',
                r'<p\b[^>]*>(.*?)</p>',
            ):
                sm = re.search(pat, block, re.I | re.S)
                if sm:
                    snippet = _strip_tags(sm.group(1))
                    if snippet:
                        break
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


# ────────────────────────── 搜狗 ──────────────────────────


class SogouEngine(Engine):
    name = "sogou"
    label = "搜狗"
    weight = 0.85
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://www.sogou.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        params: dict[str, Any] = {
            "query": query,
            "page": page,
            "ie": "utf8",
        }
        # tsn: 1=一天 2=一周 3=一月 4=一年
        if time_range:
            params["tsn"] = {"d": 1, "w": 2, "m": 3, "y": 4}.get(time_range, "")
            params["sort"] = 1
        return RequestSpec(
            url="https://www.sogou.com/web", params=params, referer=self.homepage
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(
            r'<div\b[^>]*class="[^"]*(?:vrwrap|rb)[^"]*"[^>]*>.*?</div>\s*</div>',
            html, re.I | re.S,
        ):
            block = m.group(0)
            am = re.search(
                r'<h3\b[^>]*>\s*<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.I | re.S
            )
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            # 搜狗是 /link?url=xxx 跳转，最终 URL 藏在参数里
            if url.startswith("/link"):
                url = "https://www.sogou.com" + url
            if not title:
                continue
            snippet = ""
            sm = re.search(
                r'<div\b[^>]*class="[^"]*(?:text-layout|star-wiki|fz-mid|space-txt)[^"]*"'
                r'[^>]*>(.*?)</div>',
                block, re.I | re.S,
            )
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        if not out:
            # 新版搜狗结构：class="vr-title"
            for m in re.finditer(
                r'<h3\b[^>]*class="[^"]*vr-title[^"]*"[^>]*>\s*<a\b[^>]*href="([^"]+)"'
                r'[^>]*>(.*?)</a>', html, re.I | re.S
            ):
                url, title = m.group(1), _strip_tags(m.group(2))
                if url.startswith("/link"):
                    url = "https://www.sogou.com" + url
                out.append(SearchResult(
                    title=title[:200], url=url, snippet="", engine=self.name,
                    rank=len(out), site=domain_of(url),
                ))
                if len(out) >= limit:
                    break
        return out or self._fallback(html, limit)


# ────────────────────────── 360 搜索 ──────────────────────────


class So360Engine(Engine):
    """360 搜索。反爬最弱，是很稳的兜底源。"""

    name = "so360"
    label = "360搜索"
    weight = 0.8
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://www.so.com/"

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        return RequestSpec(
            url="https://www.so.com/s",
            params={"q": query, "pn": page, "j": 1, "src": "srp"},
            referer=self.homepage,
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(r'<li\b[^>]*class="[^"]*res-list[^"]*"[^>]*>.*?</li>',
                             html, re.I | re.S):
            block = m.group(0)
            # 优先取 data-mdurl —— 那是结果的**真实地址**。
            # href 是 so.com/link?m=... 跳转壳：抓正文必失败（360 对它直接返回
            # 400 + JS 弹回首页），而且每次 m 值都不同，会让 URL 规范化去重彻底失效。
            am = re.search(
                r'<a\b[^>]*data-mdurl="(https?://[^"]+)"[^>]*>(.*?)</a>',
                block, re.I | re.S,
            )
            if not am:
                am = re.search(
                    r'<h3\b[^>]*>\s*<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                    block, re.I | re.S,
                )
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if not url.startswith("http") or not title:
                continue
            snippet = ""
            sm = re.search(
                r'<p\b[^>]*class="[^"]*res-desc[^"]*"[^>]*>(.*?)</p>'
                r'|<div\b[^>]*class="[^"]*res-desc[^"]*"[^>]*>(.*?)</div>',
                block, re.I | re.S,
            )
            if sm:
                snippet = _strip_tags(sm.group(1) or sm.group(2) or "")
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


# ────────────────────────── DuckDuckGo ──────────────────────────


class DuckDuckGoEngine(Engine):
    """DDG HTML 版。注意它的链接是跳转壳，uddg 参数里才是真 URL。"""

    name = "duckduckgo"
    label = "DuckDuckGo"
    weight = 0.95
    homepage = "https://duckduckgo.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        data = {"q": query, "b": "", "kl": region or "wt-wt"}
        if time_range:
            data["df"] = {"d": "d", "w": "w", "m": "m", "y": "y"}.get(time_range, "")
        # DDG 的 HTML 端点对 POST 更友好（GET 也行，但 POST 更少被拦）
        return RequestSpec(
            url="https://html.duckduckgo.com/html/",
            method="POST", data=data, referer=self.homepage,
        )

    @staticmethod
    def _unwrap(href: str) -> str:
        """把 //duckduckgo.com/l/?uddg=<urlencoded> 还原成真 URL。"""
        if "uddg=" in href:
            q = parse_qs(urlsplit(href).query)
            real = q.get("uddg", [""])[0]
            if real:
                return unquote(real)
        if href.startswith("//"):
            return "https:" + href
        return href

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(
            r'<a\b[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
            html, re.I | re.S,
        ):
            url = self._unwrap(m.group(1))
            title = _strip_tags(m.group(2))
            if not url.startswith("http") or not title:
                continue
            out.append(SearchResult(
                title=title[:200], url=url, snippet="", engine=self.name,
                rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        # 摘要在另一个块里，按位次对齐补上
        snips = [
            _strip_tags(x)
            for x in re.findall(
                r'<a\b[^>]*class="[^"]*result__snippet[^"]*"[^>]*>(.*?)</a>',
                html, re.I | re.S,
            )
        ]
        for i, s in enumerate(snips):
            if i < len(out):
                out[i].snippet = clean_snippet(s)
        return out or self._fallback(html, limit)


# ────────────────────────── Mojeek ──────────────────────────


class MojeekEngine(Engine):
    """Mojeek。独立索引，反爬最宽松 —— 最可靠的保底源。"""

    name = "mojeek"
    label = "Mojeek"
    weight = 0.75
    homepage = "https://www.mojeek.com/"

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        return RequestSpec(
            url="https://www.mojeek.com/search",
            params={"q": query, "s": (page - 1) * count + 1},
            referer=self.homepage,
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(r"<li\b[^>]*>.*?</li>", html, re.I | re.S):
            block = m.group(0)
            am = re.search(
                r'<a\b[^>]*class="[^"]*(?:ob|title)[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                block, re.I | re.S,
            )
            if not am:
                am = re.search(r'<h2\b[^>]*>\s*<a\b[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                               block, re.I | re.S)
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if not url.startswith("http") or not title:
                continue
            snippet = ""
            sm = re.search(r'<p\b[^>]*class="[^"]*s[^"]*"[^>]*>(.*?)</p>', block, re.I | re.S)
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


# ────────────────────────── Brave ──────────────────────────


class BraveEngine(Engine):
    name = "brave"
    label = "Brave"
    weight = 0.85
    homepage = "https://search.brave.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        params: dict[str, Any] = {"q": query, "offset": (page - 1) * count}
        if time_range:
            # Brave: tf=d/w/m/y
            params["tf"] = {"d": "d", "w": "w", "m": "m", "y": "y"}.get(time_range, "")
        return RequestSpec(
            url="https://search.brave.com/search", params=params, referer=self.homepage
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(
            r'<div\b[^>]*class="[^"]*snippet[^"]*"[^>]*>.*?</div>\s*</div>',
            html, re.I | re.S,
        ):
            block = m.group(0)
            am = re.search(
                r'<a\b[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', block, re.I | re.S
            )
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if "brave.com" in (domain_of(url) or "") or not title:
                continue
            snippet = ""
            sm = re.search(
                r'<p\b[^>]*class="[^"]*snippet-description[^"]*"[^>]*>(.*?)</p>',
                block, re.I | re.S,
            )
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


# ────────────────────────── 头条搜索 ──────────────────────────


class ToutiaoEngine(Engine):
    """头条搜索。新闻/资讯向，对时效性问题补充价值大。"""

    name = "toutiao"
    label = "头条搜索"
    weight = 0.7
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://so.toutiao.com/"

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        return RequestSpec(
            url="https://so.toutiao.com/search",
            params={"keyword": query, "pd": "information", "dvpf": "pc"},
            referer=self.homepage,
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        # SSR 结果块在 class=result-content 里。
        # 被反爬时整页只有一个 result-content 且内含 pc_captcha，
        # 那种情况由 detect_block 提前拦掉，不会走到这里。
        blocks = re.findall(
            r'<div[^>]*class="result-content"[^>]*>(.*?)'
            r'(?=<div[^>]*class="result-content"|$)',
            html, re.I | re.S,
        )
        for blk in blocks:
            am = re.search(
                r'<a[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                blk, re.I | re.S)
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if not title:
                continue
            # 站内文章 URL（www.toutiao.com/article/...、/w/...）是有价值的结果，
            # 只有搜索页/频道页这类非结果链接才排除。
            host = (domain_of(url) or "")
            if host.endswith("toutiao.com"):
                path = urlsplit(url).path or "/"
                if path in ("", "/", "/search", "/search/", "/user"):
                    continue
            snippet = ""
            sm = re.search(
                r'class="[^"]*cs-source[^"]*"[^>]*>(.*?)</div>', blk, re.I | re.S)
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=host,
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)

# ────────────────────────── 移动端引擎 ──────────────────────────
#
# 为什么单独做移动端版本（2026-10-13 实测）：
#   PC 端百度返回 1.4KB 安全验证页、搜狗返回 antispider 验证页，都是硬拦截；
#   移动端同一站点返回 2MB/315KB 的完整结果页。
#   反爬强度差一个量级，而且移动页更省流量（vivo 走 WiFi/4G，这点不是小事）。
#   代价：HTML 结构和 PC 完全不同，必须各写一套解析器。


def _mobile_headers() -> dict[str, str]:
    from .http_pool import MOBILE_UA
    import random

    return {"User-Agent": random.choice(MOBILE_UA)}


class BaiduMobileEngine(Engine):
    """百度移动版。中文覆盖最强，且是唯一能绕过百度 PC 安全验证的路径。

    真实 URL 藏在 data-log 属性 JSON 的 `mu` 字段里 —— 百度移动版的结果
    标题是 <a> 但 href 常指向自己的跳转壳。
    """

    name = "baidu_m"
    label = "百度（移动版）"
    weight = 1.0
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://m.baidu.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        params: dict[str, Any] = {"word": query, "rn": min(count * 2, 40)}
        if time_range:
            params["rtt"] = {"d": 1, "w": 2, "m": 3, "y": 4}.get(time_range, "")
        return RequestSpec(
            url="https://m.baidu.com/s", params=params, referer=self.homepage,
            extra_headers=_mobile_headers(),
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        # URL：data-log 里的 mu 字段（真实目标地址）
        urls = re.findall(r'"mu":"(https?://[^"\\]+)"', html)
        # 标题：class 含 content-link 的标签文本
        titles = [
            _strip_tags(x)
            for x in re.findall(
                r'class="[^"]*content-link[^"]*"[^>]*>(.*?)</(?:a|div|span)>', html, re.I | re.S
            )
        ]
        # 兜底标题：c-result-content 里的第一行文本
        if len(titles) < 3:
            titles += [
                _strip_tags(x)
                for x in re.findall(
                    r'class="[^"]*c-result-content[^"]*"[^>]*>(.*?)</', html, re.I | re.S
                )
            ]
        titles = [t for t in titles if len(t) >= 4]

        for i, u in enumerate(urls):
            if len(out) >= limit:
                break
            if "baidu.com" in (domain_of(u) or "") and "baidu.com" not in u:
                continue
            title = titles[i] if i < len(titles) else ""
            if not title:
                continue
            out.append(SearchResult(
                title=title[:200], url=u, snippet="", engine=self.name,
                rank=len(out), site=domain_of(u),
            ))
        if not out:
            return self._fallback(html, limit)
        # 摘要：按位次从 c-abstract / cosc-card-content 里补
        snips = [
            _strip_tags(x)
            for x in re.findall(
                r'class="[^"]*(?:c-abstract|cosc-card-content|content-desc)[^"]*"[^>]*>(.*?)</',
                html, re.I | re.S,
            )
        ]
        for i, s in enumerate(snips):
            if i < len(out) and s:
                out[i].snippet = clean_snippet(s)
        return out


class SogouMobileEngine(Engine):
    """搜狗移动版。PC 版被 antispider 拦截，移动版可用。"""

    name = "sogou_m"
    label = "搜狗（移动版）"
    weight = 0.85
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://m.sogou.com/"
    supports_time = True

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        params: dict[str, Any] = {"keyword": query, "page": page}
        if time_range:
            params["tsn"] = {"d": 1, "w": 2, "m": 3, "y": 4}.get(time_range, "")
        return RequestSpec(
            url="https://m.sogou.com/web/searchList.jsp", params=params,
            referer=self.homepage, extra_headers=_mobile_headers(),
        )

    def parse(self, html, limit=10):
        # 搜狗移动版会随机返回拦截页（只有几 KB、文案很少）。
        # 不设可见文本门槛，就会把拦截页里的导航链接当成搜索结果，
        # 那是最坏的一类错误：看起来成功了，其实返回的是拦截页。
        visible = _strip_tags(
            re.sub(r'<(?:head).*?</head>', ' ', html, flags=re.I | re.S)
        )
        if len(visible) < 800:
            return []
        out: list[SearchResult] = []
        # 结果块：vrResult / reactResult
        blocks = re.findall(
            r'<div\b[^>]*class="[^"]*(?:vrResult|reactResult)[^"]*"[^>]*>(.*?)'
            r'(?=<div\b[^>]*class="[^"]*(?:vrResult|reactResult)[^"]*"|$)',
            html, re.I | re.S,
        )
        for blk in blocks:
            # 标题：优先 saTitle / vr-tit / h3
            tm = re.search(
                r'class="[^"]*(?:title__saTitle|vr-tit)[^"]*"[^>]*>(.*?)</'
                r'|<h3\b[^>]*>(.*?)</h3>',
                blk, re.I | re.S,
            )
            title = _strip_tags((tm.group(1) or tm.group(2) or "")) if tm else ""
            # URL 三种形态都要认：绝对 http(s)、搜狗的 /link?url= 跳转壳、
            # 以及藏在 data-url 里的真实地址。只认第一种会漏掉大半结果。
            url = ""
            for pat in (r'data-url="(https?://[^"]+)"', r'href="(https?://[^"]+)"',
                        r'href="(/link\?url=[^"]+)"'):
                um = re.search(pat, blk, re.I)
                if um:
                    url = um.group(1)
                    break
            if url.startswith("/"):
                url = "https://m.sogou.com" + url
            if not url or not title:
                continue
            snippet = ""
            sm = re.search(
                r'class="[^"]*(?:text-layout|citeurl|box-translation)[^"]*"[^>]*>(.*?)</',
                blk, re.I | re.S,
            )
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


class So360MobileEngine(Engine):
    """360 移动版。真实 URL 在 data-pcurl 属性里。"""

    name = "so360_m"
    label = "360搜索（移动版）"
    weight = 0.8
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://m.so.com/"

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        return RequestSpec(
            url="https://m.so.com/s",
            params={"q": query, "pn": page},
            referer=self.homepage, extra_headers=_mobile_headers(),
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(
            r'<div\b[^>]*class="[^"]*res-list[^"]*"[^>]*data-pcurl="([^"]+)"[^>]*>(.*?)'
            r'(?=<div\b[^>]*class="[^"]*res-list[^"]*"|$)',
            html, re.I | re.S,
        ):
            url, blk = m.group(1), m.group(2)
            if not url.startswith("http"):
                continue
            tm = re.search(
                r'class="[^"]*res-title[^"]*"[^>]*>(.*?)</|<h3\b[^>]*>(.*?)</h3>',
                blk, re.I | re.S,
            )
            title = _strip_tags((tm.group(1) or tm.group(2) or "")) if tm else ""
            if not title:
                continue
            snippet = ""
            sm = re.search(
                r'class="[^"]*(?:res-desc|res-supplement|mh-gray)[^"]*"[^>]*>(.*?)</',
                blk, re.I | re.S,
            )
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


class WeixinEngine(Engine):
    """搜狗微信搜索（垂直源）。

    微信公众号文章 —— 对内容运营/竞品调研场景价值很高，
    且它不在通用搜索引擎的索引里（微信内容是封闭生态）。
    """

    name = "weixin"
    label = "微信公众号"
    weight = 0.7
    needs_proxy = False   # 国内站直连（2026-10-15）
    homepage = "https://weixin.sogou.com/"

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        return RequestSpec(
            url="https://weixin.sogou.com/weixin",
            params={"type": 2, "query": query, "page": page},
            referer=self.homepage, extra_headers=_mobile_headers(),
        )

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(
            r'<div\b[^>]*class="txt-box"[^>]*>(.*?)</div>', html, re.I | re.S
        ):
            blk = m.group(1)
            am = re.search(r'<a\b[^>]*href="([^"]+)"[^>]*>(.*?)</a>', blk, re.I | re.S)
            if not am:
                continue
            href, title = am.group(1), _strip_tags(am.group(2))
            if not title:
                continue
            url = "https://weixin.sogou.com" + href if href.startswith("/link") else href
            snippet = ""
            sm = re.search(r'class="[^"]*(?:s-p|txt-info)[^"]*"[^>]*>(.*?)</', blk, re.I | re.S)
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site="微信公众号",
            ))
            if len(out) >= limit:
                break
        if not out:
            return self._fallback(html, limit)
        return out


# ────────────────────────── SearXNG（可选） ──────────────────────────

SEARX_INSTANCES = [
    "https://searx.be",
    "https://search.bus-hit.me",
    "https://priv.au",
    "https://searxng.site",
    "https://search.inetol.net",
]


class SearXEngine(Engine):
    """公共 SearXNG 实例池。

    默认不开（公共实例可用性和速率都很随机），但接上后等于一次拿到
    多引擎聚合结果，是很好的「第 N 个源」。
    """

    name = "searx"
    label = "SearXNG"
    weight = 0.7
    homepage = "https://searx.be/"
    supports_time = True

    def __init__(self) -> None:
        self._idx = 0

    def build(self, query, *, count=10, lang="", region="", time_range="", page=1):
        # 轮询实例：一个挂了不影响整体，且天然分散速率压力
        base = SEARX_INSTANCES[self._idx % len(SEARX_INSTANCES)]
        self._idx += 1
        params: dict[str, Any] = {
            "q": query,
            "language": lang or "zh-CN",
            "safesearch": 0,
            "categories": "general",
        }
        if time_range:
            params["time_range"] = {"d": "day", "w": "week",
                                    "m": "month", "y": "year"}.get(time_range, "")
        return RequestSpec(url=f"{base}/search", params=params, referer=base + "/")

    def parse(self, html, limit=10):
        out: list[SearchResult] = []
        for m in re.finditer(
            r'<article\b[^>]*class="[^"]*result[^"]*"[^>]*>.*?</article>', html, re.I | re.S
        ):
            block = m.group(0)
            am = re.search(r'<a\b[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
                           block, re.I | re.S)
            if not am:
                continue
            url, title = am.group(1), _strip_tags(am.group(2))
            if not title:
                continue
            snippet = ""
            sm = re.search(r'<p\b[^>]*class="[^"]*content[^"]*"[^>]*>(.*?)</p>',
                           block, re.I | re.S)
            if sm:
                snippet = _strip_tags(sm.group(1))
            out.append(SearchResult(
                title=title[:200], url=url, snippet=clean_snippet(snippet),
                engine=self.name, rank=len(out), site=domain_of(url),
            ))
            if len(out) >= limit:
                break
        return out or self._fallback(html, limit)


# ────────────────────────── 注册表 ──────────────────────────

ENGINE_CLASSES: list[type[Engine]] = [
    # 国内主力（实测 2026-10-13 于 vivo 国内网络）
    BingEngine,          # 桌面版实测可用且质量最高，但对 UA 敏感
    So360Engine,         # PC 版最稳，反爬最弱
    BaiduMobileEngine,   # 中文覆盖最强（PC 版被安全验证拦死）
    SogouMobileEngine,   # PC 版 antispider，移动版可用
    So360MobileEngine,   # 与 PC 版互补
    WeixinEngine,        # 垂直：公众号
    ToutiaoEngine,       # 垂直：资讯
    # 国际源（国内网络常不可达，靠熔断自动隔离）
    DuckDuckGoEngine,
    MojeekEngine,
    BraveEngine,
    BingIntlEngine,
    SearXEngine,
    # PC 版国内源（保留，网络环境变化时可恢复）
    BaiduEngine,
    SogouEngine,
]

REGISTRY: dict[str, Engine] = {cls.name: cls() for cls in ENGINE_CLASSES}


def get_engine(name: str) -> Engine | None:
    return REGISTRY.get(name)


def available_engines() -> list[str]:
    return list(REGISTRY.keys())
