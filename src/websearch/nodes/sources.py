# -*- coding: utf-8 -*-
"""节点源 —— 全球免费节点从哪儿来。

三层搜集策略（按可靠性排序）：
  1. **种子源**：内置的、当前实测可用的订阅地址（主力）；
  2. **页面发现**：拉聚合站/GitHub README，从中正则提取订阅链接 ——
     免费节点生态是「聚合站 + README 放链接」，硬编码地址必烂，
     但「从页面里找地址」能持续跟上；
  3. **搜索自举**：用本项目自己的 web_search 搜「免费节点订阅 每日更新」，
     发现新的聚合站，再回到第 2 层挖订阅地址。
     ——这是「越搜越多」的正反馈，也是内置清单烂掉后的自愈路径。

⚠️ 安全：源地址是公开信息（不涉密），可入库。**用户自己的机场订阅
不进这里**（那是凭据），走 proxy/store 的 600 权限文件。
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urljoin, urlsplit

import httpx

from ..config import Config
from ..http_pool import (
    BlockedRedirectError,
    assert_url_async,
    check_redirect_sync,
)

log = logging.getLogger("websearch.nodes.sources")

# ── 种子源（2026-10-13 实测可拉取）──
# kind:
#   sub   = 直接是订阅内容（base64 / URI 列表 / clash yaml）
#   page  = 网页，需要先提取里面的订阅链接
SEED_SOURCES: list[dict[str, str]] = [
    # 每 12 小时聚合，发布前经 Mihomo 连通性与延迟实测 —— 质量最高的源
    {"url": "https://manifest.dpdns.org/free/latest/v2ray.txt",
     "kind": "sub", "note": "舱单 MANIFEST v2ray 订阅（预实测）"},
    # 聚合站首页：页面里能找到 /free/latest/*.txt|yaml
    {"url": "https://manifest.dpdns.org/today/",
     "kind": "page", "note": "舱单今日页（用于发现新订阅路径）"},
    # GitHub 聚合仓库 README：里面指向当日订阅地址
    {"url": "https://raw.githubusercontent.com/openRunner/clash-freenode/main/README.md",
     "kind": "page", "note": "clash-freenode README"},
    # ── 全球知名聚合仓库（2026-10-13 实测可达，解码后含节点）──
    # 加这些是为了冲「100 活节点」：免费节点实测存活率仅 ~5%，
    # 池子越大越能凑够活节点（600 节点 → ~30 活；目标 2000+ 节点）。
    {"url": "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
     "kind": "sub", "note": "NoMoreWalls 大列表（实测 ~440 节点）"},
    {"url": "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
     "kind": "sub", "note": "ShadowsocksAggregator Eternity（实测 ~200 节点）"},
    {"url": "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
     "kind": "sub", "note": "ermaozi 订阅（实测 ~60 节点）"},
    {"url": "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
     "kind": "sub", "note": "ripaojiedian freenode"},
    {"url": "https://raw.githubusercontent.com/freefq/free/master/v2",
     "kind": "sub", "note": "freefq free"},
    {"url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
     "kind": "sub", "note": "Pawdroid Free-servers"},
    {"url": "https://raw.githubusercontent.com/yaney01/Yaney01/main/yaney_01",
     "kind": "sub", "note": "yaney01（ssr 为主）"},
]

# 自举搜索词：发现新聚合站。多词覆盖不同表述（免费节点/白嫖/每日更新）
DISCOVERY_QUERIES = [
    "免费节点订阅 每日更新 clash v2ray 订阅地址",
    "免费 clash 订阅 节点 实测 可用 每日更新",
    "free v2ray subscription daily update nodes",
]

# 订阅链接的识别规则。
# ⚠️ 关键词必须**按路径段/域名词边界**匹配，不能裸子串 ——
# 踩过的坑：裸子串匹配会把 "css2"（含 ss）、"freedomport"（含 free）
# 误判成订阅链接。用段切分（/ - _ .）后做集合交集才准。
_SUB_EXTS = (".txt", ".yaml", ".yml", ".json", ".conf")
# 路径段命中的**强**特征词（订阅地址的常见形态），单独出现即认。
# ⚠️ 2026-10-14 收严（对着真实假源打的补丁）：原先 nodes/free/share
# 也单独放行，结果 poki.com 游戏页里的 "free-games" 链接被当订阅
# 地址，每轮挖一遍、抓一遍、解析 0 节点，白烧抓取与探测预算。
# 现在弱词一律不单独认 —— 带这些词的真订阅地址几乎都同时带订阅
# 扩展名或强词，那两关本来就放行，漏不了真实的。
_SUB_STRONG_WORDS = {
    "sub", "subscribe", "subscription", "clash", "mihomo", "v2ray",
    "singbox", "sing-box", "ssr", "vmess", "vless", "trojan",
    "hysteria", "hysteria2", "tuic",
}
# 域名词命中的词（订阅站常把服务放这些子域）。
# 2026-10-14：删 "free"/"api" —— 实测假订阅链接 https://api.poki.com
# 就是被 "api" 放行的；真机场的 api 域名一定带 /subscribe 路径或
# token query，不靠裸域名词认。
_SUB_HOST_WORDS = {
    "sub", "subs", "subx", "node", "nodes", "clash", "v2ray", "singbox",
    "proxy",
}
# query 里出现即强烈暗示是机场订阅（这类地址常是 /api/v1/client/subscribe?token=）
# 2026-10-14：删 "url" —— ?url=http 是跳转参数（_JUNK_URL_MARKERS 同款口径）。
_SUB_QUERY_KEYS = {"token", "access_token", "sub", "subscribe"}
_URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]，。；]+", re.I)
_SEG_SPLIT_RE = re.compile(r"[/\-_.]+")


def source_id(url: str) -> str:
    """源 id：URL 的短哈希（源地址可能很长，用哈希做键更干净）。"""
    return hashlib.sha256(url.encode()).hexdigest()[:12]


# 明确不是订阅的域名后缀（含子域，用「等于或点号后缀」匹配，
# 不能直接用 endswith —— "fonts.googleapis.com".endswith("google.com")
# 是 False，会漏拦）
_NOISE_DOMAINS = (
    "github.com", "t.me", "telegram.org", "twitter.com", "x.com",
    "youtube.com", "google.com", "gstatic.com", "w3.org", "schema.org",
    "apple.com", "microsoft.com", "cloudflare.com", "jsdelivr.net",
    "unpkg.com", "bootcdn.net", "staticfile.org", "baidu.com",
    "bing.com", "mozilla.org", "facebook.com", "instagram.com",
    # 搜索引擎域：搜索结果里常混入**自己的跳转/追踪链接**
    # （如 bing.com/ck/a?...、so.com/link?url=），误当源会每轮空转。
    # 2026-10-14 实测：bing.com/ck/a 空转 45 次、baidu.com/item/* 403 44 次。
    "sogou.com", "so.com", "360.cn", "sm.cn", "yandex.com",
    "duckduckgo.com", "mojeek.com", "brave.com", "startpage.com",
    "ecosia.org",
    # 门户/社媒/视频：不是节点源，只是结果噪声
    "douyin.com", "kuaishou.com", "weibo.com", "xiaohongshu.com",
    "bilibili.com", "toutiao.com", "qq.com", "zhihu.com", "juejin.cn",
    "csdn.net", "baiduvideo.cn", "iqiyi.com", "youku.com", "mgtv.com",
)

# URL 里出现即强烈暗示是「跳转/追踪」而非真实站点（搜索结果的中间页）。
_JUNK_URL_MARKERS = (
    "/ck/a", "/link?", "/redirect", "/jump?", "returl=",
    "target=http", "url=http%3a", "url=http", "&url=http",
)


def _host_matches(host: str, domain: str) -> bool:
    """host 是否等于该域名或是它的子域（点号边界匹配，防误伤）。"""
    return host == domain or host.endswith("." + domain)


def _looks_like_subscription_url(url: str) -> bool:
    """判断一个链接是否像订阅地址（而不是导航/文档/图片）。

    四道判据，任一命中即认为是订阅候选：
      1. 路径以订阅扩展名结尾（.txt/.yaml/.yml/.json/.conf）
      2. 路径段命中订阅**强**特征词（sub/clash/v2ray/…，词边界比对）
      3. query 带 token/access_token 等机场订阅特征键
      4. 域名段命中订阅特征词（sub.xxx / node.xxx / clash.xxx）
    先排除噪声域名与静态资源。

    2026-10-14 收严背景：poki.com 游戏页被搜索引擎自举发现成「节点源」，
    页面里的 https://api.poki.com（域名词 api）和 free-games（弱词 free）
    被当订阅地址每轮空抓。现在弱词（free/share/nodes/node/proxy）与裸
    api/free 域名一律不单独放行。
    """
    try:
        p = urlsplit(url)
    except Exception:
        return False
    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    if not host:
        return False
    # 噪声域名；githubusercontent 的 raw 路径放行（GitHub 聚合源常见）
    if any(_host_matches(host, d) for d in _NOISE_DOMAINS):
        if not (host.endswith("githubusercontent.com") or "/raw/" in path):
            return False
    # 静态资源
    if path.endswith((".css", ".js", ".png", ".jpg", ".svg", ".ico",
                      ".woff", ".woff2", ".gif", ".webp", ".xml", ".html")):
        return False
    # 1) 扩展名
    if path.endswith(_SUB_EXTS):
        return True
    # 2) 路径段词边界匹配（只认强词，理由见 _SUB_STRONG_WORDS 注释）
    seg_words = {s for s in _SEG_SPLIT_RE.split(path) if s}
    if seg_words & _SUB_STRONG_WORDS:
        return True
    # 3) query 特征（机场订阅常见）
    if p.query:
        from urllib.parse import parse_qs

        keys = {k.lower() for k in parse_qs(p.query).keys()}
        if keys & _SUB_QUERY_KEYS and len(path) <= 80:
            return True
    # 4) 域名段词边界匹配
    host_words = set(host.split("."))
    if host_words & _SUB_HOST_WORDS:
        return True
    return False


def extract_subscription_urls(text: str, base_url: str = "") -> list[str]:
    """从网页/README 文本里提取候选订阅链接。

    返回去重后的绝对 URL 列表（保持出现顺序）。
    这一步是「页面发现」的核心：聚合站和 README 里藏着当日订阅地址。
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(text or ""):
        raw = m.group(0).rstrip(").,;")
        url = urljoin(base_url, raw) if base_url else raw
        if not _looks_like_subscription_url(url):
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


# 直连失败后值得「换本地代理再试」的网络错误（httpx 异常类型名）。
# HTTP 4xx/5xx、blocked_* 不在此列：通了但被拒，换路径也白搭，
# 还会把真实状态掩盖掉（源健康度要记真实错误）。
_NET_ERROR_NAMES = frozenset({
    "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
    "PoolTimeout", "ProxyError", "RemoteProtocolError",
    "UnsupportedProtocol", "NetworkError", "AllConnectErrors",
    "ConnectionResetError", "gaierror", "TimeoutError",
})

# 这些宿主直连（墙内）超时率高，有本地代理时优先走代理。
# 2026-10-14 实测：raw.githubusercontent.com 上各聚合源 fail 51-65 次
# （ConnectTimeout/ReadTimeout），占每轮抓取失败大头，把解析量从
# 2701 拖到 83。GitHub 系在墙内基本没有直连稳定的。
_PROXY_FIRST_HOSTS = (
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "gist.githubusercontent.com",
    "codeload.github.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
)


def _is_network_error(error: str) -> bool:
    """是否网络层错误（值得换一条出网路径再试一次）。"""
    return error in _NET_ERROR_NAMES


@dataclass
class Fetched:
    """一次源抓取的结果。"""

    url: str
    ok: bool
    text: str = ""
    error: str = ""
    status: int = 0
    elapsed_ms: int = 0
    # 内容形态判定（供上层决定怎么解析）
    content_kind: str = ""      # sub / page / unknown


class SourceFetcher:
    """源抓取器。

    出网策略（2026-10-14 改，实测驱动）：
      · 用户显式配了代理（WS_PROXY）→ 只用它。用户配代理通常就是为
        强制走代理，直连兜底反而绕不过墙；
      · 否则**直连优先，网络错误自动改走本地节点代理**再试一次。
        实测 GitHub raw（NoMoreWalls/ShadowsocksAggregator/ermaozi…）
        墙内直连超时率 ~30%（fail 51-65 次），而本地 sing-box 代理
        （服务自养节点）出网稳定 —— 抓源失败直接拖垮每轮解析量
        （parsed 从 2701 暴跌到 83）；
      · 每个宿主记住最近成功的路径（TTL 10 分钟），不让「已知直连
        不通」的宿主每轮先赌一次超时；GitHub 系宿主默认代理优先。
    代理不可用（sing-box 未就绪）时自动退化成纯直连，不影响抓取。
    """

    def __init__(self, *, proxy: str = "", timeout: float = 15.0,
                 max_bytes: int = 4_000_000, cfg: Config | None = None,
                 proxy_provider: Callable[[], str] | None = None):
        self.proxy = proxy or ""
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.cfg = cfg or Config.from_env()
        # 本地代理提供者：返回 "" 表示代理没起来（退化为直连）。
        # 用 callable 而非固定字符串：本地 sing-box 随切节点重启，
        # 「起没起」是动态的，每次抓取现问最准。
        self._proxy_provider = proxy_provider
        # host -> ("direct"|"proxy", 单调时钟时间戳)
        self._path_memory: dict[str, tuple[str, float]] = {}
        self._path_ttl = 600.0
        self._path_memory_cap = 256

    async def fetch(self, url: str) -> Fetched:
        t0 = time.monotonic()
        allowed, _reason = await assert_url_async(url, self.cfg)
        if not allowed:
            return Fetched(
                url=url, ok=False, error="blocked_url", status=0,
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )
        # 用户显式代理：单路径，不兜底（见类文档字符串）
        if self.proxy:
            return await self._fetch_once(url, self.proxy, t0, self.timeout)
        local = self._local_proxy()
        host = (urlsplit(url).hostname or "").lower()
        attempts = self._plan_attempts(host, local)
        # 有第二条路时收紧超时：直连不通要 15s 才超时，等满了再换代理，
        # 一轮 hunt 全耗在超时上。8s 足够区分「慢」和「不通」。
        attempt_to = (self.timeout if len(attempts) == 1
                      else min(self.timeout, 8.0))
        last: Fetched | None = None
        for kind, px in attempts:
            res = await self._fetch_once(url, px, t0, attempt_to)
            if res.ok:
                self._remember_path(host, kind)
                return res
            last = res
            # 只有网络层错误才换路径：HTTP 错误/被拦 marker 是「通了但
            # 被拒」，换代理同样被拒，还把真实状态掩盖掉。
            if not _is_network_error(res.error):
                return res
        return last  # type: ignore[return-value]

    def _plan_attempts(self, host: str,
                       local: str) -> list[tuple[str, str]]:
        """排出抓取路径：[("direct"|"proxy", proxy_url), ...]，"" = 直连。"""
        if not local:
            return [("direct", "")]
        remembered = self._remembered_path(host)
        if remembered == "proxy":
            return [("proxy", local), ("direct", "")]
        if remembered == "direct":
            return [("direct", ""), ("proxy", local)]
        # 没记忆：GitHub 系直连超时率高（实测 ~30%），优先走代理，
        # 省掉每轮一次 8 秒直连超时；其它宿主直连优先（墙内可达，
        # 且比 5 秒延迟的节点快得多）。
        if any(_host_matches(host, h) for h in _PROXY_FIRST_HOSTS):
            return [("proxy", local), ("direct", "")]
        return [("direct", ""), ("proxy", local)]

    def _local_proxy(self) -> str:
        if self._proxy_provider is None:
            return ""
        try:
            return (self._proxy_provider() or "").strip()
        except Exception:
            # provider 炸了不该影响抓取：退化为直连
            return ""

    def _remembered_path(self, host: str) -> str:
        row = self._path_memory.get(host)
        if not row:
            return ""
        kind, ts = row
        if time.monotonic() - ts > self._path_ttl:
            self._path_memory.pop(host, None)
            return ""
        return kind

    def _remember_path(self, host: str, kind: str) -> None:
        if not host:
            return
        if (len(self._path_memory) >= self._path_memory_cap
                and host not in self._path_memory):
            # 防无界增长：超容时清掉最早的一半（dict 保序）
            for k in list(self._path_memory)[: self._path_memory_cap // 2]:
                self._path_memory.pop(k, None)
        self._path_memory[host] = (kind, time.monotonic())

    async def _fetch_once(self, url: str, proxy: str, t0: float,
                          timeout: float) -> Fetched:
        """单路径抓一次。proxy 传 "" = 直连。"""
        kwargs: dict[str, Any] = {
            "timeout": timeout,
            "follow_redirects": True,
            "event_hooks": {"response": [self._guard_redirect]},
            "headers": {
                # 有些聚合站按 UA 拦爬虫
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/126.0 Safari/537.36"),
                "Accept": "*/*",
            },
        }
        if proxy:
            kwargs["proxy"] = proxy
        try:
            async with httpx.AsyncClient(**kwargs) as c:
                r = await c.get(url)
            ms = int((time.monotonic() - t0) * 1000)
            if r.status_code >= 400:
                return Fetched(url=url, ok=False, status=r.status_code,
                               error=f"HTTP {r.status_code}", elapsed_ms=ms)
            text = r.text[: self.max_bytes]
            return Fetched(url=url, ok=bool(text.strip()), text=text,
                           status=r.status_code, elapsed_ms=ms,
                           content_kind=self._classify(text, url))
        except BlockedRedirectError:
            ms = int((time.monotonic() - t0) * 1000)
            return Fetched(url=url, ok=False, error="blocked_redirect", elapsed_ms=ms)
        except Exception as e:
            ms = int((time.monotonic() - t0) * 1000)
            # 错误信息脱敏：只留异常类型名，防 URL 里的 query 进库
            return Fetched(url=url, ok=False, error=type(e).__name__,
                           elapsed_ms=ms)

    async def _guard_redirect(self, response: httpx.Response) -> None:
        """重定向跟随前校验目标；SSRF 拒绝绝不自动重试。"""
        if response.status_code not in (301, 302, 303, 307, 308):
            return
        location = response.headers.get("location")
        if not location:
            return
        target = urljoin(str(response.request.url), location)
        allowed, _reason = await check_redirect_sync(target, self.cfg)
        if not allowed:
            raise BlockedRedirectError("subscription_source_redirect_blocked")

    @staticmethod
    def _classify(text: str, url: str) -> str:
        """判断抓到的内容是订阅本体还是网页。

        规则：
          · 看起来像 HTML（有 <html / <!doctype）→ page
          · 内容是 base64 且解出来含 "://" → sub
          · 直接含 "://" 协议头（ss:// vmess:// ...）→ sub
          · 含 "proxies:"（clash yaml）→ sub
          · 否则 unknown
        """
        head = (text or "")[:2000].lstrip().lower()
        if head.startswith("<!doctype") or "<html" in head or "<head>" in head:
            return "page"
        if "proxies:" in (text or "")[:5000].lower():
            return "sub"
        if re.search(r"(ss|ssr|vmess|vless|trojan|hysteria2?|tuic)://",
                     text or "", re.I):
            return "sub"
        # base64 订阅：整体像 base64 且长度可观。
        # 阈值 40：实测订阅的 base64 至少几百字符，40 足够排除
        # 「短纯字母串」这类噪声，又不至于漏掉小订阅。
        stripped = re.sub(r"\s", "", (text or ""))
        if len(stripped) > 40 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
            import base64

            try:
                pad = stripped + "=" * (-len(stripped) % 4)
                dec = base64.urlsafe_b64decode(pad).decode("utf-8", "replace")
                if "://" in dec:
                    return "sub"
            except Exception:
                pass
        return "unknown"


async def discover_via_search(orch, *, max_queries: int = 3,
                              per_query: int = 6) -> list[str]:
    """用本项目自己的搜索引擎发现新的聚合站 URL。

    这是「越搜越多」的自举环节：搜到新站点 → 加入 page 类源 →
    下一轮从中提取订阅地址。

    返回候选**页面** URL（不是订阅地址本身），去重后给上层。
    搜索失败不抛异常（引擎可能全挂），返回已收集到的部分。
    """
    found: list[str] = []
    seen: set[str] = set()
    for q in DISCOVERY_QUERIES[:max_queries]:
        try:
            res = await orch.search(q, max_results=per_query, fresh=True)
        except Exception as e:
            log.warning("源发现搜索失败（%s）: %s", type(e).__name__, e)
            continue
        for item in (res.get("results") or []):
            url = (item.get("url") or "").strip()
            if not url or url in seen:
                continue
            try:
                host = (urlsplit(url).hostname or "").lower()
            except Exception:
                continue
            if not host:
                continue
            # 噪声域（搜索引擎/社媒/门户）：搜索结果里的跳转与门户页
            # 会被误当聚合站。这里与 _looks_like_subscription_url 共用
            # 同一份 _NOISE_DOMAINS，避免两处黑名单漂移（2026-10-14 修：
            # 原先 discover 用的是另一套内联名单，漏了搜索域 → bing 追踪
            # 链接、百度百科词条被当源入库，每轮空转烧探测预算）。
            if any(_host_matches(host, d) for d in _NOISE_DOMAINS):
                continue
            if any(m in url.lower() for m in _JUNK_URL_MARKERS):
                continue
            seen.add(url)
            found.append(url)
    return found
