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
    # ── 2026-10-14 复盘后新增（对着实测数据加）──
    # 日更页：页内直接嵌 ~455 个裸节点 URI（实测今日页 571KB/455 URI），
    # 是新鲜度最高的源。URL 带 %Y%m%d，_build_sources 按当天格式化；
    # 日期页不进历史轮换（见 _DATED_URL_RE），不会旧页重抓。
    {"url": "https://clashgithub.com/clashnode-%Y%m%d.html",
     "kind": "page", "dated": "1", "note": "clashgithub 日更页（页内裸 URI）"},
    # 日更 clash 订阅，仓库自称发布前做过可用性检测（质量信号）
    {"url": "https://raw.githubusercontent.com/share-daily/node/main/clash.yaml",
     "kind": "sub", "note": "share-daily 日更 clash（发布前检测）"},
    # ── 2026-10-14 优化文档复盘后新增（vivo 实测产出，勿凭印象删）──
    # morpheusadam/v2ray-config：每日重建、发布前自测。取协议分文件
    # （单个小、失败影响面小）而非 all.txt（20.6s 且与协议文件重复）。
    # 实测新增：vless 15997 / trojan 8373 / vmess 7300 / ss 6742 /
    # hysteria2 1549（修 IPv6 畸形行后）/ tuic 225 / lite 281 / best 1746。
    # ⚠️ hysteria2.txt 曾因 `[IPv6]:34602/` 畸形行整份解析失败——
    # _split_hostport 已修（2026-10-14），别回退。
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt",
     "kind": "sub", "note": "morpheusadam 精选 bundle"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/lite.txt",
     "kind": "sub", "note": "morpheusadam 小型列表（慢线路）"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vless.txt",
     "kind": "sub", "note": "morpheusadam VLESS 专集"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/trojan.txt",
     "kind": "sub", "note": "morpheusadam Trojan 专集"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/vmess.txt",
     "kind": "sub", "note": "morpheusadam VMess 专集"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/shadowsocks.txt",
     "kind": "sub", "note": "morpheusadam Shadowsocks 专集"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/hysteria2.txt",
     "kind": "sub", "note": "morpheusadam Hysteria2 专集"},
    {"url": "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tuic.txt",
     "kind": "sub", "note": "morpheusadam TUIC 专集"},
    # FastNodes：多源聚合+去重+多层检查。top/verified_tls 实测新增
    # 763/10263；协议分文件各 818-933。everything/stable 与协议文件
    # 重复且 20s+，不抓。countries 补齐地区出口（JP/US/SG/KR/HK/DE）。
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt",
     "kind": "sub", "note": "FastNodes Top（欧洲向为主）"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt",
     "kind": "sub", "note": "FastNodes Xray 验证列表"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified_tls.txt",
     "kind": "sub", "note": "FastNodes TLS 验证列表"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt",
     "kind": "sub", "note": "FastNodes VLESS 专集"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt",
     "kind": "sub", "note": "FastNodes VMess 专集"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.txt",
     "kind": "sub", "note": "FastNodes Trojan 专集"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.txt",
     "kind": "sub", "note": "FastNodes Shadowsocks 专集"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt",
     "kind": "sub", "note": "FastNodes Hysteria2 专集"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/JP.txt",
     "kind": "sub", "note": "FastNodes 日本"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/US.txt",
     "kind": "sub", "note": "FastNodes 美国"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/SG.txt",
     "kind": "sub", "note": "FastNodes 新加坡"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/KR.txt",
     "kind": "sub", "note": "FastNodes 韩国"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/HK.txt",
     "kind": "sub", "note": "FastNodes 中国香港"},
    {"url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.txt",
     "kind": "sub", "note": "FastNodes 德国"},
    # ── 2026-10-15 优化文档二轮摸底后新增（vivo 实测产出）──
    # GFP wiki 系列（漏掉的超级产源）：实测每轮新增 ss 12885 /
    # trojan 17885 / vless 16665 / vmess 7029 / hy2 912。wireguard/
    # anytls 解析 0 节点（sing-box 不支持），不接。
    {"url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/ss.txt",
     "kind": "sub", "note": "GFP Shadowsocks 专集"},
    {"url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/trojan.txt",
     "kind": "sub", "note": "GFP Trojan 专集"},
    {"url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vless.txt",
     "kind": "sub", "note": "GFP VLESS 专集"},
    {"url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/vmess.txt",
     "kind": "sub", "note": "GFP VMess 专集"},
    {"url": "https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt",
     "kind": "sub", "note": "GFP Hysteria2 专集"},
    # Barabama（AI 爬虫多源聚合）：clashmeta 实测新增 1925
    {"url": "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/clashmeta.txt",
     "kind": "sub", "note": "Barabama ClashMeta 聚合"},
    # freenodess：日更多协议，实测新增 ~275
    {"url": "https://raw.githubusercontent.com/freenodess/freenodess/refs/heads/main/nodes/v2ray-base64.txt",
     "kind": "sub", "note": "freenodess 日更订阅"},
    # ── 普通 SOCKS/HTTP 代理列表（低延迟突破口，2026-10-15）──
    # 公网代理多在欧美 VPS，实测 RTT 比免费 VPN 节点（4.9s+）快一个
    # 数量级。解析走 parse_proxy_list（_sniff_proxy_proto 按 URL 判
    #协议），入库 cap=6000/源/轮（WS_NODE_INGEST_CAP）。
    # proxifly 在 jsdelivr CDN（墙内直连可达）；其余 GitHub raw 走
    # fetcher 代理兜底路径。混合 all.txt 靠 URI/ipport 行自动分辨。
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
     "kind": "sub", "note": "proxifly SOCKS5（实测 6 万条，5 分钟级更新）"},
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
     "kind": "sub", "note": "proxifly HTTP（实测 5248 条）"},
    {"url": "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/live.txt",
     "kind": "sub", "note": "HProxy 实时在线池（实测 7061 条）"},
    {"url": "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/socks5.txt",
     "kind": "sub", "note": "HProxy SOCKS5（实测 2759 条）"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
     "kind": "sub", "note": "monosans SOCKS5（每小时验证，实测 770 条）"},
    {"url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
     "kind": "sub", "note": "monosans 全协议（实测 1166 条混合）"},
    {"url": "https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/stable.txt",
     "kind": "sub", "note": "Litport 稳定候选（7 天在线率≥90%，实测 361 条）"},
    {"url": "https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/all.txt",
     "kind": "sub", "note": "Litport 全协议（实测 2438 条混合）"},
    {"url": "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/all.txt",
     "kind": "sub", "note": "Thordata 全协议（实测 502 条）"},
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


# 页面里直接嵌着的节点 URI（vmess/vless/...）。
# ⚠️ 2026-10-14 新增：实测 clashgithub.com/clashnode-YYYYMMDD.html 日更页
# 直接嵌 455 个裸 URI，而旧管线只认「订阅链接」—— 这种火源页面会被判
# no_sub_links 拉黑，456 个新鲜节点/天全部漏掉。TG 公频直连被网络层封
# （Errno 101），经本地代理可达，但实测三个频道只发聚合站链接不发裸 URI，
# 暂不作为火源。
# 字符类不含反斜杠：URI 在 HTML 属性里以引号/尖括号/空白结尾。
_NODE_URI_RE = re.compile(
    r"(?:vmess|vless|trojan|ss|ssr|hysteria2|hysteria|tuic)://"
    r"[^ \t\r\n" + chr(34) + chr(39) + "<>" + "]+",
    re.IGNORECASE,
)


def extract_node_uris(text: str) -> list[str]:
    """从网页文本里直接抠出节点 URI（去重、保序）。

    喂给解析器前调用：parse_subscription_text 是行首匹配且见 HTML 直接
    拒解（subparse 第 669 行），属性里的 href="vmess://..." 必须这里先
    抠成一行一个。HTML 实体（&amp; 等）先反转义，否则 query 参数被截断。
    """
    import html as _html

    uniq = list(dict.fromkeys(_NODE_URI_RE.findall(_html.unescape(text or ""))))
    return uniq


# 日期型 URL（clashnode-20261014.html 这类追新页）：含 8 位连续数字即视为
# 日期页。用途：历史源轮换时跳过——日期页每天一个，放进历史会被当普通源
# 永久每轮重抓，白白耗抓取预算（它们的贡献按天计，旧页没有重抓价值）。
_DATED_URL_RE = re.compile(r"(?:19|20)\d{6}")


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
