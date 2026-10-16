"""文本与 URL 规范化 —— 融合去重的基础。

这一层决定了「十条结果里有多少是真的重复的」。
现有方案普遍只做 URL 字符串相等比较，漏掉了：
  · 同一个页面带不同 utm 参数
  · 标题末尾多了「 - 知乎」「_百度百科」
  · http/https、www、末尾斜杠差异
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# 追踪参数：这些参数不影响页面内容，但会让同一 URL 变成 N 个不同字符串。
# 列表是按国内站点实际出现频率排的（spm 是阿里系，from 是知乎/微信系）。
TRACKING_PARAMS = frozenset(
    {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_name", "utm_reader", "utm_social", "utm_brand",
        "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "twclid", "igshid",
        "spm", "scm", "from", "ref", "ref_src", "ref_url", "referrer",
        "share_source", "share_medium", "share_plat", "share_session_id",
        "src", "source", "seid", "sid", "sp", "vd_source", "si",
        "_ga", "_gl", "mc_cid", "mc_eid", "yclid", "tt_from", "bd_source",
    }
)

_PREFIX_WWW = re.compile(r"^www\.", re.I)
_WS = re.compile(r"\s+")
# 标题归一化用的标点/符号（含全角）
_PUNCT = re.compile(
    r"[\s\u3000!-/:-@\[-`{-~\u2000-\u206f\u3001-\u303f\uff01-\uff0f\uff1a-\uff20\uff3b-\uff40\uff5b-\uff65]+"
)


def canonicalize_url(url: str) -> str:
    """URL 规范化 —— 作为去重主键。

    步骤：小写 scheme/host → 去 www → 去 fragment → http 升 https
          → 去追踪参数 → 剩余参数按 key 排序 → 去末尾斜杠
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()

    scheme = (parts.scheme or "https").lower()
    # http → https 归一：绝大多数站点两者内容一致
    if scheme == "http":
        scheme = "https"
    if scheme not in ("http", "https"):
        # 非 http(s)（如 javascript:、magnet:）原样返回，交给上层丢弃
        return url.strip()

    host = (parts.hostname or "").lower()
    host = _PREFIX_WWW.sub("", host)

    port = parts.port
    # 默认端口省略
    if port in (80, 443):
        port = None

    path = parts.path or "/"
    # 去末尾斜杠（保留根路径 "/"，否则 "" 会让不同 URL 反而归一到空）
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    query = ""
    if parts.query:
        pairs = [
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if k.lower() not in TRACKING_PARAMS
        ]
        if pairs:
            # 排序：?a=1&b=2 与 ?b=2&a=1 是同一个页面
            query = urlencode(sorted(pairs), doseq=True)

    netloc = host + (f":{port}" if port else "")
    return urlunsplit((scheme, netloc, path, query, ""))


def domain_of(url: str) -> str:
    """取注册域级别的主机名（去 www），用于域名配额统计。

    注意：不做完整 eTLD+1 解析（不引入 publicsuffix 依赖）。
    对域名配额这个用途，主机名级别已经够了——
    `news.qq.com` 和 `sports.qq.com` 算两个域名，只会让结果更分散，不是错误。
    """
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return _PREFIX_WWW.sub("", host)


def normalize_text(s: str) -> str:
    """文本归一化：全角转半角、去标点、去空白、小写。用于标题/摘要比较。"""
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = _PUNCT.sub("", s)
    return _WS.sub("", s).lower()


def _tokens(s: str) -> list[str]:
    """分词。中文按字切（无外部分词依赖），英文按词切。

    为什么不用 jieba：为了中文分词引入几十 MB 依赖不划算。
    对 SimHash 来说，中文按字切（bigram）效果已经足够。
    """
    s = normalize_text(s)
    if not s:
        return []
    # 中文 bigram：把「人工智能」切成「人工」「工智」「智能」，保留局部顺序信息
    grams = []
    buf = ""
    for ch in s:
        if "\u4e00" <= ch <= "\u9fff":
            buf += ch
            if len(buf) >= 2:
                grams.append(buf[-2:])
        else:
            if buf:
                buf = ""
            if ch.isalnum():
                grams.append(ch)
    # 非中文纯字母串按 3-gram 兜底
    if not grams:
        for i in range(max(0, len(s) - 2)):
            grams.append(s[i : i + 3])
    return grams or [s[:8]]


def simhash(s: str, bits: int = 64) -> int:
    """64 位 SimHash。

    用 blake2b 做 hash 而不是 Python 内置 hash()——
    内置 hash 对字符串是**随进程盐值随机化**的，重启后同一个标题得到不同指纹，
    缓存和去重会全错。这是个很容易踩的坑。
    """
    if not s:
        return 0
    vec = [0] * bits
    for tok in _tokens(s):
        h = int.from_bytes(
            hashlib.blake2b(tok.encode("utf-8"), digest_size=8).digest(), "big"
        )
        for i in range(bits):
            vec[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if vec[i] > 0:
            out |= 1 << i
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


_CJK = r"\u4e00-\u9fff"


def query_terms(query: str) -> list[str]:
    """把查询拆成用于相关性判断的关键词。

    中文按空格分词，超长串（没有空格的连续中文）切 3-gram ——
    因为「无人零售咖啡机市场」这种连写，整串去匹配必然匹配不上，
    但「咖啡机」这种 3-gram 能命中。
    """
    if not query:
        return []
    terms: list[str] = []
    for tok in re.findall(rf"[{_CJK}]+|[A-Za-z0-9]{{2,}}", query):
        if re.match(rf"^[{_CJK}]+$", tok):
            if len(tok) <= 6:
                terms.append(tok)
            else:
                for i in range(0, len(tok) - 2, 3):
                    terms.append(tok[i : i + 3])
        else:
            terms.append(tok.lower())
    # 去重保序
    seen: set[str] = set()
    out = []
    for t in terms:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# 泛化词黑名单：这些词在任何网页里都能碰到，命中它们不构成「相关」。
# 只用于相关性判定，不影响 query_terms 的切分结果（缓存 key 等仍用全量）。
_GENERIC_TERMS = frozenset(
    {
        # 单字虚词/量词
        "年", "月", "日", "个", "是", "的", "了", "和", "与", "或", "在", "有",
        # 高频泛义名词：任何一篇行业文章都可能出现
        "新闻", "最新", "消息", "资讯", "报道", "介绍", "说明", "意思", "意思",
        "是什么", "怎么样", "为什么", "哪个", "哪些", "多少", "方法", "工具",
        "官网", "首页", "登录", "注册", "下载", "安装", "教程", "视频", "图片",
        "2020", "2021", "2022", "2023", "2024", "2025", "2026", "2027",
    }
)


def _solid_terms(terms: list[str]) -> list[str]:
    """筛出有区分度的实义词。

    规则（在 query_terms 产出的词上再过一道）：
      · 命中泛化词黑名单 → 丢
      · 纯 4 位数字（年份/编号）→ 丢（区分度太低）
      · 单个汉字 → 丢
      · 长度 <2 的英文/数字串 → 丢（a、go 之类）
    全被滤光时返回空列表，调用方负责退回宽松模式。
    """
    out: list[str] = []
    for t in terms:
        tl = t.lower()
        if tl in _GENERIC_TERMS:
            continue
        if re.fullmatch(r"\d{4}", t):
            continue
        if re.fullmatch(rf"[{_CJK}]", t):
            continue
        if len(t) < 2:
            continue
        if not re.match(rf"^[{_CJK}]+$", t) and len(t) < 3:
            continue
        out.append(t)
    return out


def _numeric_query(query: str) -> bool:
    """是否纯数字串查询（单号/订单号/ID 类）。

    ≥6 位数字（允许空格/连字符分隔）。这类查询跳过投毒判定：
    引擎对陌生数字返回模糊推荐是「没收录」不是投毒。
    """
    compact = re.sub(r"[\s\-]", "", query or "")
    return bool(re.fullmatch(r"\d{6,}", compact))


def relevance_ratio(query: str, results: list[Any]) -> tuple[float, int]:
    """结果里有多少条和查询相关。返回 (比例, 命中条数)。

    用途：**识别投毒式反爬**。
    实测必应在识别为爬虫时不返回 403，而是返回一批和查询完全无关的结果
    （查「无人零售 咖啡机 市场」返回「东京爱情故事」「无的汉语解释」）。
    这种响应状态码 200、结构完整、条数正常，只有相关性检查能抓出来。

    **命中判定只看「实义词」，不看泛化词。**
    早期实现对 query_terms 的任意一个词做子串匹配就算命中，于是：
      query「2026年 无人零售 行业市场规模」
      → terms = ['2026', '年', '无人零售', '行业市场规模']
      → 必应投毒返回一堆 2026 年的日历/百科页，每条都含「2026」
      → ratio = 1.0，10 条垃圾全部漏过（实测 2026-10-13）。
    根因是 `any(term in blob)`：只要沾一个最泛的词就算「相关」，
    而泛化词（年份、单个汉字、常见后缀）在任何网页里都必然出现，
    根本不携带区分度信息。

    改成：命中任意一个**实义词**才算一条相关。实义词 = 长度 ≥2 的
    中文词/数字串，或长度 ≥3 的英文词。全部 terms 都是泛化词时
    （如 query「2026年」）退回原 any 行为，宁可放过也不误杀。
    """
    terms = query_terms(query)
    if not terms or not results:
        return 0.0, 0
    solid = _solid_terms(terms)
    probe = solid or terms
    hit = 0
    for r in results:
        blob = ((getattr(r, "title", "") or "") + " " + (getattr(r, "snippet", "") or "")).lower()
        if any(t.lower() in blob for t in probe):
            hit += 1
    return (hit / len(results), hit)


def sha1_key(*parts: str) -> str:
    """缓存 key。稳定、定长、无碰撞风险（相对内置 hash）。"""
    return hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()


def clean_snippet(s: str, limit: int = 300) -> str:
    """摘要清洗：去空白噪声、去 HTML 实体残片、截断。"""
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = s.replace("\u200b", "")
    s = _WS.sub(" ", s).strip()
    # 常见 HTML 实体（解析不全时残留）
    for a, b in (
        ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
        ("&#39;", "'"), ("&nbsp;", " "), ("&hellip;", "…"),
    ):
        s = s.replace(a, b)
    if len(s) > limit:
        s = s[: limit - 1].rstrip() + "…"
    return s
