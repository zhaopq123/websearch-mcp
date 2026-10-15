"""来源权威度分级（2026-10-15）。

用户诉求：**搜索结果必须保证真实性**——网络上有大量 SEO/GEO 脏数据
（内容农场、聚合站、AI 洗稿站、UGC 搬运），它们标题党、看起来相关，
但内容不可信。检索层唯一能做的真实性信号是**来源可信度**：把权威源
（官媒/政府/学术/官方文档/专业媒体）排前，把低质源降权。

设计原则：
  · **降权而非删除**——知乎/CSDN 也有好内容，直接删会丢信息；
    权威源 +bonus 只是让「同一话题」下更可信的来源浮上来。
  · **连续值**而非布尔——返回 -1.0（低质）~ +1.0（权威），
    由 fusion 的 authority_weight 决定实际影响力。
  · **规则 + 名单**组合——TLD 规则（.gov/.edu）稳定且有普适性；
    域名名单覆盖具体站点，随实测扩充。

⚠️ 与 engines._SEARCH_NOISE_HOSTS 的分工：
  后者是**域名级硬过滤**（游戏/小说站，对任何查询都是噪声，直接丢）；
  本模块是**软权重**（同话题下的可信度排序）。两者互补不重复。
"""
from __future__ import annotations

# ── 高权威（+1.0）：政府 / 教育 / 军队 / 顶级官媒 / 学术出版 ──
# TLD 规则见 _AUTHORITY_TLDS；这里列具体域名。
_HIGH_AUTHORITY = (
    # 顶级官媒 / 通讯社
    "xinhuanet.com", "news.cn", "people.com.cn", "peopleapp.com",
    "cctv.com", "cctv.cn", "chinanews.com.cn", "china.com.cn",
    "gmw.cn", "youth.cn", "china.org.cn", "cnr.cn", "cri.cn",
    "gov.cn", "court.gov.cn", "spp.gov.cn", "stats.gov.cn",
    "mofcom.gov.cn", "miit.gov.cn", "nmpa.gov.cn", "pbc.gov.cn",
    "csrc.gov.cn", "customs.gov.cn",
    # 学术出版 / 论文库
    "arxiv.org", "nature.com", "science.org", "sciencemag.org",
    "ieee.org", "acm.org", "springer.com", "sciencedirect.com",
    "wiley.com", "tandfonline.com", "pubmed.ncbi.nlm.nih.gov",
    "ncbi.nlm.nih.gov", "semanticscholar.org",
    # 国际权威组织
    "un.org", "who.int", "worldbank.org", "imf.org", "oecd.org",
    "iso.org", "ietf.org", "w3.org",
)

# ── 权威（+0.6）：主流媒体 / 财经 / 科技媒体 / 百科 / 官方产品站 ──
_AUTHORITY = (
    # 主流媒体（有编辑把关）
    "thepaper.cn", "caixin.com", "yicai.com", "21jingji.com",
    "stcn.com", "jiemian.com", "nbd.com.cn", "eeo.com.cn",
    "news.qq.com", "news.163.com", "news.sina.com.cn",
    "ifeng.com", "bjnews.com.cn", "beijingnews.com.cn",
    "nfnews.com", "southcn.com", "huanqiu.com", "globaltimes.cn",
    "digitalpaper.stdaily.com", "stdaily.com", "kepu.gov.cn",
    # 财经 / 数据
    "eastmoney.com", "cnstock.com", "hexun.com", "jrj.com.cn",
    "wind.com.cn", "choiceinfo.com", "sse.com.cn", "szse.cn",
    # 科技媒体（专业采编）
    "36kr.com", "huxiu.com", "tmtpost.com", "leiphone.com",
    "qbitai.com", "jiqizhixin.com", "infoq.cn", "itjuzi.com",
    "geekpark.net", "sspai.com", "zhidx.com", "aiera.com.cn",
    # 百科 / 垂直权威
    "wikipedia.org", "wikimedia.org", "baike.baidu.com",
    "mayoclinic.org", "webmd.com", "health.cn",
    # 官方产品站 / 文档（一手信息）
    "apple.com", "microsoft.com", "google.com", "openai.com",
    "anthropic.com", "deepseek.com", "moonshot.cn", "zhipuai.cn",
    "aliyun.com", "cloud.tencent.com", "huaweicloud.com",
    "python.org", "docs.python.org", "developer.mozilla.org",
    "github.com", "gitlab.com", "stackoverflow.com",
    "docker.com", "kubernetes.io", "postgresql.org",
    "nodejs.org", "golang.org", "rust-lang.org",
    # 大厂技术官方博客
    "engineering.fb.com", "netflixtechblog.com", "aws.amazon.com",
    "developers.googleblog.com", "research.google",
)

# ── 低质（-0.6）：UGC 搬运 / 文库 / 聚合农场 / SEO 站 ──
# 判定原则：内容由用户上传或机器抓取、无编辑审核、常见洗稿与标题党。
# **降权而非拉黑**——其中不少站有技术内容的偶发高质量帖。
_LOW_QUALITY = (
    # UGC 技术社区（好帖有，但大量搬运/过时/AI 洗稿）
    "csdn.net", "juejin.cn", "cnblogs.com", "51cto.com",
    "oschina.net", "iteye.com", "zhihu.com", "zhihu.com",
    "segmentfault.com", "jianshu.com", "bbs.csdn.net",
    # 自媒体平台（无编辑把关）
    "baijiahao.baidu.com", "sohu.com", "toutiao.com",
    "163.com/dy", "dy.163.com", "kuaishou.com", "douyin.com",
    "weibo.com", "mp.weixin.qq.com",
    # 文库 / 文档分享（二手转载）
    "wenku.baidu.com", "docin.com", "doc88.com", "book118.com",
    "360doc.com", "renrendoc.com", "mayiwenku.com",
    # 聚合 / 内容农场 / SEO 站（实测出现在结果里的低质源）
    "aikitapp.com", "chattools.top", "53ai.com", "aibase.com",
    "thepaper.cn/dy", "so.html5.qq.com",
    # 问答/百科农场
    "zhidao.baidu.com", "wenda.so.com", "iask.sina.com.cn",
)

# TLD 级规则（匹配则直接高权威，优先级最高）
_AUTHORITY_TLDS = (
    ".gov", ".gov.cn", ".edu", ".edu.cn", ".ac.cn", ".ac.uk",
    ".mil", ".int", ".go.jp", ".go.kr", ".gouv.fr", ".bund.de",
)

# 低质 TLD（批量 SEO 站常用）
_LOW_TLDS = (".top", ".xyz", ".buzz", ".click", ".icu", ".cyou")


def _host_match(host: str, entry: str) -> bool:
    """域名匹配：精确或子域后缀。entry 可含路径（如 163.com/dy）。"""
    if "/" in entry:
        return False   # 路径级判定在 domain_authority 里单独处理
    return host == entry or host.endswith("." + entry)


def domain_authority(url_or_host: str) -> float:
    """返回域名权威度：-1.0（低质）~ +1.0（权威），中性 0.0。

    Args:
        url_or_host: 完整 URL 或裸域名。

    Returns:
        权威度分值。fusion 用它乘 authority_weight 加到排序分上。
    """
    from .text import domain_of

    host = domain_of(url_or_host) if "//" in url_or_host else url_or_host
    host = (host or "").lower().strip()
    if not host:
        return 0.0
    low = url_or_host.lower()

    # 1) TLD 规则（最稳的先判）
    if any(host.endswith(t) for t in _AUTHORITY_TLDS):
        return 1.0
    if any(host.endswith(t) for t in _LOW_TLDS):
        return -0.6

    # 2) 路径级低质判定（自媒体号 / 百度聚合页，域是权威但路径是 UGC）
    for entry in _LOW_QUALITY:
        if "/" in entry and entry in low:
            return -0.6

    # 3) 域名名单
    if any(_host_match(host, d) for d in _HIGH_AUTHORITY):
        return 1.0
    if any(_host_match(host, d) for d in _AUTHORITY):
        return 0.6
    if any(_host_match(host, d) for d in _LOW_QUALITY):
        return -0.6
    return 0.0
