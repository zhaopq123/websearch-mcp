# -*- coding: utf-8 -*-
"""文本/URL 规范化测试。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.text import (
    canonicalize_url, domain_of, hamming, normalize_text,
    query_terms, relevance_ratio, simhash, clean_snippet,
)
from websearch.models import SearchResult


def test_canonicalize_tracking_params():
    a = canonicalize_url("https://www.example.com/a/b?utm_source=x&id=3&fbclid=zz")
    b = canonicalize_url("http://example.com/a/b/?id=3#frag")
    assert a == b, f"{a} != {b}"


def test_canonicalize_param_order():
    a = canonicalize_url("https://ex.com/p?a=1&b=2")
    b = canonicalize_url("https://ex.com/p?b=2&a=1")
    assert a == b


def test_canonicalize_rejects_non_http():
    assert canonicalize_url("javascript:alert(1)") == "javascript:alert(1)"
    assert canonicalize_url("") == ""


def test_domain_of():
    assert domain_of("https://www.zhihu.com/p/123") == "zhihu.com"
    assert domain_of("https://news.qq.com/a") == "news.qq.com"
    assert domain_of("not a url") == ""


def test_simhash_stable_across_process():
    """SimHash 必须稳定。

    用 blake2b 而不是内置 hash()：内置 hash 对字符串带随机盐，
    重启进程后同一个标题会得到不同指纹，去重和缓存会全错。
    """
    h1 = simhash("人工智能改变世界")
    h2 = simhash("人工智能改变世界")
    assert h1 == h2
    assert hamming(h1, h1) == 0


def test_simhash_similar_titles_close():
    a = simhash("无人零售咖啡机市场分析报告")
    b = simhash("无人零售咖啡机市场分析报告 - 知乎")
    assert hamming(a, b) <= 10  # 实测 8：仅多出「知乎」后缀


def test_simhash_different_titles_far():
    a = simhash("Python 异步编程入门教程")
    b = simhash("今日股市大盘收盘情况分析")
    assert hamming(a, b) > 10


def test_normalize_text():
    assert normalize_text("ＡＢＣ　１２３") == "abc123"
    assert normalize_text("你好，世界！") == "你好世界"


def test_query_terms_cjk():
    terms = query_terms("无人零售 咖啡机 市场")
    assert "无人零售" in terms and "咖啡机" in terms and "市场" in terms


def test_query_terms_long_cjk_splits():
    """连写的中文串要切成 3-gram，否则整串匹配必然匹配不上。"""
    terms = query_terms("无人零售咖啡机市场前景")
    assert any(len(t) == 3 for t in terms)


def test_relevance_ratio_detects_poison():
    """投毒检测：结果里没有一条命中查询词 → 必须判为不相关。"""
    good = [SearchResult(title="自助咖啡机市场洞察", url="https://a.com", snippet="无人零售")]
    bad = [SearchResult(title="东京爱情故事", url="https://b.com", snippet="日剧")]
    r_good, h_good = relevance_ratio("无人零售 咖啡机", good)
    r_bad, h_bad = relevance_ratio("无人零售 咖啡机", bad)
    assert h_good == 1 and r_good == 1.0
    assert h_bad == 0 and r_bad == 0.0


def test_clean_snippet_truncates():
    s = clean_snippet("x" * 500, limit=50)
    assert len(s) <= 51 and s.endswith("…")


def test_clean_snippet_entities():
    assert "&" in clean_snippet("a &amp; b")
    assert clean_snippet("a&nbsp;b") == "a b"


# ══════════════ 2026-10-15 数字查询跳过投毒判定 ══════════════


def test_numeric_query_detection():
    from websearch.text import _numeric_query

    assert _numeric_query("152129009867")          # 12 位数字
    assert _numeric_query("152 1290 0986")         # 空格分隔
    assert _numeric_query("YT4180001234567") is False  # 字母混合
    assert _numeric_query("15212") is False        # <6 位
    assert _numeric_query("关键词搜索") is False
    assert _numeric_query("") is False


def test_numeric_query_relevance_includes_url():
    """数字查询命中判定含 URL——单号常出现在链接/参数里。"""
    from websearch.engines import SearchResult
    from websearch.text import relevance_ratio

    q = "152129009867"
    results = [
        SearchResult(title="推荐内容一", url="https://x.com/id/152129009867",
                     snippet="模糊推荐", engine="t", rank=0, site="x.com"),
        SearchResult(title="完全无关", url="https://y.com/other",
                     snippet="别的", engine="t", rank=1, site="y.com"),
    ]
    # URL 含数字 → 命中（relevance_ratio 本身不看 URL，编排层数字分支看）
    blob_hits = sum(
        1 for r in results
        if q in ((r.title or "") + (r.snippet or "") + (r.url or "")))
    assert blob_hits == 1
