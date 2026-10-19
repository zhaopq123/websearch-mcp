# -*- coding: utf-8 -*-
"""结果融合测试：去重 / 交叉验证 / 域名配额。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.fusion import fuse
from websearch.models import SearchResult


def mk(title, url, engine, rank=0, snippet=""):
    return SearchResult(title=title, url=url, snippet=snippet,
                        engine=engine, rank=rank, site=url.split("/")[2])


def test_dedup_same_url_different_tracking():
    """同一个页面带不同 utm 参数必须合并成一条。"""
    a = [mk("咖啡机市场", "https://ex.com/a?utm_source=x", "bing", 0)]
    b = [mk("咖啡机市场", "https://www.ex.com/a/", "so360", 1)]
    out, stats = fuse([a, b], weights={"bing": 1.0, "so360": 0.9}, max_results=10)
    assert len(out) == 1, f"应合并为 1 条，实际 {len(out)}"
    assert stats["unique_url"] == 1
    assert stats["raw"] == 2


def test_cross_engine_bonus():
    """被多个引擎同时命中的结果必须排在只被一个引擎命中的前面。"""
    shared = mk("共同结果", "https://shared.com/x", "bing", 5)
    single = mk("单一结果", "https://single.com/y", "bing", 0)
    out, _ = fuse(
        [[shared, single], [mk("共同结果", "https://shared.com/x", "so360", 5)]],
        weights={"bing": 1.0, "so360": 1.0}, max_results=5,
    )
    assert out[0].url == "https://shared.com/x", (
        f"交叉验证结果应排第一，实际第一是 {out[0].url}"
    )
    assert len(out[0].engines) == 2


def test_domain_cap():
    """同一域名不能霸占结果列表。"""
    items = [[mk(f"页面{i}", f"https://zhihu.com/p/{i}", "bing", i) for i in range(8)]]
    out, stats = fuse(items, weights={"bing": 1.0}, max_results=10, per_domain_cap=3)
    zhihu = [r for r in out if "zhihu.com" in r.url]
    assert len(zhihu) <= 3, f"单域名配额失效：{len(zhihu)} 条"


def test_domain_cap_backfill_when_short():
    """结果只有一两条时才允许少量超配额补齐，但仍有上限（不能补满）。"""
    items = [[mk(f"页面{i}", f"https://zhihu.com/p/{i}", "bing", i) for i in range(8)]]
    out, _ = fuse(items, weights={"bing": 1.0}, max_results=8, per_domain_cap=2)
    assert 3 <= len(out) <= 4, f"补齐策略异常：{len(out)} 条"


def test_title_simhash_dedup():
    """标题高度相似但 URL 不同 → 视为同一条。"""
    a = [mk("无人零售咖啡机市场分析报告", "https://a.com/1", "bing", 0)]
    b = [mk("无人零售咖啡机市场分析报告", "https://b.com/2", "so360", 0)]
    out, stats = fuse([a, b], weights={"bing": 1.0, "so360": 1.0}, max_results=10)
    assert stats["after_title_dedup"] == 1


def test_snippet_complement():
    """一个有摘要一个没有 → 合并后要有摘要。"""
    a = [mk("标题", "https://x.com/a", "bing", 0, snippet="")]
    b = [mk("标题", "https://x.com/a", "so360", 1, snippet="这是摘要")]
    out, _ = fuse([a, b], weights={"bing": 1.0, "so360": 1.0}, max_results=5)
    assert out[0].snippet == "这是摘要"


def test_empty_input():
    out, stats = fuse([], weights={}, max_results=10)
    assert out == [] and stats["returned"] == 0


def test_max_results_respected():
    items = [[mk(f"t{i}", f"https://s{i}.com/x", "bing", i) for i in range(30)]]
    out, _ = fuse(items, weights={"bing": 1.0}, max_results=5)
    assert len(out) == 5
