"""结果融合 —— 去重、打分、域名配额。

多源聚合的价值全在这一层：不融合的话，三个源返回的就是「同一批 URL 重复三遍」，
模型拿到的信息量还不如单源。
"""

from __future__ import annotations

import logging
from collections import defaultdict

from .models import SearchResult
from .text import canonicalize_url, domain_of, hamming, simhash, normalize_text

log = logging.getLogger("websearch.fusion")

# 位置衰减系数：第 1 名 1.0，第 10 名 0.625，第 30 名 0.357
# 刻意做得平缓 —— 不同引擎的排序口径差异很大，
# 过度信任第一名会让单个引擎（通常是 Bing）单方面主导最终结果。
POS_DECAY = 0.06

CROSS_BONUS = 0.35      # 被多个引擎同时命中的加成（交叉验证是最强相关性信号）
DOMAIN_DECAY = 0.85     # 同域名第 k 条的衰减
FRESH_BONUS = 0.2


def _position_decay(rank: int) -> float:
    return 1.0 / (1.0 + POS_DECAY * max(0, rank))


def fuse(
    outcomes: list[list[SearchResult]],
    *,
    weights: dict[str, float],
    max_results: int = 20,
    per_domain_cap: int = 3,
    authority_weight: float = 0.5,
) -> tuple[list[SearchResult], dict[str, int]]:
    """把多个引擎的结果融合成一份有序结果。

    返回 (结果列表, 统计信息)。
    """
    # 1) 按规范化 URL 聚合
    by_key: dict[str, SearchResult] = {}
    key_titles: dict[str, list[str]] = defaultdict(list)

    for results in outcomes:
        for r in results:
            key = canonicalize_url(r.url)
            if not key or not key.startswith("http"):
                continue
            r._url_key = key
            exist = by_key.get(key)
            if exist is None:
                r.engines = [r.engine]
                r.score = 0.0
                by_key[key] = r
                key_titles[key].append(r.title)
            else:
                if r.engine not in exist.engines:
                    exist.engines.append(r.engine)
                # 摘要互补：谁有摘要用谁的；都没有就拼长的
                if not exist.snippet and r.snippet:
                    exist.snippet = r.snippet
                elif r.snippet and len(r.snippet) > len(exist.snippet):
                    exist.snippet = r.snippet
                # 位次取各引擎中最好的（越靠前越可信）
                if r.rank < exist.rank:
                    exist.rank = r.rank
                if not exist.published and r.published:
                    exist.published = r.published
                key_titles[key].append(r.title)

    stats = {"raw": sum(len(o) for o in outcomes), "unique_url": len(by_key)}

    # 2) 打分
    for key, r in by_key.items():
        base = 0.0
        for eng in r.engines:
            w = weights.get(eng, 0.5)
            base += w * _position_decay(r.rank)
        # 交叉验证：N 个引擎都命中 → 强信号
        base += CROSS_BONUS * (len(r.engines) - 1)
        if r.published:
            base += FRESH_BONUS
        # 有摘要的略加分（无摘要的多半是解析不全的残条）
        if r.snippet:
            base += 0.05
        # 来源权威度（2026-10-15 用户诉求：保真实性、压 SEO/GEO 脏数据）。
        # 权威源 +、低质源 −，权重可配（authority_weight，默认 0.5）。
        # 量级设计：单引擎首条约 1.0 分，±0.5 足以重排相邻档，
        # 但压不过「多引擎交叉验证」的强信号——真实性第一信号仍是
        # 多源一致，权威度是第二信号。
        try:
            from .authority import domain_authority

            base += authority_weight * domain_authority(r.url)
        except Exception:
            pass
        r.score = round(base, 4)

    # 3) 标题 SimHash 去重（同一内容不同 URL 标题一致 → 视为重复）
    deduped: list[SearchResult] = list(by_key.values())
    if len(deduped) > 1:
        seen_hash: list[int] = []
        kept: list[SearchResult] = []
        for r in sorted(deduped, key=lambda x: -x.score):
            h = simhash(normalize_text(r.title))
            dup = False
            for sh in seen_hash:
                # 阈值 6/64：实测「同一篇文章在不同站」的标题距离约 8，
                # 「完全不同的标题」距离 > 10。取 6 偏保守 ——
                # 漏掉几条重复顶多是冗余，误杀不同文章才是真丢信息。
                if hamming(h, sh) <= 6:
                    dup = True
                    break
            if dup:
                continue
            seen_hash.append(h)
            kept.append(r)
        deduped = kept
    stats["after_title_dedup"] = len(deduped)

    # 4) 域名配额 + 最终排序
    deduped.sort(key=lambda r: (-r.score, r.rank))
    domain_count: dict[str, int] = defaultdict(int)
    final: list[SearchResult] = []
    overflow: list[SearchResult] = []
    for r in deduped:
        d = domain_of(r.url)
        n = domain_count[d]
        if n >= per_domain_cap:
            overflow.append(r)
            continue
        domain_count[d] = n + 1
        # 同域名第 n 条衰减
        r.score = round(r.score * (DOMAIN_DECAY ** n), 4)
        final.append(r)

    # 配额用尽后若实在太少（比如只有一个源返回、且全站同源），
    # 从 overflow 里补一点 —— 宁可多样性差，也不要结果太少。
    # 但补齐必须**有上限**：无脑补到 max_results 会让域名配额形同虚设，
    # 出现「十条全是知乎」。这里只补到 min(max_results, cap*2)，
    # 且仅在结果数低于 3 条时才补。
    if len(final) < 3 and overflow:
        backfill_cap = min(max_results, per_domain_cap * 2)
        final.extend(overflow[: backfill_cap - len(final)])
    final.sort(key=lambda r: (-r.score, r.rank))

    stats["returned"] = len(final[:max_results])
    stats["domains"] = len(domain_count)
    return final[:max_results], stats
