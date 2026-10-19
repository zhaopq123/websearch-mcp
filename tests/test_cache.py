# -*- coding: utf-8 -*-
"""双级缓存测试。"""
import asyncio
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.cache import Cache
from websearch.config import Config


def make_cache(tmpdir, **kw):
    c = Config.from_env()
    c.cache_dir = str(tmpdir)
    c.cache_enabled = True
    c.cache_memory_items = 8
    for k, v in kw.items():
        setattr(c, k, v)
    return Cache(c)


def test_set_get_roundtrip(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        await cache.put("k1", {"a": 1}, 60, "search")
        await asyncio.sleep(0.15)  # 等异步落盘
        assert await cache.get("k1") == {"a": 1}
        await cache.aclose()
    asyncio.run(run())


def test_l1_faster_and_hits(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        await cache.put("k", "value", 60)
        v1 = await cache.get("k")
        v2 = await cache.get("k")
        assert v1 == v2 == "value"
        assert cache._l1_hits >= 1
        await cache.aclose()
    asyncio.run(run())


def test_ttl_expiry(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        await cache.put("k", "v", 1)
        await asyncio.sleep(1.2)
        assert await cache.get("k") is None
        await cache.aclose()
    asyncio.run(run())


def test_l2_survives_new_instance(tmp_path):
    """L2 的价值：重启后缓存还在。"""
    async def run():
        c1 = make_cache(tmp_path)
        await c1.put("persist", {"deep": [1, 2, 3]}, 300, "search")
        await asyncio.sleep(0.2)
        await c1.aclose()

        c2 = make_cache(tmp_path)
        assert await c2.get("persist") == {"deep": [1, 2, 3]}
        await c2.aclose()
    asyncio.run(run())


def test_l1_lru_eviction(tmp_path):
    async def run():
        cache = make_cache(tmp_path, cache_memory_items=3)
        for i in range(10):
            await cache.put(f"k{i}", i, 300)
        assert len(cache._mem) <= 3
        await cache.aclose()
    asyncio.run(run())


def test_disabled_cache(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        cache.cfg.cache_enabled = False   # 走 cfg 单一数据源
        await cache.put("k", "v", 300)
        assert await cache.get("k") is None
        await cache.aclose()
    asyncio.run(run())


def test_clear_by_kind(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        await cache.put("s1", "a", 300, "search")
        await cache.put("f1", "b", 300, "fetch")
        await asyncio.sleep(0.2)
        n = await cache.clear("search")
        assert n >= 1
        assert await cache.get("s1") is None
        assert await cache.get("f1") == "b"
        await cache.aclose()
    asyncio.run(run())


def test_stats_shape(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        await cache.put("k", "v", 60)
        s = cache.stats()
        for key in ("enabled", "l1_items", "l1_hits", "l2_hits", "misses",
                    "hit_rate", "db_path"):
            assert key in s
        await cache.aclose()
    asyncio.run(run())


def test_unicode_roundtrip(tmp_path):
    async def run():
        cache = make_cache(tmp_path)
        await cache.put("中文key", {"标题": "咖啡机市场"}, 300, "search")
        await asyncio.sleep(0.15)
        assert await cache.get("中文key") == {"标题": "咖啡机市场"}
        await cache.aclose()
    asyncio.run(run())


# ══════════════ TTL 必须从 put 时刻起算（2026-10-19 实测回归） ══════════════
#
# 背景：`_db_put` 跑在单线程 executor 里，原实现用 `time.time() + ttl`
# 在**落盘那一刻**算过期 —— 排队 0.47s 就让 ttl=1 的条目活了 1.47s。
# 症状是 test_ttl_expiry 恒红（sleep 1.2 后仍能读到）。
# 对外承诺的「缓存 TTL 5 分钟」因此是假的，必须钉死。


def test_db_expires_measured_from_put_time(tmp_path):
    """L2 的 created/expires 必须按 put 时刻算，不能按落盘时刻算。"""
    import sqlite3

    async def run():
        cache = make_cache(tmp_path)
        t0 = time.time()
        await cache.put("k", "v", 30)
        # 落盘是异步的，轮询等它出现（最多 5s），别拿固定 sleep 赌调度
        row = None
        for _ in range(100):
            await asyncio.sleep(0.05)
            try:
                conn = sqlite3.connect(cache._db_path)
                try:
                    row = conn.execute(
                        "SELECT created, expires FROM cache WHERE key='k'"
                    ).fetchone()
                finally:
                    conn.close()
            except sqlite3.OperationalError:
                row = None
            if row:
                break
        assert row, "5s 内没等到 L2 落盘"
        created, expires = row
        assert abs(created - t0) < 0.15, f"created 偏了 {created - t0:.3f}s（应按 put 时刻）"
        assert abs((expires - created) - 30) < 0.05, f"TTL 不是 30s：{expires - created}"
        await cache.aclose()
    asyncio.run(run())


def test_l2_hit_does_not_extend_ttl(tmp_path):
    """L2 命中回填 L1 必须沿用原过期时刻 —— 不能重新给一整段 TTL。

    原实现回填用 `cache_search_ttl`（默认 300s），于是每次 L2 命中都把
    短 TTL 条目续命成 300s，缓存永不过期。
    """
    async def run():
        cache = make_cache(tmp_path, cache_search_ttl=3600)
        await cache.put("k", "v", 2)
        await asyncio.sleep(0.2)      # 等落盘
        cache._mem.clear()            # 强制 L1 miss，逼它走 L2
        assert await cache.get("k") == "v", "L2 应当命中"
        expires, _ = cache._mem["k"]
        # 回填后的过期时刻仍应是 put 时刻 + 2，而不是 now + 3600
        assert expires <= time.time() + 2.01, \
            f"L2 回填把 TTL 拉长到 {expires - time.time():.1f}s"
        await cache.aclose()
    asyncio.run(run())


def test_put_then_aclose_flushes_pending_write(tmp_path):
    """put 之后立刻 aclose，落盘不能被丢掉。

    2026-10-19 实测：原实现 aclose 直接置 _closed + 关连接，排队中的
    `_db_put` 会因 `_ensure_conn()` 返回 None 而静默丢弃 ——
    `test_l2_survives_new_instance` 在机器忙时偶发红就是这个。
    """
    async def run():
        c1 = make_cache(tmp_path)
        await c1.put("flush", "v", 300)
        await c1.aclose()          # 故意不等 sleep
        c2 = make_cache(tmp_path)
        assert await c2.get("flush") == "v", "aclose 前没把排队写入刷下去"
        await c2.aclose()
    asyncio.run(run())
