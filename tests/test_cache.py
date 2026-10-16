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
