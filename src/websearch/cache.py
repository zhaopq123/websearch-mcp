"""双级缓存 —— L1 内存 LRU + L2 SQLite（WAL）。

为什么两级：
  · L1 挡住「同一个 query 在一分钟内被问 5 次」——零 IO，微秒级
  · L2 挡住「重启后又要重新爬一遍」——vivo 是常驻服务，跨重启命中很值钱

SQLite 操作是阻塞的，全部扔进单线程池执行器。
单线程（max_workers=1）是故意的：把并发写串行化，省掉锁竞争和
「database is locked」重试逻辑，代价可忽略（写入量远小于读取量）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .config import Config

log = logging.getLogger("websearch.cache")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key      TEXT PRIMARY KEY,
    kind     TEXT NOT NULL,
    value    TEXT NOT NULL,
    created  REAL NOT NULL,
    expires  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires);
CREATE INDEX IF NOT EXISTS idx_kind ON cache(kind);
"""


class Cache:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        # 注意：**不在这里**固化 enabled。
        # 早期版本把它存成实例属性，结果 cfg.cache_enabled 和 cache.enabled
        # 两处状态可能不一致（改了一个另一个没变，缓存看起来"坏了"）。
        # 现在统一走 property，单一数据源。
        self._mem: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._l1_hits = 0
        self._l2_hits = 0
        self._misses = 0
        self._writes = 0
        self._db_path = cfg.cache_path() / "cache.sqlite3"
        self._executor: asyncio.ThreadPoolExecutor | None = None
        self._conn: sqlite3.Connection | None = None
        self._closed = False

    @property
    def enabled(self) -> bool:
        return self.cfg.cache_enabled

    # ── 生命周期 ──

    def _ensure_conn(self) -> sqlite3.Connection | None:
        if not self.enabled or self._closed:
            return None
        if self._conn is None:
            try:
                conn = sqlite3.connect(
                    str(self._db_path), timeout=5.0, isolation_level=None,
                    check_same_thread=False,
                )
                # WAL：读不阻塞写，写不阻塞读。并发场景下的必选项。
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA busy_timeout=5000")
                conn.executescript(_SCHEMA)
                self._conn = conn
            except Exception as e:
                log.warning("SQLite 不可用，降级为纯内存缓存: %s", e)
                self._conn = None
        return self._conn

    def _executor_get(self):
        if self._executor is None:
            from concurrent.futures import ThreadPoolExecutor

            self._executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="wscache"
            )
        return self._executor

    async def _run(self, fn, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor_get(), fn, *args)

    # ── L1 ──

    def _mem_get(self, key: str) -> Any | None:
        hit = self._mem.get(key)
        if hit is None:
            return None
        expires, value = hit
        if expires < time.time():
            self._mem.pop(key, None)
            return None
        self._mem.move_to_end(key)
        self._l1_hits += 1
        return value

    def _mem_put(self, key: str, value: Any, ttl: int) -> None:
        if ttl <= 0:
            return
        self._mem[key] = (time.time() + ttl, value)
        self._mem.move_to_end(key)
        while len(self._mem) > self.cfg.cache_memory_items:
            self._mem.popitem(last=False)

    # ── L2 ──

    def _db_get(self, key: str) -> Any | None:
        conn = self._ensure_conn()
        if conn is None:
            return None
        try:
            row = conn.execute(
                "SELECT value, expires FROM cache WHERE key=?", (key,)
            ).fetchone()
        except Exception as e:
            log.debug("cache read 失败: %s", e)
            return None
        if not row:
            return None
        value, expires = row
        if expires < time.time():
            try:
                conn.execute("DELETE FROM cache WHERE key=?", (key,))
            except Exception:
                pass
            return None
        try:
            return json.loads(value)
        except Exception:
            return None

    def _db_put(self, key: str, kind: str, value: Any, ttl: int) -> None:
        conn = self._ensure_conn()
        if conn is None or ttl <= 0:
            return
        try:
            conn.execute(
                "INSERT OR REPLACE INTO cache(key,kind,value,created,expires) "
                "VALUES(?,?,?,?,?)",
                (key, kind, json.dumps(value, ensure_ascii=False),
                 time.time(), time.time() + ttl),
            )
            self._writes += 1
            # 过期清理按概率触发（1/64），不做常驻线程 —— 手机 CPU 省着用
            if self._writes % 64 == 0:
                conn.execute("DELETE FROM cache WHERE expires < ?", (time.time(),))
                n = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                if n > self.cfg.cache_db_items:
                    # 按创建时间淘汰最老的一批
                    conn.execute(
                        "DELETE FROM cache WHERE key IN "
                        "(SELECT key FROM cache ORDER BY created ASC LIMIT ?)",
                        (n - self.cfg.cache_db_items,),
                    )
        except Exception as e:
            log.debug("cache write 失败: %s", e)

    # ── 对外 API ──

    async def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        v = self._mem_get(key)
        if v is not None:
            return v
        v = await self._run(self._db_get, key)
        if v is not None:
            self._l2_hits += 1
            # L2 命中后回填 L1：同一个 key 的第二次访问就是内存速度
            self._mem_put(key, v, self.cfg.cache_search_ttl)
            return v
        self._misses += 1
        return None

    async def put(self, key: str, value: Any, ttl: int, kind: str = "search") -> None:
        if not self.enabled or ttl <= 0:
            return
        self._mem_put(key, value, ttl)
        # 写 DB 不 await 返回：异步落盘，不阻塞本次响应
        asyncio.create_task(self._run(self._db_put, key, kind, value, ttl))

    async def clear(self, kind: str | None = None) -> int:
        self._mem.clear()
        conn = self._ensure_conn()
        if conn is None:
            return 0
        try:
            if kind:
                cur = conn.execute("DELETE FROM cache WHERE kind=?", (kind,))
            else:
                cur = conn.execute("DELETE FROM cache")
            return cur.rowcount or 0
        except Exception:
            return 0

    def stats(self) -> dict[str, Any]:
        total = self._l1_hits + self._l2_hits + self._misses
        db_size = 0
        try:
            db_size = self._db_path.stat().st_size if self._db_path.exists() else 0
        except Exception:
            pass
        return {
            "enabled": self.enabled,
            "l1_items": len(self._mem),
            "l1_hits": self._l1_hits,
            "l2_hits": self._l2_hits,
            "misses": self._misses,
            "hit_rate": round((self._l1_hits + self._l2_hits) / total, 3) if total else 0.0,
            "writes": self._writes,
            "db_path": str(self._db_path),
            "db_size_kb": round(db_size / 1024, 1),
        }

    async def aclose(self) -> None:
        self._closed = True
        try:
            if self._conn:
                self._conn.close()
                self._conn = None
        except Exception:
            pass
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None
