"""服务自维护：把「只增不减」的垃圾就地清掉。

为什么需要（2026-10-14 实测，服务常驻数周后必然发生）：
  · `runs` 表每轮 hunt 插一行，**永不清理** → 无限增长
  · WAL 不 checkpoint 就停在上限（实测 nodes/cache 各 4MB）
  · `cache.sqlite3` 删除过期行后文件**不缩**（实测 504KB / 仅 9 行有效）
  · `node_proxy.log` / 已废机场留下的 `singbox.log` / 一次性探测配置 长期堆积
  · `backups/` 越攒越大（曾堆到 90MB）

设计原则：
  · **低频（默认 30 分钟）+ 尽力而为**：任何异常只记日志，绝不抛给调用方
    ——维护失败不该拖垮搜索。
  · **不重启任何进程、不碰正在跑的 sing-box**：文本日志用 copytruncate。
  · **VACUUM 有代价**（整库重写），只有空闲页占比超阈值才做。
  · 删除一律「有上限/有保留份数」，绝不无限删或删到空。
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("websearch.maintenance")

# ── 阈值（都可用环境变量覆盖，见 Maintenance.from_env）──
KEEP_RUNS = 500                  # runs 表只留最近 N 条（约 3-4 天）
LOG_MAX_BYTES = 1_000_000        # 单份日志上限（1MB）
LOG_KEEP = 2                     # 轮转保留份数（.1/.2）
VACUUM_FREE_RATIO = 0.30         # 空闲页占比超此值才 VACUUM
BACKUPS_MAX_BYTES = 50_000_000   # backups/ 总量上限（50MB）
STALE_ARTIFACT_SEC = 7 * 24 * 3600   # 一次性产物超过 7 天算陈旧
DEFAULT_INTERVAL_SEC = 1800.0    # 维护周期（30 分钟）


# ══════════════════ 日志轮转 ══════════════════

def rotate_log_copytruncate(path: Path, max_bytes: int = LOG_MAX_BYTES,
                            keep: int = LOG_KEEP) -> bool:
    """按大小轮转文本日志（**copytruncate** 模式）。

    为什么不用 rename：这些日志由**别的进程**持有 fd ——
    `service.log` 由宿主 shell 的 `>>` 持有、`node_proxy.log` 由 sing-box
    以 `open(..., "ab")` 持有。rename 之后写者仍往旧 inode 写，
    轮转等于没做（日志换个名字继续变大）。

    copytruncate = 先备份内容到 .1，再**原地 truncate(0)**。因为写者都是
    O_APPEND，下次写会从 0 开始，**不会留空洞**（非 O_APPEND 写者才会留，
    所以本函数只用于已确认为 O_APPEND 的写者）。
    """
    try:
        if not path.exists():
            return False
        size = path.stat().st_size
        if size < max_bytes:
            return False
        # 历史份后移：.N-1 → .N
        for i in range(keep, 1, -1):
            older = path.with_name(f"{path.name}.{i - 1}")
            newer = path.with_name(f"{path.name}.{i}")
            if older.exists():
                os.replace(older, newer)
        if keep >= 2:
            shutil.copy2(path, path.with_name(f"{path.name}.1"))
        with open(path, "r+b") as f:
            f.truncate(0)
        log.info("日志已轮转：%s（原 %d 字节）", path.name, size)
        return True
    except Exception as e:                      # 尽力而为
        log.warning("日志轮转失败（%s）: %s", path.name, e)
        return False


# ══════════════════ SQLite 维护 ══════════════════

def _connect(db_path: Path) -> sqlite3.Connection | None:
    try:
        # autocommit：PRAGMA / VACUUM 不能在事务里跑
        conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn
    except Exception as e:
        log.warning("维护连库失败（%s）: %s", db_path, e)
        return None


def prune_runs(db_path: Path, keep: int = KEEP_RUNS) -> int:
    """`runs` 表只保留最近 N 条（明细表，留最近足够回溯即可）。"""
    conn = _connect(db_path)
    if conn is None:
        return 0
    try:
        cur = conn.execute(
            "DELETE FROM runs WHERE id NOT IN"
            " (SELECT id FROM runs ORDER BY id DESC LIMIT ?)", (int(keep),))
        return int(cur.rowcount or 0)
    except Exception as e:
        log.warning("清理 runs 失败: %s", e)
        return 0
    finally:
        conn.close()


def checkpoint(db_path: Path) -> bool:
    """WAL checkpoint 到主库并截断 wal 文件（回收实测 4MB×2 的 wal）。"""
    conn = _connect(db_path)
    if conn is None:
        return False
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return True
    except Exception as e:
        log.warning("WAL checkpoint 失败（%s）: %s", db_path.name, e)
        return False
    finally:
        conn.close()


def vacuum_if_bloated(db_path: Path,
                      free_ratio: float = VACUUM_FREE_RATIO) -> bool:
    """空闲页占比超阈值才 VACUUM（整库重写有代价，别频繁做）。"""
    conn = _connect(db_path)
    if conn is None:
        return False
    try:
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
        free = conn.execute("PRAGMA freelist_count").fetchone()[0]
        if not pages or not free or (free / pages) < free_ratio:
            return False
        conn.execute("VACUUM")
        log.info("已 VACUUM %s（空闲 %d/%d 页）", db_path.name, free, pages)
        return True
    except Exception as e:
        # 有并发写时 VACUUM 会拿不到独占锁 → 记一笔，下轮再试
        log.warning("VACUUM 跳过（%s）: %s", db_path.name, e)
        return False
    finally:
        conn.close()


# ══════════════════ 文件清理 ══════════════════

def clean_stale(paths: list[Path],
                older_than_sec: int = STALE_ARTIFACT_SEC) -> list[str]:
    """删除陈旧的一次性产物（默认 7 天未改动）。"""
    removed: list[str] = []
    now = time.time()
    for p in paths:
        try:
            if p.is_file() and (now - p.stat().st_mtime) > older_than_sec:
                p.unlink()
                removed.append(p.name)
                log.info("清理陈旧文件：%s", p.name)
        except Exception:
            continue
    return removed


def trim_dir_by_size(directory: Path, max_bytes: int = BACKUPS_MAX_BYTES,
                     keep_newest: int = 1) -> list[str]:
    """目录总量超上限时删最旧的（至少保留 keep_newest 个，绝不删空）。"""
    removed: list[str] = []
    try:
        files = [f for f in directory.iterdir() if f.is_file()]
    except Exception:
        return removed
    if not files:
        return removed
    try:
        files.sort(key=lambda f: f.stat().st_mtime)      # 旧 → 新
    except Exception:
        return removed
    total = sum(f.stat().st_size for f in files)
    victims = files[:-keep_newest] if len(files) > keep_newest else []
    for f in victims:
        if total <= max_bytes:
            break
        try:
            sz = f.stat().st_size
            f.unlink()
            removed.append(f.name)
            total -= sz
            log.info("清理超限备份：%s（%d 字节）", f.name, sz)
        except Exception:
            continue
    return removed


# ══════════════════ 编排 ══════════════════

class Maintenance:
    """服务自维护器：一轮清理全部垃圾，低频循环。"""

    def __init__(self, *, data_dir: Path, app_dir: Path,
                 interval_sec: float = DEFAULT_INTERVAL_SEC):
        self.data_dir = Path(data_dir)
        self.app_dir = Path(app_dir)
        self.interval_sec = max(60.0, float(interval_sec))
        self._task: asyncio.Task | None = None
        self.last_report: dict[str, Any] = {}

    @classmethod
    def from_env(cls, *, data_dir: Path, app_dir: Path) -> "Maintenance":
        def _f(name: str, default: float) -> float:
            try:
                return float(os.environ.get(name, "") or default)
            except Exception:
                return default
        return cls(
            data_dir=data_dir, app_dir=app_dir,
            interval_sec=_f("WS_MAINTENANCE_INTERVAL", DEFAULT_INTERVAL_SEC),
        )

    # 需要轮转的日志（都是 O_APPEND 写者，copytruncate 安全）
    def _log_targets(self) -> list[Path]:
        return [
            self.app_dir / "service.log",          # 宿主 shell `>>`（O_APPEND）
            self.app_dir / "panel.log",            # run-panel.sh `>>`
            self.data_dir / "node_proxy.log",      # sing-box open(..., "ab")
        ]

    def run_once(self) -> dict[str, Any]:
        """跑一轮清理，返回做了什么（无凭据，可供工具/日志读）。"""
        rep: dict[str, Any] = {"at": time.time()}
        nodes_db = self.data_dir / "nodes.sqlite3"
        cache_db = self.data_dir / "cache.sqlite3"

        rep["runs_pruned"] = prune_runs(nodes_db) if nodes_db.exists() else 0
        rep["vacuumed"] = []
        for db in (nodes_db, cache_db):
            if not db.exists():
                continue
            checkpoint(db)          # 先把 WAL 灌回主库，page_count 才是准的
            if vacuum_if_bloated(db):
                rep["vacuumed"].append(db.name)
                # VACUUM 的产物先落进 WAL，**必须再 checkpoint 一次**才能把主库
                # 文件真正缩下来。实测（2026-10-14）：只 VACUUM 不补 checkpoint，
                # 主库仍停在旧尺寸（504KB/126 页），逻辑上已缩到 16 页却看不出来。
                checkpoint(db)

        rep["logs_rotated"] = [p.name for p in self._log_targets()
                               if rotate_log_copytruncate(p)]
        # 已废机场留下的一次性日志（无写者，纯陈旧产物）
        rep["stale_removed"] = clean_stale(
            [self.app_dir / "proxy-run" / "singbox.log"])
        rep["backups_trimmed"] = trim_dir_by_size(self.app_dir / "backups")

        self.last_report = rep
        return rep

    def _tick(self) -> dict[str, Any]:
        """跑一轮并记一行日志。

        为什么单独抽出来：`run_once` 只对**有动作**的项记日志，正常无事可做时
        整轮静默 —— 生产上就没法确认这个 janitor 还活着。每轮固定记一行
        （30 分钟一条，可忽略），运维才好判活；同时便于测试直接调用。
        """
        rep = self.run_once()
        log.info("维护完成：%s", {k: v for k, v in rep.items() if k != "at"})
        return rep

    def start(self) -> None:
        """启动低频维护循环（幂等）。启动后先跑一轮，别等整个周期。"""
        if self._task is not None and not self._task.done():
            return

        async def loop() -> None:
            loop_ = asyncio.get_running_loop()
            # 先等预热/首轮 hunt 落定，避免开机就抢 IO
            first = True
            while True:
                try:
                    await asyncio.sleep(30.0 if first else self.interval_sec)
                    first = False
                    await loop_.run_in_executor(None, self._tick)
                except asyncio.CancelledError:
                    return
                except Exception:                  # 维护失败绝不影响服务
                    continue

        self._task = asyncio.create_task(loop())
