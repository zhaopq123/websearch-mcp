# -*- coding: utf-8 -*-
"""服务自维护（垃圾数据自动清理）回归测试。

背景（2026-10-14）：服务常驻，垃圾只增不减 —— runs 表每轮一条永不清理、
WAL 停在上限、日志不轮转、backups/ 堆到 90MB。本测试钉死各清理动作的
「会清」与「有边界」（保留份数 / 至少留一个 / 只清陈旧）。
"""
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch import maintenance as m  # noqa: E402


# ── 日志轮转（copytruncate）──

def test_rotate_log_truncates_and_keeps_backup(tmp_path):
    p = tmp_path / "service.log"
    p.write_text("x" * 2000, encoding="utf-8")
    assert m.rotate_log_copytruncate(p, max_bytes=1000, keep=2) is True
    assert p.read_text(encoding="utf-8") == ""          # 原地截断
    bak = tmp_path / "service.log.1"
    assert bak.exists() and bak.stat().st_size == 2000   # 内容备份到 .1


def test_rotate_log_shifts_history(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("first" * 300, encoding="utf-8")        # 1500 字节
    m.rotate_log_copytruncate(p, max_bytes=1000, keep=2)
    p.write_text("second" * 300, encoding="utf-8")
    m.rotate_log_copytruncate(p, max_bytes=1000, keep=2)
    assert (tmp_path / "a.log.2").exists()               # 旧 .1 后移成 .2
    assert "second" in (tmp_path / "a.log.1").read_text(encoding="utf-8")


def test_rotate_log_noop_when_small(tmp_path):
    p = tmp_path / "small.log"
    p.write_text("tiny", encoding="utf-8")
    assert m.rotate_log_copytruncate(p, max_bytes=1000) is False
    assert p.read_text(encoding="utf-8") == "tiny"
    assert not (tmp_path / "small.log.1").exists()


def test_rotate_log_missing_file_is_safe(tmp_path):
    assert m.rotate_log_copytruncate(tmp_path / "nope.log") is False


# ── runs 表修剪 ──

def _make_nodes_db(path: Path, n_runs: int) -> None:
    c = sqlite3.connect(str(path))
    c.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL)")
    for i in range(n_runs):
        c.execute("INSERT INTO runs (at) VALUES (?)", (time.time() + i,))
    c.commit()
    c.close()


def test_prune_runs_keeps_newest(tmp_path):
    db = tmp_path / "nodes.sqlite3"
    _make_nodes_db(db, 20)
    assert m.prune_runs(db, keep=5) == 15
    c = sqlite3.connect(str(db))
    rows = c.execute("SELECT id FROM runs ORDER BY id").fetchall()
    c.close()
    assert [r[0] for r in rows] == [16, 17, 18, 19, 20]   # 留最新 5 条


def test_prune_runs_noop_when_under_limit(tmp_path):
    db = tmp_path / "nodes.sqlite3"
    _make_nodes_db(db, 3)
    assert m.prune_runs(db, keep=500) == 0


def test_prune_runs_missing_db_is_safe(tmp_path):
    assert m.prune_runs(tmp_path / "nope.sqlite3") == 0


# ── WAL checkpoint / VACUUM ──

def test_checkpoint_truncates_wal(tmp_path):
    db = tmp_path / "x.sqlite3"
    c = sqlite3.connect(str(db), isolation_level=None)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t (a TEXT)")
    c.executemany("INSERT INTO t VALUES (?)", [("y" * 500,) for _ in range(300)])
    # 保持连接**开着**（否则最后一个连接关闭时 sqlite 会自行 checkpoint 并删 wal）
    wal = tmp_path / "x.sqlite3-wal"
    assert wal.exists() and wal.stat().st_size > 0
    assert m.checkpoint(db) is True
    assert wal.stat().st_size == 0                      # TRUNCATE 回收
    c.close()


def test_vacuum_if_bloated_shrinks_free_pages(tmp_path):
    db = tmp_path / "y.sqlite3"
    c = sqlite3.connect(str(db), isolation_level=None)
    c.execute("CREATE TABLE t (a TEXT)")
    c.executemany("INSERT INTO t VALUES (?)", [("z" * 2000,) for _ in range(500)])
    c.execute("DELETE FROM t")
    free = c.execute("PRAGMA freelist_count").fetchone()[0]
    c.close()
    assert free > 0
    assert m.vacuum_if_bloated(db, free_ratio=0.10) is True
    c = sqlite3.connect(str(db))
    assert c.execute("PRAGMA freelist_count").fetchone()[0] == 0
    c.close()


def test_vacuum_skipped_when_not_bloated(tmp_path):
    db = tmp_path / "z.sqlite3"
    c = sqlite3.connect(str(db), isolation_level=None)
    c.execute("CREATE TABLE t (a TEXT)")
    c.execute("INSERT INTO t VALUES ('x')")
    c.close()
    assert m.vacuum_if_bloated(db, free_ratio=0.9) is False


# ── 文件清理 ──

def test_clean_stale_removes_old_only(tmp_path):
    old = tmp_path / "old.log"
    old.write_text("x", encoding="utf-8")
    new = tmp_path / "new.log"
    new.write_text("x", encoding="utf-8")
    past = time.time() - 10 * 24 * 3600
    import os
    os.utime(old, (past, past))
    removed = m.clean_stale([old, new], older_than_sec=7 * 24 * 3600)
    assert removed == ["old.log"]
    assert not old.exists() and new.exists()


def test_trim_dir_keeps_newest_and_respects_cap(tmp_path):
    import os
    for i, size in enumerate((1000, 1000, 1000)):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(b"x" * size)
        t = time.time() - (10 - i)
        os.utime(f, (t, t))
    # 上限 1500 → 必须删到 ≤1500，但至少留最新 1 个（f2）
    removed = m.trim_dir_by_size(tmp_path, max_bytes=1500, keep_newest=1)
    assert "f0.bin" in removed and "f1.bin" in removed
    assert (tmp_path / "f2.bin").exists()


def test_trim_dir_never_empties(tmp_path):
    tmp_path.joinpath("only.bin").write_bytes(b"x" * 5000)
    removed = m.trim_dir_by_size(tmp_path, max_bytes=1, keep_newest=1)
    assert removed == []
    assert (tmp_path / "only.bin").exists()


# ── 编排 ──

def test_maintenance_run_once_smoke(tmp_path):
    app = tmp_path / "app"
    data = app / "cache"
    data.mkdir(parents=True)
    (app / "backups").mkdir()
    _make_nodes_db(data / "nodes.sqlite3", 10)
    # 必须超过 LOG_MAX_BYTES 才会轮转（阈值 1MB）——写 3KB 是轮不动的
    over = m.LOG_MAX_BYTES + 4096
    (app / "service.log").write_text("y" * over, encoding="utf-8")
    (data / "node_proxy.log").write_text("z" * over, encoding="utf-8")

    mnt = m.Maintenance(data_dir=data, app_dir=app, interval_sec=60)
    rep = mnt.run_once()
    assert rep["runs_pruned"] == 0            # 10 < 500
    assert "service.log" in rep["logs_rotated"]
    assert "node_proxy.log" in rep["logs_rotated"]
    assert (app / "service.log").stat().st_size == 0
    assert isinstance(rep["backups_trimmed"], list)


def test_run_once_shrinks_bloated_db_file(tmp_path):
    """VACUUM 之后必须再 checkpoint，否则缩的是 WAL、主库文件不缩。

    实测坑（2026-10-14）：cache.sqlite3 VACUUM 后逻辑上只剩 16 页，
    但主库文件仍是 504KB/126 页 —— VACUUM 的重写产物先落在 WAL 里，
    不补一次 checkpoint 就看不到文件变小。
    """
    app = tmp_path / "app"
    data = app / "cache"
    data.mkdir(parents=True)
    (app / "backups").mkdir()
    db = data / "cache.sqlite3"
    c = sqlite3.connect(str(db), isolation_level=None)   # 保持连接（模拟常驻服务）
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE t (a TEXT)")
    c.executemany("INSERT INTO t VALUES (?)", [("z" * 2000,)] * 800)
    c.execute("DELETE FROM t")                           # 制造大量空闲页
    big = db.stat().st_size
    assert big > 200_000

    rep = m.Maintenance(data_dir=data, app_dir=app, interval_sec=60).run_once()
    assert "cache.sqlite3" in rep["vacuumed"]
    assert db.stat().st_size < big / 2                   # 主库文件真的缩了
    c.close()


def test_tick_returns_report_and_logs(tmp_path, caplog):
    """无事可做时也要留一行日志，否则生产上判不出 janitor 死活。"""
    app = tmp_path / "app"
    data = app / "cache"
    data.mkdir(parents=True)
    mnt = m.Maintenance(data_dir=data, app_dir=app, interval_sec=60)
    with caplog.at_level("INFO", logger="websearch.maintenance"):
        rep = mnt._tick()
    assert "at" in rep
    assert any("维护完成" in r.getMessage() for r in caplog.records)


async def test_start_is_idempotent(tmp_path):
    import asyncio
    mnt = m.Maintenance(data_dir=tmp_path, app_dir=tmp_path, interval_sec=60)
    mnt.start()
    t = mnt._task
    mnt.start()                       # 第二次不该再造一个任务
    assert mnt._task is t
    t.cancel()
    try:
        await t
    except asyncio.CancelledError:
        pass


def test_maintenance_from_env_defaults(tmp_path):
    mnt = m.Maintenance.from_env(data_dir=tmp_path, app_dir=tmp_path)
    assert mnt.interval_sec >= 60.0
