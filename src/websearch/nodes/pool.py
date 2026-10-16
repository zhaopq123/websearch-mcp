# -*- coding: utf-8 -*-
"""节点库 —— 免费节点的持久化层（sqlite）。

产品定位：节点从「用户自带」变成「系统自养」。本模块是那个「自养」的
粮仓 —— 搜集来的节点在这里去重、记健康分、过期淘汰。

⚠️ 安全红线（本模块是节点凭据落盘的唯一入口）：
  1. **文件权限强制 600**，目录 700。每次写完都 chmod。
  2. **对外查询绝不返回凭据** —— 工具/面板走 summary()/list_public()，
     只给「协议、国家、延迟、健康分」，不给 outbound/raw_uri。
     取实际配置只有内部接口 outbound_for(fp) 一条路。
  3. **绝不写日志** —— 本模块的 log 调用只带数量与指纹前缀。
  4. 节点库文件在 .gitignore（nodes.sqlite3*）。

设计取舍：
  · 健康分是「成功率 × 延迟」的组合，不是纯延迟 —— 纯延迟会选出
    「响应快但经常断」的节点，用户体感是「时好时坏」。
  · 节点短命是免费源的常态（实测：几小时到几天）。所以库设计成
    「宽进严出」：搜集阶段只做格式校验就入库（宁可多收），
    存活与否完全由 probe 的实测结果决定，过期自动淘汰。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("websearch.nodes.pool")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nodes (
    fp          TEXT PRIMARY KEY,   -- 指纹（协议+地址+凭据的 sha256 前 16 位）
    protocol    TEXT NOT NULL,
    server      TEXT NOT NULL,
    port        INTEGER NOT NULL,
    country     TEXT DEFAULT '',    -- 从 tag 里猜的地区标记（尽力而为）
    tag         TEXT DEFAULT '',
    pool        TEXT DEFAULT 'free',-- 池归属：cust=客户导入 / free=系统自搜
    outbound    TEXT NOT NULL,      -- sing-box outbound JSON（含凭据，600 文件内）
    sources     TEXT DEFAULT '',    -- 来源清单（逗号分隔的源 id）
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    alive       INTEGER DEFAULT 0,  -- 最近一次是否验证出网
    last_ms     INTEGER DEFAULT 0,  -- 最近一次延迟
    avg_ms      REAL DEFAULT 0,     -- 延迟 EMA（只统计成功样本）
    ok_count    INTEGER DEFAULT 0,
    fail_count  INTEGER DEFAULT 0,
    streak_fail INTEGER DEFAULT 0,  -- 连续失败次数（智能降级用）
    last_ok_at  REAL DEFAULT 0,
    last_probe_at REAL DEFAULT 0,
    -- 站点可达性抽检（2026-10-15）：0-2 = 覆盖的盲区站数（github/DDG），
    -- -1 = 未检。实测香港批次节点对 github/DDG 全不通但 google/bing 通
    -- （延迟还最优），选路若只看延迟就会选中盲区节点。
    site_ok      INTEGER DEFAULT -1,
    site_checked_at REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sources (
    sid         TEXT PRIMARY KEY,   -- 源 id（URL 的短哈希）
    url         TEXT NOT NULL,      -- 源地址（非凭据，可存）
    kind        TEXT DEFAULT 'sub', -- sub=订阅 / list=URI 列表 / page=网页
    ok_count    INTEGER DEFAULT 0,
    fail_count  INTEGER DEFAULT 0,
    last_ok_at  REAL DEFAULT 0,
    last_error  TEXT DEFAULT '',
    nodes_found INTEGER DEFAULT 0,  -- 累计贡献节点数
    last_fetch_at REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          REAL NOT NULL,
    trigger     TEXT DEFAULT '',    -- manual / auto
    sources_ok  INTEGER DEFAULT 0,
    sources_fail INTEGER DEFAULT 0,
    parsed      INTEGER DEFAULT 0,
    new_nodes   INTEGER DEFAULT 0,
    probed      INTEGER DEFAULT 0,
    alive       INTEGER DEFAULT 0,
    elapsed_ms  INTEGER DEFAULT 0,
    note        TEXT DEFAULT ''
);
"""

# ⚠️ 索引必须与建表**分开**执行：老库（无 pool 列）在 executescript 建表阶段
# 就会因「CREATE INDEX ... ON nodes(pool, alive)」报 no such column 而整体失败。
# 顺序必须是 建表 → 迁移加列 → 建索引。踩过（2026-10-13）。
_SCHEMA_INDEX = """
CREATE INDEX IF NOT EXISTS idx_alive ON nodes(alive, avg_ms);
CREATE INDEX IF NOT EXISTS idx_last_seen ON nodes(last_seen);
CREATE INDEX IF NOT EXISTS idx_pool ON nodes(pool, alive);
"""


def fingerprint(protocol: str, outbound: dict[str, Any]) -> str:
    """节点指纹：协议 + 服务地址端口 + 凭据关键字段。

    为什么不直接哈希 outbound JSON 原文：同一节点在不同源里字段顺序、
    多余字段都可能不同，原文哈希去不了重。只取**标识性字段**才能把
    「同一个节点」在不同源里认出来。
    """
    server = str(outbound.get("server", ""))
    port = str(outbound.get("server_port", outbound.get("port", "")))
    secret = ""
    for k in ("uuid", "password", "method", "alter_id", "auth_str",
              "flow", "security", "obfs", "path", "host", "service_name"):
        v = outbound.get(k)
        if v not in (None, ""):
            secret += f"|{k}={v}"
    raw = f"{protocol}|{server}|{port}{secret}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _guess_country(tag: str) -> str:
    """从节点 tag 里猜地区（尽力而为，猜不出返回空）。"""
    t = (tag or "").upper()
    table = {
        "HK": "香港", "香港": "香港", "HONGKONG": "香港", "HONG KONG": "香港",
        "TW": "台湾", "台湾": "台湾", "TAIWAN": "台湾",
        "JP": "日本", "日本": "日本", "JAPAN": "日本", "东京": "日本",
        "SG": "新加坡", "新加坡": "新加坡", "SINGAPORE": "新加坡", "狮城": "新加坡",
        "US": "美国", "美国": "美国", "UNITED STATES": "美国", "洛杉矶": "美国",
        "KR": "韩国", "韩国": "韩国", "KOREA": "韩国", "首尔": "韩国",
        "UK": "英国", "英国": "英国", "GB": "英国", "LONDON": "英国",
        "DE": "德国", "德国": "德国", "GERMANY": "德国",
        "FR": "法国", "法国": "法国", "FRANCE": "法国",
        "RU": "俄罗斯", "俄罗斯": "俄罗斯", "RUSSIA": "俄罗斯",
        "CA": "加拿大", "加拿大": "加拿大", "CANADA": "加拿大",
        "AU": "澳大利亚", "澳大利亚": "澳大利亚", "AUSTRALIA": "澳大利亚",
        "IN": "印度", "印度": "印度", "INDIA": "印度",
        "TR": "土耳其", "土耳其": "土耳其", "TURKEY": "土耳其",
        "VN": "越南", "越南": "越南", "VIETNAM": "越南",
        "MY": "马来西亚", "马来西亚": "马来西亚", "MALAYSIA": "马来西亚",
        "TH": "泰国", "泰国": "泰国", "THAILAND": "泰国",
        "PH": "菲律宾", "菲律宾": "菲律宾",
        "ID": "印尼", "印尼": "印尼", "INDONESIA": "印尼",
        "BR": "巴西", "巴西": "巴西", "BRAZIL": "巴西",
        "AR": "阿根廷", "阿根廷": "阿根廷",
        "NL": "荷兰", "荷兰": "荷兰", "NETHERLANDS": "荷兰",
        "CH": "瑞士", "瑞士": "瑞士", "SWITZERLAND": "瑞士",
        "SE": "瑞典", "瑞典": "瑞典",
        "PL": "波兰", "波兰": "波兰",
        "UA": "乌克兰", "乌克兰": "乌克兰",
        "IR": "伊朗", "伊朗": "伊朗",
        "AE": "阿联酋", "迪拜": "阿联酋", "DUBAI": "阿联酋",
    }
    for k, v in table.items():
        if k in t:
            return v
    return ""


@dataclass
class PoolStats:
    """节点库统计（**无凭据**，可给工具/面板）。"""

    total: int = 0
    alive: int = 0
    dead: int = 0
    untested: int = 0
    by_protocol: dict[str, int] | None = None
    by_country: dict[str, int] | None = None
    by_pool: dict[str, dict[str, int]] = field(default_factory=dict)
    best: dict[str, Any] | None = None
    source_count: int = 0
    healthy_sources: int = 0
    last_run: dict[str, Any] | None = None
    db_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "alive": self.alive,
            "dead": self.dead,
            "untested": self.untested,
            "by_protocol": self.by_protocol or {},
            "by_country": self.by_country or {},
            "by_pool": self.by_pool or {},
            "best": self.best,
            "source_count": self.source_count,
            "healthy_sources": self.healthy_sources,
            "last_run": self.last_run,
            "db_bytes": self.db_bytes,
        }


class NodePool:
    """节点库。一个实例绑定一个 sqlite 文件。"""

    # 过期阈值：多久没在任何源里再出现、且探测失败，就该淘汰。
    # 免费节点短命是常态，但阈值别太激进 —— 源本身可能几天不更新。
    PRUNE_AFTER_SEC = 7 * 24 * 3600
    # 连续失败多少次判定「节点死了」（智能降级的触发线）
    DEAD_STREAK = 3
    # 探测结果的有效期：超过这个时间没重新测过，节点状态算「陈旧」，
    # 需要重新测（免费节点状态漂移快，2 小时足够暴露大部分失效）。
    PROBE_REFRESH_SEC = 2 * 3600
    # ── 2026-10-14 接入公开代理列表源后新增的两条硬淘汰 ──
    # 背景：主淘汰规则要求 last_seen 也过期，但代理列表源（HProxy/
    # Proxifly/…）**每轮都列出死代理**（列表自己不删死条目）——
    # last_seen 被无限刷新，死代理永远删不掉，库无限膨胀。
    # 死透硬删：明确判死（alive=0）、测过（last_probe_at>0，没测过的
    # 不误杀）、24h 没活过 → 删，不问 last_seen。
    # 2026-10-15 收紧 48h→24h：实测公开代理存活率仅 17%、寿命以小时计
    # （13:07 入库的 socks 到 14:00 直测 0/30 全死），48h 给「假活库存」
    # 留太久。VPN 节点同理——24h 没活过的死节点没有复活动先例。
    PRUNE_DEAD_AFTER_SEC = 24 * 3600
    # 陈库存硬删：入库多久还从未排到探测（预算有限，新鲜节点一直排在
    # 前面）→ 删。实测 socks backlog 7.6k、探测 340/轮，3 天根本轮不
    # 完一轮；2 天 + 每轮新鲜度优先，保证库存持续周转。
    #
    # ⚠️ 2026-10-16 实测仍未收敛：vivo 生产 total=33892 / alive=8 /
    # untested=33528，单轮只探 172–400 个、间隔 120–600s ——
    # **17 小时才碰完一遍库存**，而入库仍在净增（单轮新增 399–522）。
    # 2 天的窗口对当前量级太宽松：被删的（238–1924/轮）追不上新进的。
    #
    # 收敛条件应是「窗口 ≤ 一轮库存扫完的时间」而不是拍脑袋的天数。
    # probe_per_round 与 interval_sec 由 hunter 规划器给出；这里给一个
    # 保守默认，并由 set_probe_throughput() 在每轮 hunt 后刷新为实测值。
    # 目标 = 能扫完库存一轮的时间（含 2 倍余量），下限 12h、上限 3 天。
    PRUNE_UNTESTED_AFTER_SEC = 2 * 24 * 3600      # 保守默认，运行期会收敛
    PRUNE_UNTESTED_MIN_SEC = 12 * 3600            # 不早于 12h（给新货窗口）
    PRUNE_UNTESTED_MAX_SEC = 3 * 24 * 3600        # 不晚于 3 天

    def __init__(self, db_path: Path | str):
        self.path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._ensure()

    # ── 生命周期 ──

    def _ensure(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        conn = sqlite3.connect(
            str(self.path), timeout=5.0, isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(_SCHEMA)
        self._migrate(conn)
        conn.executescript(_SCHEMA_INDEX)
        self._conn = conn
        self._secure()
        return conn

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """加列迁移。`CREATE TABLE IF NOT EXISTS` 不会给已存在的表补列。

        ⚠️ 老库的默认归属必须是 **cust** 而不是 free：
        建 `pool` 列这个功能之前，库里已有的节点全是客户导入的
        （那是节点库唯一的来源）。若按 schema 默认值补成 free，
        一次 prune 就会把客户的付费节点当过期免费节点清掉。
        """
        cols = {r[1] for r in conn.execute("PRAGMA table_info(nodes)")}
        if "pool" not in cols:
            # DEFAULT 'cust'：历史节点一律归客户池
            conn.execute(
                "ALTER TABLE nodes ADD COLUMN pool TEXT DEFAULT 'cust'"
            )
            log.info("节点库迁移：新增 pool 列，历史节点归入 cust 池")
        if "site_ok" not in cols:
            conn.execute("ALTER TABLE nodes ADD COLUMN site_ok INTEGER DEFAULT -1")
            conn.execute("ALTER TABLE nodes ADD COLUMN site_checked_at REAL DEFAULT 0")
            log.info("节点库迁移：新增 site_ok/site_checked_at 列（站点可达性抽检）")

    def _secure(self) -> None:
        """强制 600 —— 库里含节点凭据。"""
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # ── 写入 ──

    def known_fps(self, fps: list[str]) -> set[str]:
        """批量查哪些指纹已在库（入库前判新，省掉逐条 SELECT）。

        2026-10-15 压测后新增：morpheusadam/FastNodes 每轮解析 3.2 万
        节点，原 upsert_nodes 逐条 SELECT 3.2 万次（SQLite 全表扫），
        大 bundle 源入库耗时占满一轮 hunt。分批 IN 查询 + executemany
        后同批次从分钟级降到百毫秒级。
        """
        if not fps:
            return set()
        out: set[str] = set()
        chunk = 400   # SQLite 变量数默认上限 999，400 稳妥
        conn = self._ensure()
        for i in range(0, len(fps), chunk):
            batch = fps[i:i + chunk]
            q = ",".join("?" * len(batch))
            for (fp,) in conn.execute(
                    f"SELECT fp FROM nodes WHERE fp IN ({q})", batch):
                out.add(fp)
        return out

    def upsert_nodes(self, nodes: Iterable[tuple[str, str, dict[str, Any]]],
                     source_sid: str = "", pool: str = "free") -> int:
        """批量入库。nodes 每项 = (tag, protocol, outbound)。

        返回**新增**条数（已存在的只更新 last_seen 与 sources）。
        宽进：只做格式校验（必须有 server/port），不判存活 ——
        存活由 probe 的实测结果决定。

        `pool` 决定节点归哪个池（'cust' 客户导入 / 'free' 系统自搜），
        见 _SCHEMA.nodes.pool。同一节点被两个来源同时提供时，
        **已有记录不覆盖归属**：客户池优先，避免客户付费节点
        被一次免费源命中就降级成 free（进而被 prune 淘汰）。

        实现：两阶段批量（2026-10-15 重构，原逐条 SELECT+INSERT）。
        阶段一 known_fps 分批 IN 查已有；阶段二 executemany。
        「归属只升不降」用 SQL CASE 表达（pool='cust' 永不被降级），
        sources 合并用 instr 判重后拼接，语义与旧逐条版一致。
        """
        conn = self._ensure()
        now = time.time()
        cleaned: list[tuple[str, str, int, str, str, str, dict[str, Any]]] = []
        for tag, protocol, outbound in nodes:
            server = str(outbound.get("server", "")).strip()
            port = outbound.get("server_port", outbound.get("port", 0))
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            if not server or not port:
                continue
            cleaned.append((tag, protocol, port, server,
                            _guess_country(tag),
                            fingerprint(protocol, outbound), outbound))
        if not cleaned:
            return 0

        known = self.known_fps([c[5] for c in cleaned])
        inserts: list[tuple[Any, ...]] = []
        updates: list[tuple[Any, ...]] = []
        seen_batch: set[str] = set()
        for tag, protocol, port, server, country, fp, outbound in cleaned:
            if fp in known:
                # (now, tag, newpool, sid, sid, sid, fp)
                # sources 合并：空则直接放 sid；已含则不追加；否则追加
                updates.append((now, tag, pool, source_sid,
                                source_sid, source_sid, fp))
            elif fp in seen_batch:
                # 同批次内重复（bundle 源常见：同一节点在一个文件里
                # 出现多次）。旧逐条版靠「上一条已提交」自然走到 update
                # 分支；批量版必须显式去重，否则 executemany 撞 UNIQUE。
                updates.append((now, tag, pool, source_sid,
                                source_sid, source_sid, fp))
            else:
                seen_batch.add(fp)
                inserts.append((
                    fp, protocol, server, port, country, tag, pool,
                    json.dumps(outbound, ensure_ascii=False),
                    source_sid, now, now,
                ))
        with conn:
            if inserts:
                conn.executemany(
                    "INSERT INTO nodes (fp, protocol, server, port, country,"
                    " tag, pool, outbound, sources, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    inserts,
                )
            if updates:
                conn.executemany(
                    "UPDATE nodes SET last_seen=?, tag=?,"
                    " pool=CASE WHEN pool='cust' THEN 'cust' ELSE ? END,"
                    " sources=CASE"
                    "   WHEN IFNULL(sources,'')='' THEN ?"
                    "   WHEN instr(','||sources||',', ','||?||',') > 0"
                    "        THEN sources"
                    "   ELSE sources||','||? END"
                    " WHERE fp=?",
                    updates,
                )
        self._secure()
        return len(inserts)

    def record_probe(self, fp: str, ok: bool, ms: int = 0) -> None:
        """记录一次探测结果，更新健康分。

        avg_ms 用 EMA（只统计成功样本）。选节点时综合成功率与延迟，
        避免选出「快但常断」的节点。
        """
        conn = self._ensure()
        now = time.time()
        row = conn.execute(
            "SELECT ok_count, fail_count, avg_ms, streak_fail FROM nodes WHERE fp=?",
            (fp,),
        ).fetchone()
        if not row:
            # 2026-10-15 排查「探测记录丢失」：静默跳过改为可观测——
            # 这个分支命中说明探测结果 fp 与库对不上（候选/结果错位）
            log.warning("record_probe: fp 不在库中，跳过 %s…", fp[:12])
            return
        ok_count, fail_count, avg_ms, streak = row
        if ok:
            # 延迟 EMA，alpha=0.4（新样本权重大，快速反映节点当前状态）
            avg_ms = (ms if not avg_ms else avg_ms * 0.6 + ms * 0.4)
            conn.execute(
                "UPDATE nodes SET alive=1, last_ms=?, avg_ms=?, ok_count=?,"
                " streak_fail=0, last_ok_at=?, last_probe_at=? WHERE fp=?",
                (ms, avg_ms, ok_count + 1, now, now, fp),
            )
        else:
            streak = (streak or 0) + 1
            alive = 0 if streak >= self.DEAD_STREAK else None
            if alive is None:
                conn.execute(
                    "UPDATE nodes SET fail_count=?, streak_fail=?,"
                    " last_probe_at=? WHERE fp=?",
                    (fail_count + 1, streak, now, fp),
                )
            else:
                conn.execute(
                    "UPDATE nodes SET alive=0, fail_count=?, streak_fail=?,"
                    " last_probe_at=? WHERE fp=?",
                    (fail_count + 1, streak, now, fp),
                )
        self._secure()

    def record_site_check(self, fp: str, ok_sites: int) -> None:
        """记录一次站点可达性抽检结果（0-2 = 覆盖的盲区站数）。

        Args:
            fp: 节点指纹。
            ok_sites: 可达的盲区站数（github/DDG 两个）。
        """
        conn = self._ensure()
        conn.execute(
            "UPDATE nodes SET site_ok=?, site_checked_at=? WHERE fp=?",
            (int(ok_sites), time.time(), fp),
        )
        self._secure()

    def site_check_candidates(self, limit: int = 10) -> list[dict[str, Any]]:
        """选站点抽检对象：alive 且延迟最优的节点（选路候选所在）。

        只抽 top N——盲区是**批次特征**（实测同批 5 个香港节点全盲），
        抽检最优档即可代表选路结果，不必全池抽检（成本 ×1000）。
        """
        conn = self._ensure()
        rows = conn.execute(
            "SELECT fp, protocol, server, port, country, tag, outbound"
            " FROM nodes WHERE alive=1 AND avg_ms>0"
            " ORDER BY (CASE WHEN site_ok < 0 THEN 1 ELSE 0 END) ASC,"
            "  site_checked_at ASC, avg_ms ASC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {"fp": r[0], "protocol": r[1], "server": r[2], "port": r[3],
             "country": r[4], "tag": r[5], "outbound": json.loads(r[6])}
            for r in rows
        ]

    def upsert_source(self, sid: str, url: str, kind: str = "sub") -> None:
        conn = self._ensure()
        conn.execute(
            "INSERT INTO sources (sid, url, kind) VALUES (?,?,?)"
            " ON CONFLICT(sid) DO UPDATE SET url=excluded.url",
            (sid, url, kind),
        )
        self._secure()

    def record_source_fetch(self, sid: str, ok: bool, nodes_found: int = 0,
                            error: str = "") -> None:
        """记录一次源抓取结果。源健康度用于给源排序/降权。"""
        conn = self._ensure()
        now = time.time()
        if ok:
            conn.execute(
                "UPDATE sources SET ok_count=ok_count+1, last_ok_at=?,"
                " last_error='', nodes_found=nodes_found+?, last_fetch_at=?"
                " WHERE sid=?",
                (now, nodes_found, now, sid),
            )
        else:
            # 错误信息脱敏：只留类型化短语，防 URL 里的 token 进库
            conn.execute(
                "UPDATE sources SET fail_count=fail_count+1, last_error=?,"
                " last_fetch_at=? WHERE sid=?",
                (error[:120], now, sid),
            )
        self._secure()

    def record_run(self, run: dict[str, Any]) -> None:
        conn = self._ensure()
        conn.execute(
            "INSERT INTO runs (at, trigger, sources_ok, sources_fail, parsed,"
            " new_nodes, probed, alive, elapsed_ms, note)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run.get("at", time.time()), run.get("trigger", ""),
             run.get("sources_ok", 0), run.get("sources_fail", 0),
             run.get("parsed", 0), run.get("new_nodes", 0),
             run.get("probed", 0), run.get("alive", 0),
             run.get("elapsed_ms", 0), run.get("note", "")),
        )
        self._secure()

    # ── 查询（内部，含凭据）──

    def candidates_for_probe(self, limit: int = 200,
                             prefer_untested: bool = True,
                             pool: str = "",
                             only_protocols: tuple[str, ...] = (),
                             ) -> list[dict[str, Any]]:
        """挑一批候选节点去探测。

        优先级（**分层，不是简单按 last_probe_at 排序**）：
          1. alive 的（保持健康分新鲜，早停降级准）
          2. 从未测过的 last_probe_at=0（把「未知」变「已知」）
          3. 很久没测的（超过 PROBE_REFRESH_SEC，节点状态会漂移）

        为什么不能只按 last_probe_at ASC 排：那样每次都把
        「最近测过且死了」的节点排在最前 —— 库里死节点上千时
        （实测免费池 807 个存活 0），探测预算全花在重测已知死节点上，
        新入库的节点永远测不到。保活必须是「先测新的，再刷老的」。

        only_protocols：只返回这些协议（探测侧按协议分配额用）。
        2026-10-15 实测盲区：纯 first_seen DESC 在「同轮多源入库」
        时退化成「最后入库的源优先」——socks 13:06 入库、GFP vless
        13:07 入库，1 分钟之差让 7635 个未测 socks 被同秒入库的
        vless 全部挤出窗口。探测侧按协议分配额解决。
        """
        conn = self._ensure()
        where = ""
        params: list[Any] = []
        conds: list[str] = []
        if pool in ("cust", "free"):
            conds.append("pool=?")
            params.append(pool)
        if only_protocols:
            conds.append(
                f"protocol IN ({','.join('?' * len(only_protocols))})")
            params.extend(only_protocols)
        if conds:
            where = "WHERE " + " AND ".join(conds)
        # 活着 > 未测 > 很久没测（>2h 视为需要刷新）> 其他。
        # ⚠️ 2026-10-14 修新鲜度：未测层里必须**最新的优先**。免费节点
        # 按小时死（实测库存抽样 60 个全 ConnectError，0% 存活），旧排序
        # 是 avg_ms ASC——新节点和几千个陈库存同优先级，等轮到它早死透。
        # 改 first_seen DESC：当天解析出的节点当轮就测，才抓得住活的。
        stale_cut = time.time() - self.PROBE_REFRESH_SEC
        order = (
            "CASE WHEN alive=1 THEN 0"
            "     WHEN last_probe_at=0 THEN 1"
            f"     WHEN last_probe_at < {stale_cut} THEN 2"
            "     ELSE 3 END ASC,"
            "CASE WHEN last_probe_at=0 THEN first_seen ELSE 0 END DESC,"
            "avg_ms ASC,"
        )
        if not prefer_untested:
            order = ""
        rows = conn.execute(
            f"SELECT fp, protocol, server, port, country, tag, outbound,"
            f" alive, avg_ms, last_probe_at, pool FROM nodes"
            f" {where} ORDER BY {order}avg_ms ASC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [
            {
                "fp": r[0], "protocol": r[1], "server": r[2], "port": r[3],
                "country": r[4], "tag": r[5],
                "outbound": json.loads(r[6]),
                "alive": bool(r[7]), "avg_ms": r[8], "last_probe_at": r[9],
                "pool": r[10] or "free",
            }
            for r in rows
        ]

    def outbound_for(self, fp: str) -> dict[str, Any] | None:
        """取某个节点的 sing-box outbound（**含凭据**，仅内部用）。"""
        conn = self._ensure()
        row = conn.execute(
            "SELECT outbound, tag FROM nodes WHERE fp=?", (fp,)
        ).fetchone()
        if not row:
            return None
        ob = json.loads(row[0])
        return {"tag": row[1] or fp, **ob}

    def best(self, *, only_alive: bool = True,
            prefer: str = "cust") -> dict[str, Any] | None:
        """选最优节点（**无凭据**摘要 + fp）。

        评分 = 成功率 × 1000 − 延迟ms。只有 alive=1 的参与（默认）。

        **客户池优先（prefer='cust'，默认）**：
        先只在 cust 池里选；cust 池没有任何活节点时，才回落到 free 池。
        为什么不合并评分：免费节点和客户付费节点混在一个排序里，
        比延迟低不代表能长期用 —— 免费源的节点寿命以小时计，
        一个 200ms 的免费节点随时会消失，而客户节点有服务承诺。
        宁可慢一点，也要稳定。
        """
        conn = self._ensure()
        pools = (["cust", "free"] if prefer == "cust" else ["free", "cust"])
        for pool in pools:
            picked = self._best_in(conn, pool, only_alive)
            if picked:
                picked["pool"] = pool
                return picked
        return None

    def _best_in(self, conn: sqlite3.Connection, pool: str,
                 only_alive: bool) -> dict[str, Any] | None:
        """在单个池内选最优节点（内部）。"""
        where = "WHERE pool=?"
        params: list[Any] = [pool]
        if only_alive:
            where += " AND alive=1"
        # 排序（2026-10-15 加站点覆盖）：已抽检且盲区站全通的优先，
        # 未检的次之，已检但盲区不通的垫底；同档再按延迟。
        # 实测依据：香港批次节点延迟最优但对 github/DDG/快递100 全不通，
        # 英国节点慢 4% 但全通——只按延迟选会选中「快而残」的节点。
        rows = conn.execute(
            f"SELECT fp, protocol, server, port, country, tag, avg_ms,"
            f" ok_count, fail_count, alive, last_ok_at, site_ok FROM nodes {where}"
            f" ORDER BY"
            # 站点覆盖档位（好→差）：全通(2) > 部分(1) > 未检(-1) > 盲区(0)。
            # 未检排在盲区前——未知的值得一试，已证伪的别浪费。
            f"  (CASE WHEN site_ok >= 2 THEN 0 WHEN site_ok = 1 THEN 1"
            f"        WHEN site_ok < 0 THEN 2 ELSE 3 END) ASC,"
            f"  (CASE WHEN avg_ms>0 THEN avg_ms ELSE 99999 END) ASC"
            f" LIMIT 20",
            params,
        ).fetchall()
        if not rows:
            return None
        scored = []
        for r in rows:
            ok_c, fail_c = r[7] or 0, r[8] or 0
            total = ok_c + fail_c
            rate = (ok_c / total) if total else 0.5
            ms = r[6] or 99999
            # 站点覆盖 bonus（2026-10-15）：量级必须压过延迟差
            # （实测港/英节点延迟仅差 ~200ms，而盲区差是「能用 vs
            # 不能用」）。全通 +4000 / 部分 +2000 / 未检 +500 / 盲区 +0；
            # 延迟项是 -ms（~4000），故 bonus 与延迟同量级但方向明确。
            site_ok = r[11] if len(r) > 11 else -1
            if site_ok is None:
                site_ok = -1
            if site_ok >= 2:
                bonus = 4000
            elif site_ok == 1:
                bonus = 2000
            elif site_ok < 0:
                bonus = 500
            else:
                bonus = 0
            score = rate * 1000 - ms + bonus
            scored.append((score, r))
        scored.sort(key=lambda x: -x[0])
        r = scored[0][1]
        return {
            "fp": r[0], "protocol": r[1], "server": r[2], "port": r[3],
            "country": r[4], "tag": r[5], "avg_ms": int(r[6] or 0),
            "ok_count": r[7] or 0, "fail_count": r[8] or 0,
            "alive": bool(r[9]), "last_ok_at": r[10] or 0,
        }

    # ── 清理 ──

    def prune(self, *, max_age_sec: int | None = None,
             pool: str = "free") -> int:
        """淘汰过期节点：很久没在源里出现、且探测也早已失败。

        用 `<=` 而非 `<`：让 max_age_sec=0 的语义是「立刻全部过期」
        （测试与运维手动清库都用得上），正常 7 天阈值下两者无差别。

        **默认只清 free 池（pool='free'）**。
        客户导入的节点不能按「多久没出现在订阅里」来淘汰 —— 客户可能
        半年不换订阅，但那些付费节点一直可用；免费源的时效逻辑套到
        客户池上就是误杀。要清客户池必须显式传 pool='cust'
        （例如客户明确要求清空自己的节点时）。
        """
        conn = self._ensure()
        cutoff = time.time() - (
            self.PRUNE_AFTER_SEC if max_age_sec is None else max(0, max_age_sec)
        )
        cur = conn.execute(
            "DELETE FROM nodes WHERE pool=? AND last_seen <= ? AND last_ok_at <= ?",
            (pool, cutoff, cutoff),
        )
        n = cur.rowcount or 0
        # ── 两条不依赖 last_seen 的硬淘汰（2026-10-14，代理列表源专用）──
        # 1) 死透：alive=0 + 测过 + 48h 没活过。代理列表每轮都列出死
        #    条目（列表自身不清理），last_seen 无限刷新，主规则永远
        #    删不到它们 —— 库会膨胀到 sqlite 查询都慢。
        dead_cut = time.time() - self.PRUNE_DEAD_AFTER_SEC
        cur2 = conn.execute(
            "DELETE FROM nodes WHERE pool=? AND alive=0 AND last_probe_at>0"
            " AND last_ok_at <= ?",
            (pool, dead_cut),
        )
        n2 = cur2.rowcount or 0
        # 2) 陈库存：入库 3 天从未排到探测。探测预算有限，未被测过的
        #    陈旧库存是纯负担（还会拖慢 candidates_for_probe 查询）。
        untested_cut = time.time() - self.PRUNE_UNTESTED_AFTER_SEC
        cur3 = conn.execute(
            "DELETE FROM nodes WHERE pool=? AND last_probe_at=0"
            " AND first_seen <= ?",
            (pool, untested_cut),
        )
        n3 = cur3.rowcount or 0
        total = n + n2 + n3
        if total:
            log.info(
                "节点库清理：淘汰 %d 个过期 %s 池节点"
                "（过期 %d / 死透 %d / 未测陈库存 %d）",
                total, pool, n, n2, n3)
        self._secure()
        return total

    # ── 对外视图（无凭据）──

    def set_probe_throughput(self, probe_per_round: int,
                             interval_sec: int) -> int:
        """把「陈库存硬删」窗口收敛到实际探测吞吐（2026-10-16）。

        为什么必须动态算：库存积压是**入库速率 vs 探测吞吐**的失衡。
        固定天数（2 天）在入库 400–500/轮、探测 172–400/轮、间隔 120–600s
        的量级下，被删的追不上新进的 —— 实测 untested 稳在 33k 下不来。

        判据：窗口应等于「扫完当前库存一轮所需时间」× 2。
          · probe_per_round ≤ 0 或 interval ≤ 0 → 不动（保持上次值）
          · 结果夹在 [PRUNE_UNTESTED_MIN_SEC, PRUNE_UNTESTED_MAX_SEC]

        返回收敛后的窗口秒数（供日志/工具回显）。
        """
        if probe_per_round <= 0 or interval_sec <= 0:
            return self.PRUNE_UNTESTED_AFTER_SEC
        total = self._ensure().execute(
            "SELECT COUNT(*) FROM nodes WHERE pool='free' AND last_probe_at=0"
        ).fetchone()[0]
        if total <= 0:
            return self.PRUNE_UNTESTED_AFTER_SEC
        rounds = total / float(probe_per_round)
        sweep = rounds * interval_sec
        win = int(min(self.PRUNE_UNTESTED_MAX_SEC,
                      max(self.PRUNE_UNTESTED_MIN_SEC, sweep * 2)))
        self.PRUNE_UNTESTED_AFTER_SEC = win
        return win

    def list_public(self, limit: int = 50, *,
                    only_alive: bool = True,
                    pool: str = "") -> list[dict[str, Any]]:
        """节点列表（**无凭据**）—— 给工具/面板。

        地址本身不算敏感（公开源里就有），真正敏感的是 uuid/password；
        所以给完整地址便于用户判断，但**绝不给 outbound/raw_uri**。
        `pool` 传 'cust'/'free' 过滤某个池，留空 = 全部。
        """
        conn = self._ensure()
        where = "WHERE 1=1"
        params: list[Any] = []
        if only_alive:
            where += " AND alive=1"
        if pool in ("cust", "free"):
            where += " AND pool=?"
            params.append(pool)
        rows = conn.execute(
            f"SELECT fp, protocol, server, port, country, tag, avg_ms,"
            f" ok_count, fail_count, alive, last_ok_at, sources, pool"
            f" FROM nodes {where}"
            f" ORDER BY (CASE WHEN avg_ms>0 THEN avg_ms ELSE 99999 END)"
            f" ASC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [
            {
                "fp": r[0], "protocol": r[1], "server": r[2], "port": r[3],
                "country": r[4], "tag": r[5], "avg_ms": int(r[6] or 0),
                "ok_count": r[7] or 0, "fail_count": r[8] or 0,
                "alive": bool(r[9]), "last_ok_at": r[10] or 0,
                "sources": len([s for s in (r[11] or "").split(",") if s]),
                "pool": r[12] or "free",
            }
            for r in rows
        ]

    def source_health(self, limit: int = 100) -> list[dict[str, Any]]:
        """源健康度（无凭据）。"""
        conn = self._ensure()
        rows = conn.execute(
            "SELECT sid, url, kind, ok_count, fail_count, last_ok_at,"
            " last_error, nodes_found FROM sources"
            " ORDER BY (ok_count*1.0/(ok_count+fail_count+0.1)) DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "sid": r[0], "url": r[1], "kind": r[2],
                "ok": r[3], "fail": r[4], "last_ok_at": r[5],
                "last_error": r[6], "nodes_found": r[7],
            }
            for r in rows
        ]

    def stats(self) -> PoolStats:
        conn = self._ensure()
        total = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        alive = conn.execute("SELECT COUNT(*) FROM nodes WHERE alive=1").fetchone()[0]
        untested = conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE last_probe_at=0").fetchone()[0]
        by_proto = dict(conn.execute(
            "SELECT protocol, COUNT(*) FROM nodes WHERE alive=1"
            " GROUP BY protocol ORDER BY COUNT(*) DESC").fetchall())
        by_country = dict(conn.execute(
            "SELECT country, COUNT(*) FROM nodes WHERE alive=1 AND country<>''"
            " GROUP BY country ORDER BY COUNT(*) DESC LIMIT 12").fetchall())
        src_total = conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
        # 「健康」= 抓得到**且**有产出。只看 ok_count 会把「返回 200 但
        # 一条节点/链接都挖不出」的游戏站、词典站算成健康源（2026-10-14
        # 实测 62 个源里 37 个是这类），面板上会给出过于乐观的结论。
        src_ok = conn.execute(
            "SELECT COUNT(*) FROM sources WHERE ok_count>0 AND nodes_found>0"
        ).fetchone()[0]
        last_run_row = conn.execute(
            "SELECT at, trigger, sources_ok, sources_fail, parsed, new_nodes,"
            " probed, alive, elapsed_ms, note FROM runs"
            " ORDER BY id DESC LIMIT 1").fetchone()
        last_run = None
        if last_run_row:
            last_run = {
                "at": last_run_row[0], "trigger": last_run_row[1],
                "sources_ok": last_run_row[2], "sources_fail": last_run_row[3],
                "parsed": last_run_row[4], "new_nodes": last_run_row[5],
                "probed": last_run_row[6], "alive": last_run_row[7],
                "elapsed_ms": last_run_row[8], "note": last_run_row[9],
            }
        db_bytes = self.path.stat().st_size if self.path.exists() else 0
        # 分池统计：面板上要能一眼看出「客户池 18 个全活 / 免费池 3 个活的」
        by_pool: dict[str, dict[str, int]] = {}
        for p in ("cust", "free"):
            t = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(alive=1),0),"
                " COALESCE(SUM(last_probe_at=0),0) FROM nodes WHERE pool=?",
                (p,),
            ).fetchone()
            by_pool[p] = {"total": t[0] or 0, "alive": t[1] or 0,
                          "untested": t[2] or 0}
        return PoolStats(
            total=total, alive=alive, dead=max(0, total - alive - untested),
            untested=untested, by_protocol=by_proto, by_country=by_country,
            by_pool=by_pool,
            best=self.best(), source_count=src_total, healthy_sources=src_ok,
            last_run=last_run, db_bytes=db_bytes,
        )


# ══════════════════ 只读读取器（管理面板用）══════════════════

def read_pool_overview(db_path: Path | str, *, limit: int = 60,
                       only_alive: bool = False,
                       pool: str = "") -> dict[str, Any]:
    """**只读**读节点库，给管理面板画灯用。

    为什么不直接 new 一个 NodePool：构造函数会 `_ensure()` 建表、
    `_migrate()` 改库、`_secure()` chmod —— 而面板是**独立进程**，
    只为了在页面上画个灯就去动服务端正在用的库，风险远大于收益。

    这里用 `file:...?mode=ro` 打开：不建表、不迁移、不改权限、不拿写锁，
    连 sqlite 自己的 WAL 恢复也不会做（只读连接不允许）。服务端在写、
    面板在读，两边互不干扰。

    幂等且**绝不抛异常**：面板页面不该因为库没生成/被锁就 500。

    权限模型（用户定的，勿改）：自养池是**程序自己跑的**，用户只能看。
    所以本函数是纯读，面板上也不给任何增删入口。
    """
    p = Path(db_path)
    empty = {"available": False, "stats": {}, "nodes": []}
    if not p.exists():
        return {**empty, "note": "节点库还没生成（服务跑过一轮搜索后才会有）"}
    try:
        uri = p.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=3.0)
    except Exception as e:
        log.warning("只读打开节点库失败: %s", type(e).__name__)
        return {**empty, "note": f"节点库打不开（{type(e).__name__}）"}
    try:
        def _one(sql: str, args: tuple = ()) -> int:
            row = conn.execute(sql, args).fetchone()
            return int(row[0] or 0) if row else 0

        total = _one("SELECT COUNT(*) FROM nodes")
        alive = _one("SELECT COUNT(*) FROM nodes WHERE alive=1")
        untested = _one("SELECT COUNT(*) FROM nodes WHERE last_probe_at=0")
        by_pool: dict[str, dict[str, int]] = {}
        for name in ("cust", "free"):
            t = conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(alive=1),0),"
                " COALESCE(SUM(last_probe_at=0),0) FROM nodes WHERE pool=?",
                (name,),
            ).fetchone()
            by_pool[name] = {"total": t[0] or 0, "alive": t[1] or 0,
                             "untested": t[2] or 0}

        where, args = "WHERE 1=1", []
        if only_alive:
            where += " AND alive=1"
        if pool in ("cust", "free"):
            where += " AND pool=?"
            args.append(pool)
        # 活的排前面，其次按延迟；没测过的（avg_ms=0）排最后
        rows = conn.execute(
            f"SELECT protocol, server, port, country, tag, avg_ms, alive,"
            f" ok_count, fail_count, last_ok_at, pool FROM nodes {where}"
            f" ORDER BY alive DESC,"
            f" (CASE WHEN avg_ms>0 THEN avg_ms ELSE 99999 END) ASC LIMIT ?",
            (*args, int(limit)),
        ).fetchall()
    except sqlite3.Error as e:
        log.warning("读节点库失败: %s", e)
        return {**empty, "note": f"节点库读取失败（{e}）"}
    finally:
        conn.close()

    return {
        "available": True,
        "stats": {"total": total, "alive": alive,
                  "dead": max(0, total - alive - untested),
                  "untested": untested, "by_pool": by_pool},
        "nodes": [
            {
                "protocol": r[0], "server": r[1], "port": r[2],
                "country": r[3] or "", "tag": r[4] or "",
                "avg_ms": int(r[5] or 0), "alive": bool(r[6]),
                "ok_count": r[7] or 0, "fail_count": r[8] or 0,
                "last_ok_at": r[9] or 0, "pool": r[10] or "free",
            }
            for r in rows
        ],
    }
