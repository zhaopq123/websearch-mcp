# -*- coding: utf-8 -*-
"""节点猎手 —— 调度层：持续搜集 → 测速入库 → 智能降级。

用户需求原话：「必须一直搜，节点随时失效」。这不是可选项：
实测免费节点 TCP 可达率仅 14%（94 个里 14 个），存活寿命通常只有
几小时到几天。一次性搜集等于没搜集，所以本模块的核心是
**常驻后台循环**，默认开启。

一个 hunt 轮次（hunt()）：
  1. 组源：种子源 + 库里的历史源（按健康度排序）+ 搜索自举发现的新站
  2. 并发抓取（限流，单源失败隔离）
  3. 内容分类：
     · sub  → 直接交给 subparse 解析
     · page → 提取页面里的订阅链接，**回填成新源**（下一轮直接可用）
  4. 解析出的节点入库（指纹去重，宽进）
  5. 挑候选探测（优先从未测过的）→ 更新健康分
  6. 清理过期节点
  7. 记录本轮 run（可观测）

智能降级（smart_failover）：
  · 当前代理节点连续失败 → 从池里换下一个最优节点
  · 池里全无活节点 → 返回 None，由 gate 降级直连（不让服务挂）
  · 后台循环每轮结束顺手检查一次，实现「无人值守自愈」
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from .pool import NodePool
from .probe import NodeProber
from .sources import (
    SEED_SOURCES,
    SourceFetcher,
    discover_via_search,
    extract_subscription_urls,
    source_id,
)

log = logging.getLogger("websearch.nodes.hunter")

# 一轮 hunt 的默认规模（可用环境变量覆盖）
DEFAULT_MAX_SOURCES = 24        # 单轮最多抓多少个源
DEFAULT_PROBE_LIMIT = 120       # 单轮最多探测多少个节点
DEFAULT_FETCH_CONCURRENCY = 6   # 源抓取并发
DEFAULT_LOOP_INTERVAL = 600     # 持续搜索间隔（秒）——10 分钟一轮
LOOP_FAIL_BACKOFF_MAX = 3600    # 连续失败时最长退避到 1 小时


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass
class HunterState:
    """猎手运行状态（**无凭据**，可给工具/面板）。"""

    running: bool = False
    loop_active: bool = False
    interval_sec: int = DEFAULT_LOOP_INTERVAL
    rounds: int = 0
    last_round_at: float = 0.0
    last_round_ok: bool = False
    last_elapsed_ms: int = 0
    next_round_at: float = 0.0
    consecutive_fail: int = 0
    current_node_fp: str = ""      # 当前代理正在用的节点指纹
    failovers: int = 0             # 累计换节点次数
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        now = time.time()
        return {
            "running": self.running,
            "loop_active": self.loop_active,
            "interval_sec": self.interval_sec,
            "rounds": self.rounds,
            "last_round_at": self.last_round_at,
            "last_round_ok": self.last_round_ok,
            "last_elapsed_ms": self.last_elapsed_ms,
            "next_round_in_sec": (max(0, int(self.next_round_at - now))
                                  if self.loop_active else None),
            "consecutive_fail": self.consecutive_fail,
            "current_node_fp": self.current_node_fp,
            "failovers": self.failovers,
            "last_error": self.last_error,
        }


class NodeHunter:
    """节点猎手：搜集 + 测速 + 自愈。

    orch 可选（传了才启用搜索自举发现新源）；不传也能跑（用内置源 + 历史源）。

    **两个池子，物理隔离（同一张表，用 nodes.pool 列区分）**：
      · cust  客户导入 —— 机场订阅/自建。选路优先，不按时效淘汰。
      · free  系统自搜 —— 公开免费源。寿命以小时计，随时可清。
    混在一起会有两个后果：① 选路把付费节点和免费垃圾平等排序；
    ② 免费源数百节点的探测预算会挤掉客户节点的探测机会。
    """

    # 客户池在每轮探测里固定占的额度。取 60：客户节点通常几十个，
    # 一次能全测完；又留了余量给客户后续新增的节点。
    CUST_PROBE_QUOTA = 60

    def __init__(self, *, pool: NodePool, fetcher: SourceFetcher,
                 prober: NodeProber, orch: Any = None,
                 discover: bool = True, switch_cb: Any = None):
        self.pool = pool
        self.fetcher = fetcher
        self.prober = prober
        self.orch = orch
        self.discover = discover
        # 切换回调：async (outbound) -> bool，由 Service 提供（负责起
        # 本地 sing-box 并把 HttpPool 切过去）。不传则只更新内部状态。
        self.switch_cb = switch_cb
        self.state = HunterState(
            interval_sec=_env_int("WS_NODE_HUNT_INTERVAL", DEFAULT_LOOP_INTERVAL),
        )
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()      # 保证同一时刻只有一轮 hunt

    # ══════════════════ 主流程 ══════════════════

    async def hunt(self, *, trigger: str = "manual",
                   max_sources: int | None = None,
                   probe_limit: int | None = None,
                   discover: bool = True) -> dict[str, Any]:
        """跑一轮完整的搜集+测速。返回本轮报告（无凭据）。"""
        async with self._lock:
            t0 = time.time()
            self.state.running = True
            max_sources = max_sources or _env_int(
                "WS_NODE_HUNT_MAX_SOURCES", DEFAULT_MAX_SOURCES)
            probe_limit = probe_limit or _env_int(
                "WS_NODE_HUNT_PROBE_LIMIT", DEFAULT_PROBE_LIMIT)

            report: dict[str, Any] = {
                "at": t0, "trigger": trigger,
                "sources_ok": 0, "sources_fail": 0, "parsed": 0,
                "new_nodes": 0, "probed": 0, "alive": 0,
                "discovered": 0, "note": "",
            }
            try:
                # 1) 组源
                source_list = await self._build_sources(discover=discover,
                                                        report=report)
                source_list = source_list[:max_sources]

                # 2) 抓取 + 解析 + 入库
                parsed_nodes = await self._fetch_and_ingest(source_list, report)

                # 3) 探测候选（优先未测的）
                probe_report = await self._probe_candidates(probe_limit)
                report.update(probe_report)

                # 4) 清理
                pruned = self.pool.prune()
                if pruned:
                    report["pruned"] = pruned

                report["elapsed_ms"] = int((time.time() - t0) * 1000)
                report["ok"] = report["alive"] > 0 or report["new_nodes"] > 0
                if report["parsed"] == 0 and report["sources_ok"] == 0:
                    report["note"] = "所有源都抓取失败（网络或源已失效）"
                elif report["alive"] == 0:
                    report["note"] = "收到节点但本轮探测无存活（免费节点常态）"

                self.state.rounds += 1
                self.state.last_round_at = time.time()
                self.state.last_round_ok = bool(report["ok"])
                self.state.last_elapsed_ms = report["elapsed_ms"]
                self.state.consecutive_fail = 0
                self.state.last_error = ""
                self.pool.record_run(report)
                log.info("hunt 完成(%s)：源 %d 成功/%d 失败，解析 %d，新增 %d，"
                         "探测 %d，存活 %d，耗时 %dms",
                         trigger, report["sources_ok"], report["sources_fail"],
                         report["parsed"], report["new_nodes"],
                         report["probed"], report["alive"], report["elapsed_ms"])
                return report
            except Exception as e:
                self.state.consecutive_fail += 1
                self.state.last_error = f"{type(e).__name__}: {str(e)[:120]}"
                report["error"] = self.state.last_error
                report["elapsed_ms"] = int((time.time() - t0) * 1000)
                log.exception("hunt 异常")
                return report
            finally:
                self.state.running = False

    async def _build_sources(self, *, discover: bool, report: dict) -> list[dict[str, str]]:
        """组源清单：种子 + 历史（按健康度）+ 搜索发现。去重保序。"""
        out: list[dict[str, str]] = []
        seen: set[str] = set()

        def add(url: str, kind: str, note: str = "") -> None:
            if not url or url in seen:
                return
            seen.add(url)
            out.append({"url": url, "kind": kind, "note": note})

        for s in SEED_SOURCES:
            add(s["url"], s.get("kind", "sub"), s.get("note", ""))

        # 历史源：健康度高的在前（失败多的自然沉底）
        for s in self.pool.source_health(limit=60):
            kind = s.get("kind") or "sub"
            add(s["url"], kind, "history")

        # 搜索自举：发现新聚合站（页面类）
        if discover and self.orch is not None:
            try:
                found = await discover_via_search(self.orch)
                for u in found:
                    add(u, "page", "discovered")
                report["discovered"] = len(found)
            except Exception as e:
                log.warning("搜索发现失败（不影响本轮）: %s", type(e).__name__)

        # 落库（源本身是公开信息，可存）
        for s in out:
            self.pool.upsert_source(source_id(s["url"]), s["url"], s["kind"])
        return out

    async def _fetch_and_ingest(self, sources: list[dict[str, str]],
                                report: dict) -> int:
        """并发抓取所有源，解析节点入库；page 类源回填新订阅链接。"""
        sem = asyncio.Semaphore(_env_int("WS_NODE_FETCH_CONCURRENCY",
                                         DEFAULT_FETCH_CONCURRENCY))
        # 待处理的第二层：page 源里提取出的订阅链接
        second_wave: list[dict[str, str]] = []

        async def handle(s: dict[str, str]) -> None:
            url, kind = s["url"], s["kind"]
            sid = source_id(url)
            async with sem:
                r = await self.fetcher.fetch(url)
            if not r.ok:
                report["sources_fail"] += 1
                self.pool.record_source_fetch(sid, False, error=r.error or "fetch fail")
                return
            # 按实际内容形态决定处理方式（源声明可能不准）
            ck = r.content_kind
            if ck == "page" or kind == "page":
                # 页面：提取订阅链接，回填成下一层源
                subs = extract_subscription_urls(r.text, url)
                report["sources_ok"] += 1
                self.pool.record_source_fetch(sid, True, nodes_found=0)
                for su in subs:
                    if su != url:
                        second_wave.append({"url": su, "kind": "sub",
                                            "note": "extracted"})
                return
            if ck in ("sub", "unknown"):
                # 订阅内容：解析
                try:
                    n, added = self._ingest_text(r.text, sid)
                except Exception as e:
                    report["sources_fail"] += 1
                    self.pool.record_source_fetch(
                        sid, False, error=f"parse:{type(e).__name__}")
                    return
                report["sources_ok"] += 1
                report["parsed"] += n
                report["new_nodes"] += added
                self.pool.record_source_fetch(sid, True, nodes_found=n)
                return

        await asyncio.gather(*(handle(s) for s in sources))

        # 第二层：抓取 page 里挖出的订阅链接（限个数，防爆炸）
        second_wave = second_wave[: max(10, len(sources))]
        if second_wave:
            log.info("页面发现：第二层订阅链接 %d 个", len(second_wave))
            await asyncio.gather(*(handle(s) for s in second_wave))

        return report["parsed"]

    def _ingest_text(self, text: str, sid: str) -> tuple[int, int]:
        """解析订阅文本并入库。

        返回 (解析到的节点数, 新增入库数)。

        这里抓的是**系统自搜**的公开源，一律归 free 池。
        客户导入走 NodeHunter.import_customer()，那里传 pool='cust'。
        """
        from ..proxy.subparse import parse_subscription_text

        rep = parse_subscription_text(text)
        if not rep.nodes:
            return 0, 0
        items = [(n.tag, n.protocol, n.outbound) for n in rep.nodes]
        added = self.pool.upsert_nodes(items, source_sid=sid, pool="free")
        return len(rep.nodes), added

    def import_customer(self, text: str, sid: str = "customer") -> tuple[int, int]:
        """导入**客户自带**的订阅（机场/自建），归 cust 池。

        与 _ingest_text 的区别只有 pool='cust'，但语义完全不同：
        客户节点有服务承诺、不参与「多久没出现就淘汰」的时效清理，
        且在选路（pool.best）里优先于免费池。
        """
        from ..proxy.subparse import parse_subscription_text

        rep = parse_subscription_text(text)
        if not rep.nodes:
            return 0, 0
        items = [(n.tag, n.protocol, n.outbound) for n in rep.nodes]
        added = self.pool.upsert_nodes(items, source_sid=sid, pool="cust")
        log.info("客户节点导入：解析 %d 个，新增 %d 个", len(rep.nodes), added)
        return len(rep.nodes), added

    async def _probe_candidates(self, limit: int) -> dict[str, Any]:
        """挑候选节点探测，更新健康分。**分池配额**。

        为什么要分池：客户节点通常只有几十个，免费源一次能收几百个。
        若共用一个 limit 按「未测优先」排序，客户节点会被新到的免费节点
        全部挤出探测窗口，长期停在「未知」状态 —— 选路时无从比较，
        等于客户花钱买的节点白给。
        所以：cust 池固定拿走一部分额度（有多少测多少），
        剩下的给 free 池。
        """
        cust_quota = min(limit, self.CUST_PROBE_QUOTA)
        parts: list[dict[str, Any]] = []
        if cust_quota > 0:
            parts.append((self.pool.candidates_for_probe(
                limit=cust_quota, pool="cust"), "cust"))
        free_quota = max(0, limit - cust_quota)
        if free_quota > 0:
            parts.append((self.pool.candidates_for_probe(
                limit=free_quota, pool="free"), "free"))
        cands: list[dict[str, Any]] = []
        for batch, _pool in parts:
            cands.extend(batch)
        if not cands:
            return {"probed": 0, "alive": 0}
        nodes = [{"fp": c["fp"], "outbound": c["outbound"]} for c in cands]
        results = await self.prober.probe_batch(nodes)
        alive = 0
        for r in results:
            self.pool.record_probe(r.fp, r.ok, r.ms)
            if r.ok:
                alive += 1
        return {
            "probed": len(results),
            "alive": alive,
            "probe_mode": "exit_verified" if self.prober.has_singbox else "tcp_only",
        }

    # ══════════════════ 持续搜索循环 ══════════════════

    async def start_loop(self, *, interval: int | None = None) -> None:
        """启动常驻后台循环（幂等）。**这是「必须一直搜」的实现**。"""
        if self._task is not None and not self._task.done():
            return
        if interval:
            self.state.interval_sec = interval
        self._stop.clear()
        self.state.loop_active = True
        self._task = asyncio.create_task(self._loop(), name="node-hunter-loop")
        log.info("节点猎手持续搜索循环已启动：每 %ds 一轮", self.state.interval_sec)

    async def stop_loop(self) -> None:
        self._stop.set()
        self.state.loop_active = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        log.info("节点猎手循环已停止")

    async def _loop(self) -> None:
        """常驻循环：立即跑一轮，之后按间隔跑；失败退避。"""
        while not self._stop.is_set():
            try:
                # 启动即搜一轮（不等第一个间隔）
                await self.hunt(trigger="auto", discover=self.discover)
                # 每轮结束顺手自愈一次（换掉失效的当前节点 / 首次接入出网）
                await self.smart_failover(switch_cb=self.switch_cb)
                delay = self.state.interval_sec
                if self.state.consecutive_fail >= 2:
                    # 连续失败退避：×2，最长 1 小时（别把源打崩）
                    delay = min(LOOP_FAIL_BACKOFF_MAX,
                                self.state.interval_sec * (2 ** min(
                                    self.state.consecutive_fail, 4)))
            except asyncio.CancelledError:
                return
            except Exception as e:
                log.warning("hunt 循环异常（继续）: %s", type(e).__name__)
                delay = min(LOOP_FAIL_BACKOFF_MAX, self.state.interval_sec * 2)
            self.state.next_round_at = time.time() + delay
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                return

    # ══════════════════ 智能降级 ══════════════════

    def pick_best(self) -> dict[str, Any] | None:
        """从池里选最优节点（**无凭据**摘要）。没有活节点返回 None。"""
        return self.pool.best(only_alive=True)

    def outbound_for_best(self) -> dict[str, Any] | None:
        """取最优节点的完整 outbound（**含凭据**，供代理启动用）。"""
        b = self.pool.best(only_alive=True)
        if not b:
            return None
        return self.pool.outbound_for(b["fp"])

    async def smart_failover(self, *, switch_cb=None) -> dict[str, Any]:
        """智能降级：当前节点不行就换池里下一个最优。

        switch_cb: 可选回调 async (outbound) -> bool，负责真正让代理
        切到该节点（由 manager 提供）。不传则只更新内部状态。

        返回（无凭据）：{"switched": bool, "fp": ..., "reason": ...}
        """
        cur = self.state.current_node_fp
        best = self.pool.best(only_alive=True)

        # 情况一：池里没有活节点 → 交给 gate 降级直连
        if best is None:
            return {
                "switched": False,
                "fp": cur,
                "reason": "池内无存活节点，应降级直连（gate 处理）",
            }
        # 情况二：当前节点还有效，且就是最优 → 不动
        if cur and cur == best["fp"]:
            return {"switched": False, "fp": cur, "reason": "当前节点仍最优"}
        # 情况三：当前节点无效或不是最优 → 切换
        outbound = self.pool.outbound_for(best["fp"])
        if outbound is None:
            return {"switched": False, "fp": cur, "reason": "取节点配置失败"}
        if switch_cb is not None:
            try:
                ok = await switch_cb(outbound)
            except Exception as e:
                return {"switched": False, "fp": cur,
                        "reason": f"切换回调异常：{type(e).__name__}"}
            if not ok:
                return {"switched": False, "fp": cur, "reason": "切换失败"}
        self.state.current_node_fp = best["fp"]
        self.state.failovers += 1
        log.info("智能降级：切换到节点 %s（%s，%dms）",
                 best["fp"][:8], best.get("country") or best.get("protocol"),
                 best.get("avg_ms", 0))
        return {
            "switched": True, "fp": best["fp"],
            "reason": f"切到 {best.get('country') or best.get('protocol')} "
                      f"{best.get('avg_ms', 0)}ms",
            "node": best,
        }

    def note_node_result(self, ok: bool) -> None:
        """代理层报告当前节点的一次使用结果（供健康分修正）。"""
        fp = self.state.current_node_fp
        if fp:
            self.pool.record_probe(fp, ok, 0)

    # ══════════════════ 状态 ══════════════════

    def status(self) -> dict[str, Any]:
        """猎手状态（无凭据）。"""
        st = self.state.to_dict()
        st["env"] = {
            "singbox": self.prober.has_singbox,
            "probe_mode": ("exit_verified" if self.prober.has_singbox
                           else "tcp_only"),
            "search_discovery": self.orch is not None,
        }
        return st
