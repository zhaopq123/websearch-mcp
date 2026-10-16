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
    _DATED_URL_RE,
    discover_via_search,
    extract_node_uris,
    extract_subscription_urls,
    source_id,
)

log = logging.getLogger("websearch.nodes.hunter")

# 一轮 hunt 的默认规模（可用环境变量覆盖）
# 单轮最多抓多少个源。2026-10-15：24→40 —— 种子源涨到 37 个后，
# [:24] 截断把新种子（GFP wiki + 8 个代理列表）全挡在轮换外，
# 加了种子永远不抓（hunt 报告「源 34 成功」= 24 一层 + 11 二层）。
# 40 覆盖全部种子 + 少量历史；抓取并发 6，多 13 源约 +30s/轮。
# 代理列表源的 URL 特征（用于组源时前置，见 _build_sources）。
# 普通 SOCKS/HTTP 代理列表：5 分钟级更新、公网欧美 VPS、低延迟候选，
# 新鲜度与价值都高于日更 VPN bundle。
_PROXY_LIST_HINTS = (
    "proxifly", "hproxy-com", "monosans/proxy-list", "litportnet",
    "Thordata", "proxyscrape", "databay-labs", "proxio-io", "jetkai",
)

DEFAULT_MAX_SOURCES = 40        # 单轮最多抓多少个源
DEFAULT_PROBE_LIMIT = 120       # 单轮最多探测多少个节点
DEFAULT_FETCH_CONCURRENCY = 6   # 源抓取并发
DEFAULT_LOOP_INTERVAL = 600     # 持续搜索间隔（秒）——10 分钟一轮
LOOP_FAIL_BACKOFF_MAX = 3600    # 连续失败时最长退避到 1 小时

# 「死源」判定：从未成功过、且累计失败到这个数，就不再重复抓。
# 为什么：历史源清单按「成功率」排序取前 N，但总源数不足 N 时，
# 从未成功的高失败源会挤进来，每轮空转烧抓取预算（实测 bing 追踪链接
# 空转 45 次、百度百科词条 403 44 次）。只淘汰「零成功」的源，避免
# 误伤「偶发失败但曾成功」的正常源。已入库的旧垃圾由 source_health
# 按成功率沉底 + 本阈值双重兜底。
DEAD_SOURCE_MIN_FAILS = 8

# ── 保活闭环（维持 N 个活节点）──
#
# 为什么需要单独一套参数：默认配置是「随便搜搜」，一轮 120 个探测、
# 十分钟一轮、7 天才淘汰。而要「一直保持 100 个活节点」是**保活**
# 不是「收集」——活节点会以小时为单位死亡，必须持续补充，且死得
# 比补得快。三个调节旋钮：
TARGET_ALIVE = 100# 目标活节点数（env WS_NODE_TARGET_ALIVE）
# 实测免费节点存活率极低（2026-10-13：探测 60 存活 0）。
# 要养住 100 个活的，输入侧的候选必须远超 100 —— 否则再怎么探也是杯水车薪。
PROBE_OVERSHOOT = 4             # 每轮探测量 = target × 本值（至少 PROBE_MIN）
PROBE_MIN = 240#单轮探测下限（补库存时的最小批量）
# 活节点不够时缩短间隔，够时拉长。固定间隔是「够用就行」的做法，
# 保活必须按缺口调节，否则刚补满 100 个，下一轮又掉到 50 个。
INTERVAL_MIN = 120              # 缺货时最快 2 分钟一轮
INTERVAL_MAX = 900              # 满仓时最慢 15 分钟一轮
INTERVAL_FLOOR_RATIO = 0.5       # 缺口达此比例 → 用 INTERVAL_MIN
# 保活模式下的淘汰阈值。默认 7 天对免费节点太长：死节点堆着不删，
# 候选查询越来越慢，而免费节点本来就按小时计寿命。2 小时够筛掉
# 「源里还挂着但实际早已不可用」的那批，且不会误伤刚入库的。
FRESH_PRUNE_SEC = 2 * 3600
# 单轮探测硬上限。probe.py 的 PROBE_PORT_SPAN=800 是端口段上限，
# 这里留一半余量：手机 CPU 上一次别开太多代理端口（实测并发 12 已接近饱和）。
PROBE_HARD_CAP = 400
# 单轮**总**入库预算（跨所有源累加，env WS_NODE_ROUND_INGEST_CAP）。
# 为什么需要：ingest_cap 是「单源」上限，多个高产源叠加起来没有总量闸门
# ——实测 2026-10-15 单轮入库 13853 个，而单轮探测上限只有 400。
# 入库比探测快 34 倍，未测库存必然无限积压（当日实测全库 27265、未测
# 27161，存活率卡在 74 上不去）：新节点排不到探测窗口，永远测不到，
# 相当于白收。本闸门让入库速率与探测吞吐匹配——积压被 prune 消化后，
# 下一轮又能收新的，库保持「周转」而不是「堆积」。
# 取值取探测上限的数倍：允许入库略快于探测（源解析有随机性，偶尔小轮
# 解析少），但不允许无节制膨胀。
# 2026-10-15 两调：4000→8000→10000。配合 node_ingest_cap=2000：
# 10000/2000 = 每轮 5 个高产源都能进库（代理源前置 + cap 2000，
# 代理/VPN 混合覆盖）。实测 8000+4000 组合会让 VPN 源全部饿死
# （服务日志「单轮入库预算耗尽」刷屏），10000+2000 均衡。
# 仍是探测上限 PROBE_HARD_CAP(400) 的 25 倍，库存周转可控
#（陈库存 3 天硬删兜底）。
ROUND_INGEST_CAP = 10000


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
    # ── 保活闭环状态 ──
    target_alive: int = 0# 目标活节点数（0 = 不启用保活模式）
    alive_now: int = 0             # 上轮结束时实测存活总数
    alive_cust: int = 0            # 其中客户池
    alive_free: int = 0            # 其中免费池
    deficit: int = 0               # 缺口 = target − alive（<=0 表示达标）

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
            # 保活闭环
            "target_alive": self.target_alive,
            "alive_now": self.alive_now,
            "alive_cust": self.alive_cust,
            "alive_free": self.alive_free,
            "deficit": self.deficit,
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
                 discover: bool = True, switch_cb: Any = None,
                 customer_subs: list[str] | None = None,
                 ingest_cap: int = 0):
        self.pool = pool
        self.fetcher = fetcher
        self.prober = prober
        self.orch = orch
        self.discover = discover
        # 切换回调：async (outbound) -> bool，由 Service 提供（负责起
        # 本地 sing-box 并把 HttpPool 切过去）。不传则只更新内部状态。
        self.switch_cb = switch_cb
        # 客户订阅（cust 池唯一入口，WS_CUSTOMER_SUBS / WS_CUSTOMER_SUB_FILE）。
        # 空 = 没配，import_customer_subs 直接跳过，零开销。
        self.customer_subs = [s.strip() for s in (customer_subs or [])
                              if s and s.strip()]
        # 单源单轮入库上限（防代理列表洪水爆库）。0/负 = 不限制。
        self.ingest_cap = ingest_cap
        # 最近一次客户订阅导入结果（只计数，无凭据）
        self.last_customer_import: dict[str, Any] = {}
        self.state = HunterState(
            interval_sec=_env_int("WS_NODE_HUNT_INTERVAL", DEFAULT_LOOP_INTERVAL),
            target_alive=_env_int("WS_NODE_TARGET_ALIVE", TARGET_ALIVE),
        )
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()      # 保证同一时刻只有一轮 hunt
        # 存活率 EMA：决定探测量要放大多少倍才能养住目标活节点数。
        # 首次探测前没有样本，先用一个保守的悲观值（免费节点存活率极低）。
        self._alive_rate_ema: float = 0.0
        # 本轮剩余入库预算。None = 不受限（hunt 轮内每轮重置为
        # ROUND_INGEST_CAP；轮外单独调 _ingest_text 时不限额）。
        self._round_ingest_left: int | None = None

    # ══════════════════ 保活规划器 ══════════════════

    def plan_next_round(self) -> dict[str, Any]:
        """按当前缺口规划下一轮：探多少、隔多久再跑。

        为什么要有这个：默认参数是「随便搜搜」（一轮 120 个探测、
        10 分钟一轮），而保活的目标是**动态维持** N 个活节点。
        活节点会持续死亡（实测免费池 807 个存活 0），补的速度必须
        始终快过死的速度，缺口越大就得越激进。

        返回（无凭据）：{"probe_limit", "delay_sec", "deficit",
                        "alive", "alive_rate", "untested"}
        """
        st = self.state
        target = st.target_alive
        stats = self.pool.stats()
        alive = stats.alive
        st.alive_now = alive
        st.alive_cust = (stats.by_pool.get("cust") or {}).get("alive", 0)
        st.alive_free = (stats.by_pool.get("free") or {}).get("alive", 0)
        untested = stats.untested

        if target <= 0:
            # 未启用保活：沿用固定规模
            return {
                "probe_limit": _env_int("WS_NODE_HUNT_PROBE_LIMIT",
                                        DEFAULT_PROBE_LIMIT),
                "delay_sec": st.interval_sec,
                "deficit": 0, "alive": alive, "alive_rate": None,
                "untested": untested, "mode": "collect",
            }

        deficit = max(0, target - alive)
        st.deficit = deficit

        # 探测量：按存活率放大。存活率 10% 时要探 10 倍才够，
        # 所以下限取 PROBE_MIN（批量探测有固定开销，太少不划算）。
        rate = self._alive_rate_ema
        if rate <= 0.01:
            need = PROBE_MIN
        else:
            need = int(target / rate * PROBE_OVERSHOOT)
        probe_limit = max(PROBE_MIN, need)
        # ⚠️ 不能用 `min(probe_limit, untested)` 限制探测量 ——
        # 库存挖空（untested=0）时那会把 probe_limit 压到 0，
        # 循环变成「每轮探 0 个」→ 永远补不上活节点。
        # 正确做法是探测量由**存活率**决定（要多少探多少），
        # 探不到候选时让 probe_batch 自己少探几个即可。
        probe_limit = min(probe_limit, PROBE_HARD_CAP)

        # 间隔：缺口越大越快。
        if deficit <= 0:
            delay = INTERVAL_MAX
        elif deficit >= target * INTERVAL_FLOOR_RATIO:
            delay = INTERVAL_MIN
        else:
            ratio = deficit / max(1, target)
            delay = int(INTERVAL_MIN + (INTERVAL_MAX - INTERVAL_MIN) * ratio)
        # 已启用保活时不再用固定 interval_sec
        return {
            "probe_limit": probe_limit,
            "delay_sec": max(INTERVAL_MIN, min(INTERVAL_MAX, delay)),
            "deficit": deficit, "alive": alive, "alive_rate": rate,
            "untested": untested, "mode": "keepalive",
        }

    def _update_alive_rate(self, probed: int, alive: int) -> None:
        """更新存活率 EMA（只在有样本时更新）。"""
        if probed <= 0:
            return
        r = alive / probed
        if self._alive_rate_ema <= 0:
            self._alive_rate_ema = r
        else:
            self._alive_rate_ema = 0.7 * self._alive_rate_ema + 0.3 * r

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
            # 保活模式下 probe_limit 由规划器按缺口决定，忽略默认固定值
            plan: dict[str, Any] = {}
            if probe_limit is None:
                plan = self.plan_next_round()
                if plan.get("mode") == "keepalive":
                    probe_limit = plan["probe_limit"]
            probe_limit = probe_limit or _env_int(
                "WS_NODE_HUNT_PROBE_LIMIT", DEFAULT_PROBE_LIMIT)

            report: dict[str, Any] = {
                "at": t0, "trigger": trigger,
                "sources_ok": 0, "sources_fail": 0, "parsed": 0,
                "new_nodes": 0, "probed": 0, "alive": 0,
                "discovered": 0, "note": "",
            }
            if plan:
                report["plan"] = plan
            try:
                # 0) 客户订阅导入（cust 池唯一入口）。放在最前：客户节点
                #    要赶在本轮探测前入库，才吃得到 CUST_PROBE_QUOTA。
                if self.customer_subs:
                    report["customer"] = await self.import_customer_subs()

                # 1) 组源
                source_list = await self._build_sources(discover=discover,
                                                        report=report)
                source_list = source_list[:max_sources]

                # 2) 抓取 + 解析 + 入库
                # 每轮重置单轮入库预算（ROUND_INGEST_CAP）：它是「本轮」
                # 的闸门，跨轮累计会让服务跑几轮后再也不收新节点。
                self._round_ingest_left = _env_int(
                    "WS_NODE_ROUND_INGEST_CAP", ROUND_INGEST_CAP)
                parsed_nodes = await self._fetch_and_ingest(source_list, report)

                # 3) 探测候选（cust 配额 + free 补量）
                probe_report = await self._probe_candidates(probe_limit)
                report.update(probe_report)

                # 3b) 站点可达性抽检（2026-10-15 实测驱动）：选路只按
                # 延迟会选中「快而残」的节点——实测 5 个香港节点延迟
                # 最优但对 github/DDG/快递100 全不通，英国节点慢 4%
                # 却全通。每轮抽 3 个 top 节点测盲区站（github/DDG），
                # 结果喂 best() 的「站点覆盖优先」排序。
                site_report = await self._site_check(limit=3)
                if site_report.get("checked"):
                    report["site_checked"] = site_report["checked"]
                # 探测实例没起来（端口竞态等）造成的 0 存活不是「节点都差」，
                # 别喂给存活率 EMA —— 否则坏一轮就让下轮 batch 缩水（负反馈）
                if not report.get("probe_start_failed"):
                    self._update_alive_rate(report["probed"], report["alive"])

                # 4) 清理。保活模式要**激进淘汰**：死节点堆积会拖慢
                #    候选查询，且免费节点本就该按小时计寿命。
                pruned = (self.pool.prune(max_age_sec=FRESH_PRUNE_SEC)
                          if self.state.target_alive > 0 else self.pool.prune())
                if pruned:
                    report["pruned"] = pruned

                report["elapsed_ms"] = int((time.time() - t0) * 1000)
                report["ok"] = report["alive"] > 0 or report["new_nodes"] > 0
                if report["parsed"] == 0 and report["sources_ok"] == 0:
                    report["note"] = "所有源都抓取失败（网络或源已失效）"
                elif report["alive"] == 0:
                    report["note"] = "收到节点但本轮探测无存活（免费节点常态）"

                # 保活模式下把实时库存写回状态（下一轮规划要用）
                if self.state.target_alive > 0:
                    st2 = self.pool.stats()
                    self.state.alive_now = st2.alive
                    self.state.alive_cust = (
                        st2.by_pool.get("cust") or {}).get("alive", 0)
                    self.state.alive_free = (
                        st2.by_pool.get("free") or {}).get("alive", 0)
                    self.state.deficit = max(0, self.state.target_alive - st2.alive)
                    report["alive_total"] = st2.alive
                    report["deficit"] = self.state.deficit

                self.state.rounds += 1
                self.state.last_round_at = time.time()
                self.state.last_round_ok = bool(report["ok"])
                self.state.last_elapsed_ms = report["elapsed_ms"]
                self.state.consecutive_fail = 0
                self.state.last_error = ""
                self.pool.record_run(report)
                log.info("hunt 完成(%s)：源 %d 成功/%d 失败，解析 %d，新增 %d，"
                         "探测 %d，回写 %d，存活 %d，耗时 %dms",
                         trigger, report["sources_ok"], report["sources_fail"],
                         report["parsed"], report["new_nodes"],
                         report["probed"], report.get("probe_written", -9),
                         report["alive"], report["elapsed_ms"])
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

        # 无贡献源黑名单。判据：抓过 >=DEAD_SOURCE_MIN_FAILS 次，累计贡献
        # （解析出的节点数，或 page 源挖出的订阅链接数）仍然是 0。
        # 为什么必须在**这里**拦：主循环紧接着会 `source_list[:max_sources]`
        # 截断，无用源会实打实挤掉有用源的名额；而且搜索发现每轮都会把
        # 游戏站/词典站（爱奇艺类聚合页、4399/7k7k、cambridge/iciba…）
        # 重新塞回来，只在历史源上做过滤挡不住。
        # 历史背景（2026-10-14）：page 源抓取成功一律记 ok，`source_health`
        # 按 ok/(ok+fail) 排序，于是「返回 200 但一条链接都挖不出」的站点
        # 长期霸占榜首、每轮必抓 —— 62 个源里只有 25 个有产出。
        health = self.pool.source_health(limit=200)
        dead_sids = {
            s["sid"] for s in health
            if (s.get("nodes_found") or 0) == 0
            and ((s.get("ok") or 0) + (s.get("fail") or 0)) >= DEAD_SOURCE_MIN_FAILS
        }
        dead_skipped = 0

        def add(url: str, kind: str, note: str = "") -> None:
            nonlocal dead_skipped
            if not url or url in seen:
                return
            if source_id(url) in dead_sids:
                dead_skipped += 1
                return
            seen.add(url)
            out.append({"url": url, "kind": kind, "note": note})

        # 代理列表源优先入轮（2026-10-15 实测教训）：proxifly socks5
        # 6 万条/5 分钟级更新、公网欧美 VPS 低延迟候选，而 VPN 日更源
        # 每轮解析 6 万但新增趋近 0（指纹全覆盖）。单轮总预算
        # （ROUND_INGEST_CAP）按源序扣减 —— 代理源排后时预算已被
        # 前面的 VPN 大源吃光，实测「抓到了但一个都没进库」。
        def _is_proxy_list(u: str) -> bool:
            return any(h in u for h in _PROXY_LIST_HINTS)

        seeds = sorted(SEED_SOURCES,
                       key=lambda s: 0 if _is_proxy_list(s["url"]) else 1)
        for s in seeds:
            url = s["url"]
            # 日期型种子（clashnode-%Y%m%d.html）：按当天格式化成当日页，
            # 每天自动追新。格式化失败（URL 里没有 % 指令）就用原值。
            if s.get("dated"):
                try:
                    url = time.strftime(url)
                except Exception:
                    pass
            add(url, s.get("kind", "sub"), s.get("note", ""))

        # 历史源：健康度高的在前（失败多的自然沉底）。
        # ⚠️ 日期页跳过：它们每天产生一个新 URL，放进历史就会被当普通源
        # 永久每轮重抓（旧页的节点早过期，重抓纯耗预算），只有「当天」的
        # 日期页有抓取价值，而它已经由上面的种子机制每天生成。
        for s in health[:60]:
            if _DATED_URL_RE.search(s["url"] or ""):
                continue
            kind = s.get("kind") or "sub"
            add(s["url"], kind, "history")
        report["sources_dead_skipped"] = dead_skipped

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
                # 火源页面：先直接抠页面里嵌的裸节点 URI（vmess/vless/…）。
                # 2026-10-14 实测：clashgithub 日更页直接嵌 455 个 URI，
                # 而旧逻辑只认「订阅链接」——这类页面会被判 no_sub_links
                # 拉黑，每天几百个新鲜节点全部漏掉。抠完再走订阅链接
                # 提取（zhuhai 这类两者都有的页面，两层都不落）。
                direct_n = direct_added = 0
                try:
                    uris = extract_node_uris(r.text)
                    if uris:
                        direct_n, direct_added = self._ingest_text(
                            "\n".join(uris), sid)
                except SubscriptionError:
                    pass  # 页面里没有可解析节点行，走订阅链接提取
                except Exception as e:
                    log.warning("页面 %s 节点直解异常：%s",
                                url[:60], type(e).__name__)
                subs = [su for su in extract_subscription_urls(r.text, url)
                        if su != url]
                if direct_n > 0 or subs:
                    report["sources_ok"] += 1
                    if direct_n > 0:
                        report["parsed"] += direct_n
                        report["new_nodes"] += direct_added
                    self.pool.record_source_fetch(
                        sid, True, nodes_found=direct_n or len(subs))
                else:
                    report["sources_fail"] += 1
                    self.pool.record_source_fetch(sid, False,
                                                  error="no_sub_links")
                for su in subs:
                    second_wave.append({"url": su, "kind": "sub",
                                        "note": "extracted"})
                return
            if ck in ("sub", "unknown"):
                # 订阅内容：解析
                from ..proxy.subparse import SubscriptionError
                try:
                    n, added = self._ingest_text(r.text, sid, url=url)
                except SubscriptionError:
                    # 解析器对「空内容 / 一行节点都没有 / 订阅已失效」
                    # 一律抛 SubscriptionError（属于源没货，不是代码 bug）。
                    # 归一成 empty_sub：源健康表里能一眼区分「没货」
                    # 与真正的解析异常，也喂给无贡献源黑名单淘汰。
                    report["sources_fail"] += 1
                    self.pool.record_source_fetch(sid, False,
                                                  error="empty_sub")
                    return
                except Exception as e:
                    report["sources_fail"] += 1
                    self.pool.record_source_fetch(
                        sid, False, error=f"parse:{type(e).__name__}")
                    return
                # 解析出 0 个节点 = 这份内容里根本没有节点行（页面被换成
                # 博客/登录页、或订阅已失效），记 ok 会让它永远绿着。
                if n <= 0:
                    report["sources_fail"] += 1
                    self.pool.record_source_fetch(sid, False, error="empty_sub")
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

    def _ingest_text(self, text: str, sid: str,
                     url: str = "") -> tuple[int, int]:
        """解析订阅文本并入库。

        返回 (解析到的节点数, 新增入库数)。

        这里抓的是**系统自搜**的公开源，一律归 free 池。
        客户导入走 NodeHunter.import_customer()，那里传 pool='cust'。

        url 用于嗅探普通代理列表的协议（socks5.txt → socks5）；
        空 = 纯 VPN 订阅，不给 default_proto。
        """
        from ..proxy.subparse import parse_subscription_text

        proto = ""
        if url:
            from ..proxy.subparse import _sniff_proxy_proto
            proto = _sniff_proxy_proto(url)
        rep = parse_subscription_text(text, default_proto=proto)
        if not rep.nodes:
            return 0, 0
        items = [(n.tag, n.protocol, n.outbound) for n in rep.nodes]
        # 单源入库上限（WS_NODE_INGEST_CAP）：代理列表源动辄万行，
        # 不设限会把库撑爆、探测预算摊薄。截断是「当轮丢弃」语义——
        # 源下轮还会来，新鲜节点不受影响（优先截最新解析的尾部，
        # 因为头部通常是该源排序最前的，保留）。
        cap = getattr(self, "ingest_cap", 0) or 0
        if cap and len(items) > cap:
            items = items[:cap]
        # 单轮总预算闸（ROUND_INGEST_CAP）：保证**新增**入库速率不超过
        # 探测吞吐的合理倍数。
        #
        # 2026-10-15 关键修正：预算只对**新节点**生效，重复指纹永远
        # 不占预算、不丢弃（它们只刷新 last_seen，是 prune 语义需要）。
        # 实测库存饱和后（24k 指纹覆盖全部源）每轮解析 14 万几乎全是
        # 重复——旧口径按 len(items) 扣预算，前 5 个源解析 1 万、
        # added=0，照样烧光 10000 预算，后面的源全被「预算耗尽」丢弃
        # （服务日志刷屏，本轮 hunt 新增恒 0）。
        #
        # 实现：budget < len(items) 时先 known_fps 判新——预算内的新
        # 节点保留、超出的丢弃、重复项全部保留。budget 充足时跳过判新
        # （省一次批量查询）。
        budget = getattr(self, "_round_ingest_left", None)
        if budget is not None and budget < len(items):
            from .pool import fingerprint

            fps = [fingerprint(proto, ob) for _, proto, ob in items]
            known = self.pool.known_fps(fps)
            kept: list[tuple[str, str, dict[str, Any]]] = []
            fresh_n = 0
            for it, fp in zip(items, fps):
                if fp in known:
                    kept.append(it)                    # 重复：免费刷新
                elif fresh_n < budget:
                    kept.append(it)                    # 预算内的新节点
                    fresh_n += 1
                # else: 超预算的新节点丢弃（源下轮还会来）
            if len(kept) < len(items):
                log.info("单轮入库预算 %d：新节点 %d→%d，重复 %d 照常刷新",
                         budget, len(items) - len(known), fresh_n,
                         len(known))
            items = kept
        added = self.pool.upsert_nodes(items, source_sid=sid, pool="free")
        if budget is not None:
            self._round_ingest_left = budget - added
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

    async def import_customer_subs(self) -> dict[str, Any]:
        """抓取配置里的客户订阅 URL，导入 cust 池（每轮 hunt 开头跑）。

        与免费源抓取的区别：
          · 复用 fetcher（直连失败自动走本地代理）—— 机场订阅多在墙外；
          · **不记 source 健康度**：URL 含 token，sources 表会经
            node_pool action=sources 外泄；
          · 失败只记次数与异常类型名，不记 URL。
        返回 {"configured", "ok", "fail", "parsed", "added"}（无凭据）。
        """
        if not self.customer_subs:
            return {"configured": 0}
        rep: dict[str, Any] = {"configured": len(self.customer_subs),
                               "ok": 0, "fail": 0, "parsed": 0, "added": 0}
        for url in self.customer_subs:
            try:
                r = await self.fetcher.fetch(url)
                if not r.ok:
                    rep["fail"] += 1
                    log.warning("客户订阅抓取失败：%s", r.error or "fetch fail")
                    continue
                n, added = self.import_customer(r.text)
            except Exception as e:
                rep["fail"] += 1
                log.warning("客户订阅导入异常：%s", type(e).__name__)
                continue
            if n <= 0:
                # 订阅失效/解析不出节点：算失败，提示更换
                rep["fail"] += 1
                log.warning("客户订阅解析出 0 个节点（订阅可能已失效）")
                continue
            rep["ok"] += 1
            rep["parsed"] += n
            rep["added"] += added
        self.last_customer_import = dict(rep)
        if rep["ok"] or rep["fail"]:
            log.info("客户订阅导入：%d 成功 / %d 失败，解析 %d，新增 %d",
                     rep["ok"], rep["fail"], rep["parsed"], rep["added"])
        return rep

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
            # free 池内再按协议分额（2026-10-15）：普通代理（socks/http）
            # 拿一半 —— 实测盲区：纯 first_seen DESC 在「同轮多源入库」
            # 时退化成「最后入库的源优先」，代理源前置先入库反而永远被
            # 后入库的 VPN 源挤出窗口（7635 个未测 socks vs 候选 0 个）。
            # 普通代理探测走 httpx 直测（并发 50+，秒级一批），成本极低。
            plain_q = free_quota // 2
            plain = self.pool.candidates_for_probe(
                limit=plain_q, pool="free",
                only_protocols=("socks", "http"))
            parts.append((plain, "free"))
            tunnel_q = free_quota - len(plain)
            if tunnel_q > 0:
                parts.append((self.pool.candidates_for_probe(
                    limit=tunnel_q, pool="free"), "free"))
        cands: list[dict[str, Any]] = []
        seen_fps: set[str] = set()
        for batch, _pool in parts:
            for c in batch:
                if c["fp"] not in seen_fps:   # plain/tunnel 两查可能重叠
                    seen_fps.add(c["fp"])
                    cands.append(c)
        if not cands:
            return {"probed": 0, "alive": 0, "probe_start_failed": False}
        nodes = [{"fp": c["fp"], "outbound": c["outbound"]} for c in cands]
        probe_t0 = time.time()
        results = await self.prober.probe_batch(nodes)
        alive = 0
        start_failed = 0
        for r in results:
            self.pool.record_probe(r.fp, r.ok, r.ms)
            if r.ok:
                alive += 1
            elif getattr(r, "error", "") == "探测实例启动失败":
                start_failed += 1
        # 回写自证（2026-10-15 排查「探测记录丢失」）：数一下本轮
        # 探测的 fp 里有多少 last_probe_at 真的被更新了。理论上应
        # == len(results)；若小于，说明回写链路有问题（事务/并发/连接）。
        log.warning("probe 回写循环完成：results=%d alive=%d", len(results), alive)
        log.warning("probe 回写循环完成：results=%d alive=%d", len(results), alive)
        written = 0
        try:
            fps = list({r.fp for r in results})
            marks = ",".join("?" * len(fps))
            row = self.pool._ensure().execute(
                f"SELECT COUNT(*) FROM nodes WHERE fp IN ({marks})"
                " AND last_probe_at >= ?",
                (*fps, probe_t0 - 5),
            ).fetchone()
            written = row[0] if row else 0
        except Exception:
            written = -1
        # 整批因实例起不来而判失败 ≠ 节点都差：单独标记，别污染存活率 EMA
        systemic = bool(results) and start_failed == len(results)
        return {
            "probed": len(results),
            "alive": alive,
            "probe_written": written,
            "probe_mode": "exit_verified" if self.prober.has_singbox else "tcp_only",
            "probe_start_failed": systemic,
        }

    async def _site_check(self, limit: int = 3) -> dict[str, Any]:
        """站点可达性抽检：top alive 节点测盲区站（github/DDG）。

        为什么必须抽检而不能只看延迟：实测（2026-10-15）延迟最优的
        一批香港节点对 github/DDG/快递100 全部 ConnectError，而慢 4%
        的英国节点全通。盲区是**批次特征**（同源节点同出口段被封），
        抽 top 3 即可代表选路档位，成本可控（3 节点 × 2 站 ≈ 30s）。

        复用 NodeProber 的多节点批量机制（check_url 参数），不另起
        proxy 实例——不动服务正在用的 17892。
        """
        try:
            cands = self.pool.site_check_candidates(limit)
        except Exception:
            return {"checked": 0}
        if not cands:
            return {"checked": 0}
        nodes = [{"fp": c["fp"], "outbound": c["outbound"]} for c in cands]
        # 盲区站：实测有区分度（google/bing 全通、github/DDG 分批次）
        targets = [
            "https://github.com",
            "https://html.duckduckgo.com/html/?q=test",
        ]
        ok_map: dict[str, int] = {c["fp"]: 0 for c in cands}
        for url in targets:
            try:
                results = await self.prober.probe_batch(
                    nodes, timeout=10.0, check_url=url)
                for r in results:
                    if r.ok:
                        ok_map[r.fp] = ok_map.get(r.fp, 0) + 1
            except Exception as e:
                log.info("站点抽检异常（%s）：%s", url, type(e).__name__)
        checked = 0
        for fp, n_ok in ok_map.items():
            self.pool.record_site_check(fp, n_ok)
            checked += 1
        if checked:
            log.info("站点抽检完成：%d 个节点（github/DDG 可达数：%s）",
                     checked, sorted(ok_map.values(), reverse=True))
        return {"checked": checked}

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
        """常驻循环：**自适应间隔**的保活闭环。

        间隔不写死：每轮结束后重新规划 —— 缺口大就 2 分钟后再跑，
        达标了可以拉到 15 分钟。这是「一直保持 N 个活节点」和
        「定时收集」的根本区别。
        """
        while not self._stop.is_set():
            delay = self.state.interval_sec
            try:
                # 启动即搜一轮（不等第一个间隔）
                await self.hunt(trigger="auto", discover=self.discover)
                # 每轮结束顺手自愈一次（换掉失效的当前节点 / 首次接入出网）
                await self.smart_failover(switch_cb=self.switch_cb)
                # 规划下一轮间隔
                if self.state.target_alive > 0:
                    plan = self.plan_next_round()
                    delay = int(plan["delay_sec"])
                    if self.state.rounds % 5 == 1 or plan["deficit"] <= 0:
                        log.info(
                            "保活状态：活 %d/%d（客户 %d / 免费 %d），"
                            "缺口 %d，未测 %d，本轮探 %d，存活率 %.1f%%，"
                            "下次 %.0fs 后",
                            plan["alive"], self.state.target_alive,
                            self.state.alive_cust, self.state.alive_free,
                            plan["deficit"], plan["untested"],
                            plan["probe_limit"],
                            (plan["alive_rate"] or 0) * 100,
                            delay,
                        )
                if self.state.consecutive_fail >= 2:
                    # 连续失败退避：×2，最长 1 小时（别把源打崩）
                    delay = min(LOOP_FAIL_BACKOFF_MAX,
                                max(delay, self.state.interval_sec * (2 ** min(
                                    self.state.consecutive_fail, 4))))
            except asyncio.CancelledError:
                return
            except Exception as e:
                log.warning("hunt 循环异常（继续）: %s", type(e).__name__)
                delay = min(LOOP_FAIL_BACKOFF_MAX, max(delay, 300))
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
