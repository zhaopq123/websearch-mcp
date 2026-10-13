"""编排层 —— 真并发扇出 + 三层超时预算 + 早停 + 抓取。

这里是最能体现「和现有方案不一样」的地方：
  · 真扇出：所有引擎同时起飞，不是一个一个试
  · 真早停：达到 quorum 就取消还在飞的慢请求，把时间还给调用方
  · 取消不算失败：不污染熔断健康度（否则早停会慢性杀死慢引擎）
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from . import engines as eng_mod
from .cache import Cache
from .config import PARSER_VERSION, Config
from .engines import Engine, RequestSpec, get_engine
from .extract import decode_bytes, extract, wrap_untrusted
from .fusion import fuse
from .governor import Governor
from .http_pool import (
    BlockedRedirectError,
    HttpPool,
    TooLargeError,
    assert_url_async,
    detect_block,
)
from .models import Budget, EngineOutcome, FetchResult, SearchResult
from .text import relevance_ratio, sha1_key

log = logging.getLogger("websearch.orch")


class Orchestrator:
    def __init__(self, cfg: Config, pool: HttpPool, cache: Cache, gov: Governor):
        self.cfg = cfg
        self.pool = pool
        self.cache = cache
        self.gov = gov
        self.searches = 0
        self.fetches = 0
        self.early_stops = 0
        # 单飞（single-flight）：同一个 key 的并发搜索只做一次真实扇出，
        # 其余调用共享同一次结果。多会话/多工作区同时问同一个问题时，
        # 没有它 = N 次搜索 × M 个引擎的重复请求，全撞限流和反爬。
        self._singleflight: dict[str, asyncio.Task] = {}
        self.singleflight_hits = 0
        # fire-and-forget 任务强引用集合：asyncio 对 create_task 只持弱引用，
        # 不 await 的后台任务会被 GC 中途吞掉（官方文档点名的坑），
        # 表现为「缓存随机丢、写盘数对不上」。
        self._bg_tasks: set[asyncio.Task] = set()
        # 准入控制：限制同时在飞的搜索数。冷缓存高并发实测教训：
        # 60 个不同 query 同时扇出 240 个引擎请求 → bing 投毒 + 限流跳过
        # 风暴（95 次跳过）→ 92% 空结果。超出的进 FIFO 队列等待，
        # 令牌预算从真正出队那一刻才算。
        self._adm = asyncio.Semaphore(cfg.max_search_concurrency)
        self.admission_queued = 0
        self.admission_busy = 0

    # ══════════════════════ 单个引擎的执行 ══════════════════════

    def _spawn_bg(self, coro) -> asyncio.Task:
        """派发后台任务并持强引用，防止被 GC 吞掉。"""
        t = asyncio.create_task(coro)
        self._bg_tasks.add(t)
        t.add_done_callback(self._bg_tasks.discard)
        return t

    async def _run_engine(
        self, engine: Engine, spec: RequestSpec, *, count: int,
        budget: Budget, timeout_ms: int, query_for_check: str = "",
    ) -> EngineOutcome:
        """跑一个引擎：限流 → 请求 → 反爬识别 → 解码 → 解析 → 记账。"""
        t0 = time.monotonic()
        name = engine.name

        # 1) 放行判定（熔断 + 令牌桶）
        allowed, reason = await self.gov.acquire(
            name, timeout=self.cfg.rate_acquire_timeout
        )
        if not allowed:
            return EngineOutcome(
                engine=name, ok=False, error=f"skipped:{reason}",
                error_kind=reason, elapsed_ms=int((time.monotonic() - t0) * 1000),
            )

        # 2) 请求（含重试）
        last_err = ""
        status = 0
        try:
            resp, status = await self._request_with_retry(spec, timeout_ms)
            if resp is None:
                raise RuntimeError(last_err or "request failed")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            elapsed = int((time.monotonic() - t0) * 1000)
            kind = self._classify_exception(e)
            # 超时/网络类错误不计入熔断失败（可能只是这次网络抖了）
            penalize = kind not in ("timeout", "cancel")
            if penalize:
                self.gov.record(name, False, elapsed, str(e)[:200])
            else:
                self.gov.record(name, False, elapsed, str(e)[:200], cancelled=True)
            return EngineOutcome(
                engine=name, ok=False, error=str(e)[:200], error_kind=kind,
                elapsed_ms=elapsed,
            )

        elapsed = int((time.monotonic() - t0) * 1000)

        # 3) 解码（GBK 站必须，否则中文全是乱码）
        ct = resp.headers.get("content-type", "")
        html = decode_bytes(resp.content, ct)

        # 4) 反爬识别
        blocked, breason = detect_block(resp.status_code, html)
        if blocked:
            self.gov.record(name, False, elapsed, breason, blocked=True)
            return EngineOutcome(
                engine=name, ok=False, error=breason, error_kind="blocked",
                elapsed_ms=elapsed, blocked=True,
            )
        if resp.status_code >= 400:
            self.gov.record(name, False, elapsed, f"http_{resp.status_code}")
            return EngineOutcome(
                engine=name, ok=False, error=f"http_{resp.status_code}",
                error_kind="http", elapsed_ms=elapsed,
            )

        # 5) 解析
        try:
            results = engine.parse(html, limit=count)
        except Exception as e:
            self.gov.record(name, False, elapsed, f"parse:{e}")
            return EngineOutcome(
                engine=name, ok=False, error=f"parse error: {e}"[:200],
                error_kind="parse", elapsed_ms=elapsed,
            )

        if not results:
            # 解析出 0 条：软失败。可能是查询无匹配（正常），也可能是
            # 结构变更/软拦截的前兆。记 EMA 降权但不喂熔断（soft=True），
            # 真正的软拦截由 detect_block 标记和相关性校验兜住。
            self.gov.record(name, False, elapsed, "zero_results", soft=True)
            return EngineOutcome(
                engine=name, ok=False, error="zero_results",
                error_kind="parse", elapsed_ms=elapsed,
            )

        # ── 相关性校验：识别「投毒式反爬」──
        # 有些引擎（实测必应）被判定为爬虫时不返回 403，而是返回一批
        # **和查询完全无关的结果**。状态码 200、结构完整、条数正常，
        # 只有相关性检查能抓出来。不拦的话，垃圾结果会污染最终排序，
        # 而且会让早停条件被垃圾结果提前满足，把好引擎的结果砍掉。
        ratio, hits = relevance_ratio(query_for_check, results)
        # 用**比例**而不是「有没有命中」：投毒结果里往往混着一两条碰巧相关的
        # （实测必应投毒时 10 条里有 1 条含「咖啡」），只数命中数会漏网。
        # 正常引擎对多词查询的相关率普遍在 60% 以上，0.3 是很宽松的线。
        if hits == 0 or ratio < self.cfg.min_relevance_ratio:
            self.gov.record(name, False, elapsed,
                            f"irrelevant(0/{len(results)} 条命中查询词)", blocked=True)
            return EngineOutcome(
                engine=name, ok=False,
                error=f"irrelevant: {len(results)} 条结果无一命中查询词",
                error_kind="irrelevant", elapsed_ms=elapsed, blocked=True,
            )

        self.gov.record(name, True, elapsed)
        return EngineOutcome(engine=name, ok=True, results=results, elapsed_ms=elapsed)

    async def _request_with_retry(
        self, spec: RequestSpec, timeout_ms: int
    ) -> tuple[Any, int]:
        """瞬时错误重试；403/429 不重试（重试只会加速被封）。"""
        attempts = self.cfg.retry_on_transient + 1
        last: Exception | None = None
        for i in range(attempts):
            try:
                # 搜索页允许更大（百度移动版实测 2.1MB），正文页有单独的上限
                cap = self.cfg.search_max_bytes
                if spec.method == "POST":
                    resp = await self.pool.fetch(
                        spec.url, method="POST", data=spec.data,
                        params=spec.params, timeout_ms=timeout_ms,
                        referer=spec.referer, headers=spec.extra_headers,
                        max_bytes=cap,
                    )
                else:
                    resp = await self.pool.fetch(
                        spec.url, params=spec.params, timeout_ms=timeout_ms,
                        referer=spec.referer, headers=spec.extra_headers,
                        max_bytes=cap,
                    )
                return resp, resp.status_code
            except (httpx.TimeoutException, httpx.ConnectError,
                    httpx.ReadError, httpx.RemoteProtocolError) as e:
                last = e
                # 403/429 已经走到 detect_block，不会在这里重试
                if i < attempts - 1:
                    backoff = self.cfg.backoff_base * (2 ** i)
                    await asyncio.sleep(backoff)
                    continue
                raise
            except Exception as e:
                last = e
                raise
        raise last or RuntimeError("unreachable")

    @staticmethod
    def _classify_exception(e: Exception) -> str:
        if isinstance(e, asyncio.CancelledError):
            return "cancel"
        if isinstance(e, httpx.TimeoutException):
            return "timeout"
        if isinstance(e, httpx.ConnectError):
            return "network"
        if isinstance(e, TooLargeError):
            return "too_large"
        if isinstance(e, BlockedRedirectError):
            # 安全拦截，不是网络故障：让调用方知道是被策略挡了
            return "blocked_url"
        if isinstance(e, httpx.HTTPError):
            return "network"
        return "unknown"

    # ══════════════════════ 搜索主流程 ══════════════════════

    @staticmethod
    def _post_snippets(res: dict[str, Any], include_snippets: bool) -> dict[str, Any]:
        """按调用方偏好裁剪摘要。单飞共享的结果对象不能被原地改，
        每个调用方拿自己的一份浅拷贝。"""
        if include_snippets or not res.get("results"):
            return res
        return {**res, "results": [{**r, "snippet": ""} for r in res["results"]]}

    async def search(
        self,
        query: str,
        *,
        max_results: int | None = None,
        engine_names: list[str] | None = None,
        lang: str = "",
        region: str = "",
        time_range: str = "",
        use_cache: bool = True,
        include_snippets: bool = True,
        fresh: bool = False,
    ) -> dict[str, Any]:
        """搜索入口（单飞包装）。

        同一个「查询+参数」的并发调用只做一次真实扇出，其余共享结果。
        只对可缓存查询生效：fresh/time_range 是实时语义，不合并。
        """
        cfg = self.cfg
        realtime = fresh or bool(time_range)
        coalesce = cfg.singleflight and use_cache and cfg.cache_enabled and not realtime
        if not coalesce:
            res = await self._search_impl(
                query, max_results=max_results, engine_names=engine_names,
                lang=lang, region=region, time_range=time_range,
                use_cache=use_cache, include_snippets=include_snippets,
                fresh=fresh,
            )
            return self._post_snippets(res, include_snippets)

        key = sha1_key(
            "sf", PARSER_VERSION, query, lang, region, time_range,
            str(max(1, min(max_results or cfg.max_results, 50))),
            ",".join(sorted(engine_names)) if engine_names else "",
        )
        task = self._singleflight.get(key)
        if task is None or task.done():
            task = asyncio.create_task(self._search_impl(
                query, max_results=max_results, engine_names=engine_names,
                lang=lang, region=region, time_range=time_range,
                use_cache=use_cache, include_snippets=True, fresh=fresh,
            ))
            self._singleflight[key] = task
        else:
            self.singleflight_hits += 1
        try:
            # shield：等待者被取消（客户端断开/上层早停）不影响在飞的那次搜索
            res = await asyncio.shield(task)
        except asyncio.CancelledError:
            raise
        except Exception:
            # 在飞的共享任务失败：清掉条目自己重做一次，失败不传染给等待者
            if self._singleflight.get(key) is task:
                self._singleflight.pop(key, None)
            res = await self._search_impl(
                query, max_results=max_results, engine_names=engine_names,
                lang=lang, region=region, time_range=time_range,
                use_cache=use_cache, include_snippets=True, fresh=fresh,
            )
        finally:
            if self._singleflight.get(key) is task and task.done():
                self._singleflight.pop(key, None)
        return self._post_snippets(res, include_snippets)

    async def _search_impl(
        self,
        query: str,
        *,
        max_results: int | None = None,
        engine_names: list[str] | None = None,
        lang: str = "",
        region: str = "",
        time_range: str = "",
        use_cache: bool = True,
        include_snippets: bool = True,
        fresh: bool = False,
    ) -> dict[str, Any]:
        """准入控制包装：限制同时在飞的搜索数（FIFO），防扇出风暴。"""
        def _busy(reason: str) -> dict[str, Any]:
            return {
                "query": query,
                "results": [],
                "meta": {
                    "elapsed_ms": 0,
                    "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "realtime": bool(time_range) or fresh,
                    "time_range": time_range or "",
                    "engines": {"attempted": [], "succeeded": [], "failed": [],
                                "blocked": [], "skipped": []},
                    "error": "server_busy",
                    "message": reason,
                },
            }

        queued = self._adm.locked()
        if queued:
            self.admission_queued += 1
        # 代理恢复检查：若代理处于旁路（降级直连）状态，这里会按间隔
        # 探活一次并在恢复后自动切回。开销极小（绝大多数情况只做一次
        # 时间比较），但能让「代理恢复了却一直直连」不至于持续到重启。
        try:
            await self.pool.maybe_recover_proxy()
        except Exception:
            pass
        try:
            await asyncio.wait_for(
                self._adm.acquire(), timeout=self.cfg.search_queue_timeout
            )
        except asyncio.TimeoutError:
            self.admission_busy += 1
            log.warning("搜索排队超时（>%ss）：query=%r", self.cfg.search_queue_timeout, query[:60])
            return _busy("搜索排队超时（服务器忙），请稍后重试或减少并发")
        # 容量等待：主力引擎令牌全枯时扇出只会得到空结果——
        # 排队等令牌恢复（0.25s 粒度）。干等 3s 后放宽到"至少 1 个
        # 引擎可用"：剩一个 workhorse 也要串行服务（降级优于拒绝），
        # 令牌等待会自然把并发压到 1/s。到点仍无任何引擎可用才
        # 诚实返回 server_busy。
        cap_deadline = time.monotonic() + self.cfg.search_queue_timeout
        relax_at = time.monotonic() + 3.0
        while True:
            n_ready = self.gov.ready_count()
            if n_ready >= self.cfg.min_ready_engines:
                break
            if n_ready >= 1 and time.monotonic() >= relax_at:
                break
            if time.monotonic() >= cap_deadline:
                self.admission_busy += 1
                self._adm.release()
                log.warning("引擎容量枯竭排队超时：query=%r", query[:60])
                return _busy("搜索引擎容量暂枯竭（限流恢复中），请稍后重试")
            await asyncio.sleep(0.25)
        try:
            return await self._search_impl_gate(
                query, max_results=max_results, engine_names=engine_names,
                lang=lang, region=region, time_range=time_range,
                use_cache=use_cache, include_snippets=include_snippets,
                fresh=fresh,
            )
        finally:
            self._adm.release()

    async def _search_impl_gate(
        self,
        query: str,
        *,
        max_results: int | None = None,
        engine_names: list[str] | None = None,
        lang: str = "",
        region: str = "",
        time_range: str = "",
        use_cache: bool = True,
        include_snippets: bool = True,
        fresh: bool = False,
    ) -> dict[str, Any]:
        """搜索主实现（扇出+早停+融合）。单飞包装见 search()。

        实时性策略（这是搜索服务最容易做错的地方）：
          · `fresh=True` → 完全不走缓存，也不写缓存，**保证实时**；
          · `time_range` 非空 → 自动视为实时（用户要的是「最近一周」，
            给三天前的缓存结果等于没答）；
          · 只有「不带时间要求的普通查询」才走缓存，且默认 TTL 只有 5 分钟。
        缓存存在的意义是防反爬（同一个词 10 秒内问 5 次，不缓存会被直接封），
        不是为了拿旧数据。
        """
        t0 = time.monotonic()
        self.searches += 1
        cfg = self.cfg
        limit = max(1, min(max_results or cfg.max_results, 50))
        budget = Budget(cfg.total_budget_ms)

        # 时间过滤 = 明确要新数据 → 强制实时
        realtime = fresh or bool(time_range)
        use_cache = use_cache and not realtime

        names = engine_names or cfg.active_engines()
        engines: list[Engine] = []       # 需要发请求的
        cache_only: list[Engine] = []    # 已熔断，但缓存可能还能救
        skipped: list[dict[str, str]] = []
        for n in names:
            e = get_engine(n)
            if e is None:
                skipped.append({"engine": n, "reason": "unknown_engine"})
                continue
            ok, reason = self.gov.allow_now(n)
            if ok:
                engines.append(e)
            else:
                skipped.append({"engine": n, "reason": reason})
                cache_only.append(e)
        # 熔断的引擎**仍然查缓存**：
        # 熔断只说明「现在去请求它会被拒/会超时」，不代表五分钟前的结果不能用。
        # 跳过缓存等于白白丢掉一条可用的数据通路。
        all_engines = engines + cache_only

        # ── 构造请求 ──
        specs: dict[str, RequestSpec] = {}
        for e in engines:
            try:
                specs[e.name] = e.build(
                    query, count=limit, lang=lang, region=region, time_range=time_range
                )
            except Exception as ex:
                log.warning("引擎 %s 构造请求失败: %s", e.name, ex)
                skipped.append({"engine": e.name, "reason": f"build:{ex}"})

        # ── 缓存：逐引擎查（命中的直接返回，不用发请求）──
        cache_keys: dict[str, str] = {}
        cached_outcomes: list[EngineOutcome] = []
        todo: list[Engine] = []
        if use_cache and cfg.cache_enabled:
            # 并行查缓存：L2 每次查询要走一次线程池往返，13 个引擎串行
            # ≈ 13 次线程唤醒，gather 只付最慢那次的钱。
            cache_keys = {
                e.name: sha1_key("search", PARSER_VERSION, e.name, query, lang,
                                 region, time_range, str(limit))
                for e in all_engines
            }
            got_list = await asyncio.gather(
                *[self.cache.get(cache_keys[e.name]) for e in all_engines]
            )
            for e, got in zip(all_engines, got_list):
                if got is not None:
                    cached_outcomes.append(
                        EngineOutcome(
                            engine=e.name, ok=True, from_cache=True,
                            results=[SearchResult(**r) for r in got],
                        )
                    )
                elif e.name in specs:
                    todo.append(e)
        elif cfg.cache_enabled:
            # 实时模式（fresh / time_range）：不读缓存，但**仍然写**。
            # 冒烟测试抓到的 bug：原来这条分支不填 cache_keys，
            # 导致 fresh 查询连写入都跳过了 —— 紧接着的普通查询还得重新发请求，
            # 一次实时查询的成果完全用不上，白白多打一轮搜索引擎（还多一次被封风险）。
            for e in engines:
                cache_keys[e.name] = sha1_key(
                    "search", PARSER_VERSION, e.name, query, lang, region, time_range, str(limit)
                )
            todo = list(engines)
        else:
            todo = list(engines)

        # ── 真并发扇出 + 早停 ──
        outcomes: list[EngineOutcome] = list(cached_outcomes)
        tasks: dict[asyncio.Task, str] = {}
        early_stopped = False
        if todo:
            engine_timeout = min(cfg.engine_timeout_ms, budget.remaining_ms)
            for e in todo:
                t = asyncio.create_task(
                    self._run_engine(e, specs[e.name], count=limit,
                                     budget=budget, timeout_ms=engine_timeout,
                                     query_for_check=query)
                )
                tasks[t] = e.name

            pending: set[asyncio.Task] = set(tasks)
            ok_count = len([o for o in cached_outcomes if o.ok])
            collected: list[SearchResult] = [r for o in cached_outcomes for r in o.results]
            seen_keys = {canonical(r.url) for r in collected}

            while pending and not budget.exhausted:
                # 剩余时间不够跑完一个引擎时，缩短等待窗口，
                # 否则会在最后一次 wait 上空耗到全局预算耗尽
                wait_for = budget.clamp(min(cfg.engine_timeout_ms, budget.remaining_ms),
                                        floor_ms=100)
                done, pending = await asyncio.wait(
                    pending, timeout=wait_for, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    name = tasks[t]
                    if t.cancelled():
                        continue
                    exc = t.exception()
                    if exc is not None:
                        outcomes.append(
                            EngineOutcome(engine=name, ok=False,
                                          error=str(exc)[:200], error_kind="unknown")
                        )
                        continue
                    o: EngineOutcome = t.result()
                    outcomes.append(o)
                    if o.ok:
                        ok_count += 1
                        for r in o.results:
                            k = canonical(r.url)
                            if k not in seen_keys:
                                seen_keys.add(k)
                                collected.append(r)
                        # 写缓存（异步落盘，不阻塞）
                        ck = cache_keys.get(name)
                        if ck and self.cache.enabled:
                            self._spawn_bg(
                                self.cache.put(
                                    ck, [r.to_dict() for r in o.results],
                                    cfg.cache_search_ttl, "search",
                                )
                            )

                # ── 早停判定 ──
                if cfg.early_stop and pending:
                    quorum = min(cfg.quorum, len(todo))
                    need = min(limit, cfg.quorum_results)
                    if ok_count >= quorum and len(seen_keys) >= need:
                        early_stopped = True
                        self.early_stops += 1
                        for t in pending:
                            t.cancel()
                        # 被取消的引擎不计失败（关键：否则早停会慢性杀死慢引擎）
                        for t in pending:
                            self.gov.record(tasks[t], False, 0, "cancelled", cancelled=True)
                        break

            # 收尾：还没完成的（预算耗尽）也要取消，否则任务泄漏
            if pending:
                for t in pending:
                    t.cancel()
                for t in pending:
                    self.gov.record(tasks[t], False, 0, "cancelled", cancelled=True)
                await asyncio.gather(*pending, return_exceptions=True)

        # ── 融合 ──
        ok_outcomes = [o for o in outcomes if o.ok]
        weights = {n: self.gov.weight(n, get_engine(n).weight)
                   for n in {o.engine for o in outcomes} if get_engine(n)}
        merged, fstats = fuse(
            [o.results for o in ok_outcomes],
            weights=weights, max_results=limit,
            per_domain_cap=cfg.per_domain_cap,
        )
        if not include_snippets:
            for r in merged:
                r.snippet = ""

        attempted = [o.engine for o in outcomes] + [s["engine"] for s in skipped]
        succeeded = [o.engine for o in ok_outcomes]
        failed = [
            {"engine": o.engine, "error": o.error, "error_kind": o.error_kind,
             "ms": o.elapsed_ms}
            for o in outcomes if not o.ok
        ]
        blocked = [o.engine for o in outcomes if o.blocked]
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        # 每条结果标清楚是不是来自缓存 —— 模型需要知道这条信息有多新
        out_results = []
        for r in merged:
            d = r.to_dict()
            d["cached"] = bool(cached_outcomes)
            out_results.append(d)

        return {
            "query": query,
            "results": out_results,
            "meta": {
                "elapsed_ms": elapsed_ms,
                # 抓取完成时刻（本地时区）—— 判断信息新鲜度的第一手依据
                "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "realtime": realtime,
                "time_range": time_range or "",
                "engines": {
                    "attempted": attempted,
                    "succeeded": succeeded,
                    "failed": failed,
                    "blocked": blocked,
                    "skipped": skipped,
                },
                "cache_hits": len([o for o in outcomes if o.from_cache]),
                "cache_misses": len([o for o in outcomes if not o.from_cache]),
                "early_stopped": early_stopped,
                "total_unique": fstats["unique_url"],
                "returned": len(merged),
                "coverage": round(len(succeeded) / len(attempted), 3) if attempted else 0.0,
                "engine_timings": {
                    o.engine: o.elapsed_ms for o in outcomes
                },
            },
        }

    # ══════════════════════ 启动预热 ══════════════════════

    async def warmup(self, query: str = "", cooldown: float = 300.0) -> dict[str, Any]:
        """并发探测所有引擎，不可用的直接熔断。

        为什么值得做：实测在国内网络下 DDG/Brave/SearX/Mojeek 全部不可达，
        不预热的话每次搜索都要在它们身上各耗一个连接超时，
        四个就是 10 秒 —— 全局预算直接被烧光，好引擎的结果反倒被早停砍掉。
        """
        t0 = time.monotonic()
        query = query or self.cfg.warmup_query
        names = self.cfg.active_engines()
        engines = [get_engine(n) for n in names if get_engine(n)]

        async def probe(e: Engine) -> tuple[str, bool, str]:
            try:
                spec = e.build(query, count=5)
                o = await self._run_engine(
                    e, spec, count=5, budget=Budget(10_000), timeout_ms=8_000,
                    query_for_check=query,
                )
                return e.name, o.ok, ("" if o.ok else (o.error or o.error_kind))
            except Exception as ex:
                return e.name, False, f"{type(ex).__name__}: {str(ex)[:80]}"

        results = await asyncio.gather(*[probe(e) for e in engines])
        good, bad = [], []
        for name, ok, err in results:
            if ok:
                good.append(name)
            else:
                bad.append({"engine": name, "error": err})
                self.gov.force_open(name, cooldown, err or "warmup failed")

        info = {
            "elapsed_ms": int((time.monotonic() - t0) * 1000),
            "available": good,
            "unavailable": bad,
        }
        log.info(
            "预热完成 %dms：可用 %s；不可用 %s",
            info["elapsed_ms"], ", ".join(good) or "（无）",
            ", ".join(b["engine"] for b in bad) or "（无）",
        )
        return info

    # ══════════════════════ 正文抓取 ══════════════════════

    async def fetch_one(
        self, url: str, *, max_chars: int | None = None,
        use_cache: bool = True, untrusted_wrap: bool = True,
    ) -> FetchResult:
        cfg = self.cfg
        limit = max_chars or cfg.fetch_max_chars
        t0 = time.monotonic()

        # SSRF 校验（DNS 解析后逐 IP 检查）
        allowed, reason = await assert_url_async(url, cfg)
        if not allowed:
            return FetchResult(url=url, ok=False, error=reason, error_kind="blocked_url")

        key = sha1_key("fetch", url, str(limit))
        if use_cache and cfg.cache_enabled:
            got = await self.cache.get(key)
            if got:
                fr = FetchResult(**got)
                fr.from_cache = True
                return fr

        try:
            resp = await self.pool.fetch(
                url, timeout_ms=cfg.fetch_timeout_ms, max_bytes=cfg.fetch_max_bytes
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return FetchResult(
                url=url, ok=False, error=str(e)[:200],
                error_kind=self._classify_exception(e),
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )

        ct = resp.headers.get("content-type", "")
        html = decode_bytes(resp.content, ct)
        text, title, extractor = extract(html, url=url, limit=limit)
        if not text:
            text = ""
        truncated = len(text) >= limit
        fr = FetchResult(
            url=url, ok=bool(text), final_url=str(resp.url), title=title,
            text=wrap_untrusted(text, url) if (untrusted_wrap and text) else text,
            status_code=resp.status_code,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
            bytes_read=len(resp.content), truncated=truncated,
            extractor=extractor,
            fetched_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        if not text:
            fr.error = "empty_extraction"
            fr.error_kind = "parse"
        if use_cache and cfg.cache_enabled and fr.ok:
            self._spawn_bg(self.cache.put(key, fr.to_dict(), cfg.cache_fetch_ttl, "fetch"))
        return fr

    async def fetch_many(
        self, urls: list[str], *, max_chars: int | None = None,
        concurrency: int | None = None, use_cache: bool = True,
        untrusted_wrap: bool = True,
    ) -> list[FetchResult]:
        """批量并发抓取。

        用 Semaphore 而不是 gather 全开：一次给 10 个 URL 就打 10 个并发是可以的，
        但 deep_research 可能一次给 30 个，那会把连接池和 vivo 的内存打满。
        """
        self.fetches += len(urls)
        sem = asyncio.Semaphore(concurrency or self.cfg.fetch_concurrency)

        async def one(u: str) -> FetchResult:
            async with sem:
                # 每 URL 硬超时兜底：否则一个不可达站点能把整批拖到几十秒。
                # 实测一个抓不到的站点让 6 个 URL 的批量抓取花了 30 秒。
                try:
                    return await asyncio.wait_for(
                        self.fetch_one(
                            u, max_chars=max_chars, use_cache=use_cache,
                            untrusted_wrap=untrusted_wrap,
                        ),
                        timeout=self.cfg.fetch_timeout_ms / 1000.0 + 3.0,
                    )
                except asyncio.TimeoutError:
                    return FetchResult(
                        url=u, ok=False, error="fetch hard timeout",
                        error_kind="timeout",
                    )

        return list(await asyncio.gather(*[one(u) for u in urls]))

    # ══════════════════════ 深度检索（多任务） ══════════════════════

    async def research(
        self,
        queries: list[str],
        *,
        max_results_per_query: int = 8,
        fetch_top: int = 2,
        max_chars: int = 6000,
        engine_names: list[str] | None = None,
        time_range: str = "",
        fresh: bool = True,
    ) -> dict[str, Any]:
        """多查询并发：每个 query 独立搜索 → 汇总去重 → 并发抓 top N 正文。

        这是「多任务」场景的核心工具：模型一次问 5 个侧面问题，
        串行做要 5×(搜索+抓取) 的时间，并发做只花最慢那个的时间。
        """
        t0 = time.monotonic()
        # 阶段 1：并发搜索
        sem = asyncio.Semaphore(min(4, max(1, len(queries))))

        async def one_search(q: str):
            async with sem:
                return await self.search(
                    q, max_results=max_results_per_query,
                    engine_names=engine_names, time_range=time_range,
                )

        search_results = list(await asyncio.gather(*[one_search(q) for q in queries]))

        # 阶段 2：汇总去重，挑出要抓的 URL
        picked: dict[str, dict[str, Any]] = {}
        per_query: list[dict[str, Any]] = []
        for q, sr in zip(queries, search_results):
            items = sr["results"]
            per_query.append({
                "query": q,
                "count": len(items),
                "coverage": sr["meta"]["coverage"],
                "engines_succeeded": sr["meta"]["engines"]["succeeded"],
            })
            for r in items[:fetch_top]:
                k = canonical(r["url"])
                if k in picked:
                    picked[k]["queries"].append(q)
                    continue
                picked[k] = {"url": r["url"], "title": r["title"], "queries": [q]}

        # 阶段 3：并发抓正文
        targets = list(picked.values())
        fetches = await self.fetch_many(
            [t["url"] for t in targets], max_chars=max_chars,
            concurrency=self.cfg.fetch_concurrency,
        )
        sources: list[dict[str, Any]] = []
        for t, fr in zip(targets, fetches):
            sources.append({
                "url": t["url"], "title": t["title"], "queries": t["queries"],
                "ok": fr.ok, "error": fr.error, "extractor": fr.extractor,
                "elapsed_ms": fr.elapsed_ms, "truncated": fr.truncated,
                "content": fr.text if fr.ok else "",
            })

        return {
            "queries": queries,
            "fetched_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "per_query": per_query,
            "sources": sources,
            "meta": {
                "elapsed_ms": int((time.monotonic() - t0) * 1000),
                "queries_count": len(queries),
                "sources_fetched": len([s for s in sources if s["ok"]]),
                "sources_failed": len([s for s in sources if not s["ok"]]),
            },
        }


def canonical(url: str) -> str:
    from .text import canonicalize_url

    return canonicalize_url(url)
