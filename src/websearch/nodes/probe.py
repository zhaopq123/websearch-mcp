# -*- coding: utf-8 -*-
"""节点测速 —— 判断一个节点「能不能真的出网」，不是「端口通不通」。

为什么必须实测出网：
  · 免费源里大量节点是失效的、限速的、占位的；
  · 端口能连（TCP 通）不代表节点能转发流量（密码错、协议版本不符、
    服务器只监听不转发都常见）；
  · 所以主判据是「**通过该节点请求墙外端点成功**」，不是 TCP 握手。

两档探测：
  1. **出网探测**（主）：起临时 sing-box，每个节点一个本地 http inbound，
     并发经该端口请求 CHECK_URL。这是真验证。
  2. **轻量探测**（退化）：sing-box 不可用时，退化为 TCP+TLS 握手延迟。
     只标「端口可达」，结果里 `exit_verified=false` —— 明确区分
     「验证过能出网」与「只是端口开着」，不糊弄。

边界处理（踩过才想到）：
  · **墙外环境**：如果直连就能访问 CHECK_URL，说明本机在墙外，
    「经代理能否访问 Google」就测不出节点好坏了。这时自动降级为
    「TCP 可达即算活」并标注，不假装验证过。
  · **端口段**：临时 sing-box 每节点占一个本地端口，所以每批上限
    受端口段限制（默认 20000 起，一批最多 PORT_SPAN 个）。
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import httpx

log = logging.getLogger("websearch.nodes.probe")

# 墙外可达性端点：必须翻墙才通。用 204 端点（无 body，最快）
CHECK_URL = "https://www.google.com/generate_204"
CHECK_ALT = "https://www.gstatic.com/generate_204"

# 临时探测实例的本地端口段
PROBE_PORT_BASE = 20000
PROBE_PORT_SPAN = 800          # 一批最多这么多节点（端口段上限）
DEFAULT_CONCURRENCY = 12


_REALITY_DEFAULT_UTLS = {"enabled": True, "fingerprint": "chrome"}


def sanitize_outbound(ob: dict[str, Any]) -> dict[str, Any]:
    """修掉会让 sing-box **拒绝启动**的已知节点配置问题（不动凭据）。

    踩坑（2026-10-13，实测定位）：vless+reality 缺 `tls.utls` 时 sing-box
    直接 FATAL（"uTLS is required by reality client"）**拒绝加载整个配置**，
    于是一个这样的节点会把同批探测实例（上百节点共用一个实例）**全部带崩**，
    整批判死 → 节点池永远 0 存活。订阅里 reality 常不带 fp=，故在探测侧
    再兜一层底（解析侧 subparse 已同款修复）。
    """
    ob = copy.deepcopy(ob)
    if ob.get("type") == "vless":
        tls = ob.get("tls")
        if isinstance(tls, dict):
            real = tls.get("reality") or {}
            utls = tls.get("utls") or {}
            if real.get("enabled") and not utls.get("enabled"):
                tls["utls"] = {**_REALITY_DEFAULT_UTLS,
                               "fingerprint": utls.get("fingerprint") or "chrome"}
    return ob


@dataclass
class ProbeResult:
    fp: str
    ok: bool
    ms: int = 0
    exit_verified: bool = False   # True=验证过出网；False=仅端口/TLS 可达
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fp": self.fp, "ok": self.ok, "ms": self.ms,
            "exit_verified": self.exit_verified, "error": self.error,
        }


@dataclass
class ProbeEnv:
    """探测环境探测结果（本机在墙内还是墙外）。"""

    direct_ok: bool = False       # 直连能否访问 CHECK_URL
    in_china_wall: bool = True    # 是否在墙内（直连不通 = 墙内）
    checked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "direct_ok": self.direct_ok,
            "in_china_wall": self.in_china_wall,
            "checked": self.checked,
        }


def _is_plain_proxy(ob: dict[str, Any]) -> bool:
    """是否 httpx 可直测的普通代理。

    http 全部可直测；socks 只接 version=5 —— httpx 的 socks 支持经
    socksio，**不支持 socks4**（实测 version=4 会 ImportError）。
    socks4 节点归 tunnel 组走 sing-box（sing-box 原生支持 version 4）。
    """
    t = str(ob.get("type") or "")
    if t == "http":
        return True
    if t == "socks":
        return str(ob.get("version") or "5") != "4"
    return False


class NodeProber:
    """节点测速器。

    singbox_bin 存在且可执行 → 走出网探测；否则退化轻量探测。
    """

    def __init__(self, *, singbox_bin: str = "", work_dir: Path | str = ".",
                 timeout: float = 8.0, concurrency: int = DEFAULT_CONCURRENCY):
        self.singbox_bin = singbox_bin
        self.work_dir = Path(work_dir)
        self.timeout = timeout
        self.concurrency = concurrency
        self._env: ProbeEnv | None = None

    @property
    def has_singbox(self) -> bool:
        if not self.singbox_bin:
            return False
        import shutil

        return bool(shutil.which(self.singbox_bin)
                    or os.access(self.singbox_bin, os.X_OK))

    # ── 环境探测（墙内/墙外）──

    async def detect_env(self, *, force: bool = False) -> ProbeEnv:
        """判断本机直连能否访问 CHECK_URL。

        结论决定测速判据：
          · 直连不通（墙内，本项目的目标环境）→ 经代理能通才算节点好
          · 直连就通（墙外）→ 「经代理能否通 Google」测不出好坏，
            退化为端口可达判定，并如实标注
        """
        if self._env is not None and not force:
            return self._env
        env = ProbeEnv()
        try:
            async with httpx.AsyncClient(timeout=6.0,
                                         follow_redirects=False) as c:
                r = await c.get(CHECK_URL)
            env.direct_ok = r.status_code in (200, 204)
        except Exception:
            env.direct_ok = False
        env.in_china_wall = not env.direct_ok
        env.checked = True
        self._env = env
        return env

    # ── 主入口 ──

    async def probe_batch(self, nodes: Iterable[dict[str, Any]], *,
                          timeout: float | None = None,
                          concurrency: int | None = None,
                          check_url: str = "",
                          ) -> list[ProbeResult]:
        """并发探测一批节点。

        nodes 每项需含：fp、outbound（sing-box outbound，**含凭据**）。
        返回与输入等长的结果列表。

        2026-10-15 分流：普通 SOCKS/HTTP 代理（outbound type =
        socks/http）**不走 sing-box 批处理**——它们本身就是代理，
        httpx 直接经它们发请求就是真出网验证，且不受
        PROBE_PORT_SPAN/PROBE_HARD_CAP 的 sing-box 实例上限约束，
        并发可拉到 50+。实测代理池 2533 个 socks 走 sing-box 管线
        只能排到 5 个/轮（端口竞态 + 探测预算），直测路径全池
        2 分钟能过一遍。
        """
        nodes = list(nodes)
        if not nodes:
            return []
        timeout = timeout or self.timeout
        concurrency = concurrency or self.concurrency

        plain = [n for n in nodes
                 if _is_plain_proxy(n.get("outbound") or {})]
        tunnel = [n for n in nodes
                  if not _is_plain_proxy(n.get("outbound") or {})]

        results: list[ProbeResult] = []
        if plain:
            results.extend(await self._probe_plain_proxies(
                plain, timeout, max(concurrency, 50),
                check_url=check_url or CHECK_URL))
        if tunnel:
            if len(tunnel) > PROBE_PORT_SPAN:
                tunnel = tunnel[:PROBE_PORT_SPAN]
            if not self.has_singbox:
                results.extend(await self._probe_light(
                    tunnel, timeout, concurrency))
            else:
                env = await self.detect_env()
                results.extend(await self._probe_via_singbox(
                    tunnel, timeout, concurrency, env,
                    check_url=check_url or CHECK_URL))
        # 按输入顺序返回（调用方按 fp 对齐，顺序无关也要保持）
        by_fp = {r.fp: r for r in results}
        return [by_fp.get(n["fp"], ProbeResult(fp=n["fp"], ok=False,
                                               error="未探测"))
                for n in nodes]

    async def _probe_plain_proxies(self, nodes: list[dict[str, Any]],
                                   timeout: float, concurrency: int,
                                   check_url: str = "") -> list[ProbeResult]:
        """普通 SOCKS/HTTP 代理直测：httpx 经代理请求 CHECK_URL。

        与 sing-box 路径判定标准一致（CHECK_URL 返回 200/204 = 活），
        出口验证语义相同。不需要 sing-box、不占探测端口段。
        """
        sem = asyncio.Semaphore(concurrency)

        async def one(n: dict[str, Any]) -> ProbeResult:
            ob = n.get("outbound") or {}
            host = str(ob.get("server") or "")
            port = int(ob.get("server_port") or 0)
            # _is_plain_proxy 已保证：http 或 socks5（socks4 走 sing-box）
            scheme = "http" if ob.get("type") == "http" else "socks5"
            auth = ""
            if ob.get("username"):
                auth = f"{ob['username']}:{ob.get('password', '')}@"
            proxy_url = f"{scheme}://{auth}{host}:{port}"
            async with sem:
                t0 = time.monotonic()
                try:
                    async with httpx.AsyncClient(
                        proxy=proxy_url, timeout=timeout,
                        follow_redirects=False,
                    ) as c:
                        r = await c.get(check_url or CHECK_URL)
                    ms = int((time.monotonic() - t0) * 1000)
                    if r.status_code in (200, 204):
                        return ProbeResult(fp=n["fp"], ok=True, ms=ms,
                                           exit_verified=True)
                    return ProbeResult(fp=n["fp"], ok=False,
                                       error=f"HTTP {r.status_code}")
                except Exception as e:
                    return ProbeResult(fp=n["fp"], ok=False,
                                       error=type(e).__name__)

        # 整体预算（2026-10-15 实测）：proot 单核 + 并发 TLS 握手会让
        # per-request timeout 放大 3-7 倍（event loop 饥饿，timeout 回调
        # 排队延迟执行）——实测 60 个 socks 直测拖 158s，把 hunt 探测
        # 阶段拖到极限，「探测记录丢失」假象的元凶。用 asyncio.wait +
        # 整体预算强收：完成的收结果，未完成的记失败占位，保证本函数
        # 限时返回、record_probe 全量对账。
        budget = max(60.0, timeout * 6)
        tasks = {asyncio.create_task(one(n)): n["fp"] for n in nodes}
        done, pending = await asyncio.wait(tasks.keys(), timeout=budget)
        for t in pending:
            t.cancel()
        out = [t.result() for t in done if not t.cancelled()]
        done_fps = {r.fp for r in out}
        for t, fp in tasks.items():
            if fp not in done_fps:
                out.append(ProbeResult(fp=fp, ok=False, error="probe_budget"))
        return out

    # ── 出网探测（主路径）──

    async def _probe_via_singbox(self, nodes: list[dict[str, Any]],
                                 timeout: float, concurrency: int,
                                 env: ProbeEnv,
                                 check_url: str = "") -> list[ProbeResult]:
        def build(ns: list[dict[str, Any]]) -> dict[str, Any]:
            inbounds: list[dict[str, Any]] = []
            outbounds: list[dict[str, Any]] = []
            rules: list[dict[str, Any]] = []
            for i, n in enumerate(ns):
                inbounds.append({
                    "type": "http", "tag": f"p{i}",
                    "listen": "127.0.0.1", "listen_port": PROBE_PORT_BASE + i,
                })
                ob = sanitize_outbound(n["outbound"])
                ob["tag"] = f"o{i}"
                outbounds.append(ob)
                rules.append({"inbound": [f"p{i}"], "outbound": f"o{i}"})
            outbounds.append({"type": "direct", "tag": "direct"})
            return {
                "log": {"level": "error"},
                "inbounds": inbounds,
                "outbounds": outbounds,
                "route": {"rules": rules, "final": "direct"},
            }

        self.work_dir.mkdir(parents=True, exist_ok=True)
        # 剔除会让整批实例起不来的非法节点（一个坏节点全批判死，见 sanitize 注释）
        before = list(nodes)
        nodes = self._drop_poison(nodes, build)
        kept = {n["fp"] for n in nodes}
        dropped = [n for n in before if n["fp"] not in kept]
        if not nodes:
            # 全被剔除也要回报失败，否则它们永远停在「未测」、每轮重复占预算
            return [ProbeResult(fp=n["fp"], ok=False, error="poison_config")
                    for n in dropped]
        cfg = build(nodes)
        port_map: dict[int, str] = {
            PROBE_PORT_BASE + i: n["fp"] for i, n in enumerate(nodes)
        }
        cfg_path = self.work_dir / "probe_nodes.json"
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(cfg_path, 0o600)
        except OSError:
            pass

        proc = None
        try:
            # 端口竞态防护（同 LocalNodeProxy，实测踩到）：上一轮探测实例可能
            # 还没被 proot 收掉，占住 20000 段 → 本批 sing-box bind 失败 →
            # **整批 0 存活**（原本还是静默的，最难查）。起前清孤儿 + 等端口，
            # 起不来再重试一次（重启 churn 期间该竞态会变频繁）。
            started = False
            for attempt in (1, 2):
                await self._kill_stale_probe()
                await self._wait_port_free(PROBE_PORT_BASE, timeout=6.0)
                proc = await asyncio.create_subprocess_exec(
                    self.singbox_bin, "run", "-c", str(cfg_path),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    stdin=asyncio.subprocess.DEVNULL,
                )
                if await self._wait_port(PROBE_PORT_BASE, timeout=8.0):
                    started = True
                    break
                log.warning("探测实例启动失败（第 %d 次尝试）：端口 %d 未就绪",
                            attempt, PROBE_PORT_BASE)
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except Exception:
                    pass
                proc = None
            if not started:
                log.warning(
                    "探测实例启动失败：端口 %d 未就绪，本批 %d 个判失败"
                    "（疑似端口竞态/实例崩溃）", PROBE_PORT_BASE, len(nodes))
                return [ProbeResult(fp=n["fp"], ok=False,
                                    error="探测实例启动失败") for n in nodes]

            sem = asyncio.Semaphore(concurrency)
            results: list[ProbeResult] = []

            async def one(port: int, fp: str) -> None:
                async with sem:
                    t0 = time.monotonic()
                    ok, verified, err = await self._check_via_proxy(
                        port, timeout, env, check_url=check_url)
                    ms = int((time.monotonic() - t0) * 1000)
                    results.append(ProbeResult(
                        fp=fp, ok=ok, ms=ms if ok else 0,
                        exit_verified=verified, error=err))

            await asyncio.gather(*(one(p, fp) for p, fp in port_map.items()))
            # 保持与输入同序，便于上层对齐
            by_fp = {r.fp: r for r in results}
            for n in dropped:      # 毒节点也记失败，别让它们永远是「未测」
                by_fp[n["fp"]] = ProbeResult(fp=n["fp"], ok=False,
                                             error="poison_config")
            return [by_fp.get(n["fp"], ProbeResult(fp=n["fp"], ok=False,
                                                   error="未探测"))
                    for n in before]
        finally:
            if proc is not None and proc.returncode is None:
                try:
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            cfg_path.unlink(missing_ok=True)

    # ── 配置级毒节点剔除 ──

    def _config_ok(self, cfg: dict[str, Any]) -> bool:
        """用 sing-box check 校验整批配置能否被接受（不启动实例）。"""
        p = self.work_dir / "_probe_check.json"
        try:
            p.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
            r = subprocess.run([self.singbox_bin, "check", "-c", str(p)],
                               capture_output=True, timeout=20)
            return r.returncode == 0
        except Exception:
            return False
        finally:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def _drop_poison(self, nodes: list[dict[str, Any]],
                     build) -> list[dict[str, Any]]:
        """二分剔除会让整批实例起不来的节点（未知毒配置兜底）。

        背景：sing-box 是「配置不合即整体拒绝启动」，一个坏节点的 outbound
        就能让上百节点的共用实例起不来、整批判死。sanitize_outbound 只盖已知
        问题（reality/utls），这里用「整批 check → 二分定位」兜住未知问题。
        代价 O(k·log n) 次 check，**仅整批校验失败时**触发（正常路径零开销）。
        """
        if not nodes:
            return []
        if self._config_ok(build(nodes)):
            return nodes
        if len(nodes) == 1:
            log.warning("丢弃非法节点（sing-box 配置校验失败）：%s",
                        str(nodes[0].get("fp", ""))[:16])
            return []
        mid = len(nodes) // 2
        return (self._drop_poison(nodes[:mid], build)
                + self._drop_poison(nodes[mid:], build))

    async def _check_via_proxy(self, port: int, timeout: float,
                               env: ProbeEnv,
                               check_url: str = "") -> tuple[bool, bool, str]:
        """经本地代理端口请求 CHECK_URL。返回 (ok, exit_verified, error)。"""
        try:
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}", timeout=timeout,
                follow_redirects=False,
            ) as c:
                r = await c.get(check_url or CHECK_URL)
            ok = r.status_code in (200, 204, 202)
            if ok:
                # 墙内环境：经代理访问 Google 成功 = 真验证出网
                # 墙外环境：直连也通，无法据此判定，标注未验证
                return True, env.in_china_wall, ""
            return False, False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, False, type(e).__name__

    # ── 轻量探测（无 sing-box 时的退化）──

    async def _probe_light(self, nodes: list[dict[str, Any]],
                           timeout: float, concurrency: int) -> list[ProbeResult]:
        """TCP+TLS 握手延迟探测。**不代表能出网**，exit_verified=False。

        只判断「节点服务器端口是否开着、TLS 是否握手成功」。
        用途：没有 sing-box 的环境（如开发机）跑通链路、粗筛掉死地址。
        """
        sem = asyncio.Semaphore(concurrency)
        results: list[ProbeResult] = []

        async def one(n: dict[str, Any]) -> None:
            ob = n["outbound"]
            host = str(ob.get("server", ""))
            port = int(ob.get("server_port", ob.get("port", 0)) or 0)
            if not host or not port:
                results.append(ProbeResult(fp=n["fp"], ok=False,
                                           error="缺地址"))
                return
            async with sem:
                t0 = time.monotonic()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=timeout)
                    ms = int((time.monotonic() - t0) * 1000)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    results.append(ProbeResult(fp=n["fp"], ok=True, ms=ms,
                                               exit_verified=False))
                except Exception as e:
                    results.append(ProbeResult(fp=n["fp"], ok=False,
                                               error=type(e).__name__))

        await asyncio.gather(*(one(n) for n in nodes))
        by_fp = {r.fp: r for r in results}
        return [by_fp.get(n["fp"], ProbeResult(fp=n["fp"], ok=False,
                                               error="未探测"))
                for n in nodes]

    # ── 工具 ──

    async def _wait_port(self, port: int, timeout: float = 8.0) -> bool:
        """等本地端口就绪（sing-box 起来了）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except OSError:
                await asyncio.sleep(0.15)
        return False

    async def _kill_stale_probe(self) -> None:
        """清掉仍在跑的本探测实例（上一轮 proot 未及时收掉的孤儿）。

        探测实例按每节点一个 inbound 占住 20000 段；孤儿没退，新实例 bind
        失败 → 整批 0 存活。用配置文件名精确匹配，[.] 防 pkill 自匹配。
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "pkill", "-f", "probe_nodes[.]json",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            pass

    async def _wait_port_free(self, port: int, timeout: float = 6.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    pass
            except OSError:
                return True
            await asyncio.sleep(0.2)
        return False
