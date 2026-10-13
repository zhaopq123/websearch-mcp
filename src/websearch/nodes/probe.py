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
import json
import logging
import os
import socket
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
                          ) -> list[ProbeResult]:
        """并发探测一批节点。

        nodes 每项需含：fp、outbound（sing-box outbound，**含凭据**）。
        返回与输入等长的结果列表。
        """
        nodes = list(nodes)
        if not nodes:
            return []
        if len(nodes) > PROBE_PORT_SPAN:
            nodes = nodes[:PROBE_PORT_SPAN]
        timeout = timeout or self.timeout
        concurrency = concurrency or self.concurrency

        if not self.has_singbox:
            # 退化：没有 sing-box 就没法做真出网验证，只能测 TCP/TLS
            return await self._probe_light(nodes, timeout, concurrency)

        env = await self.detect_env()
        return await self._probe_via_singbox(nodes, timeout, concurrency, env)

    # ── 出网探测（主路径）──

    async def _probe_via_singbox(self, nodes: list[dict[str, Any]],
                                 timeout: float, concurrency: int,
                                 env: ProbeEnv) -> list[ProbeResult]:
        inbounds: list[dict[str, Any]] = []
        port_map: dict[int, str] = {}          # port -> fp
        outbounds: list[dict[str, Any]] = []
        rules: list[dict[str, Any]] = []
        for i, n in enumerate(nodes):
            p = PROBE_PORT_BASE + i
            port_map[p] = n["fp"]
            inbounds.append({
                "type": "http", "tag": f"p{i}",
                "listen": "127.0.0.1", "listen_port": p,
            })
            ob = dict(n["outbound"])
            ob["tag"] = f"o{i}"
            outbounds.append(ob)
            rules.append({"inbound": [f"p{i}"], "outbound": f"o{i}"})
        outbounds.append({"type": "direct", "tag": "direct"})

        cfg = {
            "log": {"level": "error"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules, "final": "direct"},
        }
        self.work_dir.mkdir(parents=True, exist_ok=True)
        cfg_path = self.work_dir / "probe_nodes.json"
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(cfg_path, 0o600)
        except OSError:
            pass

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.singbox_bin, "run", "-c", str(cfg_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL,
            )
            if not await self._wait_port(PROBE_PORT_BASE, timeout=8.0):
                return [ProbeResult(fp=n["fp"], ok=False,
                                    error="探测实例启动失败") for n in nodes]

            sem = asyncio.Semaphore(concurrency)
            results: list[ProbeResult] = []

            async def one(port: int, fp: str) -> None:
                async with sem:
                    t0 = time.monotonic()
                    ok, verified, err = await self._check_via_proxy(port, timeout, env)
                    ms = int((time.monotonic() - t0) * 1000)
                    results.append(ProbeResult(
                        fp=fp, ok=ok, ms=ms if ok else 0,
                        exit_verified=verified, error=err))

            await asyncio.gather(*(one(p, fp) for p, fp in port_map.items()))
            # 保持与输入同序，便于上层对齐
            by_fp = {r.fp: r for r in results}
            return [by_fp.get(n["fp"], ProbeResult(fp=n["fp"], ok=False,
                                                   error="未探测"))
                    for n in nodes]
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

    async def _check_via_proxy(self, port: int, timeout: float,
                               env: ProbeEnv) -> tuple[bool, bool, str]:
        """经本地代理端口请求 CHECK_URL。返回 (ok, exit_verified, error)。"""
        try:
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}", timeout=timeout,
                follow_redirects=False,
            ) as c:
                r = await c.get(CHECK_URL)
            ok = r.status_code in (200, 204)
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
