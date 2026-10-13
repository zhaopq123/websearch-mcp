# -*- coding: utf-8 -*-
"""本地节点代理 —— 用节点库的最优节点，服务自己起一个 sing-box。

这是「**用户不需要绑定自己的节点**」的落地：
  · 用户没配任何订阅/代理时，本模块用节点库（系统自养）里实测最优的
    免费节点，在服务进程内起一个 sing-box 实例（独立端口），
    HttpPool 走它出网 —— 开箱即用，零配置。
  · 用户配了自己的代理时，尊重用户的（本模块不启动，避免抢端口）。

与面板的 ProxyManager 的区别：
  · ProxyManager 管的是「用户订阅 → sing-box」，跑在**面板进程**，
    面向用户自配；
  · 本模块管的是「节点库最优节点 → sing-box」，跑在**服务进程**，
    面向无人值守的自动出网。两者端口不同，互不干扰。

⚠️ 安全：配置含节点凭据 → 600 权限、不进日志、不进 git。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("websearch.nodes.local_proxy")


@dataclass
class LocalProxyState:
    """本地节点代理状态（无凭据）。"""

    running: bool = False
    pid: int = 0
    http_port: int = 0
    socks_port: int = 0
    node_fp: str = ""
    node_desc: str = ""
    started_at: float = 0.0
    switches: int = 0
    last_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "http_proxy": (f"http://127.0.0.1:{self.http_port}"
                           if self.running else ""),
            "node_fp": self.node_fp,
            "node_desc": self.node_desc,
            "started_at": self.started_at,
            "switches": self.switches,
            "last_error": self.last_error,
        }


class LocalNodeProxy:
    """用节点库最优节点自养的本地 sing-box。"""

    def __init__(self, *, singbox_bin: str, work_dir: Path | str,
                 http_port: int = 17892, socks_port: int = 17893):
        self.singbox_bin = singbox_bin
        self.work_dir = Path(work_dir)
        self.http_port = http_port
        self.socks_port = socks_port
        self.state = LocalProxyState(http_port=http_port, socks_port=socks_port)
        self._proc: asyncio.subprocess.Process | None = None
        self._cfg_path = self.work_dir / "node_proxy.json"
        self._log_path = self.work_dir / "node_proxy.log"
        self._lock = asyncio.Lock()

    @property
    def available(self) -> bool:
        if not self.singbox_bin:
            return False
        return bool(shutil.which(self.singbox_bin)
                    or os.access(self.singbox_bin, os.X_OK))

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    # ── 启停 ──

    async def ensure_running(self, outbound: dict[str, Any],
                             desc: str = "") -> dict[str, Any]:
        """用给定节点确保 sing-box 在跑（已在跑且节点相同则不动）。"""
        if not self.available:
            self.state.last_error = "sing-box 不可用"
            return {"ok": False, "error": "sing-box 不存在或不可执行"}
        fp = str(outbound.get("tag") or "")
        if self.state.running and self.state.node_fp == fp:
            return {"ok": True, "already": True, "state": self.state.to_dict()}
        return await self.switch_to(outbound, desc=desc)

    async def switch_to(self, outbound: dict[str, Any],
                        desc: str = "") -> bool:
        """切换到指定节点（重启 sing-box）。返回是否成功。"""
        async with self._lock:
            if not self.available:
                self.state.last_error = "sing-box 不可用"
                return False
            ok = await self._restart_with(outbound, desc)
            return ok

    async def _restart_with(self, outbound: dict[str, Any], desc: str) -> bool:
        from ..proxy.subparse import Node, ParseReport, build_singbox_config

        tag = str(outbound.get("tag") or "node")
        node = Node(tag=tag, protocol=str(outbound.get("type") or "?"),
                    outbound={k: v for k, v in outbound.items() if k != "tag"})
        report = ParseReport(nodes=[node])
        cfg = build_singbox_config(
            report, http_port=self.http_port, socks_port=self.socks_port,
            listen="127.0.0.1", log_level="warn", default_tag=tag,
        )

        self.work_dir.mkdir(parents=True, exist_ok=True)
        # 先校验配置（sing-box check），避免用坏配置把进程起崩
        tmp = self._cfg_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2),
                       encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        if not await self._check_config(tmp):
            self.state.last_error = "sing-box 配置校验失败"
            tmp.unlink(missing_ok=True)
            log.warning("本地节点代理配置校验失败（节点 %s）", tag[:32])
            return False
        tmp.replace(self._cfg_path)

        # 端口竞态防护（实测踩到）：服务重启时旧实例的 sing-box 可能还没被
        # proot 收掉，端口仍被占用 → 新实例 bind 失败 → **静默掉回直连**。
        # 起前先清孤儿、等端口释放；起不来再重试一次，别静默失败。
        for attempt in (1, 2):
            await self._kill()
            await self._kill_stale()
            await self._wait_port_free(self.http_port, timeout=8.0)
            logf = open(self._log_path, "ab", buffering=0)
            try:
                os.chmod(self._log_path, 0o600)
            except OSError:
                pass
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    self.singbox_bin, "run", "-c", str(self._cfg_path),
                    stdout=logf, stderr=logf, stdin=asyncio.subprocess.DEVNULL,
                )
            except Exception as e:
                self.state.last_error = f"启动失败: {type(e).__name__}"
                return False
            finally:
                try:
                    logf.close()
                except Exception:
                    pass

            ready = await self._wait_port(self.http_port, timeout=8.0)
            if ready:
                self.state.running = True
                self.state.pid = self._proc.pid or 0
                self.state.node_fp = tag
                self.state.node_desc = desc or tag[:40]
                self.state.started_at = time.time()
                self.state.switches += 1
                self.state.last_error = ""
                log.info("本地节点代理已启动：%s（端口 %d）",
                         self.state.node_desc, self.http_port)
                return True
            log.warning("本地节点代理启动后端口未就绪（第 %d 次尝试）", attempt)

        self.state.running = False
        self.state.last_error = "端口未监听（sing-box 启动失败）"
        log.warning("本地节点代理启动失败（已重试）")
        return False

    async def _kill_stale(self) -> None:
        """清掉仍在跑的本代理 sing-box（含上一服务实例遗留的孤儿）。

        用配置路径精确匹配，[.] 转义防 pkill 自匹配（本仓库踩过一次）。
        误伤面：仅匹配命令行含本代理配置路径的进程，不碰别的服务。
        """
        pat = str(self._cfg_path).replace(".", "[.]")
        try:
            proc = await asyncio.create_subprocess_exec(
                "pkill", "-f", pat,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            pass

    async def _wait_port_free(self, port: int, timeout: float = 8.0) -> bool:
        import socket

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    pass                     # 仍有人在监听
            except OSError:
                return True                  # 端口已释放
            await asyncio.sleep(0.2)
        return False

    async def stop(self) -> None:
        await self._kill()
        self.state.running = False
        self.state.node_fp = ""
        self.state.node_desc = ""

    async def _kill(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None

    async def _check_config(self, path: Path) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.singbox_bin, "check", "-c", str(path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            rc = await asyncio.wait_for(proc.wait(), timeout=10)
            return rc == 0
        except Exception:
            return False

    async def _wait_port(self, port: int, timeout: float = 8.0) -> bool:
        import socket

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except OSError:
                await asyncio.sleep(0.15)
        return False

    def status(self) -> dict[str, Any]:
        st = self.state.to_dict()
        st["available"] = self.available
        return st
