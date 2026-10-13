"""代理进程管理 —— sing-box 的生命周期、健康检查、故障降级。

⚠️ 安全约定（红线区，与本包 subparse 同级）：
  1. 订阅 URL、节点凭据**只存在于内存与 600 权限文件**，绝不写日志。
     本模块所有 log 调用都只带「状态/端口/数量」，不带 URL 与凭据。
  2. 生成的 sing-box 配置写 600 权限；目录 700。
  3. 健康检查失败**不抛异常给调用方**，而是返回状态 —— 代理挂了
     不应该让搜索服务一起挂，这是降级设计的关键。

为什么自己管进程而不是用 systemd：
  目标环境是 proot 容器（vivo 手机），**没有 systemd**。
  实测 sing-box 在 proot 下可用，但必须绕过 netlink 订阅
  （见 proxy.json 里不写 auto_detect_interface 的原因）。
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

import httpx

from .subparse import ParseReport, SubscriptionError, build_singbox_config, parse_subscription_text

log = logging.getLogger("websearch.proxy")


@dataclass
class ProxyState:
    """代理运行状态。给面板/工具读，不含任何凭据。"""

    running: bool = False
    pid: int = 0
    http_port: int = 0
    socks_port: int = 0
    node_count: int = 0
    by_protocol: dict[str, int] = field(default_factory=dict)
    started_at: float = 0.0
    last_check_ok: bool = False
    last_check_ms: int = 0
    last_check_at: float = 0.0
    last_error: str = ""
    # 出口 IP 的国家/地区（用来判断代理是否真的生效）
    exit_ip: str = ""
    exit_country: str = ""
    # 最近一次节点探测结果（无凭据，可给面板展示）
    probe_result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "pid": self.pid,
            "http_proxy": f"http://127.0.0.1:{self.http_port}" if self.http_port else "",
            "socks_proxy": f"socks5h://127.0.0.1:{self.socks_port}" if self.socks_port else "",
            "node_count": self.node_count,
            "by_protocol": self.by_protocol,
            "uptime_sec": int(time.time() - self.started_at) if self.started_at else 0,
            "healthy": self.last_check_ok,
            "last_check_ms": self.last_check_ms,
            "last_error": self.last_error,
            "exit_ip": self.exit_ip,
            "exit_country": self.exit_country,
        }


class ProxyManager:
    """sing-box 进程管理器。

    用法：
        pm = ProxyManager(workdir=Path("/opt/websearch-mcp/proxy"))
        await pm.start_from_subscription("https://...")   # 或
        await pm.start_from_text(decoded_text)
        await pm.health_check()
        pm.state.to_dict()
        await pm.stop()
    """

    # 健康检查目标：走墙外、国内直连不通、且响应小
    CHECK_URL = "https://www.google.com/generate_204"
    EXIT_IP_URL = "https://api.ipify.org?format=json"

    def __init__(
        self,
        workdir: Path | str,
        *,
        singbox_bin: str = "/opt/sing-box/sing-box",
        http_port: int = 17890,
        socks_port: int = 17891,
        fetch_timeout: float = 30.0,
    ):
        self.dir = Path(workdir)
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass
        self.singbox_bin = singbox_bin
        self.http_port = http_port
        self.socks_port = socks_port
        self.fetch_timeout = fetch_timeout
        self.cfg_path = self.dir / "singbox.json"
        self.log_path = self.dir / "singbox.log"
        self.state = ProxyState(http_port=http_port, socks_port=socks_port)
        self._proc: asyncio.subprocess.Process | None = None
        self._last_report: ParseReport | None = None
        # 节点探测结果（给面板读；无凭据）
        self.probe_result: dict[str, Any] = {}

    # ── 可用性 ──

    @property
    def available(self) -> bool:
        """sing-box 二进制是否存在且可执行。"""
        return bool(shutil.which(self.singbox_bin) or os.access(self.singbox_bin, os.X_OK))

    def proxy_url(self) -> str:
        """给 httpx 用的代理地址。未运行时返回空串（调用方据此直连）。"""
        return f"http://127.0.0.1:{self.http_port}" if self.state.running else ""

    # ── 订阅拉取 ──

    async def fetch_subscription(self, url: str) -> str:
        """拉取订阅正文。

        ⚠️ 异常信息里**不带 url**（可能含 token）。
        很多机场会按 UA 返回不同格式（clash yaml / base64 / 明文），
        这里统一声明只接受纯文本，让服务端给 base64 或明文节点列表。
        """
        headers = {
            # 声明成常见客户端，避免被当成爬虫；但明确不要 clash 配置
            "User-Agent": "sing-box/1.14.3 (python-httpx)",
            "Accept": "*/*",
        }
        try:
            async with httpx.AsyncClient(timeout=self.fetch_timeout) as c:
                r = await c.get(url, headers=headers, follow_redirects=True)
                r.raise_for_status()
                return r.text
        except httpx.HTTPStatusError as e:
            raise SubscriptionError(
                f"订阅服务器返回 {e.response.status_code}（检查链接是否过期）"
            ) from None
        except httpx.HTTPError as e:
            raise SubscriptionError(f"拉取订阅失败：{type(e).__name__}") from None

    # ── 启停 ──

    async def start_from_text(
        self, text: str, *, replace_running: bool = True
    ) -> dict[str, Any]:
        """从订阅正文（已解码或明文）启动代理。"""
        report = parse_subscription_text(text)
        self._last_report = report
        return await self._start_with_report(report, replace_running=replace_running)

    async def start_from_subscription(self, url: str) -> dict[str, Any]:
        """拉取订阅并启动代理。"""
        text = await self.fetch_subscription(url)
        return await self.start_from_text(text)

    async def _start_with_report(
        self, report: ParseReport, *, replace_running: bool = True
    ) -> dict[str, Any]:
        if not self.available:
            self.state.last_error = f"sing-box 不存在或不可执行：{self.singbox_bin}"
            return {"ok": False, "error": self.state.last_error}

        if replace_running:
            await self.stop()

        cfg = build_singbox_config(
            report,
            http_port=self.http_port,
            socks_port=self.socks_port,
        )
        # 先校验配置再启动，避免起一个必然失败的进程
        ok, err = await self._check_config(cfg)
        if not ok:
            self.state.last_error = f"配置校验失败：{err}"
            return {"ok": False, "error": self.state.last_error, "summary": report.summary()}

        # 写配置：600 权限。含凭据，绝不外泄。
        tmp = self.cfg_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.cfg_path)

        # 启动进程（日志落文件，且文件本身也是 600）
        logf = open(self.log_path, "ab", buffering=0)
        try:
            os.chmod(self.log_path, 0o600)
        except OSError:
            pass
        self._proc = await asyncio.create_subprocess_exec(
            self.singbox_bin, "run", "-c", str(self.cfg_path),
            stdout=logf, stderr=logf, stdin=asyncio.subprocess.DEVNULL,
        )
        self.state.running = True
        self.state.pid = self._proc.pid or 0
        self.state.started_at = time.time()
        self.state.node_count = len(report.nodes)
        self.state.by_protocol = report.summary()["by_protocol"]
        self.state.last_error = ""

        # 等端口就绪（最多 8s）
        ready = await self._wait_port(self.http_port, timeout=8.0)
        if not ready:
            self.state.last_error = "sing-box 启动后端口未监听"
            self.state.running = False
            await self.stop()
            return {"ok": False, "error": self.state.last_error, "summary": report.summary()}

        log.info("代理已启动：节点 %d 个，HTTP 端口 %d",
                 len(report.nodes), self.http_port)
        return {"ok": True, "summary": report.summary(), "state": self.state.to_dict()}

    async def _check_config(self, cfg: dict[str, Any]) -> tuple[bool, str]:
        """用 sing-box check 校验配置。"""
        tmp = self.dir / "check.json"
        tmp.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        try:
            p = await asyncio.create_subprocess_exec(
                self.singbox_bin, "check", "-c", str(tmp),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await asyncio.wait_for(p.communicate(), timeout=15)
            if p.returncode == 0:
                return True, ""
            # 输出可能含配置片段（有凭据），只取第一行的错误关键词
            msg = out.decode("utf-8", "replace").strip().splitlines()
            return False, (msg[0][:160] if msg else "unknown")
        except asyncio.TimeoutError:
            return False, "check 超时"
        except Exception as e:
            return False, type(e).__name__
        finally:
            tmp.unlink(missing_ok=True)

    async def _wait_port(self, port: int, timeout: float = 8.0) -> bool:
        """等端口监听。用 TCP 连接探测，比读日志可靠。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=1.0
                )
                w.close()
                return True
            except Exception:
                await asyncio.sleep(0.25)
        return False

    async def stop(self) -> None:
        """停止代理进程。幂等。"""
        proc = self._proc
        self._proc = None
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            except Exception:
                pass
        self.state.running = False
        self.state.pid = 0

    # ── 健康检查 ──

    async def health_check(self, *, check_exit_ip: bool = True) -> dict[str, Any]:
        """经代理访问墙外站点，验证代理真的生效。

        返回状态字典，**不抛异常** —— 代理挂了要能被上层优雅降级。
        """
        if not self.state.running:
            self.state.last_check_ok = False
            self.state.last_error = "代理未运行"
            return self.state.to_dict()

        proxy = self.proxy_url()
        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(
                proxy=proxy, timeout=12.0, follow_redirects=False
            ) as c:
                r = await c.get(self.CHECK_URL)
                ok = r.status_code in (200, 204)
                self.state.last_check_ms = int((time.monotonic() - t0) * 1000)
                self.state.last_check_at = time.time()
                self.state.last_check_ok = ok
                if not ok:
                    self.state.last_error = f"探测返回 {r.status_code}"
                else:
                    self.state.last_error = ""
                    if check_exit_ip:
                        await self._probe_exit_ip(c)
        except Exception as e:
            self.state.last_check_ok = False
            self.state.last_check_ms = int((time.monotonic() - t0) * 1000)
            self.state.last_check_at = time.time()
            # 只记异常类型，不记 URL
            self.state.last_error = f"探测失败：{type(e).__name__}"
        return self.state.to_dict()

    async def _probe_exit_ip(self, client: httpx.AsyncClient) -> None:
        """查出口 IP。用于确认「代理真的换了出口」而不是假通。"""
        try:
            r = await client.get(self.EXIT_IP_URL, timeout=8.0)
            if r.status_code == 200:
                data = r.json()
                self.state.exit_ip = str(data.get("ip", ""))
                # 顺带用 ip-api 拿国家（失败不影响主流程）
                try:
                    r2 = await client.get(
                        f"http://ip-api.com/json/{self.state.exit_ip}"
                        "?fields=country,countryCode", timeout=6.0
                    )
                    if r2.status_code == 200:
                        d2 = r2.json()
                        self.state.exit_country = (
                            f"{d2.get('country','')} ({d2.get('countryCode','')})"
                        )
                except Exception:
                    pass
        except Exception:
            pass

    # ── 节点切换（为面板预留） ──

    def list_nodes(self) -> list[dict[str, Any]]:
        """列出节点（只给名字与协议，**不给凭据**）。"""
        if not self._last_report:
            return []
        return [
            {"tag": n.tag, "protocol": n.protocol}
            for n in self._last_report.nodes
        ]

    def summary(self) -> dict[str, Any]:
        """给面板的总览（无敏感值）。"""
        return {
            "available": self.available,
            "state": self.state.to_dict(),
            "nodes": self.list_nodes(),
            "probe": self.probe_result,
        }

    # ── 节点探测与自动选择（「自动更新节点」的核心）──

    async def probe_nodes(
        self,
        *,
        timeout: float = 6.0,
        concurrency: int = 8,
        max_probe: int = 30,
    ) -> dict[str, Any]:
        """并发探测每个节点，找出**能真正出网**的那个。

        为什么必须做这一步：机场订阅里常有失效节点、限速节点、
        以及占位条目。不探测就随机选一个的话，用户看到的是
        「代理配了但上不了网」，而真实原因只是**选错了节点**。

        实测踩坑（2026-10-13）：订阅第一个节点 server=0.0.0.0，
        被选成 default 后所有流量发往 0.0.0.0:443 →
        "connect: connection refused"，看起来像「全部节点不通」。

        做法：
          1. 起一个**临时** sing-box 实例，每个节点单独一个 inbound 端口
          2. 并发请求探测目标，看哪个端口能通
          3. 记录延迟，按延迟排序
          4. 返回最快的节点 tag（调用方据此重建正式配置）

        返回（**不含凭据**）：
          {"ok": bool, "best": "节点名", "tested": N,
           "alive": [{"tag","ms"}...], "dead": ["节点名"...],
           "error": "..."}
        """
        if not self._last_report or not self._last_report.nodes:
            return {"ok": False, "error": "没有可用节点（先加载订阅）"}
        if not self.available:
            return {"ok": False, "error": "sing-box 不可用"}

        nodes = self._last_report.nodes[:max_probe]
        base_port = 20000  # 探测用端口段，避开正式端口

        # 为每个节点建一个独立 http inbound，端口递增
        inbounds = []
        port_map: dict[int, str] = {}
        for i, n in enumerate(nodes):
            p = base_port + i
            port_map[p] = n.tag
            inbounds.append({
                "type": "http", "tag": f"probe-{i}",
                "listen": "127.0.0.1", "listen_port": p,
            })

        outbounds = [n.to_outbound() for n in nodes]
        outbounds.append({"type": "direct", "tag": "direct"})

        # 每个节点一个 route rule：把该端口的流量导向该节点
        rules = []
        for i, n in enumerate(nodes):
            rules.append({
                "inbound": [f"probe-{i}"],
                "outbound": n.tag,
            })

        cfg = {
            "log": {"level": "error"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": {"rules": rules, "final": "direct"},
        }

        probe_cfg = self.dir / "probe.json"
        probe_cfg.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        try:
            os.chmod(probe_cfg, 0o600)
        except OSError:
            pass

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                self.singbox_bin, "run", "-c", str(probe_cfg),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL,
            )
            # 等第一个端口就绪（说明 sing-box 起来了）
            if not await self._wait_port(base_port, timeout=8.0):
                return {"ok": False, "error": "探测实例启动失败（端口未监听）"}

            sem = asyncio.Semaphore(concurrency)
            results: list[dict[str, Any]] = []

            async def one(port: int, tag: str) -> None:
                async with sem:
                    t0 = time.monotonic()
                    try:
                        async with httpx.AsyncClient(
                            proxy=f"http://127.0.0.1:{port}", timeout=timeout,
                            follow_redirects=False,
                        ) as c:
                            r = await c.get(self.CHECK_URL)
                            ok = r.status_code in (200, 204)
                    except Exception:
                        ok = False
                    ms = int((time.monotonic() - t0) * 1000)
                    results.append({"tag": tag, "ok": ok, "ms": ms})

            await asyncio.gather(*(one(p, t) for p, t in port_map.items()))
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
            probe_cfg.unlink(missing_ok=True)

        alive = sorted(
            ({"tag": r["tag"], "ms": r["ms"]} for r in results if r["ok"]),
            key=lambda x: x["ms"],
        )
        dead = [r["tag"] for r in results if not r["ok"]]
        best = alive[0]["tag"] if alive else ""

        self.probe_result = {
            "tested": len(results),
            "alive_count": len(alive),
            "dead_count": len(dead),
            "best": best,
            "best_ms": alive[0]["ms"] if alive else 0,
            "alive": alive[:10],       # 只留前 10（面板够用）
            "at": time.time(),
        }
        log.info("节点探测完成：%d 个可用 / %d 个测试，最快 %s (%dms)",
                 len(alive), len(results), best or "无",
                 alive[0]["ms"] if alive else 0)

        return {
            "ok": bool(alive),
            "best": best,
            "tested": len(results),
            "alive": alive,
            "dead": dead,
            "error": "" if alive else "所有节点都无法访问外网（可能全部失效或订阅过期）",
        }

    async def start_from_subscription_auto(self, url: str) -> dict[str, Any]:
        """拉订阅 → 解析 → **探测节点** → 用最快的节点启动。

        这是「自动更新节点」的完整流程：
        用户只需点一次，服务自己找可用节点，不需要用户逐个试。
        """
        text = await self.fetch_subscription(url)
        report = parse_subscription_text(text)
        self._last_report = report

        if not report.nodes:
            return {
                "ok": False,
                "error": "订阅里没有可用节点",
                "summary": report.summary(),
            }

        # 先用第一个节点起一个临时实例做探测
        # （探测需要 sing-box 在跑；用第一个节点起正式配置即可，
        #   探测会为每个节点开独立端口，不依赖默认选择）
        first = await self._start_with_report(report, replace_running=True)
        if not first.get("ok"):
            return first

        probe = await self.probe_nodes()
        if not probe.get("ok"):
            # 探测全失败：保留已启动的实例（至少端口在听），如实报告
            return {
                "ok": False,
                "error": probe.get("error", "节点探测失败"),
                "summary": report.summary(),
                "probe": probe,
            }

        # 用探测出的最快节点重启（default_tag 换成它）
        best = probe["best"]
        if best and best != report.nodes[0].tag:
            cfg = build_singbox_config(
                report, http_port=self.http_port, socks_port=self.socks_port,
                default_tag=best,
            )
            ok, err = await self._check_config(cfg)
            if ok:
                await self._write_and_restart(cfg, report)
                log.info("已自动切换到最快节点：%s", best)

        return {
            "ok": True,
            "summary": report.summary(),
            "probe": probe,
            "state": self.state.to_dict(),
        }

    async def _write_and_restart(self, cfg: dict[str, Any], report: ParseReport) -> None:
        """写入配置并重启进程（探测完切节点时用）。"""
        await self.stop()
        tmp = self.cfg_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.cfg_path)

        logf = open(self.log_path, "ab", buffering=0)
        try:
            os.chmod(self.log_path, 0o600)
        except OSError:
            pass
        self._proc = await asyncio.create_subprocess_exec(
            self.singbox_bin, "run", "-c", str(self.cfg_path),
            stdout=logf, stderr=logf, stdin=asyncio.subprocess.DEVNULL,
        )
        self.state.running = True
        self.state.pid = self._proc.pid or 0
        self.state.started_at = time.time()
        self.state.node_count = len(report.nodes)
        self.state.by_protocol = report.summary()["by_protocol"]
        self.state.last_error = ""
        await self._wait_port(self.http_port, timeout=8.0)
