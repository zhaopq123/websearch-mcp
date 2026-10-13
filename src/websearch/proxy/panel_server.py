"""管理面板入口 —— 独立进程，与搜索服务解耦。

为什么独立进程而不是塞进 websearch 服务：
  1. **故障隔离** —— 面板崩了不影响搜索；代理重启不影响面板。
  2. **权限隔离** —— 面板持有订阅凭据，搜索服务不需要它。
     搜索服务只被告知一个本地代理地址（127.0.0.1:17890），
     这样「搜索服务」这个更暴露的组件不接触任何凭据。
  3. **可独立重启** —— 换订阅时只重启面板侧的代理，搜索服务无感。

启动：
    python -m websearch.proxy.panel_server
环境变量：
    WS_PANEL_HOST   默认 127.0.0.1（只回环；局域网访问需显式改且必须有口令）
    WS_PANEL_PORT   默认 8500
    WS_CONFIG_FILE  默认 /opt/websearch-mcp/.env
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

log = logging.getLogger("websearch.panel")


def setup_logging(level: str = "info") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


async def _auto_start_proxy(store, manager) -> None:
    """按配置自动拉起代理（可选）。失败只记日志，不影响面板启动。"""
    if not store.get_bool("WS_PROXY_AUTO_START", True):
        log.info("未启用自动启动代理（WS_PROXY_AUTO_START=0）")
        return
    url = store.get("WS_SUBSCRIPTION_URL", "")
    if not url:
        log.info("尚未配置订阅，代理未启动（可在面板里配置）")
        return
    from .subparse import SubscriptionError

    try:
        result = await manager.start_from_subscription(url)
        if result.get("ok"):
            s = result.get("summary", {})
            log.info("代理自动启动成功：%d 个节点 %s",
                     s.get("parsed", 0), s.get("by_protocol", {}))
            state = await manager.health_check()
            log.info("健康检查：%s", "可出网" if state.get("healthy") else
                     f"不可用（{state.get('last_error','')}）")
        else:
            log.warning("代理自动启动失败：%s", result.get("error", "unknown"))
    except SubscriptionError as e:
        # subparse 保证消息里不含订阅 URL
        log.warning("拉取订阅失败：%s", e)
    except Exception as e:
        log.warning("代理自动启动异常：%s", type(e).__name__)


async def _health_loop(store, manager, stop_event: asyncio.Event) -> None:
    """后台健康检查循环。代理挂了要能及时发现。"""
    while not stop_event.is_set():
        interval = max(60, store.get_int("WS_PROXY_HEALTH_INTERVAL", 300))
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            return   # 收到停止信号
        except asyncio.TimeoutError:
            pass
        if not manager.state.running:
            continue
        try:
            state = await manager.health_check()
            if not state.get("healthy"):
                log.warning("代理健康检查失败：%s", state.get("last_error", ""))
        except Exception as e:
            log.warning("健康检查异常：%s", type(e).__name__)


def _detect_lan_ip() -> str:
    """探测本机在局域网里的 IP。

    用一个连向公网地址的 UDP socket 拿到「出口网卡」的 IP ——
    UDP 不真正发包，只是让内核选出路由，所以不需要网络可达。
    比解析 `hostname -I` / 遍历网卡可靠得多（容器里常有多个虚拟网卡）。
    """
    import socket

    for target in (("8.8.8.8", 80), ("1.1.1.1", 80), ("223.5.5.5", 80)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(target)
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            continue
    return ""


def _print_access_info(store, host: str, port: int) -> None:
    """打印访问方式 —— 尽量让用户「点一下就进去」。

    这是安装体验的关键：不要求用户去 grep 口令、不要求手工建隧道。
    生成一次性登录链接，点开即登录。
    """
    print("═" * 62)
    print(" websearch-mcp 管理面板")
    print()

    # 本机访问地址
    local_url = f"http://127.0.0.1:{port}"

    # 局域网访问地址（面板绑非回环时才有意义）
    lan_ip = _detect_lan_ip()
    lan_url = f"http://{lan_ip}:{port}" if lan_ip else ""

    if host in ("127.0.0.1", "localhost", "::1"):
        # 只绑回环：只有本机能访问
        print(f" ⚠️  面板只监听本机（{host}）")
        print(f"     本机访问:  {local_url}")
        print()
        print("     要从其他设备访问，两种方式：")
        print(f"       A) SSH 端口转发（推荐，面板不暴露）")
        print(f"          ssh -N -L {port}:127.0.0.1:{port} <user>@<服务器>")
        print(f"          然后浏览器开 {local_url}")
        print(f"       B) 改监听地址（面板暴露到局域网，需靠口令保护）")
        print(f"          在 {store.path} 里加：WS_PANEL_HOST=0.0.0.0")
        print(f"          重启面板后即可用 {lan_url or 'http://<服务器IP>:' + str(port)} 访问")
    else:
        # 绑了非回环：可直接访问
        print(f" 访问地址: {lan_url or f'http://{host}:{port}'}")

    # 一键登录链接（免手工复制口令）
    try:
        ticket = store.issue_login_ticket(ttl_sec=300)
        base = lan_url if (host not in ("127.0.0.1", "localhost", "::1") and lan_url) else local_url
        print()
        print(" ┌─ 点这个链接直接进面板（5 分钟内有效，一次性）─────────")
        print(f" │ {base}/_open?t={ticket}")
        print(" └──────────────────────────────────────────────────────")
    except Exception as e:
        log.warning("生成一键登录链接失败：%s", type(e).__name__)

    print()
    print(f" 配置:   {store.path}")
    print(f" 口令:   {store.path} 里的 WS_PANEL_TOKEN（遗失可删该行重新生成）")
    print("═" * 62)


def main() -> None:
    setup_logging(os.environ.get("LOG_LEVEL", "info"))

    from .manager import ProxyManager
    from .panel import build_panel_app
    from .store import Store

    cfg_file = Path(os.environ.get("WS_CONFIG_FILE", "/opt/websearch-mcp/.env"))

    store = Store(cfg_file)

    # ⚠️ 配置读取必须**先 .env 后环境变量**，而不是只读 os.environ。
    # 曾经只读环境变量，导致用户在面板/配置文件里改了监听地址、
    # 重启后毫无变化 —— 用户会认为「程序坏了」。
    # 这是产品级缺陷，不是小事。
    # Store.get() 的优先级：环境变量 > .env > 默认值（运维临时覆盖仍可用）。
    host = store.get("WS_PANEL_HOST", "127.0.0.1")
    port = store.get_int("WS_PANEL_PORT", 8500)

    # ── 启动自检：这些检查失败就不该继续 ──

    # 1) 权限必须 600
    ok, detail = store.check_permissions()
    if not ok:
        log.error("配置目录权限不安全：%s", detail)
        log.error("修复：chmod 600 %s", cfg_file)
        raise SystemExit(2)

    # 2) 必须被 git 忽略（防凭据被提交）
    ignored, note = store.check_gitignored()
    if not ignored:
        log.warning("凭据文件可能未被 git 忽略：%s", note)
        log.warning("请确认 .gitignore 含 .env，否则订阅链接有被提交的风险")

    # 3) 面板口令：不存在就生成并**只打印这一次**
    fresh = store.ensure_panel_token()
    if fresh:
        print("═" * 62)
        print(" 面板口令已生成（只显示这一次，请立即保存到密码管理器）：")
        print(f"   {fresh}")
        print(f" 口令文件：{cfg_file}（600 权限）")
        print(" 遗失后可在服务器上重新生成：删除该文件的 WS_PANEL_TOKEN 行后重启")
        print("═" * 62)

    if not store.get("WS_PANEL_TOKEN", ""):
        log.error("面板口令缺失，拒绝启动（不接受无鉴权的面板）")
        raise SystemExit(2)

    # 4) 绑定非回环必须有口令 —— 这里恒成立（上面已保证），
    #    但显式再拦一次，防止将来有人改动顺序
    if host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("面板绑定到 %s（非回环）——请确认网络环境可信，"
                    "并已在防火墙上限制来源", host)

    manager = ProxyManager(
        workdir=Path(os.environ.get("WS_PROXY_WORKDIR", "/opt/websearch-mcp/proxy-run")),
        singbox_bin=os.environ.get("WS_SINGBOX_BIN", "/opt/sing-box/sing-box"),
        http_port=store.get_int("WS_HTTP_PROXY_PORT", 17890),
        socks_port=store.get_int("WS_SOCKS_PROXY_PORT", 17891),
    )

    app = build_panel_app(store, manager)

    async def on_startup() -> None:
        await _auto_start_proxy(store, manager)

    print(f" 代理:   HTTP 127.0.0.1:{manager.http_port} / SOCKS5 127.0.0.1:{manager.socks_port}")
    print(f" sing-box: {'已找到' if manager.available else '未找到（代理功能不可用）'}")
    # 访问方式（含一键登录链接）—— 这是安装体验的关键，别让用户去 grep 口令
    _print_access_info(store, host, port)

    import uvicorn
    from contextlib import asynccontextmanager

    stop_event = asyncio.Event()

    # ⚠️ 必须加 @asynccontextmanager —— Starlette 的 lifespan_context
    # 要求的是一个「异步上下文管理器」，裸的 async 生成器函数赋给它
    # 会在启动时报 TypeError: 'async_generator' object does not support
    # the asynchronous context manager protocol。
    @asynccontextmanager
    async def lifespan(app):  # type: ignore[no-untyped-def]
        await on_startup()
        task = asyncio.create_task(_health_loop(store, manager, stop_event))
        try:
            yield
        finally:
            stop_event.set()
            task.cancel()
            await manager.stop()

    app.router.lifespan_context = lifespan
    uvicorn.run(app, host=host, port=port,
                log_level=os.environ.get("LOG_LEVEL", "info"),
                timeout_graceful_shutdown=5)


if __name__ == "__main__":
    main()
