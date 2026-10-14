"""管理面板 —— 用户自助配置代理，凭据只在自己浏览器与服务器之间流动。

⚠️ 安全设计（本模块是唯一对外暴露的写入口，逐条都是刻意的）：

  1. **强制鉴权**：面板口令不存在就拒绝启动。绑非回环地址而没口令时
     直接 SystemExit，与 websearch 服务同规格 —— 不接受静默裸奔。
  2. **不回显凭据**：GET /api/config 只返回掩码与 host，永远不回传
     订阅链接原文。前端拿到的东西截图分享也不会泄密。
  3. **只接受白名单键**：写配置走 store 的白名单，面板被攻破也不能
     借此注入任意环境变量。
  4. **默认只监听回环**：想局域网访问必须显式设 host 且必须带口令。
  5. **Cookie 不放口令明文**：登录后发一个随机会话 id，服务端内存持有，
     比把口令塞 Cookie 安全（口令不会出现在浏览器历史/日志里）。
  6. **登录失败限速**：防暴力破解。5 次失败锁 5 分钟。

前端是单文件内联 HTML（无外部 CDN 依赖）—— 部署环境可能不通外网，
引 CDN 会让面板在没代理时直接白屏。
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from ..nodes.pool import read_pool_overview
from .manager import ProxyManager
from .store import ConfigError, Store
from .subparse import SubscriptionError

log = logging.getLogger("websearch.panel")

SESSION_COOKIE = "ws_panel_sid"
SESSION_TTL = 12 * 3600          # 会话 12 小时
LOGIN_MAX_FAILS = 5              # 连续失败次数
LOGIN_LOCK_SEC = 300             # 锁定时长


async def _tcp_ok(host: str, port: int, timeout: float = 1.5) -> bool:
    """探 TCP 端口是否可连（判断服务在不在跑）。

    为什么不用 HTTP 探活：搜索服务要带 token 才能探，而面板判断
    「服务在不在」不该依赖 token；TCP 层足够且更快。
    """
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        w.close()
        return True
    except Exception:
        return False


class Panel:
    """面板状态容器（会话、限速计数）。"""

    def __init__(self, store: Store, manager: ProxyManager):
        self.store = store
        self.manager = manager
        self.sessions: dict[str, float] = {}
        self.fails: dict[str, list[float]] = {}   # ip -> [失败时间戳]
        self._lock = asyncio.Lock()

    # ── 会话 ──

    def new_session(self) -> str:
        sid = secrets.token_urlsafe(32)
        self.sessions[sid] = time.time() + SESSION_TTL
        return sid

    def session_valid(self, sid: str) -> bool:
        exp = self.sessions.get(sid)
        if not exp:
            return False
        if exp < time.time():
            self.sessions.pop(sid, None)
            return False
        return True

    def drop_session(self, sid: str) -> None:
        self.sessions.pop(sid, None)

    # ── 登录限速 ──

    def locked_for(self, ip: str) -> int:
        """返回剩余锁定秒数，0 表示未锁。"""
        rec = self.fails.get(ip) or []
        now = time.time()
        recent = [t for t in rec if now - t < LOGIN_LOCK_SEC]
        self.fails[ip] = recent
        if len(recent) >= LOGIN_MAX_FAILS:
            return int(LOGIN_LOCK_SEC - (now - recent[-1]))
        return 0

    def note_fail(self, ip: str) -> None:
        self.fails.setdefault(ip, []).append(time.time())

    def clear_fails(self, ip: str) -> None:
        self.fails.pop(ip, None)


def _detect_lan_ip_safe() -> str:
    """探测局域网 IP（失败返回空串，不抛异常）。"""
    import socket

    for target in (("8.8.8.8", 80), ("223.5.5.5", 80)):
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


def _read_mcp_token() -> str:
    """从 .tokens 读 MCP 服务 token。

    只取第一个非注释行的 token 部分。读不到返回空串。
    注意：这个值会出现在客户端配置片段里（客户端必须要有它），
    所以只在已登录的会话里返回。
    """
    import os as _os
    from pathlib import Path as _Path

    for p in (_Path(_os.environ.get("WS_TOKEN_FILE", "/opt/websearch-mcp/.tokens")),
              _Path("/opt/websearch-mcp/.tokens")):
        try:
            if not p.exists():
                continue
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                return line.split(":")[-1].strip()
        except Exception:
            continue
    return ""


def build_panel_app(store: Store, manager: ProxyManager, *,
                    require_token: bool = True,
                    pool_db: Path | str | None = None):
    """构造面板 ASGI 应用。

    pool_db：节点库路径。面板是独立进程，读池走**只读** sqlite 连接
    （见 nodes.pool.read_pool_overview），不依赖搜索服务在线。留空则按
    与搜索服务相同的配置解析（WS_CACHE_DIR/nodes.sqlite3）。
    """
    panel = Panel(store, manager)
    if pool_db is None:
        # 不能走 Config.from_env()：那只读环境变量，而 WS_CACHE_DIR 在
        # start-mcp.sh 里是给**搜索服务**导出的，面板进程拿不到 ——
        # 会解析到系统临时目录，池子卡片永远是空的。
        # Store.get 的优先级是「环境变量 > .env > 默认值」，才对得上
        # 搜索服务实际用的那个库。默认值取配置文件同级目录下的 cache/
        # （与 start-mcp.sh 的 ${WS_CACHE_DIR:-$APP/cache} 一致）。
        try:
            cache_dir = store.get("WS_CACHE_DIR", "")
            base = (Path(cache_dir) if cache_dir
                    else Path(store.path).resolve().parent / "cache")
            pool_db = base / "nodes.sqlite3"
        except Exception as e:            # 解析失败不该让面板起不来
            log.warning("解析节点库路径失败（节点池卡片将不可用）: %s", e)
            pool_db = None

    def client_ip(request) -> str:
        # 不信任 X-Forwarded-For（面板直接暴露，没有可信代理在前面）
        return request.client.host if request.client else "unknown"

    def authed(request) -> bool:
        sid = request.cookies.get(SESSION_COOKIE, "")
        return panel.session_valid(sid)

    # ── 页面 ──

    async def index(request):
        if not authed(request):
            return RedirectResponse("/login")
        return HTMLResponse(_PAGE_HTML)

    async def login_page(request):
        return HTMLResponse(_LOGIN_HTML)

    async def magic_login(request):
        """一键登录：用 URL 里的票据换会话，然后跳转到面板。

        这是给「安装完直接能用」体验用的 —— 用户不需要去 grep 口令、
        不需要手工粘贴。票据一次性、5 分钟失效、存哈希。

        跳转时用 303 把带票据的 URL 换成干净的 /，避免票据留在
        浏览器历史里。
        """
        ticket = request.query_params.get("t", "")
        if not store.consume_login_ticket(ticket):
            # 票据无效/过期：退回正常登录页，不提示细节（防探测）
            return RedirectResponse("/login?expired=1", status_code=303)
        sid = panel.new_session()
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(
            SESSION_COOKIE, sid,
            # ⚠️ 必须用 lax 而不是 strict：
            # strict 会让「从外部链接点进来」的首次跳转**不携带 Cookie**，
            # 而这正是本功能的核心场景 —— 用户从面板日志/聊天里点链接进来。
            # 用 strict 时表现是：链接能点、303 也正常、但下一跳就掉登录，
            # 用户看到「刚进去又让我登录」。
            # lax 仍然阻止跨站 POST（CSRF 防护），对本场景足够安全。
            httponly=True, samesite="lax", max_age=SESSION_TTL,
        )
        log.info("面板：一键登录成功")
        return resp

    # ── API ──

    async def api_login(request):
        ip = client_ip(request)
        remain = panel.locked_for(ip)
        if remain > 0:
            return JSONResponse(
                {"ok": False, "error": f"失败次数过多，请 {remain} 秒后再试"},
                status_code=429,
            )
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "请求格式错误"}, status_code=400)

        token = str(body.get("token", ""))
        if not store.verify_panel_token(token):
            panel.note_fail(ip)
            left = LOGIN_MAX_FAILS - len(panel.fails.get(ip, []))
            return JSONResponse(
                {"ok": False, "error": f"口令错误（剩余 {max(left,0)} 次机会）"},
                status_code=401,
            )
        panel.clear_fails(ip)
        sid = panel.new_session()
        resp = JSONResponse({"ok": True})
        resp.set_cookie(
            SESSION_COOKIE, sid,
            # 与 /_open 保持一致用 lax（见那里的说明）
            httponly=True, samesite="lax", max_age=SESSION_TTL,
            # 面板通常跑在 http 上（内网），所以不设 secure，否则 Cookie 发不出去
        )
        return resp

    async def api_logout(request):
        sid = request.cookies.get(SESSION_COOKIE, "")
        panel.drop_session(sid)
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE)
        return resp

    async def api_config(request):
        """读配置（**只返回掩码，无凭据**）。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        data = store.read_public()
        data["proxy"] = manager.summary()
        return JSONResponse({"ok": True, "config": data})

    async def api_health_summary(request):
        """**产品视角的状态**：用人话告诉用户「现在能不能用、哪里坏了、怎么办」。

        为什么不用原始字段：用户看到 {"bypassed": true, "consecutive_failures": 3}
        不知道该怎么办。产品应该直接说：
          「🟢 一切正常，可以开始用」
          「🟡 能用，但只搜到国内网站（墙外源没开）」
          「🔴 搜索服务没在跑 —— 点这里启动」

        返回 items 列表，每项含 level（ok/warn/error）+ 标题 + 说明 + 可选操作。
        """
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

        items: list[dict[str, Any]] = []

        # 1) 搜索服务是否在跑（探 TCP，不依赖它是否响应正确）
        svc_port = store.get_int("WS_PORT", 8300)
        svc_up = await _tcp_ok("127.0.0.1", svc_port, timeout=1.5)
        if svc_up:
            items.append({
                "level": "ok", "title": "搜索服务正在运行",
                "detail": f"监听 {svc_port} 端口，可以接受 AI 客户端连接。",
            })
        else:
            items.append({
                "level": "error", "title": "搜索服务没有运行",
                "detail": "AI 客户端现在连不上。请启动搜索服务。",
                "action": {"label": "启动搜索服务", "id": "start_search"},
            })

        # 2) 出网状态：**先看你自己的订阅代理，再看程序自养的节点池兜底**。
        #    只看 manager.state 是不够的：用户「只用节点池」时 manager 没在
        #    跑，但墙外搜索其实是通的 —— 那时报「只搜国内网站」是给错结论，
        #    还会把用户误导去填订阅链接（线上实测踩到，与池子卡片自相矛盾）。
        pool_alive = 0
        if pool_db is not None:
            try:
                _p = read_pool_overview(pool_db, limit=1)
                pool_alive = int((_p.get("stats") or {}).get("alive") or 0)
            except Exception:
                pool_alive = 0

        st = manager.state
        if st.running and st.last_check_ok:
            items.append({
                "level": "ok", "title": "代理工作正常，能访问墙外网站",
                "detail": (f"出口 IP {st.exit_ip} {st.exit_country}"
                           if st.exit_ip else "已通过健康检查。"),
            })
        elif st.running:
            items.append({
                "level": "error", "title": "代理配置了但连不上",
                "detail": (f"原因：{st.last_error or '未知'}。"
                           "可能是节点失效或订阅过期 —— 换个节点或更新订阅。"
                           "搜索会自动降级为直连，不会完全用不了。"),
                "action": {"label": "重新检测", "id": "recheck_proxy"},
            })
        elif pool_alive > 0:
            items.append({
                "level": "ok",
                "title": (f"没配你自己的代理，但自养节点池在兜底"
                          f"（{pool_alive} 个实测可用）"),
                "detail": ("墙外搜索由服务自己搜集的免费节点池提供，现在是通的。"
                           "这些节点寿命短、稳定性不如你自己订阅的机场；"
                           "哪个通、哪个不通看下面「节点池」卡片。"),
            })
        else:
            items.append({
                "level": "warn", "title": "没有配置代理（只搜国内网站）",
                "detail": ("现在能搜到百度、必应、360、微信等国内源。"
                           "想搜 Google、DuckDuckGo 这些墙外源，可以填一个"
                           "订阅链接；不填也行 —— 服务会自己搜集节点兜底。"),
                "action": {"label": "去配置", "id": "focus_sub"},
            })

        # 3) 配置安全
        pub = store.read_public()
        if pub["file_permissions"]["secure"]:
            items.append({
                "level": "ok", "title": "凭据文件权限安全",
                "detail": "订阅链接和口令只存在本机，权限 600，不会被别人读到。",
            })
        else:
            items.append({
                "level": "warn", "title": "凭据文件权限过宽",
                "detail": f"{pub['file_permissions']['detail']} —— 建议收紧。",
                "action": {"label": "修复权限", "id": "fix_perm"},
            })

        # 4) sing-box
        if not manager.available:
            items.append({
                "level": "warn", "title": "未安装 sing-box（代理功能不可用）",
                "detail": "没有它就无法使用墙外搜索源，但国内源仍可用。",
            })

        # 总体结论
        levels = {i["level"] for i in items}
        if "error" in levels:
            overall = "error"
        elif "warn" in levels:
            overall = "warn"
        else:
            overall = "ok"

        return JSONResponse({"ok": True, "overall": overall, "items": items})

    async def api_fix_permissions(request):
        """一键修复凭据文件权限（用户不用懂 chmod）。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        import os as _os

        try:
            _os.chmod(store.path, 0o600)
            _os.chmod(store.path.parent, 0o700)
            ok, detail = store.check_permissions()
            return JSONResponse({"ok": ok, "detail": detail})
        except Exception as e:
            return JSONResponse(
                {"ok": False, "detail": f"修复失败：{type(e).__name__}"}, status_code=500
            )

    async def api_search_restart(request):
        """重启搜索服务 —— 用户不用懂 tmux / 看门狗。

        做法：杀掉搜索进程，宿主看门狗会在 10-20 秒内重拉。
        这是这个部署环境里最可靠的「重启」方式（proot 没有 systemd）。
        """
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

        import subprocess

        try:
            # 只杀 websearch.server 进程，不动别的服务
            r = subprocess.run(
                ["pkill", "-f", "websearch.server"],
                capture_output=True, timeout=5,
            )
            killed = r.returncode == 0
        except Exception as e:
            return JSONResponse({
                "ok": False,
                "error": f"执行失败：{type(e).__name__}",
            }, status_code=500)

        if not killed:
            return JSONResponse({
                "ok": False,
                "error": "没找到搜索服务进程 —— 它可能本来就没在跑，或需要手工启动",
            }, status_code=400)

        # 等服务回来（最多 40 秒）
        svc_port = store.get_int("WS_PORT", 8300)
        for _ in range(20):
            await asyncio.sleep(2)
            if await _tcp_ok("127.0.0.1", svc_port, timeout=1.0):
                log.info("面板：搜索服务已重启")
                return JSONResponse({"ok": True, "message": "搜索服务已重启"})
        return JSONResponse({
            "ok": False,
            "error": "搜索服务重启后没有回来，请检查服务器上的看门狗（tmux 会话 websearch）",
        }, status_code=500)

    async def api_client_config(request):
        """**最后一公里**：生成「复制到 AI 客户端」的配置片段。

        为什么这个接口最重要：服务跑起来了，但用户不知道怎么把它接到
        自己的 AI 客户端 —— 这是从「安装成功」到「真正用上」之间那道墙。

        返回多种客户端格式（Claude Desktop / Cursor / 通用 JSON /
        命令行），用户复制粘贴即可，不需要理解 MCP 协议。

        ⚠️ 这个响应**含访问 token**（客户端需要它才能连）——
        所以必须登录后才能取，且只回给已认证的会话。
        """
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

        # 服务地址：优先用请求 Host（用户就是从那个地址访问的，说明可达）
        req_host = request.headers.get("host", "")
        port = store.get_int("WS_PORT", 8300)
        # 面板端口可能是 8500，但 MCP 服务是 8300 —— 取请求 Host 的 IP 部分
        ip = req_host.split(":")[0] if req_host else ""
        if not ip or ip in ("localhost", "127.0.0.1"):
            lan = _detect_lan_ip_safe()
            ip = lan or "127.0.0.1"
        url = f"http://{ip}:{port}/mcp"

        token = store.get("WS_MCP_TOKEN", "")
        if not token:
            token = _read_mcp_token()
        if not token:
            return JSONResponse({
                "ok": False,
                "error": "读不到 MCP 服务 token（检查 .tokens 文件是否存在）",
            }, status_code=400)

        server_name = "websearch"
        entry = {"url": url, "headers": {"Authorization": f"Bearer {token}"}}

        return JSONResponse({
            "ok": True,
            "url": url,
            "snippets": {
                # 通用 JSON（多数客户端可粘贴）
                "generic_json": json.dumps(
                    {"mcpServers": {server_name: entry}},
                    ensure_ascii=False, indent=2,
                ),
                # Claude Desktop（claude_desktop_config.json）
                "claude_desktop": json.dumps(
                    {"mcpServers": {server_name: {
                        "command": "npx",
                        "args": ["-y", "mcp-remote", url,
                                 "--header", f"Authorization: Bearer {token}"],
                    }}},
                    ensure_ascii=False, indent=2,
                ),
                # DSH / dsh-mcp-manager 的格式
                "dsh": json.dumps({
                    "name": server_name,
                    "transport": "streamable-http",
                    "enabled": True,
                    "url": url,
                    "headers": {"Authorization": f"Bearer {token}"},
                    "toolCallTimeoutMs": 120000,
                    "description": "多引擎聚合联网搜索",
                }, ensure_ascii=False, indent=2),
                # 命令行自检
                "curl": (
                    f'curl -s -X POST {url} \\\n'
                    f'  -H "Content-Type: application/json" \\\n'
                    f'  -H "Accept: application/json, text/event-stream" \\\n'
                    f'  -H "Authorization: Bearer {token}" \\\n'
                    f"  -d '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                    f"\"params\":{{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{{}},"
                    f"\"clientInfo\":{{\"name\":\"test\",\"version\":\"1\"}}}}}}'"
                ),
            },
        })

    async def api_save(request):
        """保存订阅/设置。凭据只在此刻从浏览器流向服务器，不落日志。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"ok": False, "error": "请求格式错误"}, status_code=400)

        values: dict[str, str] = {}
        sub = body.get("subscription_url")
        if isinstance(sub, str) and sub.strip():
            # 基本校验：必须是 http(s)，且不能是内网（防 SSRF 拉内网）
            if not sub.strip().lower().startswith(("http://", "https://")):
                return JSONResponse(
                    {"ok": False, "error": "订阅链接必须以 http:// 或 https:// 开头"},
                    status_code=400,
                )
            values["WS_SUBSCRIPTION_URL"] = sub.strip()

        # 前端字段名 → 配置键的映射。
        # 注意方向：请求体里出现的是**前端字段名**（proxy_enabled），
        # 要写入的是**配置键**（WS_PROXY_ENABLED）。之前写成
        # `if field in body` 判反了，导致一个字段都存不进去
        # （表现为「没有要保存的改动」）。
        bool_fields = {
            "proxy_enabled": "WS_PROXY_ENABLED",
            "auto_start": "WS_PROXY_AUTO_START",
        }
        int_fields = {
            "http_port": "WS_HTTP_PROXY_PORT",
            "socks_port": "WS_SOCKS_PROXY_PORT",
            "health_interval": "WS_PROXY_HEALTH_INTERVAL",
        }
        for name, cfg_key in bool_fields.items():
            if name in body:
                values[cfg_key] = "1" if body[name] else "0"
        for name, cfg_key in int_fields.items():
            if name in body:
                try:
                    values[cfg_key] = str(int(body[name]))
                except (TypeError, ValueError):
                    return JSONResponse(
                        {"ok": False, "error": f"{name} 必须是整数"}, status_code=400
                    )

        if not values:
            return JSONResponse({"ok": False, "error": "没有要保存的改动"}, status_code=400)

        try:
            store.set_many(values)
        except ConfigError as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)

        log.info("面板已更新配置项: %s", ", ".join(sorted(values)))
        return JSONResponse({"ok": True, "config": store.read_public()})

    async def api_clear_subscription(request):
        """清除订阅（用户想换机场时用）。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        store.delete(["WS_SUBSCRIPTION_URL"])
        await manager.stop()
        log.info("面板已清除订阅并停止代理")
        return JSONResponse({"ok": True, "config": store.read_public()})

    async def api_proxy_start(request):
        """用已保存的订阅启动代理，**自动探测并选择可用节点**。

        产品考量：用户不该自己逐个试节点。点一次「启动」，
        服务自动做：拉订阅 → 解析 → 探测每个节点 → 用最快的启动。
        如果全部不通，如实报告而不是假装成功。
        """
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        url = store.get("WS_SUBSCRIPTION_URL", "")
        if not url:
            return JSONResponse(
                {"ok": False, "error": "尚未配置订阅链接"}, status_code=400
            )
        try:
            # 走「自动选节点」流程（带探测）
            result = await manager.start_from_subscription_auto(url)
        except SubscriptionError as e:
            # 消息里不含 URL（subparse 保证）
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        except Exception as e:
            return JSONResponse(
                {"ok": False, "error": f"启动失败：{type(e).__name__}"}, status_code=500
            )
        if not result.get("ok"):
            # 启动失败也要给可读信息（探测报告能告诉用户「N 个节点全不通」）
            return JSONResponse(result, status_code=200)
        # 启动成功后立刻做一次健康检查，让用户马上看到能不能出网
        try:
            await manager.health_check()
        except Exception:
            pass
        return JSONResponse({"ok": True, **result})

    async def api_proxy_stop(request):
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        await manager.stop()
        return JSONResponse({"ok": True, "state": manager.state.to_dict()})

    async def api_proxy_check(request):
        """健康检查：验证代理真的能出网。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        state = await manager.health_check()
        return JSONResponse({"ok": True, "state": state})

    async def api_proxy_nodes(request):
        """列出节点（只给名字与协议，**无凭据**）。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        return JSONResponse({"ok": True, "nodes": manager.list_nodes()})

    async def api_pool(request):
        """自养节点池概览 —— **只读**，给面板画灯。

        权限模型（用户定的，勿改）：自养池是程序自己搜来、自己实测维护的，
        用户**只能看**，不能碰。所以这里没有 POST、没有增删改，页面上也不
        给任何入口 —— 唯一动作是把灯点亮，让用户知道哪个通、哪个不通。

        走只读 sqlite（不是 MCP、不是搜索服务的接口），因为面板是独立进程：
        搜索服务挂了/在重启时，池子的历史状态照样能看。
        """
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"},
                                status_code=401)
        if pool_db is None:
            return JSONResponse({"ok": False, "available": False,
                                 "note": "节点库路径未解析（面板配置受限）"})
        try:
            limit = int(request.query_params.get("limit", "60"))
        except ValueError:
            limit = 60
        limit = max(1, min(limit, 200))
        only_alive = request.query_params.get("only_alive") in ("1", "true")
        try:
            data = read_pool_overview(pool_db, limit=limit,
                                     only_alive=only_alive)
        except Exception as e:            # 兜底：面板页面不该 500
            log.warning("读节点池失败: %s", e)
            return JSONResponse({"ok": False, "available": False,
                                 "note": f"节点池读取失败（{type(e).__name__}）"})
        return JSONResponse({"ok": True, **data})

    # ── 路由 ──

    routes = [
        Route("/", index),
        Route("/login", login_page),
        Route("/_open", magic_login),        # 一键登录（票据换会话）
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", api_logout, methods=["POST"]),
        Route("/api/config", api_config),
        Route("/api/client-config", api_client_config),
        Route("/api/health-summary", api_health_summary),
        Route("/api/fix-permissions", api_fix_permissions, methods=["POST"]),
        Route("/api/search/restart", api_search_restart, methods=["POST"]),
        Route("/api/save", api_save, methods=["POST"]),
        Route("/api/subscription/clear", api_clear_subscription, methods=["POST"]),
        Route("/api/proxy/start", api_proxy_start, methods=["POST"]),
        Route("/api/proxy/stop", api_proxy_stop, methods=["POST"]),
        Route("/api/proxy/check", api_proxy_check, methods=["POST"]),
        Route("/api/proxy/nodes", api_proxy_nodes),
        # 自养节点池：只读，仅用于展示「哪个通/哪个不通」
        Route("/api/pool", api_pool),
        # 健康探活：不回显任何状态，专供不带口令的监控
        Route("/healthz", lambda r: JSONResponse({"ok": True})),
    ]
    return Starlette(routes=routes)


# ══════════════════════ 前端（单文件内联，无 CDN 依赖）══════════════════════

_LOGIN_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>websearch-mcp 管理面板 · 登录</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:#0f1115;color:#e6e8eb;font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
.card{width:min(400px,92vw);background:#171a21;border:1px solid #262b36;border-radius:14px;padding:32px}
h1{margin:0 0 6px;font-size:19px}
p.sub{margin:0 0 22px;color:#8b93a3;font-size:13px}
label{display:block;font-size:13px;color:#a8b0bf;margin-bottom:7px}
input{width:100%;padding:11px 13px;border-radius:9px;border:1px solid #2d3340;
  background:#0f1115;color:#e6e8eb;font-size:14px;font-family:inherit}
input:focus{outline:none;border-color:#4c7dff}
button{width:100%;margin-top:18px;padding:12px;border:0;border-radius:9px;
  background:#4c7dff;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:hover{background:#3d6ce8}
.msg{margin-top:14px;font-size:13px;min-height:20px;color:#ff6b6b}
</style></head><body>
<div class="card">
  <h1>管理面板</h1>
  <p class="sub">输入面板口令以继续</p>
  <label for="t">面板口令</label>
  <input id="t" type="password" autocomplete="current-password" autofocus>
  <button id="b">登录</button>
  <div class="msg" id="m"></div>
</div>
<script>
const t=document.getElementById('t'),b=document.getElementById('b'),m=document.getElementById('m');
async function go(){
  m.textContent='';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({token:t.value})});
    const d=await r.json();
    if(d.ok){location.href='/';}else{m.textContent=d.error||'登录失败';}
  }catch(e){m.textContent='网络错误';}
}
b.onclick=go;
t.addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script></body></html>"""


_PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>websearch-mcp 管理面板</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0f1115;color:#e6e8eb;
  font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:28px 20px 60px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
h1{margin:0;font-size:20px}
.sub{color:#8b93a3;font-size:13px;margin:0 0 24px}
.card{background:#171a21;border:1px solid #262b36;border-radius:14px;
  padding:22px;margin-bottom:18px}
.card h2{margin:0 0 4px;font-size:15px}
.card .hint{color:#8b93a3;font-size:12.5px;margin:0 0 16px}
label{display:block;font-size:13px;color:#a8b0bf;margin:14px 0 7px}
input[type=text],input[type=password],input[type=number]{
  width:100%;padding:10px 12px;border-radius:9px;border:1px solid #2d3340;
  background:#0f1115;color:#e6e8eb;font-size:14px;font-family:inherit}
input:focus{outline:none;border-color:#4c7dff}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.row>*{flex:1;min-width:130px}
button{padding:10px 18px;border:0;border-radius:9px;background:#4c7dff;color:#fff;
  font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
button:hover{background:#3d6ce8}
button.ghost{background:#252b36;color:#c8cfdb}
button.ghost:hover{background:#2f3644}
button.danger{background:#7a2b2b}
button.danger:hover{background:#8f3232}
.btns{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600}
.b-ok{background:#14351f;color:#4ade80}
.b-warn{background:#3a2f12;color:#fbbf24}
.b-off{background:#2a2f3a;color:#9aa3b2}
.b-bad{background:#3a1a1a;color:#f87171}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:8px}
td{padding:7px 0;border-bottom:1px solid #22262f;vertical-align:top}
td:first-child{color:#8b93a3;width:38%}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;word-break:break-all}
.msg{margin-top:14px;font-size:13.5px;min-height:20px}
.msg.ok{color:#4ade80}.msg.err{color:#ff6b6b}
.warn{background:#2a1f10;border:1px solid #4a3a1a;color:#fbbf24;
  padding:11px 14px;border-radius:9px;font-size:13px;margin-top:14px}
</style></head><body>
<div class="wrap">
  <header>
    <h1>websearch-mcp 管理面板</h1>
    <button class="ghost" id="logout" style="flex:0 0 auto">退出</button>
  </header>
  <p class="sub">代理与订阅只保存在本机（600 权限、不入 git）。面板永不回显凭据原文。</p>

  <div class="card" id="healthCard">
    <h2>现在能不能用</h2>
    <p class="hint">用人话告诉你当前状态；有问题会直接给出该做什么。</p>
    <div id="health"><span style="color:#8b93a3">检查中…</span></div>
    <div class="btns">
      <button class="ghost" id="btnRefreshHealth">重新检查</button>
    </div>
  </div>

  <div class="card">
    <h2>代理状态</h2>
    <p class="hint">服务出网能力来自你配置的节点；未配置时代理功能自动降级，搜索仍可用。</p>
    <table id="status"><tr><td>加载中…</td><td></td></tr></table>
    <div class="btns">
      <button id="btnStart">启动代理</button>
      <button class="ghost" id="btnStop">停止</button>
      <button class="ghost" id="btnCheck">健康检查</button>
    </div>
    <div class="msg" id="statusMsg"></div>
  </div>

  <div class="card">
    <h2>你自己的订阅（可增可删）</h2>
    <p class="hint">填入你的订阅链接。它只写入本机 600 权限文件，不会上传到任何地方。</p>
    <label for="sub">订阅链接</label>
    <div class="row">
      <input id="sub" type="password" placeholder="留空 = 不修改现有订阅　（点右边可显示）"
             autocomplete="off" spellcheck="false">
      <button class="ghost" id="btnShowSub" type="button"
              style="flex:0 0 auto;min-width:0">显示</button>
    </div>
    <div class="warn">当前订阅：<span id="curSub">未配置</span>　
      出于安全只显示掩码与域名。<b>保存后输入框会清空，这是正常的（不是没存上）</b> ——
      要删掉它，点下面的「删除订阅」。</div>
    <label for="httpPort">本地 HTTP 代理端口</label>
    <input id="httpPort" type="number" min="1024" max="65535">
    <label for="socksPort">本地 SOCKS5 端口</label>
    <input id="socksPort" type="number" min="1024" max="65535">
    <div class="btns">
      <button id="btnSave">保存</button>
      <button class="danger" id="btnClear">删除订阅</button>
    </div>
    <div class="msg" id="saveMsg"></div>
  </div>

  <div class="card">
    <h2>订阅里的节点</h2>
    <p class="hint">你订阅解析出来的节点（只显示名称与协议）。凭据不出现在页面里。</p>
    <div id="nodes"><span style="color:#8b93a3">未配置订阅 / 代理未启动</span></div>
  </div>

  <div class="card" id="poolCard">
    <h2>节点池（程序自动维护 · 只读）</h2>
    <p class="hint">这些是服务自己满世界搜来、并逐一实测过出网的节点，用来给墙外搜索兜底。
      你只能看 —— 🟢通 / ⚪不通。它们的搜集与淘汰由程序负责，页面不提供任何增删入口。</p>
    <div id="poolStats" class="mono" style="color:#8b93a3">加载中…</div>
    <div class="btns" style="margin-top:12px">
      <button class="ghost" id="btnPoolAlive">只看可用的</button>
      <button class="ghost" id="btnPoolRefresh">刷新</button>
    </div>
    <div id="pool"></div>
  </div>

  <div class="card" id="connectCard">
    <h2>把它接到你的 AI 客户端</h2>
    <p class="hint">复制下面任意一段，粘到你的 AI 客户端配置里，就能开始用搜索了。</p>
    <div class="btns" style="margin-top:0;margin-bottom:12px">
      <button class="ghost" data-fmt="dsh">DSH / dsh-mcp-manager</button>
      <button class="ghost" data-fmt="generic_json">通用 JSON</button>
      <button class="ghost" data-fmt="claude_desktop">Claude Desktop</button>
      <button class="ghost" data-fmt="curl">命令行自检</button>
    </div>
    <div class="mono" id="snippet" style="background:#0f1115;border:1px solid #2d3340;
      border-radius:9px;padding:14px;white-space:pre-wrap;max-height:320px;overflow:auto">加载中…</div>
    <div class="btns">
      <button id="btnCopy">复制</button>
    </div>
    <div class="msg" id="copyMsg"></div>
  </div>
</div>
<script>
const $=id=>document.getElementById(id);
function setMsg(el,txt,ok){el.textContent=txt;el.className='msg '+(ok?'ok':'err');}
function badge(ok,t){return `<span class="badge ${ok?'b-ok':'b-off'}">${t}</span>`;}

async function load(){
  const r=await fetch('/api/config');
  if(r.status===401){location.href='/login';return;}
  const {config:c}=await r.json();
  const p=c.proxy||{},s=p.state||{};
  const rows=[
    ['代理进程', s.running?badge(true,'运行中')+' <span class="mono">pid '+s.pid+'</span>':badge(false,'未运行')],
    ['节点数', s.node_count?`${s.node_count} 个`:'—'],
    ['健康状态', s.healthy?badge(true,'可出网'):badge(false, s.last_error?s.last_error:'未检测')],
    ['出口 IP', s.exit_ip?`<span class="mono">${s.exit_ip}</span> ${s.exit_country||''}`:'—'],
    ['HTTP 代理', s.http_proxy?`<span class="mono">${s.http_proxy}</span>`:'—'],
    ['配置文件权限', c.file_permissions.secure?badge(true,'600'):badge(false,c.file_permissions.detail)],
    ['sing-box', p.available?badge(true,'已安装'):badge(false,'未找到')],
  ];
  $('status').innerHTML=rows.map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('');
  $('curSub').textContent=c.subscription.configured
    ? `${c.subscription.masked}　${c.subscription.host?('@ '+c.subscription.host):''}`
    : '未配置';
  $('httpPort').value=c.http_port;
  $('socksPort').value=c.socks_port;
}

async function post(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},
    body:body?JSON.stringify(body):undefined});
  if(r.status===401){location.href='/login';return {};}
  return r.json();
}

// 订阅链接默认打码 —— 但用户得能确认自己到底粘了什么，所以给一个显示开关
$('btnShowSub').onclick=()=>{
  const i=$('sub'),show=i.type==='password';
  i.type=show?'text':'password';
  $('btnShowSub').textContent=show?'隐藏':'显示';
};
function resetSubField(){
  $('sub').value='';$('sub').type='password';$('btnShowSub').textContent='显示';
}
function subLabel(s){
  return s&&s.configured?`${s.masked}${s.host?' @ '+s.host:''}`:'未配置';
}
$('btnSave').onclick=async()=>{
  const b={};
  if($('sub').value.trim())b.subscription_url=$('sub').value.trim();
  b.http_port=+$('httpPort').value; b.socks_port=+$('socksPort').value;
  const d=await post('/api/save',b);
  if(!d.ok){setMsg($('saveMsg'),d.error||'保存失败',false);return;}
  // 别静默清空 —— 明确告诉用户「存进去了、现在存的是哪个」
  const s=(d.config&&d.config.subscription)||{};
  setMsg($('saveMsg'),
    b.subscription_url?`已保存：${subLabel(s)}　（可点「启动代理」生效）`
                      :'已保存。可点「启动代理」生效。',true);
  resetSubField();load();
};
$('btnClear').onclick=async()=>{
  if(!confirm('删除订阅？\n\n会清掉本机保存的订阅链接并停止代理。\n（搜索服务的自养节点池不受影响。）'))return;
  const d=await post('/api/subscription/clear');
  setMsg($('saveMsg'),d.ok?'订阅已删除（输入框和上方状态都已清空）':(d.error||'删除失败'),d.ok);
  resetSubField();load();
};
$('btnStart').onclick=async()=>{
  setMsg($('statusMsg'),'启动中…',true);
  const d=await post('/api/proxy/start');
  setMsg($('statusMsg'),d.ok?'代理已启动':(d.error||'启动失败'),d.ok);
  load();loadNodes();
};
$('btnStop').onclick=async()=>{await post('/api/proxy/stop');setMsg($('statusMsg'),'已停止',true);load();};
$('btnCheck').onclick=async()=>{
  setMsg($('statusMsg'),'检测中…',true);
  const d=await post('/api/proxy/check');
  const s=d.state||{};
  setMsg($('statusMsg'),s.healthy?`可出网（${s.last_check_ms}ms）`:(s.last_error||'检测失败'),s.healthy);
  load();
};
async function loadNodes(){
  const r=await fetch('/api/proxy/nodes');
  const d=await r.json();
  if(!d.nodes||!d.nodes.length){$('nodes').innerHTML='<span style="color:#8b93a3">未配置订阅 / 代理未启动</span>';return;}
  $('nodes').innerHTML='<table>'+d.nodes.map(n=>
    `<tr><td>${esc(n.tag)}</td><td><span class="mono">${esc(n.protocol)}</span></td></tr>`).join('')+'</table>';
}
// 池子里的 server/country 来自**第三方公开源**，是不可信输入 → 必须转义再进 innerHTML
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

// ── 自养节点池（只读：只看哪个通、哪个不通）──
let poolOnlyAlive=false;
function lamp(a){return a?'<span class="badge b-ok">🟢 通</span>'
                         :'<span class="badge b-off">⚪ 不通</span>';}
async function loadPool(){
  const st=$('poolStats'),box=$('pool');
  let d={};
  try{
    const r=await fetch('/api/pool?limit=60'+(poolOnlyAlive?'&only_alive=1':''));
    if(r.status===401)return;
    d=await r.json();
  }catch(e){st.textContent='节点池读取失败（网络错误）';box.innerHTML='';return;}
  if(!d.ok||!d.available){st.textContent=d.note||'节点池不可用';box.innerHTML='';return;}
  const s=d.stats||{},by=s.by_pool||{},free=by.free||{},cust=by.cust||{};
  const rate=s.total?Math.round(s.alive/s.total*100):0;
  st.innerHTML=`共 <b>${s.total}</b> 个 · 🟢通 <b>${s.alive}</b> · ⚪不通 ${s.dead} ·`
    +` 待测 ${s.untested} · 存活率 ${rate}%`
    +`<br>自养池 ${free.total||0}（通 ${free.alive||0}）`
    +(cust.total?`　订阅池 ${cust.total}（通 ${cust.alive||0}）`:'');
  if(!d.nodes.length){box.innerHTML='<span style="color:#8b93a3">暂无节点</span>';return;}
  box.innerHTML='<table>'+d.nodes.map(n=>
    `<tr><td style="width:34%">${lamp(n.alive)} <span class="mono">${esc(n.protocol)}</span></td>
      <td>${esc(n.country)||'—'}${n.avg_ms?` <span class="mono">${n.avg_ms}ms</span>`:''}
      <div class="mono" style="color:#6b7280">${esc(n.server)}:${esc(n.port)}</div></td></tr>`).join('')+'</table>';
}
$('btnPoolAlive').onclick=()=>{
  poolOnlyAlive=!poolOnlyAlive;
  $('btnPoolAlive').textContent=poolOnlyAlive?'看全部':'只看可用的';
  loadPool();
};
$('btnPoolRefresh').onclick=loadPool;
$('logout').onclick=async()=>{await post('/api/logout');location.href='/login';};

// ── 接入 AI 客户端（最后一公里）──
let snippets={},curFmt='dsh';
async function loadSnippets(){
  const r=await fetch('/api/client-config');
  if(r.status===401){return;}
  const d=await r.json();
  if(!d.ok){$('snippet').textContent=d.error||'读取失败';return;}
  snippets=d.snippets||{};
  render();
}
function render(){
  $('snippet').textContent=snippets[curFmt]||'（无此格式）';
}
document.querySelectorAll('[data-fmt]').forEach(b=>{
  b.onclick=()=>{
    curFmt=b.dataset.fmt;
    document.querySelectorAll('[data-fmt]').forEach(x=>x.className='ghost');
    b.className='';
    render();
  };
});
$('btnCopy').onclick=async()=>{
  const t=snippets[curFmt]||'';
  try{
    await navigator.clipboard.writeText(t);
    setMsg($('copyMsg'),'已复制到剪贴板',true);
  }catch(e){
    // 非 HTTPS 环境下 clipboard API 不可用 —— 退化到选中文本让用户手动复制
    const r=document.createRange();r.selectNodeContents($('snippet'));
    const s=getSelection();s.removeAllRanges();s.addRange(r);
    setMsg($('copyMsg'),'已选中文本，请按 Ctrl+C 复制',true);
  }
};
// ── 人话状态（产品视角：告诉用户能不能用、哪里坏了、怎么办）──
function healthIcon(lv){return lv==='ok'?'🟢':(lv==='warn'?'🟡':'🔴');}
async function loadHealth(){
  const r=await fetch('/api/health-summary');
  if(r.status===401){return;}
  const d=await r.json();
  if(!d.ok){$('health').textContent='读取失败';return;}
  $('health').innerHTML=d.items.map(it=>{
    const act=it.action
      ? `<button class="ghost" style="margin-top:8px;padding:6px 12px;font-size:13px"
           data-action="${it.action.id}">${it.action.label}</button>` : '';
    return `<div style="padding:10px 0;border-bottom:1px solid #22262f">
      <div style="font-weight:600">${healthIcon(it.level)} ${it.title}</div>
      <div style="color:#8b93a3;font-size:13px;margin-top:4px">${it.detail}</div>
      ${act}</div>`;
  }).join('');
  $('health').querySelectorAll('[data-action]').forEach(b=>{
    b.onclick=()=>doAction(b.dataset.action,b);
  });
}
async function doAction(id,btn){
  const old=btn.textContent; btn.textContent='处理中…'; btn.disabled=true;
  if(id==='start_search'){ await post('/api/proxy/start'); }
  else if(id==='recheck_proxy'){ await post('/api/proxy/check'); }
  else if(id==='fix_perm'){ await post('/api/fix-permissions'); }
  else if(id==='focus_sub'){
    $('sub').focus(); $('sub').scrollIntoView({behavior:'smooth'});
    btn.textContent=old; btn.disabled=false; return;
  }
  btn.textContent=old; btn.disabled=false;
  loadHealth(); load(); loadNodes(); loadPool();
}
$('btnRefreshHealth').onclick=()=>loadHealth();
load();loadNodes();loadSnippets();loadHealth();loadPool();
</script></body></html>"""
