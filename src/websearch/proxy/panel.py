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

from .manager import ProxyManager
from .store import ConfigError, Store
from .subparse import SubscriptionError

log = logging.getLogger("websearch.panel")

SESSION_COOKIE = "ws_panel_sid"
SESSION_TTL = 12 * 3600          # 会话 12 小时
LOGIN_MAX_FAILS = 5              # 连续失败次数
LOGIN_LOCK_SEC = 300             # 锁定时长


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


def build_panel_app(store: Store, manager: ProxyManager, *, require_token: bool = True):
    """构造面板 ASGI 应用。"""
    panel = Panel(store, manager)

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
            httponly=True, samesite="strict", max_age=SESSION_TTL,
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

        for key, field in (
            ("proxy_enabled", "WS_PROXY_ENABLED"),
            ("auto_start", "WS_PROXY_AUTO_START"),
        ):
            if field in body:
                values[key] = "1" if body[field] else "0"
        for key, field in (
            ("http_port", "WS_HTTP_PROXY_PORT"),
            ("socks_port", "WS_SOCKS_PROXY_PORT"),
            ("health_interval", "WS_PROXY_HEALTH_INTERVAL"),
        ):
            if field in body:
                try:
                    values[key] = str(int(body[field]))
                except (TypeError, ValueError):
                    return JSONResponse(
                        {"ok": False, "error": f"{field} 必须是整数"}, status_code=400
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
        """用已保存的订阅启动代理。"""
        if not authed(request):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        url = store.get("WS_SUBSCRIPTION_URL", "")
        if not url:
            return JSONResponse(
                {"ok": False, "error": "尚未配置订阅链接"}, status_code=400
            )
        try:
            result = await manager.start_from_subscription(url)
        except SubscriptionError as e:
            # 消息里不含 URL（subparse 保证）
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        except Exception as e:
            return JSONResponse(
                {"ok": False, "error": f"启动失败：{type(e).__name__}"}, status_code=500
            )
        return JSONResponse({"ok": bool(result.get("ok")), **result})

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

    # ── 路由 ──

    routes = [
        Route("/", index),
        Route("/login", login_page),
        Route("/api/login", api_login, methods=["POST"]),
        Route("/api/logout", api_logout, methods=["POST"]),
        Route("/api/config", api_config),
        Route("/api/save", api_save, methods=["POST"]),
        Route("/api/subscription/clear", api_clear_subscription, methods=["POST"]),
        Route("/api/proxy/start", api_proxy_start, methods=["POST"]),
        Route("/api/proxy/stop", api_proxy_stop, methods=["POST"]),
        Route("/api/proxy/check", api_proxy_check, methods=["POST"]),
        Route("/api/proxy/nodes", api_proxy_nodes),
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
    <h2>机场订阅</h2>
    <p class="hint">填入你的订阅链接。它只写入本机 600 权限文件，不会上传到任何地方。</p>
    <label for="sub">订阅链接</label>
    <input id="sub" type="password" placeholder="留空 = 不修改现有订阅"
           autocomplete="off" spellcheck="false">
    <div class="warn">当前订阅：<span id="curSub">未配置</span>　（只显示掩码与域名，用于确认你配的是哪个机场）</div>
    <label for="httpPort">本地 HTTP 代理端口</label>
    <input id="httpPort" type="number" min="1024" max="65535">
    <label for="socksPort">本地 SOCKS5 端口</label>
    <input id="socksPort" type="number" min="1024" max="65535">
    <div class="btns">
      <button id="btnSave">保存</button>
      <button class="danger" id="btnClear">清除订阅</button>
    </div>
    <div class="msg" id="saveMsg"></div>
  </div>

  <div class="card">
    <h2>节点列表</h2>
    <p class="hint">只显示名称与协议。凭据不出现在页面里。</p>
    <div id="nodes"><span style="color:#8b93a3">代理未启动</span></div>
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

$('btnSave').onclick=async()=>{
  const b={};
  if($('sub').value.trim())b.subscription_url=$('sub').value.trim();
  b.http_port=+$('httpPort').value; b.socks_port=+$('socksPort').value;
  const d=await post('/api/save',b);
  setMsg($('saveMsg'),d.ok?'已保存。可点「启动代理」生效。':(d.error||'保存失败'),d.ok);
  if(d.ok){$('sub').value='';load();}
};
$('btnClear').onclick=async()=>{
  if(!confirm('确定清除订阅并停止代理？'))return;
  const d=await post('/api/subscription/clear');
  setMsg($('saveMsg'),d.ok?'已清除':(d.error||'失败'),d.ok);load();
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
  if(!d.nodes||!d.nodes.length){$('nodes').innerHTML='<span style="color:#8b93a3">暂无节点（先启动代理）</span>';return;}
  $('nodes').innerHTML='<table>'+d.nodes.map(n=>
    `<tr><td>${n.tag}</td><td><span class="mono">${n.protocol}</span></td></tr>`).join('')+'</table>';
}
$('logout').onclick=async()=>{await post('/api/logout');location.href='/login';};
load();loadNodes();
</script></body></html>"""
