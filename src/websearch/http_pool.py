"""传输层 —— httpx 连接池 + 浏览器伪装 + 反爬识别 + SSRF 防护。

三个职责合一的原因：它们都作用在「一次 HTTP 请求」这个粒度上，
拆开会导致调用方要连着调三个模块，容易漏掉安全检查。
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import re
import socket
from typing import Any
from urllib.parse import urlsplit

import httpx

from .config import Config

log = logging.getLogger("websearch.http")


class TooLargeError(Exception):
    """响应体积超过上限。

    自定义而不是用 httpx 的内置异常：httpx 各版本对「响应过大」的异常名
    并不统一（早期版本根本没有），自定义一个最稳。
    """


class BlockedRedirectError(Exception):
    """重定向目标未通过 SSRF 校验。

    单独一个异常类型而不是复用 TooLargeError 那种通用错误：
    调用方要能把它归类成 blocked_url（安全拦截），
    而不是当成网络故障去重试——重试一个被安全策略拦下的 URL 没有意义。
    """

# ── UA 池：真实浏览器版本号 ──
# ⚠️ 实测教训（2026-10-13，vivo 国内网络）：
# 必应对 UA 极其敏感 —— 用 Firefox/Safari/Edge 的 UA 时，它**不返回 403，
# 而是返回一批和查询完全无关的随机结果**（东京爱情故事、考研、DOVE 论文…）。
# 这种「投毒式反爬」比直接封禁危险得多：调用方拿到的是看起来正常的成功响应。
# 解决办法：UA 池按市场份额**加权**，Chrome/Windows 占绝大多数。
# 纯随机轮换在这里是负优化。
_CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
_CHROME_WIN2 = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
_CHROME_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
_FF_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
_SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
           "(KHTML, like Gecko) Version/18.1 Safari/605.1.15")
_EDGE = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
         "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0")
_MOBILE_IOS = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1")
_MOBILE_ANDROID = ("Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")

# 加权池：Chrome/Windows 出现 4 次，其余各 1 次
USER_AGENTS = [
    _CHROME_WIN, _CHROME_WIN, _CHROME_WIN2, _CHROME_WIN,
    _CHROME_MAC, _FF_WIN, _SAFARI, _EDGE,
]
MOBILE_UA = [_MOBILE_IOS, _MOBILE_ANDROID]

_ACCEPT_LANGS = [
    "zh-CN,zh;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "zh-TW,zh;q=0.9,en;q=0.8",
]

# Accept-Encoding 必须按实际解压能力声明。
# 血泪教训：无脑写 "gzip, deflate, br" 而环境没装 brotli 时，
# 服务端会愉快地返回 br 压缩的内容，httpx 解不开，
# 拿到的就是一堆二进制乱码 —— 而且**不会报错**，
# 表现为「引擎解析出 0 条」，极难定位。
try:
    import brotli  # noqa: F401

    ACCEPT_ENCODING = "gzip, deflate, br"
    HAVE_BROTLI = True
except ImportError:  # pragma: no cover
    ACCEPT_ENCODING = "gzip, deflate"
    HAVE_BROTLI = False


def browser_headers(referer: str = "", ua: str = "", mobile: bool = False) -> dict[str, str]:
    """构造一套完整的浏览器请求头。

    关键：只换 UA 而其它头保持 httpx 默认值 = 一眼假。
    Sec-Fetch-* 是现代浏览器必带的，缺了会被 CDN 风控直接判为脚本。

    ua 非空时**强制使用**指定 UA —— 引擎层可以据此固定 UA，
    避免随机轮换踩到「投毒式反爬」。
    """
    if not ua:
        ua = random.choice(MOBILE_UA if mobile else USER_AGENTS)
    h = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(_ACCEPT_LANGS),
        "Accept-Encoding": ACCEPT_ENCODING,
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if not referer else "same-origin",
        "Sec-Fetch-User": "?1",
        "Connection": "keep-alive",
    }
    # Sec-CH-UA 只对 Chromium 系发；Firefox/Safari 发这个反而露馅
    if "Chrome" in ua and "Edg" not in ua and "Firefox" not in ua:
        h["Sec-CH-UA"] = '"Chromium";v="131", "Not_A Brand";v="24"'
        h["Sec-CH-UA-Mobile"] = "?0"
        h["Sec-CH-UA-Platform"] = '"Windows"'
    if referer:
        h["Referer"] = referer
    return h


# ── 反爬识别 ──
BLOCK_STATUS = {401, 403, 429, 503}
BLOCK_MARKERS = (
    "captcha", "recaptcha", "are you a human", "verify you are human",
    "unusual traffic", "automated access", "access denied", "robot check",
    "访问验证", "请输入验证码", "安全验证", "检测到异常", "异常流量",
    "人机验证", "请完成验证", "拒绝访问", "访问过于频繁", "操作过于频繁",
    "too many requests", "rate limit exceeded", "blocked by",
    # 反爬页的**资源指纹**：这些是搜狗/百度验证页特有的 js/css 引用，
    # 页面文案可能没有关键词，但资源名一定在。
    "antispider", "verify.css", "seccodeInput", "wappass",
    # 头条的反爬页特征：文案干净，只有 JS 标记，抓不到就永远被误判成解析失败
    "isCheating", "pc_captcha", "id=\"pc_captcha\"",
)


# 只出现在页面中部的反爬标记（头部扫描抓不到，需要扫全文）
DEEP_BLOCK_MARKERS = (
    "ischeating", "pc_captcha", "antispider", "verify.css",
    "seccodeinput", "wappass", "unusual traffic",
)


# 预编译正则：IGNORECASE 直接扫原串，不做 body.lower() 全量拷贝。
# 压测实测：4MB 响应页 lower() 单次约 1.5ms，高并发 × 多引擎下每秒几十 MB 的
# 拷贝在手机 CPU 上是净浪费。re 的 IGNORECASE 扫描在 C 层完成，零拷贝。
# 语义与旧版一致：DEEP 列表当前全部已包含在 BLOCK_MARKERS 里（大小写不敏感），
# 头部未命中时增量只来自 4000 字符之后的正文，与旧版「全文扫描」等价。
_BLOCK_RE = re.compile("|".join(re.escape(m) for m in BLOCK_MARKERS), re.IGNORECASE)
_DEEP_RE = re.compile("|".join(re.escape(m) for m in DEEP_BLOCK_MARKERS), re.IGNORECASE)


def detect_block(status: int, body: str) -> tuple[bool, str]:
    """判断是否被反爬拦截。

    两段扫描（零拷贝实现）：
      · 短关键词扫前 4000 字符（绝大多数验证页在头部）；
      · 反爬特征标记只扫 4000 字符之后的部分（头条/搜狗这类把
        pc_captcha、isCheating 埋在页面中部的，必须扫到中部以后）。
    """
    if status in BLOCK_STATUS:
        return True, f"http_{status}"
    if not body:
        return False, ""
    m = _BLOCK_RE.search(body, 0, 4000)
    if m:
        return True, f"marker:{m.group(0)}"
    if len(body) > 4000:
        m = _DEEP_RE.search(body, 4000)
        if m:
            return True, f"deep_marker:{m.group(0)}"
    return False, ""


# ── SSRF 防护 ──

def _is_disallowed_ip(ip: ipaddress._BaseAddress) -> bool:
    # IPv4-mapped IPv6（::ffff:127.0.0.1、::ffff:169.254.169.254）必须先解包：
    # 这类地址的 is_private / is_loopback 对映射部分**不生效**，
    # 直接判会把内网地址当公网放过去 —— 经典 SSRF 绕过手法。
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def check_url(url: str, cfg: Config) -> tuple[bool, str]:
    """同步部分的 URL 安全检查（scheme / 端口 / 凭据 / 字面 IP）。

    返回 (allowed, reason)。DNS 解析放异步函数里做，见 assert_url_async。
    """
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return False, "bad_url"

    if p.scheme.lower() not in ("http", "https"):
        return False, f"scheme_not_allowed:{p.scheme}"
    if p.username or p.password:
        return False, "credentials_in_url"
    host = p.hostname
    if not host:
        return False, "no_host"

    # 指向本机的**名字**也要拦：只查字面 IP 会漏掉 localhost / *.local /
    # metadata.google.internal 这类（它们靠 DNS 才解析得出是内网）。
    hl = host.lower().rstrip(".")
    if hl == "localhost" or hl.endswith(".localhost") or hl.endswith(".local"):
        return False, f"private_host:{host}"
    if hl in ("metadata.google.internal", "metadata", "instance-data"):
        return False, f"private_host:{host}"

    if cfg.domain_blocklist:
        h = host.lower()
        for d in cfg.domain_blocklist:
            if h == d.lower() or h.endswith("." + d.lower()):
                return False, f"domain_blocked:{d}"
    if cfg.domain_allowlist:
        h = host.lower()
        ok = any(h == d.lower() or h.endswith("." + d.lower()) for d in cfg.domain_allowlist)
        if not ok:
            return False, "domain_not_in_allowlist"

    port = p.port or (443 if p.scheme.lower() == "https" else 80)
    if not cfg.allow_nonstd_port and port not in (80, 443):
        return False, f"port_not_allowed:{port}"

    # 字面 IP 直接判定（无需 DNS）
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and not cfg.allow_private_net and _is_disallowed_ip(ip):
        return False, f"private_ip:{host}"

    return True, ""


async def assert_url_async(url: str, cfg: Config) -> tuple[bool, str]:
    """完整校验：同步检查 + DNS 解析后逐 IP 检查。

    DNS 解析是阻塞调用，扔进线程池避免卡住事件循环——
    这是 asyncio 服务里最常见的性能事故来源。
    """
    allowed, reason = check_url(url, cfg)
    if not allowed:
        return False, reason
    if cfg.allow_private_net:
        return True, ""

    host = urlsplit(url.strip()).hostname or ""
    try:
        infos = await _resolve_host(host)
    except Exception as e:  # 解析失败 = 域名不存在，放行让请求自己失败
        log.debug("DNS 解析失败 %s: %s", host, e)
        return True, ""

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _is_disallowed_ip(ip):
            return False, f"private_ip_resolved:{ip}"
    return True, ""


async def _resolve_host(host: str, timeout: float = 2.0) -> list:
    """解析域名，**最多等 timeout 秒**。

    为什么必须卡时间：`loop.getaddrinfo` 扔进线程池执行，取消等待它的任务
    并不能让那个线程停下 —— 它照样占着线程、照样最后把结果写回来。
    vivo 生产实测：站点被网络层黑洞时 DNS 能拖十几秒，`wait_for` 的取消
    就一直等这个线程，硬超时 17s 等出 24s。用 `wait_for` 包一层，让等待方
    到点就走（线程爱跑多久跑多久，不再占调用方的预算）。

    超时按「解析不出来」处理，和 DNS 失败同路径 —— 交给真正的请求去失败，
    错误信息反而更诚实。
    """
    return await asyncio.wait_for(
        asyncio.get_running_loop().getaddrinfo(
            host, None, proto=socket.IPPROTO_TCP
        ),
        timeout=timeout,
    )


async def check_redirect_sync(url: str, cfg: Config) -> tuple[bool, str]:
    """**重定向每一跳**都要过的 SSRF 校验。

    为什么必须单独做：httpx 的 follow_redirects=True 会在库内部自动跟随
    302/307，而 assert_url_async 只校验了**最初**那个 URL。攻击流程很直接：
    给一个公网 URL，让它 302 跳到 http://169.254.169.254/（云元数据）或
    内网某服务 —— 首跳校验全是公网 IP，顺利通过，然后 httpx 替我们把请求
    打进了内网。SSRF 防线形同虚设。

    这里挂 httpx 的 response 校验钩子：每收到一个响应，如果它是重定向，
    就把 Location 目标也送进同一套 check_url 流程。拦下的重定向直接抛
    _BlockedRedirect，最终由调用方归类成 blocked_url。
    """
    if cfg.allow_private_net:
        return True, ""
    allowed, reason = check_url(url, cfg)
    if not allowed:
        return False, reason

    host = urlsplit(url.strip()).hostname or ""
    try:
        infos = await _resolve_host(host)
    except Exception as e:
        log.debug("重定向目标 DNS 解析失败 %s: %s", host, e)
        return True, ""

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _is_disallowed_ip(ip):
            return False, f"redirect_private_ip:{ip}"
    return True, ""


class HttpPool:
    """全局共享的 httpx 连接池。

    为什么全局单例：
      · TCP/TLS 握手在手机 ARM + 4G/WiFi 上的代价很高，复用连接是最大的单点优化
      · 每引擎建一个 client 会让连接池碎片化，keepalive 命中率暴跌
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        limits = httpx.Limits(
            max_connections=cfg.max_concurrency,
            # keepalive 池跟随连接上限：早停/限流跳过的请求会瞬间释放连接，
            # 保留更多空闲连接让下一波搜索直接复用。手机 ARM 上一次 TCP+TLS
            # 握手实测 200-400ms，比搜索本身还贵，复用是最大的单点优化。
            max_keepalive_connections=cfg.max_concurrency,
            keepalive_expiry=60.0,
        )
        timeout = httpx.Timeout(
            connect=cfg.connect_timeout_ms / 1000.0,
            read=cfg.engine_timeout_ms / 1000.0,
            write=5.0,
            # 连接池获取超时 2s->5s：高并发下等连接槽位是正常排队，
            # 2s 就 PoolTimeout 会把本来能成功的请求白白判失败。
            pool=5.0,
        )
        kwargs: dict[str, Any] = dict(
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=cfg.max_redirects,
            verify=cfg.verify_ssl,
            headers=browser_headers(),
        )
        if cfg.proxy:
            kwargs["proxy"] = cfg.proxy
        # HTTP/2 需要 h2 包。没装就降级到 1.1，而不是让整个服务起不来 ——
        # 搜索结果页走 1.1 完全够用，h2 的收益主要在高并发同域复用。
        if cfg.http2:
            try:
                import h2  # noqa: F401

                kwargs["http2"] = True
                self.http2_enabled = True
            except ImportError:
                log.warning("未安装 h2，HTTP/2 已禁用（pip install 'httpx[http2]' 可启用）")
                self.http2_enabled = False
        else:
            self.http2_enabled = False

        # 代理健康门：只管决策（该走代理还是直连），client 由这里建。
        # 为什么不在 gate 里建 client：会变成两套连接池，keepalive 复用失效。
        # 手机 ARM 上一次 TCP+TLS 握手 200-400ms，比搜索本身还贵。
        from .proxy.gate import ProxyGate

        self._base_kwargs = kwargs      # 供 attach_proxy 动态重建 client
        self.gate = ProxyGate(cfg.proxy, enabled=bool(cfg.proxy))

        self._client = httpx.AsyncClient(**kwargs)
        self._client.event_hooks["response"].append(self._guard_redirect)
        # 直连 client：仅当配了代理时才需要（用于降级）。
        # 未配代理时 _client 本身就是直连，不重复建。
        self._direct_client: httpx.AsyncClient | None = None
        if self.gate.enabled:
            direct_kwargs = {k: v for k, v in kwargs.items() if k != "proxy"}
            self._direct_client = httpx.AsyncClient(**direct_kwargs)
            self._direct_client.event_hooks["response"].append(self._guard_redirect)
        # 并发闸门：限制同时在飞的请求数，保护 vivo 的 3.7G 内存和有限 fd
        self._sem = asyncio.Semaphore(cfg.max_concurrency)
        self.inflight = 0
        self.total_requests = 0
        # 代理自动恢复的后台任务（配了代理才启动）
        self._recovery_task: asyncio.Task | None = None

    async def _guard_redirect(self, response: httpx.Response) -> None:
        """httpx 的 response event hook：自动跟随重定向前逐跳校验 SSRF。

        httpx 每次准备跟随重定向时都会调这个钩子。抛出异常即中止整条
        重定向链，请求方拿到的是 BlockedRedirectError。

        只校验 3xx：非重定向响应没有下一个目标，无需检查。
        """
        if response.status_code < 300 or response.status_code >= 400:
            return
        loc = response.headers.get("location", "")
        if not loc:
            return
        # 相对地址要按当前 URL 拼成绝对地址，否则 urlsplit 出来的 host 是空
        target = str(response.url.join(loc))
        allowed, reason = await check_redirect_sync(target, self.cfg)
        if not allowed:
            log.warning("拦截危险重定向 %s -> %s (%s)",
                        response.url, target, reason)
            raise BlockedRedirectError(
                f"redirect_blocked:{reason}")

    @property
    def client(self) -> httpx.AsyncClient:
        return self._client

    def active_client(self) -> httpx.AsyncClient:
        """当前该用哪个 client（代理 or 直连）。

        未配代理时恒返回主 client，行为与加代理功能之前完全一致。
        """
        if self.gate.enabled and self.gate.state.bypassed and self._direct_client:
            return self._direct_client
        return self._client

    async def probe_proxy(self) -> bool:
        """探活：经代理访问墙外站点，判定代理是否真能出网。

        不用「TCP 端口通」判定：sing-box 进程活着但节点失效时端口照样
        监听，那种「健康」会让服务一直走死代理。
        """
        try:
            r = await self._client.get(
                self.gate.PROBE_URL, timeout=8.0, follow_redirects=False
            )
            return r.status_code in (200, 204)
        except Exception:
            return False

    async def maybe_recover_proxy(self) -> None:
        """旁路状态下定期探活并在恢复后切回代理。搜索前调用，开销极小。"""
        if self.gate.enabled and self.gate.state.bypassed:
            await self.gate.maybe_probe(self.probe_proxy)

    async def attach_proxy(self, proxy_url: str) -> bool:
        """运行时把出网切到指定代理（用于「服务自养节点」自动出网）。

        为什么需要动态切换：节点猎手在服务进程内用节点库最优节点起了
        一个 sing-box（见 nodes/local_proxy.py），而起之前 HttpPool 已经
        按 cfg.proxy 建好了 client。没有这个方法，就得重启服务才能用上
        自养节点 —— 那「不用用户配节点」就是空话。

        做四件事：关旧 client → 重建走代理 client → 重建直连 client
        （降级用）→ 重建 gate（重置失败计数与降级状态）。
        """
        from .proxy.gate import ProxyGate

        if not proxy_url:
            return False
        try:
            await self._client.aclose()
            if self._direct_client is not None:
                await self._direct_client.aclose()
        except Exception:
            pass
        kwargs = dict(self._base_kwargs)
        kwargs["proxy"] = proxy_url
        self._client = httpx.AsyncClient(**kwargs)
        self._client.event_hooks["response"].append(self._guard_redirect)
        direct_kwargs = {k: v for k, v in kwargs.items() if k != "proxy"}
        self._direct_client = httpx.AsyncClient(**direct_kwargs)
        self._direct_client.event_hooks["response"].append(self._guard_redirect)
        self.gate = ProxyGate(proxy_url, enabled=True)
        log.info("出网已切到自养节点代理：%s", proxy_url)
        return True

    def start_proxy_recovery_loop(self) -> None:
        """后台探活循环：即使**没有任何搜索请求**，也能自动恢复代理。

        为什么必须有这个：恢复逻辑原来只挂在搜索路径上
        （maybe_recover_proxy 由 orchestrator 调）。于是
        「代理坏了 → 降级 → 之后没人搜 → 永远不恢复」。
        实测踩坑：代理明明正常，服务却一直直连，且没有任何自愈迹象。

        无流量时每 15 秒探一次（有流量时由搜索路径探，不重复）。
        """
        if not self.gate.enabled or self._recovery_task is not None:
            return

        async def loop() -> None:
            while True:
                try:
                    await asyncio.sleep(15)
                    if self.gate.state.bypassed:
                        await self.gate.maybe_probe(self.probe_proxy)
                except asyncio.CancelledError:
                    return
                except Exception:
                    continue

        self._recovery_task = asyncio.create_task(loop())

    @property
    def sem(self) -> asyncio.Semaphore:
        return self._sem

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        timeout_ms: int | None = None,
        max_bytes: int | None = None,
        referer: str = "",
        direct: bool = False,
    ) -> httpx.Response:
        """发起请求，带并发闸门 + 大小上限。

        direct=True 时绕过本地代理走直连（2026-10-15：国内引擎用）——
        直连 client 在 __init__ 里已按需建好（_direct_client）。
        

        max_bytes 用流式读取实现：先看 Content-Length，超了直接放弃，
        避免把 100MB 的页面读进内存（vivo 只有 3.7G）。
        """
        cap = max_bytes or self.cfg.fetch_max_bytes
        async with self._sem:
            self.inflight += 1
            self.total_requests += 1
            try:
                req_headers = browser_headers(
                    referer=referer,
                    ua=(headers or {}).get("User-Agent", ""),
                    mobile=(headers or {}).get("X-Mobile", "") == "1",
                )
                if headers:
                    req_headers.update(headers)
                req_headers.pop("X-Mobile", None)

                kw: dict[str, Any] = {}
                if timeout_ms:
                    kw["timeout"] = httpx.Timeout(
                        connect=self.cfg.connect_timeout_ms / 1000.0,
                        read=timeout_ms / 1000.0,
                        write=5.0,
                        pool=2.0,
                    )

                # 按代理健康状态选 client（未配代理时恒为主 client，行为不变）
                # direct=True（国内引擎）：绕过代理走直连。
                # 其余沿用 active_client()（含代理 bypass 的自愈逻辑）。
                client = ((self._direct_client or self._client)
                          if direct else self.active_client())
                try:
                    if method.upper() == "POST":
                        resp = await client.post(
                            url, headers=req_headers, data=data, params=params, **kw
                        )
                    else:
                        resp = await client.get(
                            url, headers=req_headers, params=params, **kw
                        )
                except Exception as e:
                    # 把失败反馈给代理门：连续「代理类」失败会触发降级直连。
                    # 非代理类错误（如 DNS 解析失败）不计入，避免误降级。
                    self.gate.note_result(False, f"{type(e).__name__}: {e}")
                    raise
                self.gate.note_result(True)

                # 体积预检：Content-Length 超标直接放弃，省掉传输。
                # ⚠️ 必须 await resp.aclose() —— httpx.Response.close() 是**同步**
                # 关闭，作用在 async 流上会抛
                # "Attempted to call an sync close on an async stream."
                # （2026-10-13 实测：tiddlywiki.com / example.com 必现，
                #  不带 content-length 的 example.org 反而正常，所以极难复现定位）
                cl = resp.headers.get("content-length")
                if cl and cl.isdigit() and int(cl) > cap:
                    try:
                        await resp.aclose()
                    except Exception:
                        pass
                    raise TooLargeError(f"content-length {cl} > cap {cap}")
                await resp.aread()
                if len(resp.content) > cap:
                    raise TooLargeError(
                        f"body {len(resp.content)} > cap {cap}")
                return resp
            finally:
                self.inflight -= 1

    async def aclose(self) -> None:
        if self._recovery_task is not None:
            self._recovery_task.cancel()
            self._recovery_task = None
        await self._client.aclose()
        if self._direct_client is not None:
            await self._direct_client.aclose()

    def stats(self) -> dict[str, Any]:
        return {
            "inflight": self.inflight,
            "total_requests": self.total_requests,
            "max_concurrency": self.cfg.max_concurrency,
            "proxy": self.gate.state.to_dict(),
        }
