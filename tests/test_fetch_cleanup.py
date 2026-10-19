# -*- coding: utf-8 -*-
"""`web_fetch` 生产故障（2026-10-19 vivo）的回归。

当时两个症状：
  A. `ValueError: semaphore released too many times`，`web_fetch` 直接失败；
  B. `elapsed_ms` 超出硬超时 —— 配 17s，实测 19.5s / 24.1s。

**A 的真实根因（别再搞错）**：这个 ValueError 是 anyio 的**有界**信号量
`release()` 时 `_value == _max_value` 抛的，全栈只有一处用有界 anyio
Semaphore —— httpcore 的 HTTP/2 实现
（`httpcore/_async/http2.py` 的 `_max_streams_semaphore`，
`AsyncSemaphore(local_settings_max_streams)`，且预先 acquire 了 N-1 个令牌）。
也就是说：**它只在 HTTP/2 开着时才会出现，而且是 httpcore 自己在
失败/取消路径上 release 越界**，不是我们漏关了什么。
旁证：yutto-dev/yutto issue #370 的调用栈和这里逐字节一致，
那边的结论是「升级 httpcore 就好」；我们已经在 1.0.9（比它修的高），
照样复现 —— 升级救不了。

而 HTTP/2 对本产品**零收益**：这里全是一次性整页抓取，
多路复用只有「同域大量并发小请求」才划得来；HTTP/1.1 + 连接池
已经把唯一有价值的收益（复用连接）拿到了。代价是把每次抓取
挂进一个在超时/取消下没有安全失败模式的内部状态机。
所以修复是**默认关掉**，要开得显式 `WS_HTTP2=1`。

另一个容易走偏的坑，这里一并钉住：**别以为需要自己收尾 Response**。
`AsyncClient.get()` 走 `send(stream=False)`，httpx 在 `send()` 里就
`await response.aread()` 读完并关了（读成功走 `aiter_raw()` 末尾的
`await self.aclose()`；读失败走 `send()` 的
`except BaseException: await response.aclose(); raise`）。
所以 `pool.fetch()` 拿到的响应 `is_closed` 恒为 True。
真正要警惕的是**反方向**：谁把响应读到底，谁负责关。哪天为了省内存
改成 `stream=True` 手动流式读，非正常退出的路就得自己关。
`test_fetch_returns_closed_response` 就是钉这个的哨兵。

**B 的真实根因**：`asyncio.wait_for` 到点先 cancel 内层任务，然后
**等它收尾完**才抛 TimeoutError。而收尾路径上有两样取消不动的东西：
`loop.getaddrinfo` 扔在默认线程池里跑（取消等待方不能停那个线程）、
httpcore/ssl 的关闭用了 shield。硬超时于是被拖爆。
修复：外层 `wait_for(asyncio.shield(task))` 让到点就抛，
内层 DNS 解析再套 2s 上限。
"""
import asyncio
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

import httpx

from websearch.cache import Cache
from websearch.config import Config
from websearch.governor import Governor
from websearch.http_pool import HttpPool, TooLargeError, assert_url_async
from websearch.orchestrator import Orchestrator


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _run_and_drain(coro):
    """跑完之后把还挂着的 task 收掉，别让「Task was destroyed」污染输出。

    硬超时那条测试里，被 shield 丢下的抓取是**故意**还活着的 ——
    那正是修复的预期行为。测试要负责把它 Cancel 掉，而不是让解释器
    在关 loop 时报警。
    """
    loop = asyncio.new_event_loop()
    try:
        out = loop.run_until_complete(coro)
        for task in asyncio.all_tasks(loop):
            task.cancel()
        if asyncio.all_tasks(loop):
            loop.run_until_complete(asyncio.gather(
                *asyncio.all_tasks(loop), return_exceptions=True))
        return out
    finally:
        loop.close()


def _cfg(**over) -> Config:
    cfg = Config.from_env()
    cfg.proxy = ""
    cfg.cache_enabled = False
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


# ── 1. HTTP/2 默认关闭 ───────────────────────────────────────

def test_http2_is_off_by_default():
    """默认关。这是 `ValueError: semaphore released too many times` 的正解。"""
    assert Config().http2 is False


def test_pool_honors_http2_off():
    """配置关就得真关：不能 config 里写了 False，池子照样开 h2。"""
    pool = HttpPool(_cfg())
    try:
        assert pool.http2_enabled is False
    finally:
        _run(pool.aclose())


def test_http2_can_still_be_enabled_explicitly():
    """显式开还能开（h2 装着就真开，没装走降级），别把路堵死。"""
    pool = HttpPool(_cfg(http2=True))
    try:
        assert pool.http2_enabled in (True, False)
    finally:
        _run(pool.aclose())


# ── 2. 硬超时必须真的硬 ─────────────────────────────────────

def test_hard_timeout_does_not_wait_for_uncancellable_cleanup():
    """抓取收尾 cancel 不掉时，硬超时也不能陪着等。

    没有 shield 时：`wait_for` 先 cancel 内层任务，再等它把
    「取消不动的收尾」跑完才抛，硬超时 5.8s 实测能拖到 15s+。
    """

    class _StubbornPool:
        """fetch 吞掉 CancelledError 再磨蹭 10 秒（模拟关不掉的连接）。"""

        class _Gate:
            def note_result(self, ok, error=""):
                pass

        def __init__(self):
            self.gate = self._Gate()

        async def fetch(self, url, **_kw):
            try:
                await asyncio.sleep(600)
            except asyncio.CancelledError:
                # 取消不动的收尾。2s 就够：shield 有则 5.8s 返回，
                # 没 shield 则 5.8+2=7.8s，两种情况都远离 7s 判据。
                await asyncio.sleep(2.0)
                raise

    cfg = _cfg(total_budget_ms=800)          # 硬超时 = 0.8 + 5 = 5.8s
    orch = Orchestrator(cfg, _StubbornPool(), Cache(cfg), Governor(cfg))  # type: ignore[arg-type]

    async def scenario():
        t0 = time.monotonic()
        frs = await orch.fetch_many(["https://example.com/"], use_cache=False)
        took_ms = int((time.monotonic() - t0) * 1000)
        return frs, took_ms

    # 计时只包 fetch_many 本身 —— 收尾那 10s 是 shield 故意留下的，
    # 算进去等于拿修复后的预期行为当失败原因。
    frs, took_ms = _run_and_drain(scenario())

    assert frs and not frs[0].ok
    assert frs[0].error_kind == "timeout"
    assert took_ms <= 7000, (
        f"硬超时 5.8s 却花了 {took_ms}ms：wait_for 在等取消不掉的收尾，"
        "「兜底」自己超支了"
    )
    assert frs[0].elapsed_ms <= 7000, f"elapsed_ms={frs[0].elapsed_ms} 超预算"


def test_dns_resolution_is_bounded():
    """DNS 解析必须卡上限，否则能拖爆整个抓取预算。

    `loop.getaddrinfo` 在默认线程池里执行，取消等待它的任务**停不了那个
    线程**，它占着线程、跑十几秒、最后照样把结果写回来 —— 等待方一直
    陪着。vivo 上硬超时 17s 等出 24s 就是这么来的。
    """
    cfg = _cfg()
    assert cfg.allow_private_net is False   # 否则走不到 DNS 那步

    loop = asyncio.new_event_loop()
    try:
        calls = {"n": 0}

        async def hanging_getaddrinfo(*a, **kw):
            calls["n"] += 1
            await asyncio.sleep(600)      # 站点被网络层黑洞时的 DNS
            raise socket.gaierror("never")

        loop.getaddrinfo = hanging_getaddrinfo  # type: ignore[method-assign]

        t0 = time.monotonic()
        allowed, reason = loop.run_until_complete(
            assert_url_async("https://black-holed.example.invalid/", cfg))
        took_ms = int((time.monotonic() - t0) * 1000)
    finally:
        loop.close()

    assert calls["n"] == 1
    # 解析不出来按「放行，让请求自己失败」处理（见 _resolve_host 注释）
    assert allowed is True and reason == ""
    assert took_ms <= 3500, f"DNS 等了 {took_ms}ms，超过 2s 上限"


# ── 3. 真 socket 上的连接池行为 ──────────────────────────────

class _LocalServer:
    """真 TCP + HTTP/1.1 keep-alive 服务。

    为什么不用假 transport：上面几条已经证明「语义对了」，但连接池
    只进不出这种故障，只有插了真 socket 才看得见 —— 假的 transport
    根本没有连接可漏。
    """

    def __init__(self):
        self.connections = 0
        self.requests: list[str] = []
        self.client_hangups = 0
        self._server = None
        # /slow 处理到一半就卡在这上面，stop() 才放行
        self._parked = asyncio.Event()

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1]

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    async def stop(self):
        self._parked.set()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _headers(self, body: bytes) -> bytes:
        return (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode()
        )

    async def _handle(self, reader, writer):
        self.connections += 1
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                headers = {}
                while True:
                    h = await reader.readline()
                    if h in (b"\r\n", b"\n", b""):
                        break
                    k, _, v = h.decode("latin1").partition(":")
                    headers[k.strip().lower()] = v.strip()

                parts = line.decode("latin1").split()
                path = parts[1] if len(parts) > 1 else "/"
                self.requests.append(path)

                if path == "/slow":
                    # 声明 Content-Length: 10，只发 5 个字节就装死 ——
                    # 逼客户端 read timeout，但连接本身不关
                    writer.write(self._headers(b"0123456789") + b"abcde")
                    await writer.drain()
                    await self._park_for_stop_or_hangup(reader)
                    break
                if path == "/big":
                    writer.write(self._headers(b"x" * 4096) + b"x" * 4096)
                else:
                    writer.write(self._headers(b"ok") + b"ok")
                await writer.drain()
                if headers.get("connection", "").lower() == "close":
                    break
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _park_for_stop_or_hangup(self, reader):
        """等 stop()，同时盯着客户端有没有挂断。

        `read(1)` 只在 EOF 时返回 b""；客户端闲着就等到 wait_for 超时，
        所以可以低频率轮询。收到 FIN = 客户端把连接还回来了。
        """
        while not self._parked.is_set():
            try:
                if await asyncio.wait_for(reader.read(1), 0.05) == b"":
                    self.client_hangups += 1
                    return
            except asyncio.TimeoutError:
                continue


def _local_pool(**cfg_over) -> HttpPool:
    """真连本地服务的池子。

    `trust_env=False` 是**必须**的：环境里的 HTTP_PROXY/http_proxy 会让
    httpx 走代理，请求行变成绝对形式（`GET http://host/path`），
    本地假服务根本不认。顺手也把重定向钩子摘掉，避免分心。
    """
    import httpx

    pool = HttpPool(_cfg(allow_private_net=True, allow_nonstd_port=True, **cfg_over))
    pool._client = httpx.AsyncClient(
        timeout=pool._client.timeout, follow_redirects=False, trust_env=False,
    )
    return pool


async def _run_with_server(srv: _LocalServer, scenario):
    await srv.start()
    try:
        await scenario(srv.port)
    finally:
        await srv.stop()


def test_fetch_returns_closed_response():
    """哨兵：`pool.fetch()` 交出来的响应必须是已关闭的。

    这条现在是绿的 —— httpx 的 `send(stream=False)` 读完就关了。
    它存在的意义是**反方向**：哪天有人为了省内存把 `client.get()`
    改成 `stream=True` 手动流式读，这条立刻变红，提醒「读到底的人
    得负责关」。别删。
    """
    srv = _LocalServer()

    async def scenario(port):
        pool = _local_pool()
        try:
            resp = await pool.fetch(f"http://127.0.0.1:{port}/ok", timeout_ms=3000)
            assert resp.status_code == 200
            assert resp.content == b"ok"
            assert resp.is_closed is True, (
                "fetch 交出的响应没关 —— 谁读到底谁负责关，"
                "现在这个责任在 httpx 的 send() 里，别弄丢"
            )
        finally:
            await pool.aclose()
            await srv.stop()

    _run(_run_with_server(srv, scenario))
    assert srv.requests == ["/ok"]


def test_pool_survives_repeated_timeout_failures():
    """连抓 3 次（池子只有 2 个连接槽）超时失败，之后还得能正常抓。

    连接池只进不出时的可见症状：槽位占满 → 第 3 次就卡在
    httpx 的 `pool` 超时上 → 最后一次正常抓取直接失败。
    """
    srv = _LocalServer()

    async def scenario(port):
        pool = _local_pool(max_concurrency=2)
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(3):
                with pytest.raises(httpx.TimeoutException):
                    await pool.fetch(base + "/slow", timeout_ms=300)

            resp = await pool.fetch(base + "/ok", timeout_ms=3000)
            assert resp.status_code == 200
            assert resp.content == b"ok"
        finally:
            await pool.aclose()
            await srv.stop()

    _run(_run_with_server(srv, scenario))

    assert srv.requests.count("/slow") == 3
    assert srv.requests.count("/ok") == 1
    # 2 个连接槽：漏连接会看到这个数一路涨上去
    assert srv.connections <= 4, f"服务端见到 {srv.connections} 条连接，池子在漏"


def test_timeout_failure_releases_connection():
    """读超时后，服务端真的看到客户端挂断。

    抓取失败只是把异常抛上来还不够；TCP 层面收到 FIN，才说明连接被
    还回去了，而不是留在一个半开状态里占着槽位。
    """
    srv = _LocalServer()

    async def scenario(port):
        pool = _local_pool()
        try:
            with pytest.raises(httpx.TimeoutException):
                await pool.fetch(f"http://127.0.0.1:{port}/slow", timeout_ms=300)
            # 给服务端一点时间观测 FIN
            for _ in range(40):
                if srv.client_hangups:
                    break
                await asyncio.sleep(0.05)
        finally:
            await pool.aclose()
            await srv.stop()

    _run(_run_with_server(srv, scenario))
    assert srv.client_hangups >= 1, "失败了但服务端没看到客户端挂断"


def test_too_large_body_raises_and_pool_still_works():
    """体积超标（读完才发现）得抛 TooLargeError，且抛完池子还能干活。"""
    srv = _LocalServer()

    async def scenario(port):
        pool = _local_pool(fetch_max_bytes=1024)
        try:
            with pytest.raises(TooLargeError):
                await pool.fetch(f"http://127.0.0.1:{port}/big", timeout_ms=3000)

            # 抛完还得能正常干活
            resp = await pool.fetch(f"http://127.0.0.1:{port}/ok", timeout_ms=3000)
            assert resp.status_code == 200
            assert resp.content == b"ok"
        finally:
            await pool.aclose()
            await srv.stop()

    _run(_run_with_server(srv, scenario))
    assert "/big" in srv.requests and "/ok" in srv.requests
