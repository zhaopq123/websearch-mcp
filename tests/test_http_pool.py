# -*- coding: utf-8 -*-
"""传输层专项测试：体积上限 + schema 兼容。

这里盯两个 2026-10-13 冒烟测试抓出来的 bug：

1. **sync close 崩 async 流**：
   `HttpPool.fetch()` 的 Content-Length 预检分支曾经写 `resp.close()`
   （httpx 的同步关闭），作用在 async 流上直接抛
   "Attempted to call an sync close on an async stream."
   实测带 content-length 且超过 fetch_max_bytes 的站点**必现**
   （tiddlywiki.com / example.com），不带 content-length 的反而正常，
   所以极难在开发机复现 —— 只能靠测试钉住。

2. **参数 schema 与实现矛盾**：
   web_fetch.urls / deep_research.queries 描述写「也可传 JSON 数组」，
   inputSchema 却声明 type:string，传原生数组被 pydantic 拒。
   这里验证三种输入形态（原生数组 / JSON 数组字符串 / 逗号分隔）
   都能被正确解析。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import httpx
import pytest

from websearch.config import Config
from websearch.http_pool import HttpPool, TooLargeError


def cfg(**kw):
    c = Config.from_env()
    c.allow_private_net = True      # 这些测试不打真网络，放开内网限制
    c.allow_nonstd_port = True
    for k, v in kw.items():
        setattr(c, k, v)
    return c


async def test_no_sync_close_on_oversized_response():
    """超限响应必须抛 TooLargeError，而不是 sync-close 崩溃。"""
    pool = HttpPool(cfg(fetch_max_bytes=1024))
    captured = {}

    class FakeResponse:
        """只实现 fetch 用到的面。close() 一被调用就记录下来当失败。"""

        def __init__(self):
            self.headers = {"content-length": "999999"}
            self.content = b""

        def close(self):
            captured["sync_close"] = True

        async def aclose(self):
            captured["aclose"] = True

        async def aread(self):
            return b""

    async def fake_get(url, **kw):
        return FakeResponse()

    pool._client = httpx.AsyncClient()
    pool._client.get = fake_get  # type: ignore[method-assign]
    try:
        with pytest.raises(TooLargeError):
            await pool.fetch("http://example.com/big")
        # 关键断言：不能走同步 close 那条路
        assert "sync_close" not in captured, (
            "调了同步 close() —— 这就是生产环境的 "
            "'Attempted to call an sync close on an async stream.'"
        )
        assert captured.get("aclose") is True, "应使用 await aclose()"
    finally:
        await pool._client.aclose()
        await pool.aclose()


async def test_oversize_by_actual_body_also_raises():
    """没有 content-length 但正文超限，也要拦。"""
    pool = HttpPool(cfg(fetch_max_bytes=100))
    captured = {}

    class FakeResponse:
        def __init__(self):
            self.headers = {}          # 无 content-length，走 aread 后判长
            self.content = b"x" * 500

        async def aread(self):
            return self.content

    async def fake_get(url, **kw):
        return FakeResponse()

    pool._client = httpx.AsyncClient()
    pool._client.get = fake_get  # type: ignore[method-assign]
    try:
        with pytest.raises(TooLargeError):
            await pool.fetch("http://example.com/big")
        assert "sync_close" not in captured
    finally:
        await pool._client.aclose()
        await pool.aclose()


async def test_normal_response_passes_through():
    """正常响应不应被误伤。"""
    pool = HttpPool(cfg(fetch_max_bytes=100000))

    class FakeResponse:
        def __init__(self):
            self.headers = {"content-length": "5"}
            self.content = b"hello"
            self.url = httpx.URL("http://example.com/")
            self.status_code = 200

        async def aread(self):
            return self.content

    async def fake_get(url, **kw):
        return FakeResponse()

    pool._client = httpx.AsyncClient()
    pool._client.get = fake_get  # type: ignore[method-assign]
    try:
        resp = await pool.fetch("http://example.com/")
        assert resp.content == b"hello"
    finally:
        await pool._client.aclose()
        await pool.aclose()


# ══════════════════ 参数形态兼容 ══════════════════

@pytest.mark.parametrize("raw,expected", [
    # 逗号分隔字符串（文档主推形式）
    ("https://a.com/,https://b.com/", ["https://a.com/", "https://b.com/"]),
    # JSON 数组字符串
    ('["https://a.com/", "https://b.com/"]', ["https://a.com/", "https://b.com/"]),
    # 单个 URL
    ("https://a.com/", ["https://a.com/"]),
    # 空串 / 空数组
    ("", []),
    ("[]", []),
    # 坏 JSON 不能崩，退化成当整体处理
    ("[not-json", ["[not-json"]),
])
def test_parse_url_forms(raw, expected):
    """web_fetch.urls 三种形态都要能解析。"""
    from websearch.server import _parse_url_list

    assert _parse_url_list(raw) == expected


def test_parse_url_list_native_list():
    from websearch.server import _parse_url_list

    assert _parse_url_list(["https://a.com/", " https://b.com/ "]) == \
        ["https://a.com/", "https://b.com/"]
    assert _parse_url_list([]) == []


@pytest.mark.parametrize("raw,expected", [
    ("q1, q2", ["q1", "q2"]),
    ('["q1","q2"]', ["q1", "q2"]),
    ("q1", ["q1"]),
    ("", []),
    ("[]", []),
])
def test_parse_query_forms(raw, expected):
    """deep_research.queries 同样三种形态。"""
    from websearch.server import _parse_query_list

    assert _parse_query_list(raw) == expected


def test_parse_query_list_native_list():
    from websearch.server import _parse_query_list

    assert _parse_query_list(["q1", " q2 "]) == ["q1", "q2"]
