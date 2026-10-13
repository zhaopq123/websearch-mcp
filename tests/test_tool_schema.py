# -*- coding: utf-8 -*-
"""工具 schema 兼容性回归测试。

背景（2026-10-13）：严格模型（Step-5-Preview / GLM-5.3-Flash /
Deepseek-V4.1-Flash）逐字校验 tools/list 的工具定义，两个构造会
让整个请求在进模型前被拒：

  1. outputSchema —— FastMCP 默认对返回 dict 的工具自动生成
     （{"additionalProperties": true, "type": "object"}），
     模型侧报 11129 "The tool definition does not meet the model
     requirements"，inputTokens: 0；
  2. inputSchema 里的 anyOf —— 参数写 `str | list[str]` 就会生成，
     同样被拒（11133 input_invalid）。

本测试锁死这两个约束：新增/修改工具时若破坏，CI 直接红。
"""
import json

import pytest

from websearch.config import Config
from websearch.server import build_mcp

# 注意：pytest 已配置 asyncio_mode=auto，async 测试自动生效。
# 这里刻意不再写模块级 pytestmark —— 会把同步测试也标成 asyncio，
# 触发 "marked with '@pytest.mark.asyncio' but it is not an async function" 警告。


def _walk(node, key):
    """递归收集 schema 里指定 key 出现的路径。"""
    hits = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                hits.append("$.anyOf" if key == "anyOf" else f"$.{k}")
            else:
                hits.extend(_walk(v, key))
    elif isinstance(node, list):
        for v in node:
            hits.extend(_walk(v, key))
    return hits


@pytest.fixture(scope="module")
def tool_schemas():
    """走真实 MCP 协议路径拿 tools/list —— 和客户端看到的一致。"""
    from fastmcp import Client

    async def collect():
        mcp = build_mcp(Config.from_env())
        async with Client(mcp) as client:
            ret = await client.list_tools_mcp()
            return {t.name: t for t in ret.tools}

    import asyncio

    return asyncio.run(collect())


def test_all_tools_have_no_output_schema(tool_schemas):
    """任何工具都不许生成 outputSchema（严格模型 11129 根因）。"""
    offenders = [n for n, t in tool_schemas.items() if t.output_schema is not None]
    assert not offenders, (
        f"这些工具还带着 outputSchema，严格模型会拒：{offenders}。"
        "检查 @mcp.tool(...) 是否漏了 output_schema=None"
    )


def test_all_tools_input_schema_has_no_anyof(tool_schemas):
    """inputSchema 里不许出现 anyOf（严格模型 11133 根因）。

    注意：参数要支持多形态（如 urls 收字符串/数组），类型必须写 Any，
    写 `str | list[str]` 会生成 anyOf。
    """
    offenders = {n: _walk(t.input_schema, "anyOf")
                 for n, t in tool_schemas.items()}
    offenders = {n: p for n, p in offenders.items() if p}
    assert not offenders, (
        f"这些工具的 inputSchema 含 anyOf：{offenders}。"
        "把联合类型参数改成 Any（运行时解析函数已支持多形态）"
    )


def test_tool_count_stable(tool_schemas):
    """工具数量锁定 9 个——新增工具必须同步过上面两条约束。

    9 = 7 个搜索类工具 + node_hunt / node_pool（节点自养池）。
    """
    assert len(tool_schemas) == 9


def test_multi_form_params_accept_any_type(tool_schemas):
    """web_fetch.urls / deep_research.queries 必须是无约束参数。"""
    for name, param in [("web_fetch", "urls"), ("deep_research", "queries")]:
        spec = tool_schemas[name].input_schema["properties"][param]
        assert spec.get("type") is None, f"{name}.{param} 应有 type 约束"
        assert "anyOf" not in spec, f"{name}.{param} 不应含 anyOf"
        assert param in tool_schemas[name].input_schema["required"]


async def test_multi_form_urls_runtime_behavior(tool_schemas):
    """回归运行时：三种 urls 形态都必须解析出正确条数。"""
    from websearch.server import _parse_url_list, _parse_query_list

    target = "http://127.0.0.1:9/x"
    for form in (target, json.dumps([target]), [target]):
        assert _parse_url_list(form) == [target]
    assert _parse_url_list(f"{target},{target}") == [target, target]
    assert _parse_query_list("a,b") == ["a", "b"]
    assert _parse_query_list(["a", "b"]) == ["a", "b"]
    assert _parse_query_list('["a"]') == ["a"]


async def test_call_tool_through_real_protocol():
    """端到端：真实协议调用一次 web_search 空参数（错误路径不崩）。"""
    from fastmcp import Client

    mcp = build_mcp(Config.from_env())
    async with Client(mcp) as client:
        r = await client.call_tool("web_search", {"query": ""})
        data = r.data if isinstance(r.data, dict) else json.loads(r.content[0].text)
        assert "error" in data
        assert data["results"] == []
