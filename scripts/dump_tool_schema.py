# -*- coding: utf-8 -*-
"""dump websearch-mcp 的 tools/list schema，定位严格模型不兼容的构造。

走真实 MCP 协议路径（fastmcp Client 内存传输），看到的就是
WorkBuddy / dsh 等客户端在 tools/list 时看到的 schema —— 包括
outputSchema。内部 FunctionTool 对象看不到这些。

用法: PYTHONPATH=src python scripts/dump_tool_schema.py [--json]
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from websearch.config import Config  # noqa: E402
from websearch.server import build_mcp  # noqa: E402


def find_keys(node, key, path="$"):
    """递归找出 schema 里所有指定 key 的位置。"""
    hits = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                hits.append(path)
            else:
                hits.extend(find_keys(v, key, f"{path}.{k}"))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits.extend(find_keys(v, key, f"{path}[{i}]"))
    return hits


async def dump(mcp):
    out = {}
    from fastmcp import Client
    async with Client(mcp) as client:
        ret = await client.list_tools_mcp()
        tools = ret.tools if hasattr(ret, "tools") else (
            ret[1] if isinstance(ret, tuple) else ret)
        for t in tools:
            out[t.name] = {
                "inputSchema": t.inputSchema,
                "outputSchema": t.outputSchema,
                "description": t.description,
            }
    return out


def main():
    mcp = build_mcp(Config.from_env())
    data = asyncio.run(dump(mcp))

    print(f"工具数: {len(data)}\n")
    bad = 0
    for name in sorted(data):
        d = data[name]
        ischema = d["inputSchema"]
        anyof = find_keys(ischema, "anyOf")
        os_ = d["outputSchema"]
        os_anyof = find_keys(os_, "anyOf") if os_ else []
        flag = ""
        if anyof:
            flag += f"  ← inputSchema anyOf x{len(anyof)}"
        if os_:
            flag += "  ← 有 outputSchema"
        if os_anyof:
            flag += f"（outputSchema anyOf x{len(os_anyof)}）"
        if flag:
            bad += 1
        print(f"[{name}]{flag}")
        for pname, pspec in (ischema.get("properties") or {}).items():
            t = pspec.get("type")
            if t is None:
                if "anyOf" in pspec:
                    t = f"anyOf{[x.get('type') for x in pspec['anyOf']]}"
                else:
                    t = "任意类型（无约束）"
            req = "必填" if pname in (ischema.get("required") or []) else "选填"
            print(f"    参数 {pname}（{req}）: {t}")
    print(f"\n合计: {bad}/{len(data)} 个工具的 schema 含严格模型不兼容构造"
          f"（anyOf / outputSchema）")

    if "--json" in sys.argv:
        print("\n" + json.dumps(data, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
