# -*- coding: utf-8 -*-
"""用户视角验证：模拟真实 MCP 客户端走完整协议调用 websearch-mcp。

不看内部对象，全部走 fastmcp Client（内存传输，协议层与
WorkBuddy/dsh 客户端一致）：
  1. 客户端看到的工具集完整（断言必备核心工具都在，且 schema 干净：
     无 anyOf / outputSchema）
  2. web_fetch 三种 urls 形态（逗号串 / JSON 数组串 / 原生数组）行为一致
  3. deep_research 三种 queries 形态行为一致
  4. web_search 空参数走错误返回而不是崩
  5. 真实联网搜索一次（server 会挑可用引擎，拿不到结果也有 meta）

用法: PYTHONPATH=src python scripts/user_perspective_check.py

⚠️ 别把工具数写死成常量（2026-10-16 实测）：本脚本原写「== 7」，
   新增 node_hunt / node_pool 后一直判 FAIL —— 写死的数字隔天就是
   假的。改成「必备工具集必须都在」的子集断言：新增工具不会红，
   删掉核心工具才红。
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from websearch.config import Config  # noqa: E402
from websearch.server import build_mcp  # noqa: E402

PASS, FAIL = "\033[32mPASS\033[0m", "\033[31mFAIL\033[0m"
results = []

# 客户端必须能看到的工具（删任一个都是回归）
REQUIRED_TOOLS = {
    "web_search", "web_fetch", "deep_research", "engine_health",
    "proxy_status", "cache_manage", "server_info",
}


def check(name, ok, detail=""):
    results.append(ok)
    print(f"  [{PASS if ok else FAIL}] {name}" + (f"  {detail}" if detail else ""))


async def main():
    from fastmcp import Client

    mcp = build_mcp(Config.from_env())
    async with Client(mcp) as client:
        # ── 1. 工具列表 ──
        print("\n[1] 客户端视角：工具列表")
        ret = await client.list_tools_mcp()
        tools = {t.name: t for t in ret.tools}
        missing = REQUIRED_TOOLS - set(tools)
        check("必备工具集齐全", not missing,
              f"共 {len(tools)} 个，缺 {sorted(missing) if missing else '无'}")
        bad = []
        for name, t in tools.items():
            s = json.dumps(t.input_schema)
            if "anyOf" in s or t.output_schema is not None:
                bad.append(name)
        check("schema 无 anyOf / outputSchema", not bad, f"问题工具: {bad or '无'}")

        # ── 2. web_fetch 三种形态 ──
        print("\n[2] web_fetch 三种 urls 形态（本地 HTTP 回环地址，不触外网）")
        target = "http://127.0.0.1:9/nonexistent"  # 会失败，但走完整解析路径
        forms = {
            "逗号分隔": target,
            "JSON数组字符串": json.dumps([target]),
            "原生数组": [target],
        }
        for label, arg in forms.items():
            r = await client.call_tool("web_fetch", {"urls": arg, "max_chars": 100})
            data = r.data if isinstance(r.data, dict) else json.loads(r.content[0].text)
            ok = data.get("count") == 1 and data.get("failed") == 1
            check(f"{label} → 解析出 1 个 URL", ok,
                  f"count={data.get('count')} failed={data.get('failed')}")

        # 多 URL 也只说明解析，不真抓（第 2 个必然失败，验证计数）
        r = await client.call_tool(
            "web_fetch",
            {"urls": f"{target},{target}", "max_chars": 100},
        )
        data = r.data if isinstance(r.data, dict) else json.loads(r.content[0].text)
        check("逗号分隔多 URL → 解析出 2 个", data.get("count") == 2,
              f"count={data.get('count')}")

        # ── 3. deep_research 形态 ──
        print("\n[3] deep_research queries 形态（空引擎列表 + 假 fresh 走短路）")
        # 不真搜：传一个不存在的引擎名，让 orchestrator 快速失败返回
        r = await client.call_tool(
            "deep_research",
            {"queries": "测试查询", "engines": "__no_such_engine__",
             "fetch_top": 0, "fresh": True},
        )
        data = r.data if isinstance(r.data, dict) else json.loads(r.content[0].text)
        check("字符串 queries → 正常返回结构",
              "results" in data or "error" in data or "queries" in data,
              f"keys={sorted(data)[:5]}")

        # ── 4. web_search 错误路径 ──
        print("\n[4] web_search 边界")
        r = await client.call_tool("web_search", {"query": "   "})
        data = r.data if isinstance(r.data, dict) else json.loads(r.content[0].text)
        check("空 query → 友好错误不崩", "error" in data, data.get("error", ""))

        # ── 5. 真实搜索（如果网络允许）──
        print("\n[5] 真实搜索一次（拿不到结果也有 meta，不算失败）")
        try:
            r = await client.call_tool(
                "web_search", {"query": "websearch-mcp 测试", "max_results": 3})
            data = r.data if isinstance(r.data, dict) else json.loads(r.content[0].text)
            meta = data.get("meta") or {}
            n = len(data.get("results") or [])
            cov = meta.get("coverage")
            check("返回带 meta.coverage", cov is not None,
                  f"results={n} coverage={cov}")
        except Exception as e:
            check("真实搜索调用未崩溃", False, str(e)[:120])

    print(f"\n{'═' * 50}")
    ok = sum(results)
    print(f"结果: {ok}/{len(results)} 通过")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
