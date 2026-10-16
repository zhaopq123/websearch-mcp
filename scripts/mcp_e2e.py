#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP 协议端到端验证：initialize → tools/list → tools/call(web_search)。

不依赖任何 MCP 客户端库，纯 HTTP，走和 WorkBuddy 完全一样的协议路径。
"""
import json
import subprocess
import sys
import time
import urllib.request

APP = "/opt/websearch-mcp"
PORT = 8300
URL = f"http://127.0.0.1:{PORT}/mcp"


def token():
    with open(f"{APP}/.tokens") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                return line.split(":")[-1]
    raise SystemExit("没有 token")


TOK = token()


def rpc(method, params, sid=None, rid=1):
    """发一次 JSON-RPC，返回 (session_id, 响应体)。"""
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if sid:
        req.add_header("mcp-session-id", sid)
    with urllib.request.urlopen(req, timeout=90) as r:
        new_sid = r.headers.get("mcp-session-id") or sid
        raw = r.read().decode("utf-8", "replace")
    # streamable-http 返回 SSE 格式，取 data: 那行
    payload = None
    for line in raw.splitlines():
        if line.startswith("data:"):
            payload = json.loads(line[5:].strip())
    if payload is None and raw.strip().startswith("{"):
        payload = json.loads(raw)
    return new_sid, payload


def main():
    print("═" * 66)
    print(" MCP 协议端到端验证")
    print("═" * 66)

    t0 = time.time()
    sid, r = rpc("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "e2e-probe", "version": "1.0"},
    })
    print(f"\n[1] initialize       {'OK' if sid else 'FAIL'}  session={sid}")
    print(f"    server: {json.dumps(r.get('result', {}).get('serverInfo', {}), ensure_ascii=False)}")
    print(f"    耗时 {int((time.time()-t0)*1000)}ms")

    # initialized 通知
    body = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {TOK}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    req.add_header("mcp-session-id", sid)
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception:
        pass

    t1 = time.time()
    _, r = rpc("tools/list", {}, sid, rid=2)
    tools = r.get("result", {}).get("tools", [])
    print(f"\n[2] tools/list       {'OK' if tools else 'FAIL'}  {len(tools)} 个工具 "
          f"({int((time.time()-t1)*1000)}ms)")
    for t in tools:
        print(f"    · {t['name']:<16} {t['description'].splitlines()[0][:60]}")

    t2 = time.time()
    _, r = rpc("tools/call", {
        "name": "web_search",
        "arguments": {"query": "无人零售 咖啡机 市场", "max_results": 6, "fresh": True},
    }, sid, rid=3)
    print(f"\n[3] tools/call web_search  ({int((time.time()-t2)*1000)}ms)")
    text = ""
    for c in r.get("result", {}).get("content", []):
        if c.get("type") == "text":
            text = c.get("text", "")
    if not text:
        print("    没有返回内容:", json.dumps(r, ensure_ascii=False)[:400])
        return 1
    data = json.loads(text)
    meta = data.get("meta", {})
    print(f"    实时: {meta.get('realtime')}   抓取时刻: {meta.get('fetched_at')}")
    print(f"    耗时 {meta.get('elapsed_ms')}ms   覆盖率 {meta.get('coverage')}   "
          f"结果 {len(data.get('results', []))} 条")
    print(f"    引擎成功: {meta.get('engines', {}).get('succeeded')}")
    print(f"    引擎失败: {[(x['engine'], x['error'][:28]) for x in meta.get('engines', {}).get('failed', [])]}")
    print()
    for i, x in enumerate(data.get("results", [])[:6], 1):
        print(f"    {i}. [{x['score']:.2f}] {x['title'][:50]}")
        print(f"       {x['url'][:76]}")
        if x.get("snippet"):
            print(f"       ↳ {x['snippet'][:66]}")

    # 实时性验证：同一 query 连续两次，第二次带 fresh 应完全不走缓存
    t3 = time.time()
    _, r2 = rpc("tools/call", {
        "name": "web_search",
        "arguments": {"query": "无人零售 咖啡机 市场", "max_results": 6, "fresh": True},
    }, sid, rid=4)
    d2 = json.loads(r2["result"]["content"][0]["text"])
    print(f"\n[4] 实时性复验       连续两次 fresh 调用")
    print(f"    第一次 realtime={meta.get('realtime')} cache_hits={meta.get('cache_hits')}")
    print(f"    第二次 realtime={d2['meta'].get('realtime')} "
          f"cache_hits={d2['meta'].get('cache_hits')}")
    ok = (d2["meta"].get("realtime") is True and d2["meta"].get("cache_hits") == 0)
    print(f"    {'OK — fresh 确实绕过了缓存' if ok else 'FAIL — fresh 没绕过缓存'}")

    # SSRF 防护验证
    _, r3 = rpc("tools/call", {
        "name": "web_fetch",
        "arguments": {"urls": "http://127.0.0.1:8300/health"},
    }, sid, rid=5)
    d3 = json.loads(r3["result"]["content"][0]["text"])
    res0 = d3.get("results", [{}])[0]
    print(f"\n[5] SSRF 防护        请求 http://127.0.0.1:8300/health")
    print(f"    ok={res0.get('ok')}  error_kind={res0.get('error_kind')}  "
          f"error={str(res0.get('error'))[:50]}")
    print(f"    {'OK — 内网地址被拒绝' if not res0.get('ok') else 'FAIL — 内网地址竟然抓成功了'}")

    print("\n" + "═" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())