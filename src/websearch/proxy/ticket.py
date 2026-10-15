#!/usr/bin/env python3
"""签发「一键登录链接」—— 用户不用复制口令，点开即进面板。

为什么需要独立工具（而不是靠面板启动时打印）：
  面板每次启动都会签发一张票据，而**新票据会让旧票据失效**
  （同一时间只允许一个待用票据，防重放）。
  在「看门狗托管」的部署里，面板可能被重启多次 —— 启动日志里
  打印的链接可能已经被后来的实例作废了。
  由本工具在**面板稳定运行之后**签发，链接才确定可用。

顺带解决一个产品问题：用户口令丢了、或想把面板发给自己的手机用，
跑一下这个就能拿到新链接，不用去 grep .env。

用法：
    python -m websearch.proxy.ticket              # 打印链接（默认 5 分钟有效）
    python -m websearch.proxy.ticket --ttl 1800   # 自定义有效期（秒）
    python -m websearch.proxy.ticket --host 192.168.1.100 # 指定地址
"""
from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path


def detect_lan_ip() -> str:
    """探测本机局域网 IP（UDP 连接不真发包，只让内核选路由）。"""
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


def main() -> int:
    ap = argparse.ArgumentParser(description="签发 websearch-mcp 面板一键登录链接")
    ap.add_argument("--ttl", type=int, default=300, help="有效期秒数（默认 300）")
    ap.add_argument("--host", default="", help="面板地址（默认自动探测局域网 IP）")
    ap.add_argument("--config", default="", help="配置文件路径")
    args = ap.parse_args()

    # 让 import 能找到包（脚本可能从任意目录调用）
    here = Path(__file__).resolve().parents[2]
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))

    from websearch.proxy.store import Store

    cfg = Path(args.config or os.environ.get(
        "WS_CONFIG_FILE", "/opt/websearch-mcp/.env"))

    if not cfg.exists():
        print(f"找不到配置文件：{cfg}", file=sys.stderr)
        print("面板还没装？先跑 install.sh", file=sys.stderr)
        return 2

    store = Store(cfg)

    # 权限自检：不安全的文件不该继续用
    ok, detail = store.check_permissions()
    if not ok:
        print(f"⚠️  配置文件权限不安全：{detail}", file=sys.stderr)
        print(f"   修复：chmod 600 {cfg}", file=sys.stderr)
        return 2

    host = args.host or store.get("WS_PANEL_HOST", "127.0.0.1")
    port = store.get_int("WS_PANEL_PORT", 8500)

    # 面板只绑回环时，局域网地址访问不到 —— 但用户可能想用 SSH 隧道
    if host in ("127.0.0.1", "localhost", "::1"):
        lan = detect_lan_ip()
        if lan:
            # 给出两种都提示，用户按自己的部署选
            print("提示：面板只监听本机（127.0.0.1）。", file=sys.stderr)
            print("      本机访问用下面的链接；从别的设备访问需要 SSH 隧道：", file=sys.stderr)
            print(f"        ssh -N -L {port}:127.0.0.1:{port} <user>@<服务器>", file=sys.stderr)
            print(file=sys.stderr)
        base = f"http://127.0.0.1:{port}"
    else:
        lan = detect_lan_ip() or "127.0.0.1"
        base = f"http://{lan}:{port}"

    ticket = store.issue_login_ticket(ttl_sec=args.ttl)
    url = f"{base}/_open?t={ticket}"

    print()
    print("点这个链接直接进面板（不用输口令）：")
    print()
    print(f"  {url}")
    print()
    mins = args.ttl // 60
    print(f"有效期 {args.ttl} 秒（约 {mins} 分钟），用过一次即失效。")
    print("再要新链接就重跑本命令。")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
