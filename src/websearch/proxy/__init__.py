"""代理子系统 —— 让 websearch-mcp 能出网，但自己不携带任何节点。

设计立场（重要，写进代码也是写进文档）：

  **本包不内置、不收集、不代理任何人的节点。**
  用户的订阅链接/节点凭据只从「用户浏览器 → 本机面板」流入，
  落在 600 权限的本地文件里，不进 git、不进日志、不进遥测。

  服务出网能力的来源永远是「用户自己提供的代理」——
  本包只负责把它变成 sing-box 能吃的配置并管好进程。

模块：
  subparse —— 订阅/节点链接 → sing-box outbound 配置
  manager  —— sing-box 进程生命周期、健康检查、故障降级
"""

from .manager import ProxyManager, ProxyState
from .subparse import (
    Node,
    NodeParseError,
    ParseReport,
    SubscriptionError,
    build_singbox_config,
    parse_node,
    parse_subscription_text,
)

__all__ = [
    "Node",
    "NodeParseError",
    "ParseReport",
    "ProxyManager",
    "ProxyState",
    "SubscriptionError",
    "build_singbox_config",
    "parse_node",
    "parse_subscription_text",
]
