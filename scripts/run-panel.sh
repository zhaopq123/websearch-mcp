#!/bin/bash
# websearch-mcp 管理面板 —— 看门狗入口（容器内执行）
#
# 与 run-logged.sh 同结构：日志重定向必须发生在容器内
# （宿主侧没有 /opt 路径，宿主 shell 里 `>> /opt/...` 会空转）。
#
# 被 Termux 层 tmux 会话 `websearch-panel` 的守护循环调用：
#   while true; do proot-distro login ubuntu -- run-panel.sh; sleep 10; done
set -euo pipefail

APP=/opt/websearch-mcp
export PYTHONPATH="$APP/src"
export WS_CONFIG_FILE="$APP/.env"
export LOG_LEVEL="${LOG_LEVEL:-info}"

mkdir -p "$(dirname "$APP/panel.log")"
exec "$APP/venv/bin/python" -m websearch.proxy.panel_server >> "$APP/panel.log" 2>&1
