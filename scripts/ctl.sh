#!/bin/bash
# websearch-mcp 运维脚本（不在 PATH，用绝对路径调用）
#   bash /opt/websearch-mcp/scripts/ctl.sh {status|restart|logs|health|warmup|token|test}
#
# 监督模型（2026-10-13 起：宿主看门狗，原容器内 tmux 方案已废弃）
#   Termux 宿主 tmux 会话 websearch：
#     while true; do proot-distro login ubuntu -- start-mcp.sh >> service.log 2>&1; sleep 10; done
#   开机由 ~/.termux/boot/start-services -> ubuntu-autostart 第 2e 节幂等创建
#   => python 崩溃 10s 内自动重拉；手机重启后自动恢复
#   restart 的语义 = 杀 python，看门狗约 15-25s 后重拉
set -uo pipefail

APP=/opt/websearch-mcp
LOGFILE="$APP/service.log"
PORT="${WS_PORT:-8300}"
MCP_PATH="${WS_MCP_PATH:-/mcp}"
TOKEN_FILE="$APP/.tokens"

port_pid() {
  ss -tlnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $NF}' \
    | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1
}

wait_health() { # $1=超时秒
  local deadline=$(( $(date +%s) + ${1:-60} ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    curl -s -m 3 "http://127.0.0.1:$PORT/health" | grep -q '"ok":true' && return 0
    sleep 2
  done
  return 1
}

case "${1:-status}" in
  status)
    PID=$(port_pid)
    if [ -n "$PID" ]; then
      echo "运行中 (pid $PID, :$PORT)"
      curl -s -m 5 "http://127.0.0.1:$PORT/health" | head -c 600; echo
    else
      echo "未监听 :$PORT —— 查宿主看门狗面板："
      echo "  ssh <your-host> 'tmux capture-pane -t websearch -p | tail -20'"
      exit 1
    fi
    ;;
  restart)
    PID=$(port_pid)
    if [ -z "$PID" ]; then
      echo "当前未运行，等待看门狗重拉"
    else
      echo "停止 pid $PID ..."
      kill "$PID" 2>/dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$PID" 2>/dev/null || break
        sleep 1
      done
      kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
    fi
    echo "等待看门狗重拉（约 15-25s）..."
    if wait_health 90; then
      echo "已恢复："
      curl -s -m 5 "http://127.0.0.1:$PORT/health" | head -c 400; echo
    else
      echo "90s 未恢复，查宿主面板："
      echo "  ssh <your-host> 'tmux capture-pane -t websearch -p | tail -20'"
      exit 1
    fi
    ;;
  start)
    echo "服务由 Termux 宿主看门狗守护，容器内不直接启动（会双开）。"
    echo "如端口未监听，在宿主执行：/data/data/com.termux/files/usr/bin/ubuntu-autostart"
    exit 1
    ;;
  stop)
    echo "看门狗会自动重拉，容器内杀 python 停不干净。彻底停止请在宿主执行："
    echo "  ssh <your-host> 'tmux kill-session -t websearch'"
    echo "（若要重启手机后也保持停止，注释掉 ubuntu-autostart 第 2e 节）"
    exit 1
    ;;
  logs)
    tail -n "${2:-60}" "$LOGFILE"
    ;;
  health)
    curl -s -m 5 "http://127.0.0.1:$PORT/health"; echo
    ;;
  warmup)
    # 手动重跑引擎探测（网络环境变了、或想提前解除熔断时用）
    curl -s -m 30 "http://127.0.0.1:$PORT/warmup"; echo
    ;;
  token)
    if [ -f "$TOKEN_FILE" ]; then
      echo "token 文件：$TOKEN_FILE"
      cat "$TOKEN_FILE"
    else
      echo "还没有 token（异常：start-mcp.sh 应已生成）"
    fi
    ;;
  test)
    # 端到端探活：initialize -> tools/list -> 调一次 web_search
    TOK=$(grep -v '^#' "$TOKEN_FILE" | head -1 | awk -F: '{print $NF}')
    SID=$(curl -s -D - -o /dev/null -m 10 \
      -X POST "http://127.0.0.1:$PORT$MCP_PATH" \
      -H "Authorization: Bearer $TOK" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
           "protocolVersion":"2025-06-18",
           "capabilities":{},
           "clientInfo":{"name":"ctl","version":"1"}}}' \
      | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
    echo "session: ${SID:-<无>}"
    curl -s -m 10 -X POST "http://127.0.0.1:$PORT$MCP_PATH" \
      -H "Authorization: Bearer $TOK" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      -H "mcp-session-id: $SID" \
      -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
    echo "--- tools/list ---"
    curl -s -m 10 -X POST "http://127.0.0.1:$PORT$MCP_PATH" \
      -H "Authorization: Bearer $TOK" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      -H "mcp-session-id: $SID" \
      -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
      | sed 's/data: //' | head -c 1200
    echo
    ;;
  *)
    echo "用法: $0 {status|restart|logs|health|warmup|token|test}"
    exit 1
    ;;
esac
