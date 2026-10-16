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

# ── 日志轮转兜底（copytruncate）──
# 面板崩了看门狗每 10s 重拉，日志由 >> 无限追加；起前兜底转存超限日志。
# 必须 copytruncate（先 cp 后 > 截断），不能 mv：日志以 O_APPEND 打开，
# 重命名会让后续进程继续写旧 inode，新文件永远为空。
_rotate_log() {
  local f="$1" max=$((1024 * 1024)) sz
  [ -f "$f" ] || return 0
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  [ "$sz" -gt "$max" ] 2>/dev/null || return 0
  cp -f "$f" "$f.1" 2>/dev/null || return 0
  : > "$f"
}

# ── 自愈：清掉残留的孤儿面板 ──
# proot 会话被冻/杀时，python 会变成 ppid=1 的孤儿继续占住 8500，
# 本看门狗就会每 10s 起一次、绑不上端口、空转刷日志（实测踩到）。
# 起前清掉旧实例并等端口释放，保证新实例拿到端口。用 [.] 防 pkill 自匹配。
pkill -f "websearch[.]proxy[.]panel_server" 2>/dev/null || true
for _ in $(seq 1 16); do
  (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':8500 ' || break
  sleep 0.5
done

mkdir -p "$(dirname "$APP/panel.log")"
_rotate_log "$APP/panel.log"
exec "$APP/venv/bin/python" -m websearch.proxy.panel_server >> "$APP/panel.log" 2>&1
