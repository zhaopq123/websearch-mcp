#!/bin/bash
# websearch-mcp 管理面板运维脚本（不在 PATH，用绝对路径调用）
#   bash /opt/websearch-mcp/scripts/panel-ctl.sh {status|restart|logs|health|token|proxy|test}
#
# 监督模型（与 websearch 服务一致：宿主看门狗）
#   Termux 宿主 tmux 会话 websearch-panel：
#     while true; do proot-distro login ubuntu -- run-panel.sh; sleep 10; done
#   开机由 ubuntu-autostart 幂等创建
#   => 面板崩溃 10s 内自动重拉；手机重启后自动恢复
#
# ⚠️ 本脚本**不打印任何凭据**（口令、订阅链接）。token 子命令只显示
#    「已配置 / 未配置」与长度，要查看请自行读 .env。
set -uo pipefail

APP=/opt/websearch-mcp
ENVFILE="$APP/.env"
LOGFILE="$APP/panel.log"
PORT="${WS_PANEL_PORT:-8500}"

port_pid() {
  ss -tlnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $NF}' \
    | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1
}

case "${1:-status}" in
  status)
    PID=$(port_pid)
    if [ -n "$PID" ]; then
      echo "面板运行中 (pid $PID, :$PORT)"
      curl -s -m 5 "http://127.0.0.1:$PORT/healthz"; echo
    else
      echo "面板未监听 :$PORT"
      echo "查宿主看门狗：tmux attach -t websearch-panel"
    fi
    ;;

  health)
    echo -n "面板探活: "
    curl -s -m 5 -o /dev/null -w "http=%{http_code}\n" "http://127.0.0.1:$PORT/healthz"
    echo -n "未鉴权应 401: "
    curl -s -m 5 -o /dev/null -w "http=%{http_code}\n" "http://127.0.0.1:$PORT/api/config"
    ;;

  restart)
    # 杀面板 python，宿主看门狗会重拉
    if pkill -f "websearch.proxy.panel_server"; then
      echo "已发 SIGTERM，看门狗约 10-20s 后重拉"
      for i in $(seq 1 20); do
        sleep 3
        if curl -s -m 3 -o /dev/null -w "%{http_code}" \
             "http://127.0.0.1:$PORT/healthz" 2>/dev/null | grep -q 200; then
          echo "面板已就绪（约 $((i*3))s）"; exit 0
        fi
      done
      echo "超时未就绪，查日志：bash $0 logs"; exit 1
    else
      echo "未找到面板进程（可能没在跑）"
    fi
    ;;

  logs)
    tail -n "${2:-60}" "$LOGFILE" 2>/dev/null || echo "无日志文件 $LOGFILE"
    ;;

  token)
    # 只报状态，**不打印口令**
    if [ ! -f "$ENVFILE" ]; then
      echo "配置文件不存在：$ENVFILE（面板首次启动会创建并生成口令）"; exit 0
    fi
    LEN=$(grep '^WS_PANEL_TOKEN=' "$ENVFILE" 2>/dev/null | cut -d= -f2- | tr -d '\n' | wc -c)
    if [ "$LEN" -gt 0 ]; then
      echo "面板口令：已配置（${LEN} 字符）"
      echo "查看方式（自行在服务器上执行）：grep WS_PANEL_TOKEN $ENVFILE"
      echo "遗失处置：删掉该行后重启面板，会重新生成并打印一次"
    else
      echo "面板口令：未配置"
    fi
    MODE=$(stat -c '%a' "$ENVFILE" 2>/dev/null)
    echo "配置权限：${MODE:-未知}（应为 600）"
    if [ "$MODE" != "600" ]; then
      echo "⚠️ 权限过宽，正在收紧…"; chmod 600 "$ENVFILE" && echo "已改为 600"
    fi
    ;;

  proxy)
    # 代理与订阅状态（不含凭据）
    if [ ! -f "$ENVFILE" ]; then echo "无配置文件"; exit 0; fi
    echo "--- 订阅 ---"
    if grep -q '^WS_SUBSCRIPTION_URL=.\+' "$ENVFILE" 2>/dev/null; then
      HOST=$(grep '^WS_SUBSCRIPTION_URL=' "$ENVFILE" | cut -d= -f2- \
             | sed -E 's#https?://([^/]+).*#\1#')
      echo "  已配置（域名：$HOST）"
    else
      echo "  未配置"
    fi
    echo "--- 代理进程 ---"
    ss -tlnp 2>/dev/null | grep -E ':(17890|17891)\b' || echo "  未监听 17890/17891"
    echo "--- 健康检查 ---"
    if curl -s -m 10 -x http://127.0.0.1:17890 -o /dev/null -w "%{http_code}" \
         "https://www.google.com/generate_204" 2>/dev/null | grep -qE '200|204'; then
      echo "  ✅ 经代理可访问墙外"
    else
      echo "  ❌ 经代理无法访问墙外（节点失效 / 未启动 / 无订阅）"
    fi
    ;;

  test)
    bash "$0" status; echo; bash "$0" health; echo; bash "$0" proxy
    ;;

  *)
    echo "用法: bash $0 {status|restart|logs [行数]|health|token|proxy|test}"
    ;;
esac
