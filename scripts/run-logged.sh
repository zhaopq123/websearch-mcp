#!/bin/bash
# websearch-mcp 看门狗入口（容器内执行）
# 宿主看门狗循环通过 proot-distro login 调用本脚本；
# 日志重定向必须发生在容器内——宿主侧没有 /opt 路径。
# 直接跑 start-mcp.sh 会把 python 的输出丢给 pane，本脚本统一落 service.log。
APP=/opt/websearch-mcp
# ── 自愈：清掉残留的孤儿服务实例 ──
# 同 run-panel.sh：proot 冻结会留下 ppid=1 的老 python 占住 8300。
# 起前清掉旧实例并等端口释放。用 [.] 防 pkill 自匹配。
pkill -f "websearch[.]server" 2>/dev/null || true
for _ in $(seq 1 16); do
  (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':8300 ' || break
  sleep 0.5
done

mkdir -p "$(dirname "$APP/service.log")"
exec "$APP/scripts/start-mcp.sh" >> "$APP/service.log" 2>&1
