#!/bin/bash
# websearch-mcp 看门狗入口（容器内执行）
# 宿主看门狗循环通过 proot-distro login 调用本脚本；
# 日志重定向必须发生在容器内——宿主侧没有 /opt 路径。
# 直接跑 start-mcp.sh 会把 python 的输出丢给 pane，本脚本统一落 service.log。
APP=/opt/websearch-mcp
mkdir -p "$(dirname "$APP/service.log")"
exec "$APP/scripts/start-mcp.sh" >> "$APP/service.log" 2>&1
