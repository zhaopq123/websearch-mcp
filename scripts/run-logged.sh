#!/bin/bash
# websearch-mcp 看门狗入口（容器内执行）
# 宿主看门狗循环通过 proot-distro login 调用本脚本；
# 日志重定向必须发生在容器内——宿主侧没有 /opt 路径。
# 直接跑 start-mcp.sh 会把 python 的输出丢给 pane，本脚本统一落 service.log。
APP=/opt/websearch-mcp

# ── 日志轮转兜底（copytruncate）──
# 正常运行时 maintenance.py 会定期轮转；但当服务**起不来**（端口被占/
# 依赖缺失）时 python 退出、看门狗每 10s 重拉，日志会无限追加。这里在
# 起服务前兜底检查一次大小，超限转存为 .1 再清空。
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

# ── 自愈：清掉残留的孤儿服务实例 ──
# 同 run-panel.sh：proot 冻结会留下 ppid=1 的老 python 占住 8300。
# 起前清掉旧实例并等端口释放。用 [.] 防 pkill 自匹配。
pkill -f "websearch[.]server" 2>/dev/null || true
for _ in $(seq 1 16); do
  (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -q ':8300 ' || break
  sleep 0.5
done

mkdir -p "$(dirname "$APP/service.log")"
_rotate_log "$APP/service.log"
exec "$APP/scripts/start-mcp.sh" >> "$APP/service.log" 2>&1
