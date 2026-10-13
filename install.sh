#!/usr/bin/env bash
# websearch-mcp 一键安装 —— 装完直接给你一个可点开的链接，零手工配置
#
# 用法（在服务器上执行）：
#   bash install.sh              # 默认：面板绑局域网，装完打印直达链接
#   bash install.sh --local-only # 面板只绑本机（更保守）
#
# 它做这些事（全部幂等，可重复执行）：
#   1. 检查 python / venv
#   2. 装 sing-box（代理客户端，可选但推荐）
#   3. 装 Python 依赖
#   4. 生成配置与面板口令（600 权限）
#   5. 启动面板并打印「点开即登录」的链接
#
# ⚠️ 不碰任何凭据：订阅链接由用户在面板里填，脚本不接收、不打印。
set -euo pipefail

APP="${WS_APP_DIR:-/opt/websearch-mcp}"
PANEL_PORT="${WS_PANEL_PORT:-8500}"
LOCAL_ONLY=0
for a in "$@"; do
  case "$a" in
    --local-only) LOCAL_ONLY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac
done

say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[0;32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[0;33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[0;31m✘\033[0m %s\n' "$*" >&2; exit 1; }

say "═══ websearch-mcp 安装 ═══"

# ── 1. 目录与 Python ──
[ -d "$APP" ] || die "找不到 $APP（先把项目放上去，或用 WS_APP_DIR 指定）"
cd "$APP"

if [ ! -x "$APP/venv/bin/python" ]; then
  say "1/5 创建 Python 虚拟环境"
  python3 -m venv "$APP/venv" || die "创建 venv 失败（需要 python3-venv）"
  ok "venv 已创建"
else
  ok "1/5 venv 已存在"
fi
PY="$APP/venv/bin/python"

say "2/5 安装 Python 依赖"
"$PY" -m pip install -q --upgrade pip 2>/dev/null || true
"$PY" -m pip install -q -e ".[extract]" 2>/dev/null \
  || "$PY" -m pip install -q fastmcp uvicorn starlette httpx trafilatura \
  || die "依赖安装失败"
ok "依赖已安装"

# ── 2. sing-box（可选）──
say "3/5 检查 sing-box（代理客户端，没它就只能用国内源）"
SB="${WS_SINGBOX_BIN:-/opt/sing-box/sing-box}"
if [ -x "$SB" ]; then
  ok "已安装：$("$SB" version 2>/dev/null | head -1)"
else
  warn "未安装。要出网（用 Google/DDG 等墙外源）需要它。"
  echo "     装法（ARM64 服务器，如树莓派/手机容器）："
  echo "       VER=\$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep -o '\"tag_name\": *\"[^\"]*\"' | head -1 | cut -d'\"' -f4)"
  echo "       curl -sL -o /tmp/sb.tgz \"https://github.com/SagerNet/sing-box/releases/download/\$VER/sing-box-\${VER#v}-linux-arm64.tar.gz\""
  echo "       mkdir -p /opt/sing-box && tar -xzf /tmp/sb.tgz -C /tmp --strip-components=1 && cp /tmp/sing-box /opt/sing-box/ && chmod +x /opt/sing-box/sing-box"
  echo "     x86_64 把 linux-arm64 换成 linux-amd64"
fi

# ── 3. 配置 ──
say "4/5 初始化配置"
ENVFILE="$APP/.env"
if [ ! -f "$ENVFILE" ]; then
  # 面板监听：默认局域网可达（安装体验优先），口令是唯一防线
  if [ "$LOCAL_ONLY" = "1" ]; then
    HOSTVAL="127.0.0.1"
  else
    HOSTVAL="0.0.0.0"
  fi
  cat > "$ENVFILE" <<EOF
# websearch-mcp 配置（含凭据，权限 600，已在 .gitignore）
WS_PANEL_HOST=$HOSTVAL
WS_PANEL_PORT=$PANEL_PORT
WS_HTTP_PROXY_PORT=17890
WS_SOCKS_PROXY_PORT=17891
WS_PROXY_ENABLED=0
WS_PROXY_AUTO_START=1
WS_PROXY_HEALTH_INTERVAL=300
WS_SINGBOX_BIN=$SB
WS_PROXY_WORKDIR=$APP/proxy-run
WS_CONFIG_FILE=$ENVFILE
EOF
  chmod 600 "$ENVFILE"
  ok "配置已生成（$ENVFILE，600 权限）"
else
  chmod 600 "$ENVFILE"
  ok "配置已存在（权限已收紧为 600）"
fi

# gitignore 自检 —— 防凭据被提交
if [ -f "$APP/.gitignore" ] && ! grep -q '^\.env$' "$APP/.gitignore"; then
  warn ".gitignore 里没有 .env —— 凭据有被提交的风险，已自动补上"
  printf '\n.env\n.env.*\n!.env.example\nsingbox.json\nsingbox.log\nproxy-run/\n' >> "$APP/.gitignore"
fi

# ── 4. 启动 ──
say "5/5 启动面板"
pkill -f "websearch.proxy.panel_server" 2>/dev/null || true
sleep 1
mkdir -p "$APP/proxy-run"; chmod 700 "$APP/proxy-run"

export PYTHONPATH="$APP/src"
export WS_CONFIG_FILE="$ENVFILE"
nohup "$PY" -m websearch.proxy.panel_server > "$APP/panel.log" 2>&1 &
sleep 4

if curl -s -m 5 -o /dev/null "http://127.0.0.1:$PANEL_PORT/healthz"; then
  ok "面板已启动（:$PANEL_PORT）"
else
  die "面板启动失败，看日志：tail -30 $APP/panel.log"
fi

echo
say "═══ 安装完成 ═══"
echo
echo "面板的访问链接与说明已打印在上面的启动日志里："
echo
sed -n '/点这个链接直接进面板/,/^═/p' "$APP/panel.log" 2>/dev/null | head -20 \
  || tail -25 "$APP/panel.log"
echo
echo "以后常用命令："
echo "  看状态:   bash $APP/scripts/panel-ctl.sh status"
echo "  重启:     bash $APP/scripts/panel-ctl.sh restart"
echo "  看日志:   bash $APP/scripts/panel-ctl.sh logs"
echo "  配代理:   在面板里填订阅链接 → 启动代理 → 健康检查"
echo
echo "搜索服务要用代理时，设这个环境变量后重启搜索服务："
echo "  export WS_PROXY=http://127.0.0.1:17890"
