#!/usr/bin/env bash
# websearch-mcp 一键安装 —— 装完直接给你一个可点开的链接，零手工配置
#
# 用法（在服务器上执行）：
#   bash install.sh                 # 默认：面板局域网可达，装完给直达链接
#   bash install.sh --local-only    # 面板只绑本机（更保守，需 SSH 隧道访问）
#
# 它做这些事（全部幂等，可重复执行）：
#   1. 检查/创建 Python 虚拟环境
#   2. 安装 Python 依赖
#   3. 检查 sing-box（代理客户端，可选但推荐）
#   4. 生成配置与面板口令（600 权限）
#   5. 启动面板并打印「点开即登录」的链接
#
# ⚠️ 本脚本不接收也不打印任何凭据：订阅链接由用户在面板里填。
set -euo pipefail

APP="${WS_APP_DIR:-/opt/websearch-mcp}"
PANEL_PORT_DEFAULT="${WS_PANEL_PORT:-8500}"
LOCAL_ONLY=0
for a in "$@"; do
  case "$a" in
    --local-only) LOCAL_ONLY=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
  esac
done

say()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[0;32m✔\033[0m %s\n' "$*"; }
warn() { printf '  \033[0;33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[0;31m✘\033[0m %s\n' "$*" >&2; exit 1; }

say "═══ websearch-mcp 安装 ═══"

# ── 0. 前置检查 ──
[ -d "$APP" ] || die "找不到 $APP（先把项目放上去，或用 WS_APP_DIR 指定）"
cd "$APP"

if ! command -v python3 >/dev/null 2>&1; then
  die "缺少 python3。Ubuntu/Debian 装法：sudo apt install -y python3 python3-venv"
fi
ok "python3 已就绪（$(python3 -V 2>&1)）"

# ── 1. 虚拟环境 ──
say "1/5 准备 Python 环境"
if [ ! -x "$APP/venv/bin/python" ]; then
  python3 -m venv "$APP/venv" 2>/dev/null \
    || die "创建虚拟环境失败。多半缺 python3-venv：sudo apt install -y python3-venv"
  ok "虚拟环境已创建"
else
  ok "虚拟环境已存在"
fi
PY="$APP/venv/bin/python"

# ── 2. 依赖 ──
say "2/5 安装依赖（可能需要 1-2 分钟）"
"$PY" -m pip install -q --upgrade pip 2>/dev/null || true
if "$PY" -m pip install -q -e ".[extract]" 2>/dev/null; then
  ok "依赖已安装（含正文提取增强）"
elif "$PY" -m pip install -q fastmcp uvicorn starlette httpx 2>/dev/null; then
  warn "基础依赖已安装（trafilatura 装失败，正文提取退化为内置算法）"
else
  die "依赖安装失败。检查网络，或手动跑：$PY -m pip install fastmcp uvicorn starlette httpx"
fi

# ── 3. sing-box（可选）──
say "3/5 检查 sing-box（用来访问墙外搜索源）"
SB="${WS_SINGBOX_BIN:-/opt/sing-box/sing-box}"
if [ -x "$SB" ]; then
  ok "已安装（$("$SB" version 2>/dev/null | head -1)）"
else
  warn "未安装 —— 只能搜国内源（百度/必应/360/微信）。要搜 Google/DDG 需要它。"
  ARCH=$(uname -m)
  case "$ARCH" in
    aarch64|arm64) SBFILE="linux-arm64" ;;
    x86_64|amd64)  SBFILE="linux-amd64" ;;
    *) SBFILE="" ;;
  esac
  if [ -n "$SBFILE" ]; then
    echo "     你的架构 $ARCH，装法："
    echo "       VER=\$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep -o '\"tag_name\": *\"[^\"]*\"' | head -1 | cut -d'\"' -f4)"
    echo "       curl -sL -o /tmp/sb.tgz \"https://github.com/SagerNet/sing-box/releases/download/\$VER/sing-box-\${VER#v}-$SBFILE.tar.gz\""
    echo "       mkdir -p /opt/sing-box && tar -xzf /tmp/sb.tgz -C /tmp --strip-components=1"
    echo "       cp /tmp/sing-box /opt/sing-box/ && chmod +x /opt/sing-box/sing-box"
    echo "     （装完重新跑一次本脚本即可）"
  else
    echo "     你的架构 $ARCH 没有官方预编译包，需自行编译。"
  fi
fi

# ── 4. 配置 ──
say "4/5 初始化配置"
ENVFILE="$APP/.env"
if [ ! -f "$ENVFILE" ]; then
  if [ "$LOCAL_ONLY" = "1" ]; then HOSTVAL="127.0.0.1"; else HOSTVAL="0.0.0.0"; fi
  cat > "$ENVFILE" <<EOF
# websearch-mcp 配置（含凭据，权限 600，已在 .gitignore）
# 这个文件由管理面板读写；手工改完重启面板生效。
WS_PANEL_HOST=$HOSTVAL
WS_PANEL_PORT=$PANEL_PORT_DEFAULT
WS_PORT=8300
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
  ok "配置已生成（600 权限）"
else
  chmod 600 "$ENVFILE"
  ok "配置已存在（权限已收紧为 600）"
fi

# gitignore 自检 —— 防凭据被提交
if [ -f "$APP/.gitignore" ]; then
  if ! grep -q '^\.env$' "$APP/.gitignore"; then
    warn ".gitignore 缺 .env —— 凭据有被提交风险，已自动补上"
    printf '\n.env\n.env.*\n!.env.example\nsingbox.json\nsingbox.log\nproxy-run/\n' >> "$APP/.gitignore"
  fi
fi

# ── 5. 启动 ──
say "5/5 启动面板"
pkill -f "websearch.proxy.panel_server" 2>/dev/null || true
sleep 1
mkdir -p "$APP/proxy-run"; chmod 700 "$APP/proxy-run"

export PYTHONPATH="$APP/src"
export WS_CONFIG_FILE="$ENVFILE"
nohup "$PY" -m websearch.proxy.panel_server > "$APP/panel.log" 2>&1 &
sleep 5

PANEL_PORT=$(grep '^WS_PANEL_PORT=' "$ENVFILE" 2>/dev/null | cut -d= -f2 | tr -d ' \r')
PANEL_PORT="${PANEL_PORT:-$PANEL_PORT_DEFAULT}"

if curl -s -m 5 -o /dev/null "http://127.0.0.1:$PANEL_PORT/healthz"; then
  ok "面板已启动（端口 $PANEL_PORT）"
else
  die "面板启动失败。看日志：tail -30 $APP/panel.log"
fi

# 等一秒让面板稳定 —— 若有看门狗在管，它可能还会拉起自己的实例，
# 而**新实例签发的票据会让旧的失效**。所以票据由 ticket 工具
# 在面板稳定后单独签发，而不是靠面板启动日志里的那个。
sleep 2

echo
say "═══ 安装完成 ═══"
echo
# 用 ticket 工具签发链接（比面板启动日志里的可靠：
# 看门狗重启面板会让启动时签的票据失效）
"$PY" -m websearch.proxy.ticket --config "$ENVFILE" 2>&1 || {
  echo "（自动签发链接失败，可以手动跑：$PY -m websearch.proxy.ticket）"
}
echo
echo "常用命令："
echo "  拿新登录链接: $PY -m websearch.proxy.ticket"
echo "  看状态:       bash $APP/scripts/panel-ctl.sh status"
echo "  重启面板:     bash $APP/scripts/panel-ctl.sh restart"
echo "  看日志:       bash $APP/scripts/panel-ctl.sh logs"
echo
echo "下一步："
echo "  1. 点开上面那个链接（自动登录）"
echo "  2. 在「机场订阅」填你的订阅链接 → 保存 → 启动代理"
echo "  3. 在「把它接到你的 AI 客户端」里复制配置，粘到你的 AI 客户端"
