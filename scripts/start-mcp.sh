#!/bin/bash
# websearch-mcp 生产启动脚本
#
# 设计要点（都是踩过坑的）：
#  1. token 从文件读，不写进脚本/环境变量（环境变量会出现在 ps e 和崩溃转储里）
#  2. 绑定 0.0.0.0 必须有 token，否则服务会拒绝启动（局域网裸奔 = 送 SSRF 跳板）
#  3. 缓存目录固定放 /opt 下，proot 重启不会丢
#  4. **统一读 .env** —— 用户在面板里改的配置必须真正生效。
#     之前这里只用 ${VAR:-default} 读环境变量，而面板写的是 .env 文件，
#     导致「面板里改了代理配置，重启后搜索服务仍然直连」。
#     现在先 source .env，再用默认值兜底，两条路都通。
set -euo pipefail

APP=/opt/websearch-mcp
cd "$APP"

# ── 读 .env（面板写的配置在这里）──
# 只导出符合 KEY=VALUE 的行，避免执行 .env 里的任意内容
if [ -f "$APP/.env" ]; then
  while IFS='=' read -r k v; do
    case "$k" in
      ''|'#'*|*[!A-Za-z0-9_]*) continue ;;   # 跳过注释与非法键名
    esac
    export "$k=$v"
  done < "$APP/.env"
fi

# ── 配置（.env 优先，环境变量可覆盖）──
export WS_HOST="${WS_HOST:-0.0.0.0}"
export WS_PORT="${WS_PORT:-8300}"
export WS_MCP_PATH="${WS_MCP_PATH:-/mcp}"
export LOG_LEVEL="${LOG_LEVEL:-info}"

# 预算：总 12s / 单引擎 6s / 连接 2.5s。
# 调大总预算前先想清楚：慢引擎会各自吃掉一个超时，引擎越多总预算越要留够。
export WS_TOTAL_BUDGET_MS="${WS_TOTAL_BUDGET_MS:-12000}"
export WS_ENGINE_TIMEOUT_MS="${WS_ENGINE_TIMEOUT_MS:-6000}"
export WS_CONNECT_TIMEOUT_MS="${WS_CONNECT_TIMEOUT_MS:-2500}"

# 并发与限流：vivo 只有 8 核 3.7G 内存，数值要保守
export WS_MAX_CONCURRENCY="${WS_MAX_CONCURRENCY:-24}"
export WS_RATE_PER_SEC="${WS_RATE_PER_SEC:-1.0}"
export WS_RATE_BURST="${WS_RATE_BURST:-5}"
export WS_FETCH_TIMEOUT_MS="${WS_FETCH_TIMEOUT_MS:-6000}"

# 熔断：连续 3 次失败跳闸，冷却 60s 起，翻倍到 600s 封顶
export WS_CB_THRESHOLD="${WS_CB_THRESHOLD:-3}"
export WS_CB_COOLDOWN="${WS_CB_COOLDOWN:-60}"
export WS_CB_COOLDOWN_MAX="${WS_CB_COOLDOWN_MAX:-600}"

# 相关性校验：0 关闭。开着能挡住「投毒式反爬」（引擎返回无关结果）
export WS_MIN_RELEVANCE="${WS_MIN_RELEVANCE:-0.3}"

# 缓存：搜索 5 分钟、正文 30 分钟。缓存只用来防反爬，不是数据源
export WS_CACHE_ENABLED="${WS_CACHE_ENABLED:-1}"
export WS_CACHE_DIR="${WS_CACHE_DIR:-$APP/cache}"
export WS_CACHE_SEARCH_TTL="${WS_CACHE_SEARCH_TTL:-300}"
export WS_CACHE_FETCH_TTL="${WS_CACHE_FETCH_TTL:-1800}"

# 预热：启动时并发探测全部引擎，不可用���直接熔断，省掉每次搜索的超时等待
export WS_WARMUP="${WS_WARMUP:-1}"

# 节点探测并发：单轮 = probe_limit/并发 × 每次耗时。12 时单轮要 300s+，
# 提到 20（探测是网络 I/O 为主，vivo 8 核扛得住）把单轮压到 ~200s。
export WS_NODE_PROBE_CONCURRENCY="${WS_NODE_PROBE_CONCURRENCY:-20}"

export PYTHONPATH="$APP/src"
export PYTHONUNBUFFERED=1

# ── 凭据 ──
TOKEN_FILE="${WS_TOKEN_FILE:-$APP/.tokens}"
if [ ! -f "$TOKEN_FILE" ]; then
  umask 077
  NEW=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  echo "# websearch-mcp 访问 token（每行一个）" > "$TOKEN_FILE"
  echo "admin:$NEW" >> "$TOKEN_FILE"
  echo "已生成新 token，路径：$TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE" 2>/dev/null || true
export WS_TOKEN_FILE="$TOKEN_FILE"

mkdir -p "$WS_CACHE_DIR"

exec "$APP/venv/bin/python" -m websearch.server