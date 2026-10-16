"""配置层 —— 全部走环境变量，零硬编码。

为什么全用环境变量而不是配置文件：
  部署目标是局域网内一台常驻主机上的进程，改配置要能不碰代码重启。
  环境变量 + start-mcp.sh 里 export 是最省事、也是 shared-memory-mcp 已验证的做法。

命名统一前缀 WS_，避免和同机其它服务撞车。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("websearch.config")


def _env_str(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v.strip() if v and v.strip() else default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on", "y")


def _env_list(name: str, default: list[str]) -> list[str]:
    v = os.environ.get(name)
    if not v or not v.strip():
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


# 默认启用引擎。
# 顺序只影响「同分时谁在前」，不影响并发（所有引擎同时起飞）。
#
# 这份列表是 2026-10-13 在 vivo（国内网络）实测出来的，不是拍脑袋排的：
#   bing / so360 / baidu_m / sogou_m / so360_m / weixin  实测能出相关结果
#   baidu / sogou（PC 版）被反爬硬拦，保留但排后面，靠预热熔断自动跳过
#   ddg / mojeek / brave / searx  国内网络不可达，同上
DEFAULT_ENGINES = [
    "bing",        # 桌面版实测相关度最高；注意对 UA 敏感
    "so360",       # PC 版最稳，反爬最弱
    "baidu_m",     # 中文覆盖最强（移动版绕过安全验证）
    "sogou_m",     # 移动版可用
    "so360_m",     # 与 PC 版互补
    "weixin",      # 垂直：微信公众号
    "toutiao",     # 垂直：资讯，时效性强
    "bing_intl",   # 必应国际版：实测与 cn 版结果有差异，是有效的交叉验证源
    "duckduckgo",  # 国际（2026-10-15 实测唯一稳定的国外引擎）
    # mojeek / brave 已移除（2026-10-15 全天实测 0 命中且硬封：
    # mojeek 恒定 http_403、brave 恒定 http_429；国外需求由
    # duckduckgo 覆盖，留着只增加每轮的无效请求与熔断噪声）。
    "baidu",       # PC 版（常被拦，保留待恢复）
    "sogou",       # PC 版（常被拦，保留待恢复）
]

# 可选引擎（默认不开，需要外部 SearXNG 实例）
OPTIONAL_ENGINES = ["searx"]

# per-engine 限速覆盖（rate, burst）—— 一视同仁的限速是错的：
#   bing / bing_intl  投毒式反爬的触发器就是「短时间多请求」，压 burst 保平安
#   so360 / weixin    实测反爬最弱、最耐操，加 burst（瞬时容量）不加 rate
#                     （持续 rate 仍保持 1.0/s 这个 30s 长跑零熔断的校准值）
# 格式："engine:rate:burst,engine:rate:burst"，可用 WS_ENGINE_RATES 覆盖。
DEFAULT_ENGINE_RATES: dict[str, tuple[float, int]] = {
    "bing": (0.7, 3),
    "bing_intl": (0.7, 3),
    "so360": (1.0, 16),
    "so360_m": (1.0, 16),
    "weixin": (1.0, 12),
    "baidu": (0.8, 6),
}


@dataclass
class Config:
    """运行时配置。所有字段都可在 start-mcp.sh 里用环境变量覆盖。"""

    # ── 服务 ──
    host: str = "0.0.0.0"
    port: int = 8300
    transport: str = "http"          # http | stdio
    mcp_path: str = "/mcp"           # streamable-http 端点路径
    log_level: str = "info"

    # ── 鉴权（部署到局域网必须开）──
    token_file: str = ""             # WS_TOKEN_FILE，600 权限，一行一个 token
    auth_required: bool | None = None  # None = 自动判断（非 loopback 则强制）

    # ── 引擎 ──
    engines: list[str] = field(default_factory=lambda: list(DEFAULT_ENGINES))
    # per-engine 覆盖：WS_DISABLE_ENGINES=baidu,sogou
    disable_engines: list[str] = field(default_factory=list)

    # ── 超时预算（毫秒）—— 三层，必须满足 connect < engine < total ──
    total_budget_ms: int = 12_000
    engine_timeout_ms: int = 6_000
    connect_timeout_ms: int = 2_500

    # ── 并发 ──
    max_concurrency: int = 48        # 全局在飞请求上限（实测 fd 32768/内存 2.5G 可用；
                                      # 早停和限流会让槽位快速释放，48 不会堆积）
    # 单飞合并：同 query+参数的并发搜索只扇出一次（多会话/多工作区场景的
    # 核心优化）。只对可缓存查询生效；fresh/time_range 实时语义不合并。
    singleflight: bool = True
    # 准入控制：同时在飞的搜索数上限。超出的进 FIFO 队列等待，
    # 预算从真正出队那一刻才算。没有它，60 个冷 query 并发会同时扇出
    # 240 个引擎请求 → 触发投毒 + 限流跳过风暴 → 大面积空结果。
    max_search_concurrency: int = 14
    # 容量感知：至少这么多个非熔断引擎的令牌桶里有令牌才放行扇出。
    # 全枯竭时扇出 = 白白等 3s 令牌然后空手而归，不如排队等恢复。
    min_ready_engines: int = 2
    search_queue_timeout: float = 12.0   # 排队超过这么久返回 server_busy（=总预算）
    engine_rates: dict[str, tuple[float, int]] = field(
        default_factory=lambda: dict(DEFAULT_ENGINE_RATES)
    )
    # 令牌桶等待超时（秒）。1.5s 太短：高并发下大量请求等不到令牌被跳过，
    # 宁可多等两秒换个真实结果，也不要把搜索变成空返回。
    rate_acquire_timeout: float = 4.0
    quorum: int = 2                  # 早停所需的最小成功源数
    quorum_results: int = 12         # 早停所需的去重结果数（太低会砍掉更全的结果）
    early_stop: bool = True

    # ── 结果 ──
    max_results: int = 20
    per_domain_cap: int = 3          # 单域名最多几条（多样性）
    # 相关性校验开关：设为 0 关闭。
    # 开启后，「结果里没有任何一条命中查询词」的引擎会被判为投毒并标记失败。
    min_relevance_ratio: float = 0.3
    warmup_query: str = "中国 新闻"   # 预热探测词（用中文，避免英文词触发异常路径）

    # ── 限流（per engine 令牌桶）──
    # 实测校准：vivo 国内网络下 so360 / weixin 在 1.0 rps、burst 5 下
    # 连续 30 秒长跑零熔断、零 403。原值 0.5/3 是拍脑袋的保守值，
    # 结果是压测里 1700+ 次请求被限流挡在门外，白白拖慢自己又不换来保护。
    rate_per_sec: float = 1.0
    rate_burst: int = 5

    # ── 熔断 ──
    cb_failure_threshold: int = 3    # 连续失败几次跳闸
    cb_cooldown_sec: int = 60        # 初始冷却（每次再触发翻倍，上限见下）
    cb_cooldown_max_sec: int = 600
    cb_ema_alpha: float = 0.2        # 成功率 EMA 平滑系数
    # 来源权威度权重（2026-10-15）：fusion 排序里乘 domain_authority()
    # 的分值。保真实性、压 SEO/GEO 脏数据（用户诉求）。0 = 关闭。
    authority_weight: float = 0.5
    # 连续 soft fail（zero_results/timeout）几次跳闸。默认 hard 阈值
    # 的 3 倍：偶发无结果不杀（weixin 误熔断 600s 的教训），持续死透
    # 才杀（实测 DDG 被免费池出口 IP 全量拉黑后 sr=0.065 仍永远
    # closed，每轮搜索白跑一次）。2026-10-15 压测新增。
    cb_soft_failure_threshold: int = 9

    # ── 缓存 ──
    cache_dir: str = ""              # 空 = 系统临时目录下 websearch-cache
    cache_search_ttl: int = 300      # 5 分钟：搜索缓存只防反爬，不当数据源
    cache_fetch_ttl: int = 1800      # 30 分钟：网页正文相对稳定
    cache_negative_ttl: int = 30     # 失败负缓存，防反复撞墙
    cache_memory_items: int = 512    # L1 LRU 容量
    cache_db_items: int = 5000       # L2 SQLite 上限
    cache_enabled: bool = True

    # ── 抓取 ──
    # 搜索结果页比正文页大得多（百度移动版实测 2.1MB），
    # 用正文的上限去卡搜索页会把正常响应判成「过大」。
    search_max_bytes: int = 4_000_000
    fetch_max_bytes: int = 1_500_000   # 单页读取上限（vivo 内存只有 3.7G）
    fetch_max_chars: int = 20_000      # 返回正文字符上限
    fetch_timeout_ms: int = 6_000
    max_redirects: int = 5
    fetch_concurrency: int = 8         # web_fetch 批量并发度
    user_agent_pool: list[str] = field(default_factory=list)

    # ── 网络 ──
    proxy: str = ""                  # http://user:pass@host:port
    verify_ssl: bool = True
    http2: bool = True

    # ── 节点猎手（免费节点自养池）──
    # 产品定位：节点从「用户自带」变成「系统自养」——没配订阅也能出墙。
    node_hunt_enabled: bool = True   # 后台持续搜集（默认开：节点随时失效）
    node_hunt_interval: int = 600    # 每轮间隔（秒）
    node_hunt_max_sources: int = 24  # 单轮最多抓多少源
    node_hunt_probe_limit: int = 120  # 单轮最多探测多少节点
    node_hunt_discover: bool = True  # 用搜索引擎自举发现新源
    singbox_bin: str = "/opt/sing-box/sing-box"  # 出网验证用（没有则退化 TCP）
    node_probe_concurrency: int = 24
    node_probe_timeout_ms: int = 8000
    # 单源单轮入库上限：普通代理列表源（HProxy/Proxifly/…）动辄几千
    # 上万条，不设上限会把库和探测预算一起撑爆（实测 GFP 系列表单文件
    # 万行级）。超出的部分当轮丢弃（源本身还会下轮再来，不失新鲜度）。
    # ⚠️ cust 客户导入**不受此限**（用户自己的订阅，条条都是刚需）。
    # 2026-10-15 两调：6000→4000→2000。实测教训链：
    #   · 6000 时一个源吃掉 8000 总预算的 3/4，后面的源全饿死；
    #   · 4000 时代理源前置，前两个代理源（proxifly+hproxy）正好
    #     吃光 8000，VPN 源（morpheusadam/FastNodes）全被丢弃
    #     （服务日志「单轮入库预算耗尽」刷屏）。
    # 2000 = 总预算(10000)的 1/5，保证每轮至少 5 个高产源都能
    # 进库（2 代理 + 3 VPN 或任意组合）。单源 2000 对探测吞吐
    # （340/轮）已过剩——库存 6 千 socks 十几轮才能轮检一遍，
    # 入库再多也只是排队。
    node_ingest_cap: int = 2000

    # ── 客户订阅（cust 池唯一入口）──
    # ⚠️ 含 token = 凭据：只走环境变量（WS_CUSTOMER_SUBS，逗号分隔）或
    # WS_CUSTOMER_SUB_FILE 指向的 600 权限文件（一行一个 URL，# 注释）。
    # 绝不进日志、绝不进 sources 健康表 —— 那张表会经 node_pool
    # action=sources 原样外泄 URL。
    customer_subs: list[str] = field(default_factory=list)
    customer_sub_file: str = ""     # WS_CUSTOMER_SUB_FILE

    # ── 安全 ──
    allow_private_net: bool = False  # 默认禁内网（SSRF 防护）
    allow_nonstd_port: bool = False  # 默认只放行 80/443
    domain_blocklist: list[str] = field(default_factory=list)
    domain_allowlist: list[str] = field(default_factory=list)

    # ── 反爬 ──
    retry_on_transient: int = 1      # 瞬时错误重试次数（403/429 不重试）
    backoff_base: float = 0.3

    @classmethod
    def from_env(cls) -> "Config":
        c = cls()
        c.host = _env_str("WS_HOST", c.host)
        c.port = _env_int("WS_PORT", c.port)
        c.transport = _env_str("WS_TRANSPORT", c.transport).lower()
        c.mcp_path = _env_str("WS_MCP_PATH", c.mcp_path)
        c.log_level = _env_str("LOG_LEVEL", c.log_level).lower()

        c.token_file = _env_str("WS_TOKEN_FILE", "")
        if _env_bool("WS_AUTH_REQUIRED", False):
            c.auth_required = True
        elif _env_bool("WS_AUTH_DISABLED", False):
            c.auth_required = False

        eng = _env_list("WS_ENGINES", DEFAULT_ENGINES)
        c.engines = eng
        c.disable_engines = _env_list("WS_DISABLE_ENGINES", [])

        c.total_budget_ms = _env_int("WS_TOTAL_BUDGET_MS", c.total_budget_ms)
        c.engine_timeout_ms = _env_int("WS_ENGINE_TIMEOUT_MS", c.engine_timeout_ms)
        c.connect_timeout_ms = _env_int("WS_CONNECT_TIMEOUT_MS", c.connect_timeout_ms)
        # 预算关系校正：这条不校正会出现「单引擎超时 > 全局超时」的荒谬配置，
        # 结果就是第一个慢引擎独占全部预算，后面的引擎永远没机会跑
        # （这正是调研里 leanzero 实测到的 10.4s 吃光 8s 预算的成因）。
        c.engine_timeout_ms = min(c.engine_timeout_ms, c.total_budget_ms)
        c.connect_timeout_ms = min(c.connect_timeout_ms, c.engine_timeout_ms)

        c.max_concurrency = _env_int("WS_MAX_CONCURRENCY", c.max_concurrency)
        c.singleflight = _env_bool("WS_SINGLEFLIGHT", c.singleflight)
        c.max_search_concurrency = _env_int("WS_MAX_SEARCH_CONCURRENCY", c.max_search_concurrency)
        c.min_ready_engines = _env_int("WS_MIN_READY_ENGINES", c.min_ready_engines)
        c.search_queue_timeout = _env_float("WS_SEARCH_QUEUE_TIMEOUT", c.search_queue_timeout)
        c.rate_acquire_timeout = _env_float("WS_RATE_ACQUIRE_TIMEOUT", c.rate_acquire_timeout)
        # WS_ENGINE_RATES="bing:0.7:3,so360:1.0:8" 覆盖单引擎限速
        rates: dict[str, tuple[float, int]] = dict(DEFAULT_ENGINE_RATES)
        for item in _env_list("WS_ENGINE_RATES", []):
            parts = item.split(":")
            if len(parts) == 3:
                try:
                    rates[parts[0].strip()] = (float(parts[1]), int(parts[2]))
                except ValueError:
                    pass
        c.engine_rates = rates
        c.quorum = _env_int("WS_QUORUM", c.quorum)
        c.quorum_results = _env_int("WS_QUORUM_RESULTS", c.quorum_results)
        c.early_stop = _env_bool("WS_EARLY_STOP", c.early_stop)

        c.max_results = _env_int("WS_MAX_RESULTS", c.max_results)
        c.per_domain_cap = _env_int("WS_PER_DOMAIN_CAP", c.per_domain_cap)
        c.min_relevance_ratio = _env_float("WS_MIN_RELEVANCE", c.min_relevance_ratio)
        c.warmup_query = _env_str("WS_WARMUP_QUERY", c.warmup_query)

        c.rate_per_sec = _env_float("WS_RATE_PER_SEC", c.rate_per_sec)
        c.rate_burst = _env_int("WS_RATE_BURST", c.rate_burst)

        c.cb_failure_threshold = _env_int("WS_CB_THRESHOLD", c.cb_failure_threshold)
        c.cb_soft_failure_threshold = _env_int(
            "WS_CB_SOFT_THRESHOLD", c.cb_soft_failure_threshold)
        c.cb_cooldown_sec = _env_int("WS_CB_COOLDOWN", c.cb_cooldown_sec)
        c.cb_cooldown_max_sec = _env_int("WS_CB_COOLDOWN_MAX", c.cb_cooldown_max_sec)
        c.cb_ema_alpha = _env_float("WS_CB_EMA_ALPHA", c.cb_ema_alpha)

        c.cache_dir = _env_str("WS_CACHE_DIR", "")
        c.cache_search_ttl = _env_int("WS_CACHE_SEARCH_TTL", c.cache_search_ttl)
        c.cache_fetch_ttl = _env_int("WS_CACHE_FETCH_TTL", c.cache_fetch_ttl)
        c.cache_negative_ttl = _env_int("WS_CACHE_NEG_TTL", c.cache_negative_ttl)
        c.cache_memory_items = _env_int("WS_CACHE_MEM_ITEMS", c.cache_memory_items)
        c.cache_db_items = _env_int("WS_CACHE_DB_ITEMS", c.cache_db_items)
        c.cache_enabled = _env_bool("WS_CACHE_ENABLED", c.cache_enabled)

        c.search_max_bytes = _env_int("WS_SEARCH_MAX_BYTES", c.search_max_bytes)
        c.fetch_max_bytes = _env_int("WS_FETCH_MAX_BYTES", c.fetch_max_bytes)
        c.fetch_max_chars = _env_int("WS_FETCH_MAX_CHARS", c.fetch_max_chars)
        c.fetch_timeout_ms = _env_int("WS_FETCH_TIMEOUT_MS", c.fetch_timeout_ms)
        c.max_redirects = _env_int("WS_MAX_REDIRECTS", c.max_redirects)
        c.fetch_concurrency = _env_int("WS_FETCH_CONCURRENCY", c.fetch_concurrency)

        c.proxy = _env_str("WS_PROXY", "") or _env_str("HTTPS_PROXY", "") or _env_str("HTTP_PROXY", "")
        c.verify_ssl = _env_bool("WS_VERIFY_SSL", c.verify_ssl)
        c.http2 = _env_bool("WS_HTTP2", c.http2)

        # 节点猎手
        c.node_hunt_enabled = _env_bool("WS_NODE_HUNT", c.node_hunt_enabled)
        c.node_hunt_interval = _env_int("WS_NODE_HUNT_INTERVAL", c.node_hunt_interval)
        c.node_hunt_max_sources = _env_int("WS_NODE_HUNT_MAX_SOURCES",
                                           c.node_hunt_max_sources)
        c.node_hunt_probe_limit = _env_int("WS_NODE_HUNT_PROBE_LIMIT",
                                           c.node_hunt_probe_limit)
        c.node_hunt_discover = _env_bool("WS_NODE_HUNT_DISCOVER",
                                         c.node_hunt_discover)
        c.singbox_bin = _env_str("WS_SINGBOX_BIN", c.singbox_bin)
        c.node_probe_concurrency = _env_int("WS_NODE_PROBE_CONCURRENCY",
                                            c.node_probe_concurrency)
        c.node_probe_timeout_ms = _env_int("WS_NODE_PROBE_TIMEOUT_MS",
                                           c.node_probe_timeout_ms)
        c.node_ingest_cap = _env_int("WS_NODE_INGEST_CAP",
                                     c.node_ingest_cap)

        # 客户订阅：env 列表 + 可选文件（合并去重，文件读取失败只记类型名）
        subs = _env_list("WS_CUSTOMER_SUBS", [])
        c.customer_sub_file = _env_str("WS_CUSTOMER_SUB_FILE", "")
        if c.customer_sub_file:
            try:
                for line in Path(c.customer_sub_file).read_text(
                        encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and line not in subs:
                        subs.append(line)
            except OSError as e:
                # 只报路径与异常类型；文件内容含 token，绝不进日志
                log.warning("客户订阅文件读取失败（%s）：%s",
                            c.customer_sub_file, type(e).__name__)
        c.customer_subs = subs

        c.allow_private_net = _env_bool("WS_ALLOW_PRIVATE_NET", c.allow_private_net)
        c.allow_nonstd_port = _env_bool("WS_ALLOW_NONSTD_PORT", c.allow_nonstd_port)
        c.domain_blocklist = _env_list("WS_DOMAIN_BLOCKLIST", [])
        c.domain_allowlist = _env_list("WS_DOMAIN_ALLOWLIST", [])

        c.retry_on_transient = _env_int("WS_RETRY", c.retry_on_transient)
        c.backoff_base = _env_float("WS_BACKOFF_BASE", c.backoff_base)

        return c

    def cache_path(self) -> Path:
        """缓存目录。未配置时落在系统临时目录，避免污染项目目录。"""
        if self.cache_dir:
            p = Path(self.cache_dir)
        else:
            import tempfile

            p = Path(tempfile.gettempdir()) / "websearch-cache"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def nodes_db_path(self) -> Path:
        """节点库文件路径。

        ⚠️ 含节点凭据 —— 与缓存同目录，但 NodePool 会强制 600 权限。
        之所以不单独给配置项：节点库就该跟缓存放一起（都是运行期数据），
        少一个配置项少一处出错机会。
        """
        return self.cache_path() / "nodes.sqlite3"

    def active_engines(self) -> list[str]:
        """启用引擎 = 配置列表 - 显式禁用。"""
        disabled = {d.lower() for d in self.disable_engines}
        return [e for e in self.engines if e.lower() not in disabled]


# 搜索引擎解析器版本。改过任何引擎的 parse() 之后，必须手动 +1。
# 否则旧缓存里的旧格式 URL 会一直命中（360 从 so.com/link 跳转壳改成
# data-mdurl 真实 URL 时就踩过：缓存不过期，错误结果一直复现）。
PARSER_VERSION = "2026-10-13.2"

CONFIG = Config.from_env()
