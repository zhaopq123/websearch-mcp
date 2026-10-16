# websearch-mcp

**给你的 AI 装上联网搜索能力。** 多引擎聚合 · 零 API Key · 自带管理面板 · 内置节点池自运维。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 一条命令装好，打开面板填个订阅链接（可选），AI 客户端立刻获得联网搜索。
> 不依赖任何商业搜索 API，不需要申请 Key。

---

## 特性

| 能力 | 说明 |
|---|---|
| **多引擎聚合** | 国内 9 引擎直连（必应/百度/360/搜狗/微信/头条，含移动版）+ 国外引擎经代理（DuckDuckGo/必应国际版）；并发扇出 + 交叉验证融合 |
| **国内引擎直连** | 国内站在国内直连 1-2s；只有需要翻墙的引擎才走代理 —— 实测经海外出口访问百度恒被拒 |
| **权威源优先** | 来源权威度分级（官媒/政府/学术 +1.0、主流媒体/科技 +0.6、内容农场/UGC −0.6），把 SEO 脏数据压下去 |
| **结果质量过滤** | 投毒式反爬识别（相关性比例校验）、游戏/小说聚合站域名硬过滤、数字串查询专门处理 |
| **节点池自运维** | 自动搜集全球免费节点、多站点可达性抽检（不是只看延迟）、智能更新与淘汰，出网断了自己修 |
| **零 API Key** | 不依赖 Serper/Bing API/Google CSE；搜索引擎直连 + 你自己的节点 |
| **9 个 MCP 工具** | 搜索 / 抓正文 / 深度研究 / 引擎健康 / 代理状态 / 节点管理 / 缓存 / 服务信息 |
| **管理面板** | Web 面板看状态、填订阅、一键接入 AI 客户端；不用碰命令行 |
| **实时性保证** | 缓存 TTL 5 分钟（仅防反爬）；`fresh`/`time_range` 可绕过；每条结果带 `fetched_at` 与来源引擎 |
| **可信度可见** | 每次返回带 `meta`（覆盖率、各引擎成败、是否走缓存）——静默失败是最坏的失败 |

---

## 快速开始

```bash
# 1. 装（一条命令，幂等，可重复执行）
bash install.sh

# 2. 点开它打印的链接（自动登录，不用复制口令）
#    在「机场订阅」填你的订阅链接 → 保存 → 启动代理
#    （不填也能用：国内引擎开箱即用）

# 3. 复制面板里「把它接到你的 AI 客户端」的配置，粘到 AI 客户端
```

装完会打印管理面板地址，面板里用人话告诉你当前状态：

```
🟢 搜索服务正在运行          监听 8300 端口，可以接受 AI 客户端连接
🟡 没有配置代理（只搜国内网站） 现在能搜到百度、必应、360、微信等国内源。
                             想搜 Google 需要填一个订阅链接。[去配置]
🟢 凭据文件权限安全          订阅链接和口令只存在本机，权限 600
```

**手动启动**（不想用 install.sh）：

```bash
python -m venv venv && ./venv/bin/pip install -e .
WS_MCP_PORT=8300 ./venv/bin/python -m websearch.server
```

---

## 接入 AI 客户端

MCP 服务走 HTTP + Bearer token（面板里一键生成配置）。以 Claude Desktop 为例：

```json
{
  "mcpServers": {
    "websearch": {
      "url": "http://<你的主机>:8300/mcp",
      "headers": { "Authorization": "Bearer <面板里复制的 token>" }
    }
  }
}
```

不同客户端的配置格式不通用，面板会给当前主机的正确写法（自动按请求 Host 生成 URL）。

---

## 工具一览

| 工具 | 用途 |
|---|---|
| `web_search` | **主力**。多引擎并发搜索 + 去重融合 + 权威加权，返回带 `meta.coverage` |
| `web_fetch` | 批量抓网页正文（转 Markdown） |
| `deep_research` | 一次问多个侧面问题，并发搜索 + 抓正文 |
| `engine_health` | 各引擎健康度与熔断状态 |
| `proxy_status` | 代理/出网状态（含降级提示） |
| `node_hunt` | 立刻跑一轮节点搜集 + 实测 |
| `node_pool` | 节点库管理（统计 / 列表 / 源健康度 / 一致性自检 / 导入自有订阅） |
| `cache_manage` | 缓存统计与清理 |
| `server_info` | 服务信息 |

所有工具返回都带 `meta`，AI 能据此判断这次结果可信度如何——几个源挂了、
覆盖率多少、有没有走缓存。**静默失败是最坏的失败。**

---

## 能搜什么

| 情况 | 能搜到 | 说明 |
|---|---|---|
| **不配代理**（默认） | 必应、百度、360、搜狗、微信、头条 | 开箱即用，零配置，直连 1-2 秒 |
| **配上代理** | 上面全部 **+ DuckDuckGo、必应国际版** | 需要你自己的节点（订阅链接或自建） |

**关于节点**：本服务内置「节点池」——自动从公开源搜集免费节点、实测筛选、
按**站点可达性**选路（不只看延迟），出网断了自己换。但免费节点寿命以小时计，
**长期稳定出网还是建议用自己的订阅**（填进面板即可，选路优先）。

**已实测证伪的两条路**（别重复投入）：

- 公开免费代理池（SOCKS/HTTP）：直测存活率 ~17%，且大量出口 IP 已被目标站拉黑
- 公共 SearXNG 实例：实测多批全部不可达（域名被 DNS 投毒）

---

## 工程要点

### 反爬认知（重写一次要几天）

- **必应投毒**：识别为爬虫时不返回 403，而是返回一批与查询完全无关的结果。
  HTTP 200、结构完整、每次 10 条，HTTP 层检测完全无效——只有相关性**比例**
  校验能抓（相关率 <30% 判投毒）。数「有没有命中」会漏，投毒会混进 1-2 条碰巧相关的。
- **必应对 UA 极敏感**：Firefox/Safari/Edge UA 下开始投毒，Chrome/Windows 正常。
  UA 池 Chrome Win 占一半，随机轮换是负优化。
- **移动端比 PC 端好破**：百度 PC 返回安全验证页、搜狗 PC 返回 antispider，
  移动端都能拿到完整结果页（代价是各写一套解析器）。
- **Accept-Encoding 必须按实际能力声明**：写 `br` 而没装 brotli → httpx 解不开 →
  不报错、直接乱码、表现成「引擎解析 0 条」，极难定位。
- **数字串查询要区别对待**：搜索引擎对陌生数字返回「无结果 + 模糊推荐页」，
  按投毒判定会把整批引擎熔断——实测一次纯数字查询熔断 9 个引擎 600 秒。

### 实时性设计（硬要求）

- 缓存 TTL 仅 5 分钟且只用于防反爬，**不是数据源**
- `fresh=true` 或传 `time_range` 自动绕过缓存读，但仍写缓存
- 每次返回带 `fetched_at` + `realtime` + 逐条 `cached` 标记
- `PARSER_VERSION` 在缓存 key 里：解析器升级后不会读到旧格式 URL

### 工具 schema 红线（改工具前必读）

严格模型（Step-5-Preview / GLM-5.3-Flash / Deepseek-V4.1-Flash）逐字校验
工具定义，两个构造会让整个请求在进模型前被拒（11129 / 11133，inputTokens: 0，
表现是「工具一多就全线崩」）：

1. **不许有 outputSchema** —— 所有 `@mcp.tool()` 必须带 `output_schema=None`
   （用 `_MCP` 字典展开）。FastMCP 默认会给返回 dict 的工具自动生成
   `{"additionalProperties": true, ...}` 的 outputSchema，纯负担；
2. **inputSchema 不许有 anyOf** —— 参数要支持多形态（如 `urls` 收字符串/数组），
   类型写 `Any`，别写 `str | list[str]`（后者生成 anyOf）。

`tests/test_tool_schema.py` 把这两条锁死了。

---

## 测试

```bash
PYTHONPATH=src ./venv/bin/python -m pytest tests/ -m 'not online'   # 离线用例
PYTHONPATH=src ./venv/bin/python scripts/mcp_e2e.py                 # MCP 协议 E2E
PYTHONPATH=src ./venv/bin/python scripts/dump_tool_schema.py        # 打印 tools/list 全量 schema
PYTHONPATH=src ./venv/bin/python scripts/user_perspective_check.py  # 用户视角协议验证
PYTHONPATH=src ./venv/bin/python scripts/stress.py                  # 压测
```

当前基线：**466 passed**（离线）。`scripts/diag/` 下有各引擎的独立诊断脚本
（解析器改不动时用它们抓真实 HTML 比对）。

---

## 部署

服务是普通 Python 进程，任何常驻环境都能跑：

- **systemd**：`ExecStart=/opt/websearch-mcp/venv/bin/python -m websearch.server`
  加 `Restart=always`；`install.sh` 会给出对应 unit 文件
- **无 systemd**（容器 / 安卓 Termux / 路由器）：用任何进程守护
  （tmux + `while true` 循环、runit、supervisord 都行）——
  关键是**崩溃后自动重拉**
- 端口：**8300**（MCP 服务）+ **8500**（管理面板，只监听内网）
- 日志重定向要在**服务所在环境内**做，别在宿主 shell 里 `>> /opt/...`
  （宿主没有 `/opt` 会空转循环）

`scripts/ctl.sh` 提供 `status|restart|logs|health|warmup|token|test`。

---

## 依赖

- **Python ≥ 3.11**（`pyproject.toml` 声明）
- 核心依赖：`fastmcp`、`uvicorn`、`starlette`、`httpx`、`socksio`
  （`socksio` 是 httpx 走 SOCKS 代理的必需品，漏装表现为「代理直测全 ImportError」）
- 可选：`trafilatura`（正文提取准确率更高，没装自动降级内置提取器）
- 出网组件：`sing-box`（面板会检查并给出安装方法）

---

## 架构

```
websearch-mcp/
├── src/websearch/
│   ├── server.py         # MCP 服务入口（9 工具）+ 生命周期
│   ├── orchestrator.py   # 搜索编排：扇出 → 熔断 → 校验 → 融合 → 早停
│   ├── engines.py        # 引擎定义（build/parse）+ 结果过滤
│   ├── authority.py      # 来源权威度分级
│   ├── fusion.py         # 多引擎结果融合排序（权威加权 / SimHash 去重）
│   ├── governor.py       # per-engine 熔断 + 限流 + 健康画像
│   ├── http_pool.py      # 连接池（代理 / 直连双通道）+ 请求闸门
│   ├── cache.py          # 实时性缓存（TTL 5min + PARSER_VERSION）
│   ├── nodes/            # 节点池：搜集 / 探测 / 选路 / 本地代理
│   ├── proxy/            # 出网：订阅解析 / 代理门控 / 管理面板
│   └── text.py           # 相关性校验 / SimHash / 摘要清洗
├── tests/                # 466 离线用例
├── scripts/              # 安装 / 启动 / 运维 / 诊断 / E2E / 压测
└── docs/                 # 代理与出网配置详解
```

---

## License

MIT —— 见 [LICENSE](LICENSE)。
