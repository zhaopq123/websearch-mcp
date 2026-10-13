# websearch-mcp

**给你的 AI 装上联网搜索能力。** 多引擎聚合、零 API Key、自带管理面板。

## 三步用起来

```bash
# 1. 装（一条命令，幂等，可重复执行）
bash install.sh

# 2. 点开它打印的链接（自动登录，不用复制口令）
#    在「机场订阅」填你的订阅链接 → 保存 → 启动代理

# 3. 复制面板里「把它接到你的 AI 客户端」的配置，粘到你的 AI 客户端
```

装完你会看到这样的输出：

```
══════════════════════════════════════════════════════════════
 websearch-mcp 管理面板
 访问地址: http://192.168.1.100:8500

 ┌─ 点这个链接直接进面板（5 分钟内有效，一次性）─────────
 │ http://192.168.1.100:8500/_open?t=xxxxxxxx
 └──────────────────────────────────────────────────────
══════════════════════════════════════════════════════════════
```

面板里会用人话告诉你当前状态，并直接给出该做什么：

```
🟢 搜索服务正在运行          监听 8300 端口，可以接受 AI 客户端连接
🟡 没有配置代理（只搜国内网站） 现在能搜到百度、必应、360、微信等国内源。
                             想搜 Google 需要填一个订阅链接。[去配置]
🟢 凭据文件权限安全          订阅链接和口令只存在本机，权限 600
```

## 能搜什么

| 情况 | 能搜到 | 说明 |
|---|---|---|
| **不配代理**（默认） | 百度、必应、360、搜狗、微信、头条 | 开箱即用，零配置 |
| **配上代理** | 上面全部 **+ Google、DuckDuckGo、Brave** | 需要你自己的节点 |

墙内直连的实测结论（2026-10-13，中国大陆网络）：

- Google / DuckDuckGo / Brave / Wikipedia → **不可达**（网络层）
- 公开免费代理池：19710 个样本测 1800 个，**能通 Google 的 0 个**
- 公共 SearXNG 实例：12 个全部不可达（域名被 DNS 投毒）

所以：**想出网只能用你自己的节点。** 本服务不内置、不收集、不代理
任何人的节点。

## 关于代理

**为什么需要**：Google 等优质源在墙内不可达。想用就得有节点。

**怎么配**：装 [sing-box](https://github.com/SagerNet/sing-box)（`install.sh`
会检查并给出装法），然后在面板里填订阅链接。支持 ss / vmess / trojan /
vless（含 Reality）/ hysteria2 / tuic。

**安全**：订阅链接只写进你服务器上 600 权限的 `.env`，不入 git、不进日志、
面板不回显（只显示掩码和域名）。详见 [docs/代理与出网配置.md](docs/代理与出网配置.md)。

**代理挂了不影响搜索**：连续失败 3 次自动降级直连（仍能用国内源），
每 60s 探活，恢复后自动切回。这是刻意的设计 —— 代理是增强功能，
不该变成单点故障。

## 给 AI 用的工具（7 个）

| 工具 | 用途 |
|---|---|
| `web_search` | 主力。多引擎并发搜索 + 去重融合，返回带 `meta.coverage` |
| `web_fetch` | 批量抓网页正文（转 Markdown）|
| `deep_research` | 一次问多个侧面问题，并发搜索 + 抓正文 |
| `engine_health` | 看各引擎健康度与熔断状态 |
| `proxy_status` | 看代理/出网状态（含降级提示）|
| `cache_manage` | 缓存统计与清理 |
| `server_info` | 服务信息 |

所有工具返回都带 `meta`，AI 能据此判断「这次结果可信度如何」——
几个源挂了、覆盖率多少、有没有走缓存。**静默失败是最坏的失败。**

## 运维

```bash
bash scripts/panel-ctl.sh status     # 面板状态
bash scripts/panel-ctl.sh restart    # 重启面板
bash scripts/panel-ctl.sh logs       # 看日志
bash scripts/panel-ctl.sh proxy      # 代理与订阅状态（不含凭据）
```

面板里也能直接管搜索服务（「现在能不能用」卡片上的按钮），
不需要懂 tmux 或 systemd。

## 技术信息

- 端口 **8300**（MCP 服务）、**8500**（管理面板）
- MCP 服务用 Bearer token 鉴权（密钥在 `.tokens`，勿入 git）
- 面板用独立口令鉴权（首次启动生成，只打印一次）
- 生产部署：vivo 容器 `/opt/websearch-mcp/`；版本权威副本 = Termux 宿主
  `~/git/websearch-mcp.git`（bare）

## 引擎态势（2026-10-13 实测）

| 状态 | 引擎 |
|---|---|
| 稳定 | so360、weixin（搜狗微信，高价值垂直源） |
| 间歇 | bing、bing_intl（投毒式反爬，相关性校验兜底） |
| 封锁 | baidu/sogou PC 端、baidu_m/sogou_m/so360_m/toutiao 移动端 |
| 不可达 | duckduckgo / mojeek / brave（国内网络，熔断自动隔离） |

搜索靠 so360 + weixin 出结果；`/health` 的 `warmup.available` 是当前真正能用的源。
配上代理后 Google / DDG / Brave 会重新可用（它们的失败原因是网络不可达，
不是反爬）。

**已实测证伪的两条路**（别重复投入）：

- 公开免费代理池：19710 个样本测 1800 个，能通 Google 的 **0 个**
  （连不需翻墙的 httpbin.org 都连不上，池子本身已死）
- 公共 SearXNG 实例：12 个全部不可达，根因是**域名被 DNS 投毒**
  （`priv.au` 被解析到 Facebook 的 IP 段 `2a03:2880:...face:b00c`）

## 反爬核心认知（重写一次要几天，别自己重试）

- **必应投毒**：识别为爬虫时不返回 403，返回一批与查询完全无关的结果。HTTP 200、结构完整、每次 10 条，HTTP 层检测完全无效，只有相关性**比例**校验能抓（相关率 <30% 判投毒）。数「有没有命中」会漏——投毒里会混进 1-2 条碰巧相关的。
- **必应对 UA 极敏感**：Firefox/Safari/Edge UA 下开始投毒，Chrome/Windows 正常。UA 池 Chrome Win 占一半，随机轮换是负优化。
- **移动端比 PC 端好破**：百度 PC 返回安全验证页、搜狗 PC 返回 antispider，两者移动端都能拿到完整结果页。代价是各写一套解析器。
- **Accept-Encoding 必须按实际能力声明**：写 `br` 而没装 brotli → httpx 解不开 → 不报错、直接乱码、表现成「引擎解析 0 条」，极难定位。

## 实时性设计（硬要求）

- 缓存 TTL 仅 5 分钟且只用于防反爬，**不是数据源**
- `fresh=true` 或传 `time_range` 自动绕过缓存读，但仍写缓存
- 每次返回带 `fetched_at` + `realtime` + 逐条 `cached` 标记
- `PARSER_VERSION` 在缓存 key 里：解析器升级后不会读到旧格式 URL（so.com/link?m= redirect 壳这类）

## 运维

```bash
bash /opt/websearch-mcp/scripts/ctl.sh {status|restart|logs|health|warmup|token|test}   # 不在 PATH
```

- `restart` = 杀 python 等宿主看门狗重拉（15-25 秒恢复）；`start/stop` 会提示去宿主操作，防双开
- 监督模型：**Termux 宿主 tmux 会话 `websearch`** 里 `while true; do proot-distro login ubuntu -- run-logged.sh; sleep 10; done`，开机由 `ubuntu-autostart`（`/data/data/com.termux/files/usr/bin/`）幂等创建。python 崩溃 10 秒内重拉，手机重启自动恢复。
- 日志重定向必须在容器内做（`run-logged.sh`）——宿主没有 `/opt`，`>> /opt/...` 在宿主 shell 会空转循环。
- **绝不要 `tmux kill-server`**：同机跑着 8000/8200/8300，会被一起杀。只 `tmux kill-session -t websearch`。

## 部署流程

```text
改代码 → git commit → push 到宿主 bare → 宿主侧 cd 容器 rootfs 路径 git pull → 杀 python 让看门狗重拉
```

容器 rootfs 宿主侧路径：`/data/data/com.termux/files/usr/var/lib/proot-distro/containers/ubuntu/rootfs/opt/websearch-mcp`

杀法：`ps -eo pid,cmd | grep 'venv/bin/pytho[n] -m websearch'` 取 pid kill；优雅停机约 16 秒释放端口，重启测试要留窗口。

## 测试

```bash
cd /opt/websearch-mcp
PYTHONPATH=src ./venv/bin/python -m pytest tests/ -m 'not online'   # 离线用例（含 schema 兼容性回归）
./venv/bin/python scripts/mcp_e2e.py            # MCP 协议 E2E（initialize→tools/list→tools/call→实时→SSRF）
PYTHONPATH=src ./venv/bin/python scripts/dump_tool_schema.py   # 打印 tools/list 全量 schema（排查兼容性用）
PYTHONPATH=src ./venv/bin/python scripts/user_perspective_check.py  # 用户视角协议验证（9 项）
./venv/bin/python scripts/diag/smoke.py   # 冒烟
./venv/bin/python scripts/stress.py       # 压测
```

**工具 schema 红线（改工具前必读）**：严格模型（Step-5-Preview /
GLM-5.3-Flash / Deepseek-V4.1-Flash）逐字校验工具定义，两个构造会让
整个请求在进模型前被拒（11129 / 11133，inputTokens: 0，表现是
「工具一多就全线崩」）：

1. **不许有 outputSchema** —— 所有 `@mcp.tool()` 必须带
   `output_schema=None`（用 `_MCP` 字典展开）。FastMCP 默认会给返回
   dict 的工具自动生成一个 `{"additionalProperties": true, ...}` 的
   outputSchema，纯负担；
2. **inputSchema 不许有 anyOf** —— 参数要支持多形态（如 `urls` 收
   字符串/数组），类型写 `Any`，别写 `str | list[str]`（后者会生成
   anyOf）。运行时解析函数（`_parse_url_list` / `_parse_query_list`）
   本来就吃三种形态。

`tests/test_tool_schema.py` 把这两条锁死了，破坏它 CI 直接红。

## 已调好的参数（别乱动）

限流 1.0 rps / burst 5 · quorum_results 12 · 早停时 cancel 的引擎只记延迟不记失败 · 熔断的引擎仍要查缓存 · 批量抓取每 URL 硬超时兜底。
