# websearch-mcp

零 API Key 的多引擎聚合联网搜索 MCP 服务（fastmcp + streamableHttp）。

## 基本信息

- 端口 **8300**，Bearer token 鉴权（密钥在 `.tokens`，勿入 git）
- 工具 6 个：`web_search` / `web_fetch` / `deep_research` / `engine_health` / `cache_manage` / `server_info`
- 生产部署：vivo 容器 `/opt/websearch-mcp/`；版本权威副本 = Termux 宿主 `~/git/websearch-mcp.git`（bare）
- serverInfo 报的 `4.1.0` 是 fastmcp 库版本，不是项目版本

## 引擎态势（2026-10-13 实测）

| 状态 | 引擎 |
|---|---|
| 稳定 | so360、weixin（搜狗微信，高价值垂直源） |
| 间歇 | bing、bing_intl（投毒式反爬，相关性校验兜底） |
| 封锁 | baidu/sogou PC 端、baidu_m/sogou_m/so360_m/toutiao 移动端 |
| 不可达 | duckduckgo / mojeek / brave（国内网络，熔断自动隔离） |

搜索靠 so360 + weixin 出结果；`/health` 的 `warmup.available` 是当前真正能用的源。

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
PYTHONPATH=src ./venv/bin/python -m pytest tests/ -m 'not online'   # 离线 76 用例
./venv/bin/python scripts/mcp_e2e.py      # MCP 协议 E2E（initialize→tools/list→tools/call→实时→SSRF）
./venv/bin/python scripts/diag/smoke.py   # 冒烟
./venv/bin/python scripts/stress.py       # 压测
```

## 已调好的参数（别乱动）

限流 1.0 rps / burst 5 · quorum_results 12 · 早停时 cancel 的引擎只记延迟不记失败 · 熔断的引擎仍要查缓存 · 批量抓取每 URL 硬超时兜底。
