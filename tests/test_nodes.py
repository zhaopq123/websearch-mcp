# -*- coding: utf-8 -*-
"""节点猎手子系统测试（全离线，不触网）。

覆盖：节点库去重/健康分/无凭据视图、Clash YAML 解析、订阅链接识别、
猎手组源与智能降级决策。
"""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.http_pool import BlockedRedirectError
from websearch.nodes import sources as node_sources
from websearch.nodes.pool import NodePool, fingerprint
from websearch.nodes.sources import (
    SourceFetcher,
    _looks_like_subscription_url,
    extract_subscription_urls,
    source_id,
)

IS_WIN = sys.platform == "win32"


# ══════════════════════ 节点库 ══════════════════════


@pytest.fixture
def pool(tmp_path):
    return NodePool(tmp_path / "nodes.sqlite3")


def test_fingerprint_ignores_field_order():
    """同一节点在不同源里字段顺序不同，指纹必须一致（去重的前提）。"""
    a = {"server": "x.com", "server_port": 443, "method": "aes-256-gcm",
         "password": "p"}
    b = {"password": "p", "method": "aes-256-gcm", "server_port": 443,
         "server": "x.com"}
    assert fingerprint("shadowsocks", a) == fingerprint("shadowsocks", b)


def test_fingerprint_distinguishes_nodes():
    a = {"server": "x.com", "server_port": 443, "password": "p1"}
    b = {"server": "x.com", "server_port": 443, "password": "p2"}
    c = {"server": "x.com", "server_port": 444, "password": "p1"}
    assert fingerprint("ss", a) != fingerprint("ss", b)
    assert fingerprint("ss", a) != fingerprint("ss", c)


def test_upsert_dedup_and_reject_invalid(pool):
    """重复入库只算一次；缺 server/port 的坏节点被拒。"""
    nodes = [
        ("n1", "shadowsocks",
         {"server": "a.com", "server_port": 443, "password": "p"}),
        ("n1 重复", "shadowsocks",
         {"server_port": 443, "password": "p", "server": "a.com"}),
        ("n2", "trojan", {"server": "b.com", "server_port": 8443,
                          "password": "q"}),
        ("坏", "vmess", {"server": "", "server_port": 0}),
    ]
    assert pool.upsert_nodes(nodes, "src1") == 2
    assert pool.upsert_nodes(nodes, "src2") == 0   # 再入无新增
    assert pool.stats().total == 2


def test_probe_updates_health_and_dead_streak(pool):
    """连续失败到阈值判死；成功则复活并累计延迟。"""
    pool.upsert_nodes([("n", "ss",
                        {"server": "a.com", "server_port": 443,
                         "password": "p"})], "s")
    fp = pool.candidates_for_probe()[0]["fp"]
    pool.record_probe(fp, True, 100)
    pool.record_probe(fp, True, 200)
    b = pool.best()
    assert b["alive"] is True
    assert b["ok_count"] == 2
    assert 100 <= b["avg_ms"] <= 200     # EMA 在两者之间

    for _ in range(NodePool.DEAD_STREAK):
        pool.record_probe(fp, False)
    assert pool.best(only_alive=True) is None      # 已判死
    assert pool.stats().alive == 0


def test_best_prefers_success_rate_over_pure_speed(pool):
    """最优节点是「成功率 × 延迟」综合，不是纯最快。"""
    pool.upsert_nodes([
        ("fast-flaky", "ss", {"server": "fast.com", "server_port": 1,
                              "password": "p"}),
        ("slow-solid", "ss", {"server": "solid.com", "server_port": 2,
                              "password": "p"}),
    ], "s")
    cands = {c["server"]: c["fp"] for c in pool.candidates_for_probe()}
    fast, solid = cands["fast.com"], cands["solid.com"]
    # 快节点：1 次成功 3 次失败（成功率低）
    pool.record_probe(fast, True, 50)
    for _ in range(2):      # 未到 DEAD_STREAK，仍 alive
        pool.record_probe(fast, False)
    # 慢节点：3 次全成功
    for _ in range(3):
        pool.record_probe(solid, True, 300)
    assert pool.best()["server"] == "solid.com"


def test_public_views_never_leak_credentials(pool):
    """对外视图（list_public / stats / source_health）绝不含凭据。"""
    pool.upsert_nodes([("🇯🇵JP", "trojan",
                        {"server": "a.com", "server_port": 443,
                         "password": "SUPER_SECRET"})], "s")
    fp = pool.candidates_for_probe()[0]["fp"]
    pool.record_probe(fp, True, 100)
    blob = json.dumps([
        pool.list_public(), pool.stats().to_dict(), pool.source_health(),
    ], ensure_ascii=False)
    for secret in ("SUPER_SECRET", "outbound", "password", "uuid"):
        assert secret not in blob, f"对外视图泄露了 {secret}"
    # 内部接口能取到（供代理启动用）
    ob = pool.outbound_for(fp)
    assert ob and "password" in json.dumps(ob)


def test_country_guess_from_tag(pool):
    pool.upsert_nodes([
        ("🇸🇬 SG | node-1", "ss", {"server": "a.com", "server_port": 1,
                                   "password": "p"}),
        ("日本 东京 02", "ss", {"server": "b.com", "server_port": 1,
                              "password": "p"}),
    ], "s")
    for c in pool.candidates_for_probe():
        assert c["country"] in ("新加坡", "日本")


def test_prune_removes_stale(pool):
    """很久没在源里出现、且没成功过的节点被淘汰。"""
    pool.upsert_nodes([("old", "ss", {"server": "a.com", "server_port": 1,
                                      "password": "p"})], "s")
    assert pool.prune(max_age_sec=0) == 1     # 立刻视为过期
    assert pool.stats().total == 0


@pytest.mark.skipif(IS_WIN, reason="Windows 无 POSIX 权限语义")
def test_db_file_is_600(pool):
    mode = stat.S_IMODE(os.stat(pool.path).st_mode)
    assert mode == 0o600


# ══════════════════════ Clash YAML 解析 ══════════════════════


def test_clash_yaml_all_protocols():
    from websearch.proxy.subparse import parse_clash_yaml
    yaml_text = """
proxies:
  - name: "ss-1"
    type: ss
    server: a.com
    port: 443
    cipher: aes-256-gcm
    password: pw1
  - name: "trojan-1"
    type: trojan
    server: b.com
    port: 8443
    password: pw2
    sni: b.com
    skip-cert-verify: true
  - name: "vmess-1"
    type: vmess
    server: c.com
    port: 443
    uuid: u-1
    alterId: 4
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: cdn.com
  - name: "vless-1"
    type: vless
    server: d.com
    port: 443
    uuid: u-2
    tls: true
    servername: d.com
    reality-opts:
      public-key: PK
      short-id: "12"
    client-fingerprint: chrome
  - name: "hy2-1"
    type: hysteria2
    server: e.com
    port: 443
    password: pw3
"""
    rep = parse_clash_yaml(yaml_text)
    assert rep.summary()["parsed"] == 5
    by_tag = {n.tag: n for n in rep.nodes}
    assert by_tag["ss-1"].outbound["method"] == "aes-256-gcm"
    assert by_tag["ss-1"].outbound["password"] == "pw1"
    # trojan 必须强制 TLS（协议本身即全 TLS）
    assert by_tag["trojan-1"].outbound["tls"]["enabled"] is True
    assert by_tag["trojan-1"].outbound["tls"]["insecure"] is True
    # vmess ws + alter_id + tls
    vm = by_tag["vmess-1"].outbound
    assert vm["alter_id"] == 4
    assert vm["transport"]["type"] == "ws"
    assert vm["transport"]["path"] == "/path"
    assert vm["transport"]["headers"]["Host"] == "cdn.com"
    # vless reality + utls
    vl = by_tag["vless-1"].outbound
    assert vl["tls"]["reality"]["public_key"] == "PK"
    assert vl["tls"]["utls"]["fingerprint"] == "chrome"
    # hysteria2 强制 TLS
    assert by_tag["hy2-1"].outbound["tls"]["enabled"] is True


def test_clash_yaml_skips_unsupported_but_reports():
    """不支持的协议要列出原因，不静默丢弃。"""
    from websearch.proxy.subparse import parse_clash_yaml
    rep = parse_clash_yaml("""
proxies:
  - name: ssr-1
    type: ssr
    server: a.com
    port: 443
  - name: ok
    type: ss
    server: b.com
    port: 443
    cipher: aes-128-gcm
    password: p
""")
    assert len(rep.nodes) == 1
    assert len(rep.skipped) == 1
    assert "ssr" in rep.skipped[0]["scheme"]


def test_parse_subscription_text_routes_clash_yaml():
    """含 proxies: 的 yaml 自动走 clash 解析分支。"""
    from websearch.proxy.subparse import parse_subscription_text
    text = "proxies:\n  - name: n\n    type: ss\n    server: a.com\n" \
           "    port: 443\n    cipher: aes-128-gcm\n    password: p\n"
    rep = parse_subscription_text(text)
    assert rep.summary()["parsed"] == 1


# ══════════════════════ 订阅链接识别 ══════════════════════


@pytest.mark.parametrize("url,expected", [
    ("https://fonts.googleapis.com/css2?family=x", False),   # 曾误判（css2 含 ss）
    ("https://wiki.freedomport.cc/", False),                 # 曾误判（含 free）
    ("https://manifest.dpdns.org/free/latest/v2ray.txt", True),
    ("https://example.com/sub?token=abc", True),
    ("https://raw.githubusercontent.com/u/r/main/list.txt", True),
    ("https://github.com/user/repo", False),
    ("https://t.me/freenodedaily", False),
    ("https://a.com/logo.png", False),
    ("https://api.example.com/api/v1/client/subscribe?token=x", True),
    ("https://node.foo.cn/", True),
])
def test_subscription_url_word_boundary(url, expected):
    """关键词必须词边界匹配 —— 裸子串会把 css2/freedomport 误判。"""
    assert _looks_like_subscription_url(url) is expected


def test_extract_from_page_text():
    # 注意：不要用 x.com 当样本 —— 它是 twitter 域名，在噪声表里
    html = ('<a href="https://sub.example.com/link?token=1">a</a>'
            '<link href="https://fonts.googleapis.com/css2">f</link>'
            ' see https://y.com/free/latest/clash.yaml')
    urls = extract_subscription_urls(html)
    assert any("sub.example.com" in u for u in urls)
    assert any("clash.yaml" in u for u in urls)
    assert not any("fonts.googleapis" in u for u in urls)


@pytest.mark.asyncio
async def test_source_fetcher_blocks_unsafe_initial_url(monkeypatch):
    """猎手不应绕过主抓取器的 SSRF 入口校验。"""
    async def deny(_url, _cfg):
        return False, "private_ip:127.0.0.1"

    def no_request(*_args, **_kwargs):
        raise AssertionError("SSRF-blocked URL must not create an HTTP client")

    monkeypatch.setattr(node_sources, "assert_url_async", deny)
    monkeypatch.setattr(node_sources.httpx, "AsyncClient", no_request)
    result = await SourceFetcher().fetch("http://127.0.0.1/sub.txt")
    assert result.ok is False
    assert result.error == "blocked_url"


@pytest.mark.asyncio
async def test_source_fetcher_blocks_redirect_to_private_target(monkeypatch):
    """公网源 302 到内网地址也必须在 httpx 跟随前拦截。"""
    async def deny(_url, _cfg):
        return False, "redirect_private_ip:169.254.169.254"

    monkeypatch.setattr(node_sources, "check_redirect_sync", deny)
    request = httpx.Request("GET", "https://public.example/sub.txt")
    response = httpx.Response(
        302, request=request,
        headers={"location": "http://169.254.169.254/latest/meta-data/"},
    )
    with pytest.raises(BlockedRedirectError):
        await SourceFetcher()._guard_redirect(response)


def test_source_fetcher_classify():
    """内容形态判定：订阅本体 vs 网页 vs 未知。"""
    f = SourceFetcher._classify
    assert f("<!doctype html><html>", "http://x") == "page"
    assert f("ss://abc\nvmess://xyz", "http://x") == "sub"
    assert f("proxies:\n  - type: ss", "http://x") == "sub"
    import base64
    # 用真实量级的 base64（阈值 40，短串按未知处理）
    b64 = base64.b64encode(b"ss://abc\nss://def\nss://ghi\nss://jkl").decode()
    assert f(b64, "http://x") == "sub"
    assert f("hello world", "http://x") == "unknown"
    assert f("short", "http://x") == "unknown"


def test_source_id_stable():
    assert source_id("https://a.com/x") == source_id("https://a.com/x")
    assert source_id("https://a.com/x") != source_id("https://a.com/y")


# ══════════════════════ 猎手：组源与降级决策 ══════════════════════


@pytest.mark.asyncio
async def test_hunter_build_sources_dedup(tmp_path):
    """组源：种子 + 历史，去重保序；不重复加同一个 URL。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    pool = NodePool(tmp_path / "p.sqlite3")
    hunter = NodeHunter(
        pool=pool,
        fetcher=SourceFetcher(timeout=1),
        prober=NodeProber(singbox_bin="", work_dir=tmp_path),
        orch=None,
    )
    srcs = await hunter._build_sources(discover=False, report={})
    urls = [s["url"] for s in srcs]
    assert len(urls) == len(set(urls)), "组源有重复"
    assert urls, "至少要有种子源"


@pytest.mark.asyncio
async def test_discover_via_search_filters_junk(tmp_path):
    """源发现必须挡掉搜索引擎跳转/门户噪声。

    2026-10-14 实测：bing.com/ck/a 追踪链接、baike.baidu.com 词条被当成
    聚合站入库，每轮空转抓取烧预算。这里钉死：垃圾 URL 不进、正常聚合站进。
    """
    class _FakeOrch:
        async def search(self, q, max_results=6, fresh=True):
            return {"results": [
                {"url": "https://www.bing.com/ck/a?!&&p=deadbeef&u=a1aHR0"},
                {"url": "https://baike.baidu.com/item/free!/2929353"},
                {"url": "https://baiduvideo.cn/"},
                {"url": "https://www.zhihu.com/question/123"},
                {"url": "https://aggregator.example.org/subscribe"},   # 合法
                {"url": "https://sub.example.net/free/latest/"},        # 合法
            ]}

    found = await node_sources.discover_via_search(_FakeOrch(), max_queries=1)
    hosts = [u.split("/")[2] for u in found]
    assert "aggregator.example.org" in "".join(found)
    assert "sub.example.net" in "".join(found)
    assert not any("bing.com" in h for h in hosts)
    assert not any("baidu.com" in h for h in hosts)
    assert not any("baiduvideo.cn" in h for h in hosts)
    assert not any("zhihu.com" in h for h in hosts)


@pytest.mark.asyncio
async def test_build_sources_skips_dead_sources(tmp_path):
    """从未成功且反复失败的「死源」不再进组源清单。"""
    from websearch.nodes.hunter import (
        DEAD_SOURCE_MIN_FAILS, NodeHunter,
    )
    from websearch.nodes.probe import NodeProber

    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_source("dead_sid", "https://junk.example/dead", "page")
    for _ in range(DEAD_SOURCE_MIN_FAILS):
        pool.record_source_fetch("dead_sid", False, error="fetch fail")
    pool.upsert_source("ok_sid", "https://good.example/sub.txt", "sub")
    pool.record_source_fetch("ok_sid", True, nodes_found=12)

    hunter = NodeHunter(
        pool=pool, fetcher=SourceFetcher(timeout=1),
        prober=NodeProber(singbox_bin="", work_dir=tmp_path), orch=None,
    )
    urls = [s["url"] for s in await hunter._build_sources(discover=False, report={})]
    assert "https://junk.example/dead" not in urls, "死源应被跳过"
    assert "https://good.example/sub.txt" in urls, "健康源应保留"

    # 反例：还没到阈值（失败 DEAD-1 次）仍应保留，避免误伤偶发失败
    pool2 = NodePool(tmp_path / "p2.sqlite3")
    pool2.upsert_source("flaky_sid", "https://flaky.example/sub.txt", "sub")
    for _ in range(DEAD_SOURCE_MIN_FAILS - 1):
        pool2.record_source_fetch("flaky_sid", False, error="fetch fail")
    h2 = NodeHunter(
        pool=pool2, fetcher=SourceFetcher(timeout=1),
        prober=NodeProber(singbox_bin="", work_dir=tmp_path), orch=None,
    )
    urls2 = [s["url"] for s in await h2._build_sources(discover=False, report={})]
    assert "https://flaky.example/sub.txt" in urls2, "未到阈值的源不应被跳过"


@pytest.mark.asyncio
async def test_smart_failover_no_alive_returns_none(tmp_path):
    """池里无存活节点 → 报告「应降级直连」，不假装切换。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    pool = NodePool(tmp_path / "p.sqlite3")
    hunter = NodeHunter(pool=pool, fetcher=SourceFetcher(timeout=1),
                        prober=NodeProber(singbox_bin="", work_dir=tmp_path))
    r = await hunter.smart_failover()
    assert r["switched"] is False
    assert "降级直连" in r["reason"]


@pytest.mark.asyncio
async def test_smart_failover_switches_to_best(tmp_path):
    """有活节点且当前不是最优 → 通过回调切换。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([("n", "ss", {"server": "a.com", "server_port": 443,
                                    "password": "p"})], "s")
    fp = pool.candidates_for_probe()[0]["fp"]
    pool.record_probe(fp, True, 120)

    seen: list[dict] = []

    async def cb(outbound: dict) -> bool:
        seen.append(outbound)
        return True

    hunter = NodeHunter(pool=pool, fetcher=SourceFetcher(timeout=1),
                        prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                        switch_cb=cb)
    r = await hunter.smart_failover(switch_cb=cb)
    assert r["switched"] is True
    assert seen and seen[0]["server"] == "a.com"
    assert hunter.state.current_node_fp == fp
    assert hunter.state.failovers == 1

    # 再跑一次：当前已是最优 → 不再切换
    r2 = await hunter.smart_failover(switch_cb=cb)
    assert r2["switched"] is False
    assert len(seen) == 1


# ══════════════════════ cust / free 双池隔离 ══════════════════════
#
# 背景：客户导入的节点（机场订阅）与系统自搜的免费节点混在一个池里，
# 会有两类后果，都会在这里用「坏数据」钉死：
#   1. 选路把付费节点和免费垃圾平等排序 → 可能选出随时会消失的免费节点
#   2. 免费源数百节点的探测预算挤掉客户节点的探测机会 → 客户节点永远「未知」


def _node(host: str, port: int = 443) -> tuple[str, str, dict]:
    return (host, "ss", {"server": host, "server_port": port,
                         "method": "aes-256-gcm", "password": "pw"})


def test_cust_pool_wins_even_if_free_is_faster(tmp_path):
    """客户池优先：免费节点延迟再低也不能顶掉可用的客户节点。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("cust.example.com")], "s1", pool="cust")
    pool.upsert_nodes([_node("free.example.com")], "s2", pool="free")
    cust_fp = pool.candidates_for_probe(pool="cust")[0]["fp"]
    free_fp = pool.candidates_for_probe(pool="free")[0]["fp"]
    pool.record_probe(cust_fp, True, 900)    # 客户节点慢
    pool.record_probe(free_fp, True, 50)      # 免费节点快

    best = pool.best()
    assert best["server"] == "cust.example.com", "免费节点不该顶掉客户节点"
    assert best["pool"] == "cust"


def test_best_falls_back_to_free_when_cust_all_dead(tmp_path):
    """客户池全挂 → 回落免费池（兜底必须能生效）。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("cust.example.com")], "s1", pool="cust")
    pool.upsert_nodes([_node("free.example.com")], "s2", pool="free")
    cust_fp = pool.candidates_for_probe(pool="cust")[0]["fp"]
    free_fp = pool.candidates_for_probe(pool="free")[0]["fp"]
    # 客户节点连续失败到判定死亡
    for _ in range(pool.DEAD_STREAK):
        pool.record_probe(cust_fp, False)
    pool.record_probe(free_fp, True, 300)

    best = pool.best()
    assert best["server"] == "free.example.com"
    assert best["pool"] == "free"


def test_free_node_does_not_downgrade_cust(tmp_path):
    """同一节点被免费源命中 → 归属保持 cust（否则会被 prune 误杀付费节点）。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("shared.example.com")], "cust-sub", pool="cust")
    pool.upsert_nodes([_node("shared.example.com")], "free-src", pool="free")
    rows = pool.list_public(only_alive=False)
    assert len(rows) == 1
    assert rows[0]["pool"] == "cust", "免费源命中不该把客户节点降级成 free"


def test_prune_default_only_touches_free_pool(tmp_path):
    """默认清理只清 free 池 —— 客户节点不能按「多久没出现」被淘汰。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("cust.example.com")], "s1", pool="cust")
    pool.upsert_nodes([_node("free.example.com")], "s2", pool="free")
    # max_age_sec=0 = 立刻全部过期
    n = pool.prune(max_age_sec=0)
    assert n == 1
    left = {r["server"] for r in pool.list_public(only_alive=False)}
    assert left == {"cust.example.com"}, "客户节点被误删了"
    # 显式指定才清客户池
    assert pool.prune(max_age_sec=0, pool="cust") == 1
    assert pool.list_public(only_alive=False) == []


def test_probe_candidates_respect_pool_filter(tmp_path):
    """分池取候选：客户节点不会被免费源挤出探测窗口。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node(f"free{i}.example.com") for i in range(50)],
                      "s2", pool="free")
    pool.upsert_nodes([_node("cust.example.com")], "s1", pool="cust")
    # 免费源 50 个候选先到，但取 10 个候选时客户节点必须在其中
    cands = pool.candidates_for_probe(limit=10, pool="cust")
    assert [c["server"] for c in cands] == ["cust.example.com"]
    assert all(c["pool"] == "cust" for c in cands)


def test_stats_report_both_pools(tmp_path):
    """面板统计要能一眼看出两池差别。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("cust.example.com")], "s1", pool="cust")
    pool.upsert_nodes([_node("free.example.com")], "s2", pool="free")
    st = pool.stats().to_dict()
    assert st["by_pool"]["cust"]["total"] == 1
    assert st["by_pool"]["free"]["total"] == 1


def test_migration_puts_legacy_nodes_in_cust(tmp_path):
    """老库没有 pool 列 → 历史节点必须归 cust，不能被当免费节点清掉。"""
    import sqlite3
    db = tmp_path / "legacy.sqlite3"
    conn = sqlite3.connect(str(db))
    conn.executescript("""
        CREATE TABLE nodes (
            fp TEXT PRIMARY KEY, protocol TEXT, server TEXT, port INTEGER,
            country TEXT DEFAULT '', tag TEXT DEFAULT '', outbound TEXT,
            sources TEXT DEFAULT '', first_seen REAL, last_seen REAL,
            alive INTEGER DEFAULT 0, last_ms INTEGER DEFAULT 0,
            avg_ms REAL DEFAULT 0, ok_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0, streak_fail INTEGER DEFAULT 0,
            last_ok_at REAL DEFAULT 0, last_probe_at REAL DEFAULT 0);
    """)
    conn.execute(
        "INSERT INTO nodes (fp, protocol, server, port, outbound,"
        " first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
        ("abc123", "ss", "old.example.com", 443, "{}",
         1000.0, 1000.0),
    )
    conn.commit()
    conn.close()

    pool = NodePool(db)
    rows = pool.list_public(only_alive=False)
    assert len(rows) == 1 and rows[0]["pool"] == "cust"


async def test_hunter_import_customer_goes_to_cust(tmp_path):
    """import_customer 与自搜入库分属不同池。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber
    from websearch.nodes.sources import SourceFetcher

    pool = NodePool(tmp_path / "p.sqlite3")
    hunter = NodeHunter(pool=pool, fetcher=SourceFetcher(timeout=1),
                        prober=NodeProber(singbox_bin="", work_dir=tmp_path))
    cust_sub = "trojan://pw@cust.example.com:443#my-node"
    free_sub = "trojan://pw2@free.example.com:443#other"
    parsed, added = hunter.import_customer(cust_sub)
    assert parsed == 1 and added == 1
    parsed2, added2 = hunter._ingest_text(free_sub, "free-src")
    assert parsed2 == 1 and added2 == 1

    cust = pool.list_public(only_alive=False, pool="cust")
    free = pool.list_public(only_alive=False, pool="free")
    assert [r["server"] for r in cust] == ["cust.example.com"]
    assert [r["server"] for r in free] == ["free.example.com"]


# ══════════════════════ 保活闭环（维持 N 个活节点）══════════════════════
#
# 需求：搜→跑→测→删一直跑，保持 100 个活节点。
# 关键约束：活节点持续死亡，补充速度必须快过死亡速度，且探测预算
# 不能浪费在重测已知死节点上（实测免费池 807 个存活 0）。

def _hunter(tmp_path):
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber
    from websearch.nodes.sources import SourceFetcher
    pool = NodePool(tmp_path / "p.sqlite3")
    return NodeHunter(pool=pool, fetcher=SourceFetcher(timeout=1),
                      prober=NodeProber(singbox_bin="", work_dir=tmp_path)), pool


def test_keepalive_probe_scales_with_deficit(tmp_path):
    """缺口大 → 探测量放大（存活率决定要探多少才够）。"""
    h, pool = _hunter(tmp_path)
    h.state.target_alive = 100
    # 模拟存活率 5%（免费节点实测极低）
    h._alive_rate_ema = 0.05
    plan = h.plan_next_round()
    assert plan["mode"] == "keepalive"
    assert plan["deficit"] == 100
    # 要养 100 个活的、存活率 5%，至少得探 100/0.05 = 2000，
    # 乘overshoot 后远超库存 → 撞硬上限 400
    assert plan["probe_limit"] == 400


def test_keepalive_interval_fast_when_short_fast_when_full(tmp_path):
    """缺口大 → 间隔短；达标 → 间隔长。"""
    from websearch.nodes import hunter as H

    h, pool = _hunter(tmp_path)
    h.state.target_alive = 100

    # 一个活节点都没有 → 最快间隔
    plan = h.plan_next_round()
    assert plan["deficit"] == 100
    assert plan["delay_sec"] == H.INTERVAL_MIN

    # 全部达标 → 最慢间隔
    pool.upsert_nodes([(f"a{i}.example.com", "ss",
                        {"server": f"a{i}.example.com", "server_port": 443,
                         "method": "aes-256-gcm", "password": "p"})
                       for i in range(100)], "s", pool="free")
    for c in pool.candidates_for_probe(limit=200):
        pool.record_probe(c["fp"], True, 300)
    plan = h.plan_next_round()
    assert plan["deficit"] == 0
    assert plan["delay_sec"] == H.INTERVAL_MAX


def test_keepalive_not_stalled_when_inventory_empty(tmp_path):
    """⚠️ 库存挖空时探测量不能被压成0（否则永远补不上）。"""
    from websearch.nodes import hunter as H

    h, pool = _hunter(tmp_path)
    h.state.target_alive = 100
    h._alive_rate_ema = 0.3
    # 库里一个节点都没有 → untested=0
    assert pool.stats().untested == 0
    plan = h.plan_next_round()
    # 关键：不能是 0/1，probe_batch 探不到候选会自己少探，但计划值必须有量
    assert plan["probe_limit"] >= H.PROBE_MIN
    assert plan["probe_limit"] > 1


def test_probe_prefers_untested_over_known_dead(tmp_path):
    """⚠️ 探测预算不能浪费在重测已知死节点上。

    库里 5 个刚测过的死节点 + 3 个从未测过的新节点 → 取 3 个候选
    必须全是新节点。早期实现按 last_probe_at ASC 排会把死节点排在
    最前，保活就永远测不到新货。
    """
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("dead.example.com")], "s", pool="free")
    dead_fp = pool.candidates_for_probe(pool="free")[0]["fp"]
    pool.record_probe(dead_fp, False)          # 刚测过，死
    pool.upsert_nodes([_node(f"new{i}.example.com") for i in range(3)],
                      "s", pool="free")
    cands = pool.candidates_for_probe(limit=3, pool="free")
    assert all("new" in c["server"] for c in cands), \
        f"候选里混进了已知死节点: {[c['server'] for c in cands]}"


def test_keepalive_prune_is_aggressive_but_not_cust(tmp_path):
    """保活模式：死节点快速淘汰，但客户池仍不动。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_nodes([_node("cust.example.com")], "s1", pool="cust")
    pool.upsert_nodes([_node("free.example.com")], "s2", pool="free")
    # 两个都标记为「很久没出现且从没活过」
    n = pool.prune(max_age_sec=0)
    assert n == 1
    assert [r["server"] for r in pool.list_public(only_alive=False)] \
        == ["cust.example.com"]


def test_alive_rate_ema_needs_samples(tmp_path):
    """没有样本时不能瞎猜存活率（否则探测量会被算成极小值）。"""
    h, pool = _hunter(tmp_path)
    h.state.target_alive = 100
    h._alive_rate_ema = 0.0
    plan = h.plan_next_round()
    assert plan["alive_rate"] == 0.0
    # 无样本 → 用 PROBE_MIN 兜底，不是 0
    assert plan["probe_limit"] >= 240
    # 有样本后才更新
    h._update_alive_rate(100, 5)
    assert 0.04 < h._alive_rate_ema < 0.06
