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
