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
from websearch.nodes.pool import NodePool, fingerprint, read_pool_overview
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
    # ── 2026-10-14 收严：poki.com 游戏页实测假源 ──
    ("https://api.poki.com", False),                    # 实测假订阅链接（裸 api 域名）
    ("https://poki.com/en/free-games", False),          # 弱词 free 不再单独放行
    ("https://poki.com/en/g/subway-surfers", False),    # 无任何订阅特征
    ("https://free.example.com/", False),               # 裸 free 域名不再放行
    ("https://example.com/jump?url=https://evil", False),  # ?url= 是跳转不是订阅
    ("https://4399.com/", False),
    ("https://sub.example.net/free/latest/", True),     # 强主机词仍放行
])
def test_subscription_url_word_boundary(url, expected):
    """关键词必须词边界匹配 —— 裸子串会把 css2/freedomport 误判；
    弱词（free/share/nodes）与裸 api/free 域名不单独放行（poki 假源）。"""
    assert _looks_like_subscription_url(url) is expected


def test_extract_from_poki_page_yields_nothing():
    """poki 游戏页整页提取：一个订阅链接都不该有（2026-10-14 实测假源）。"""
    html = ('<a href="https://api.poki.com">api</a>'
            '<a href="https://poki.com/en/free-games">games</a>'
            '<a href="https://poki.com/en/g/subway-surfers">s</a>')
    assert extract_subscription_urls(html) == []


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


# ══════════════════ 抓源出网路径：直连 ↔ 本地代理 ══════════════════


def _patch_client(monkeypatch, *, direct_exc=None, proxy_exc=None):
    """把 httpx.AsyncClient 换成按 proxy 参数决定行为的假 client。

    返回 calls 列表：每次实例化记录传入的 proxy（"" = 直连），
    用来断言「走了哪条路、走了一条还是两条」。
    """
    calls: list[str] = []

    class _Resp:
        status_code = 200
        text = "ss://abc\nvmess://def"

    class _Client:
        def __init__(self, **kwargs):
            self._proxy = kwargs.get("proxy") or ""
            calls.append(self._proxy)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            if self._proxy:
                if proxy_exc is not None:
                    raise proxy_exc
            elif direct_exc is not None:
                raise direct_exc
            return _Resp()

    monkeypatch.setattr(node_sources.httpx, "AsyncClient", _Client)
    return calls


@pytest.mark.asyncio
async def test_fetcher_falls_back_to_local_proxy(monkeypatch):
    """直连网络错误 → 自动改走本地代理；两条路都试过才认输。"""
    calls = _patch_client(monkeypatch,
                          direct_exc=httpx.ConnectTimeout("direct dead"))
    f = SourceFetcher(timeout=1,
                      proxy_provider=lambda: "http://127.0.0.1:17892")
    r = await f.fetch("https://manifest.dpdns.org/free/latest/v2ray.txt")
    assert r.ok is True
    assert calls == ["", "http://127.0.0.1:17892"]   # 先直连后代理
    # 成功路径被记住：下次同一宿主不再先赌直连超时
    assert f._remembered_path("manifest.dpdns.org") == "proxy"


@pytest.mark.asyncio
async def test_fetcher_proxy_first_for_github_raw(monkeypatch):
    """GitHub raw 宿主默认代理优先 —— 不为已知不通的直连浪费一轮超时。"""
    calls = _patch_client(monkeypatch)
    f = SourceFetcher(timeout=1,
                      proxy_provider=lambda: "http://127.0.0.1:17892")
    r = await f.fetch(
        "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt")
    assert r.ok is True
    assert calls == ["http://127.0.0.1:17892"]        # 只走代理，没赌直连
    assert f._remembered_path("raw.githubusercontent.com") == "proxy"


@pytest.mark.asyncio
async def test_fetcher_path_memory_skips_dead_direct(monkeypatch):
    """记住「代理通」后，同宿主第二把直接走代理（不重复试直连）。"""
    calls = _patch_client(monkeypatch,
                          direct_exc=httpx.ConnectTimeout("direct dead"))
    f = SourceFetcher(timeout=1,
                      proxy_provider=lambda: "http://127.0.0.1:17892")
    url = "https://manifest.dpdns.org/free/latest/v2ray.txt"
    assert (await f.fetch(url)).ok is True
    calls.clear()
    assert (await f.fetch(url)).ok is True
    assert calls == ["http://127.0.0.1:17892"]


@pytest.mark.asyncio
async def test_fetcher_no_retry_on_http_error(monkeypatch):
    """HTTP 4xx/5xx 不是网络错误：不换路径，如实返回（源健康度要记真实状态）。"""
    class _Resp:
        status_code = 403
        text = "forbidden"

    class _Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            return _Resp()

    monkeypatch.setattr(node_sources.httpx, "AsyncClient", _Client)
    f = SourceFetcher(timeout=1,
                      proxy_provider=lambda: "http://127.0.0.1:17892")
    r = await f.fetch("https://example.com/sub.txt")
    assert r.ok is False and r.error == "HTTP 403"


@pytest.mark.asyncio
async def test_fetcher_proxy_unavailable_degrades_to_direct(monkeypatch):
    """sing-box 没起来（provider 返回 ""）→ 纯直连，不报错。"""
    calls = _patch_client(monkeypatch)
    f = SourceFetcher(timeout=1, proxy_provider=lambda: "")
    r = await f.fetch("https://example.com/sub.txt")
    assert r.ok is True
    assert calls == [""]


@pytest.mark.asyncio
async def test_fetcher_user_proxy_single_path(monkeypatch):
    """用户显式配了代理：只用它，不做直连兜底。"""
    calls = _patch_client(monkeypatch)
    f = SourceFetcher(timeout=1, proxy="http://user:pass@host:7897",
                      proxy_provider=lambda: "http://127.0.0.1:17892")
    r = await f.fetch("https://example.com/sub.txt")
    assert r.ok is True
    assert calls == ["http://user:pass@host:7897"]


# ══════════════════ 客户订阅导入（cust 池）══════════════════


@pytest.mark.asyncio
async def test_import_customer_subs_goes_to_cust_pool(tmp_path):
    """配置了客户订阅：抓取→解析→cust 池；不记 source 健康表（URL 含 token）。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    class _Stub:
        async def fetch(self, url):
            from websearch.nodes.sources import Fetched
            return Fetched(url=url, ok=True, text="trojan://pw@cust.example.com:443#n",
                           content_kind="sub")

    pool = NodePool(tmp_path / "p.sqlite3")
    hunter = NodeHunter(pool=pool, fetcher=_Stub(),
                        prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                        customer_subs=["https://airport.example/sub?token=SECRET"])
    rep = await hunter.import_customer_subs()
    assert rep == {"configured": 1, "ok": 1, "fail": 0, "parsed": 1, "added": 1}
    cust = pool.list_public(only_alive=False, pool="cust")
    assert [r["server"] for r in cust] == ["cust.example.com"]
    # 订阅 URL（含 token）绝不能进 sources 表
    assert pool.source_health(limit=50) == []


@pytest.mark.asyncio
async def test_import_customer_subs_failure_counted(tmp_path):
    """订阅抓取失败/解析 0 节点：记 fail，不炸、不记 URL。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber
    from websearch.nodes.sources import Fetched

    class _Dead:
        async def fetch(self, url):
            return Fetched(url=url, ok=False, error="ConnectTimeout")

    class _Empty:
        async def fetch(self, url):
            return Fetched(url=url, ok=True, text="<html>登录页</html>",
                           content_kind="page")

    pool = NodePool(tmp_path / "p.sqlite3")
    prober = NodeProber(singbox_bin="", work_dir=tmp_path)
    h1 = NodeHunter(pool=pool, fetcher=_Dead(), prober=prober,
                    customer_subs=["https://a.example/s?token=x"])
    rep = await h1.import_customer_subs()
    assert rep["ok"] == 0 and rep["fail"] == 1

    h2 = NodeHunter(pool=pool, fetcher=_Empty(), prober=prober,
                    customer_subs=["https://b.example/s?token=x"])
    rep2 = await h2.import_customer_subs()
    assert rep2["ok"] == 0 and rep2["fail"] == 1


def test_config_customer_subs_from_env_and_file(tmp_path, monkeypatch):
    """WS_CUSTOMER_SUBS + WS_CUSTOMER_SUB_FILE 合并去重；文件含 token 不外泄。"""
    from websearch.config import Config

    sub_file = tmp_path / "subs.txt"
    sub_file.write_text("# 注释\nhttps://a.example/s?token=T1\n\n"
                        "https://b.example/s?token=T2\n", encoding="utf-8")
    monkeypatch.setenv("WS_CUSTOMER_SUBS", "https://c.example/s?token=T3, https://a.example/s?token=T1")
    monkeypatch.setenv("WS_CUSTOMER_SUB_FILE", str(sub_file))
    c = Config.from_env()
    assert c.customer_subs == [
        "https://c.example/s?token=T3",
        "https://a.example/s?token=T1",
        "https://b.example/s?token=T2",
    ]
    # 文件不存在：不炸，只留 env 的
    monkeypatch.setenv("WS_CUSTOMER_SUB_FILE", str(tmp_path / "nope.txt"))
    c2 = Config.from_env()
    assert len(c2.customer_subs) == 2


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
    dead_url = "https://junk.example/dead"
    pool.upsert_source(source_id(dead_url), dead_url, "page")
    for _ in range(DEAD_SOURCE_MIN_FAILS):
        pool.record_source_fetch(source_id(dead_url), False, error="fetch fail")
    pool.upsert_source(source_id("https://good.example/sub.txt"),
                       "https://good.example/sub.txt", "sub")
    pool.record_source_fetch(source_id("https://good.example/sub.txt"),
                             True, nodes_found=12)

    hunter = NodeHunter(
        pool=pool, fetcher=SourceFetcher(timeout=1),
        prober=NodeProber(singbox_bin="", work_dir=tmp_path), orch=None,
    )
    urls = [s["url"] for s in await hunter._build_sources(discover=False, report={})]
    assert "https://junk.example/dead" not in urls, "死源应被跳过"
    assert "https://good.example/sub.txt" in urls, "健康源应保留"

    # 反例：还没到阈值（失败 DEAD-1 次）仍应保留，避免误伤偶发失败
    pool2 = NodePool(tmp_path / "p2.sqlite3")
    flaky_url = "https://flaky.example/sub.txt"
    pool2.upsert_source(source_id(flaky_url), flaky_url, "sub")
    for _ in range(DEAD_SOURCE_MIN_FAILS - 1):
        pool2.record_source_fetch(source_id(flaky_url), False, error="fetch fail")
    h2 = NodeHunter(
        pool=pool2, fetcher=SourceFetcher(timeout=1),
        prober=NodeProber(singbox_bin="", work_dir=tmp_path), orch=None,
    )
    urls2 = [s["url"] for s in await h2._build_sources(discover=False, report={})]
    assert "https://flaky.example/sub.txt" in urls2, "未到阈值的源不应被跳过"


@pytest.mark.asyncio
async def test_build_sources_skips_zero_contribution_sources(tmp_path):
    """返回 200 但贡献恒为 0 的源必须被淘汰，哪怕 ok_count 很高。

    2026-10-14 生产实测：62 个源里 37 个是这样 —— 智能发现把
    poki.com / 4399 / 7k7k / cambridge / iciba / runoob 当成了节点源，
    它们 HTTP 200 但一条节点/订阅链接都挖不出来。旧逻辑把它们记成
    ok=True，`source_health` 按 ok/(ok+fail) 排序，于是它们长期霸占
    榜首、每轮必抓，还挤掉 `source_list[:max_sources]` 的名额。
    """
    from websearch.nodes.hunter import DEAD_SOURCE_MIN_FAILS, NodeHunter
    from websearch.nodes.probe import NodeProber

    pool = NodePool(tmp_path / "p.sqlite3")
    junk = "https://www.poki.com/category/games"
    good = "https://good.example/sub.txt"
    pool.upsert_source(source_id(junk), junk, "page")
    # 旧口径：抓取成功但零产出 → ok_count 一路涨，nodes_found 恒为 0
    for _ in range(DEAD_SOURCE_MIN_FAILS + 40):
        pool.record_source_fetch(source_id(junk), True, nodes_found=0)
    pool.upsert_source(source_id(good), good, "sub")
    pool.record_source_fetch(source_id(good), True, nodes_found=12)

    hunter = NodeHunter(
        pool=pool, fetcher=SourceFetcher(timeout=1),
        prober=NodeProber(singbox_bin="", work_dir=tmp_path), orch=None,
    )
    report: dict = {}
    urls = [s["url"] for s in await hunter._build_sources(discover=False,
                                                          report=report)]
    assert junk not in urls, "零贡献源不该再占用抓取预算"
    assert good in urls, "有产出的源必须保留"
    assert report["sources_dead_skipped"] >= 1


@pytest.mark.asyncio
async def test_page_source_with_no_links_counts_as_failure(tmp_path):
    """page 源挖不出订阅链接 → 记失败，而不是永远记成功。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    class _Stub:
        def __init__(self, text: str, kind: str):
            self._text, self._kind = text, kind

        async def fetch(self, url: str):
            return type("R", (), {"ok": True, "text": self._text,
                                  "content_kind": self._kind, "error": ""})()

    pool = NodePool(tmp_path / "p.sqlite3")
    page = "https://game.example/list"
    pool.upsert_source(source_id(page), page, "page")

    # 1) 游戏站：200，但页面里没有任何订阅链接
    h = NodeHunter(pool=pool, fetcher=_Stub("<html>小游戏大全</html>", "page"),
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                   orch=None)
    rep1 = {"sources_ok": 0, "sources_fail": 0, "parsed": 0, "new_nodes": 0}
    await h._fetch_and_ingest([{"url": page, "kind": "page"}], rep1)
    assert rep1["sources_ok"] == 0 and rep1["sources_fail"] == 1
    row = [s for s in pool.source_health(limit=10) if s["url"] == page][0]
    assert row["ok"] == 0 and row["fail"] == 1
    assert row["last_error"] == "no_sub_links"

    # 2) 真聚合页：页面里能挖出订阅链接 → 记成功，且贡献数 = 链接数。
    #    stub 按 URL 分流：page 返回 HTML，第二层的订阅地址返回真订阅内容
    #    （否则第二层抓到同一份 HTML，自指链接被滤掉后会反记一条失败）。
    sub_url = "https://agg.example/sub.txt"
    body = f'<a href="{sub_url}">sub</a>'

    class _Stub2:
        async def fetch(self, url: str):
            if url == page:
                return type("R", (), {"ok": True, "text": body,
                                      "content_kind": "page", "error": ""})()
            return type("R", (), {"ok": True,
                                  "text": "trojan://pw@agg.example.com:443#n",
                                  "content_kind": "sub", "error": ""})()

    h2 = NodeHunter(pool=pool, fetcher=_Stub2(),
                    prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                    orch=None)
    rep2 = {"sources_ok": 0, "sources_fail": 0, "parsed": 0, "new_nodes": 0}
    await h2._fetch_and_ingest([{"url": page, "kind": "page"}], rep2)
    # 第一层 page 记 1 次成功；第二层订阅也记 1 次成功（含解析出的节点）
    assert rep2["sources_ok"] == 2 and rep2["sources_fail"] == 0
    assert rep2["parsed"] == 1 and rep2["new_nodes"] == 1
    row2 = [s for s in pool.source_health(limit=10) if s["url"] == page][0]
    assert row2["ok"] == 1 and row2["nodes_found"] >= 1


@pytest.mark.asyncio
async def test_sub_source_yielding_no_nodes_counts_as_failure(tmp_path):
    """订阅内容里一行节点都没有（失效订阅/被换成博客）→ 记失败。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    class _Stub:
        async def fetch(self, url: str):
            return type("R", (), {"ok": True, "text": "not a subscription",
                                  "content_kind": "sub", "error": ""})()

    pool = NodePool(tmp_path / "p.sqlite3")
    url = "https://dead.example/sub.txt"
    pool.upsert_source(source_id(url), url, "sub")
    h = NodeHunter(pool=pool, fetcher=_Stub(),
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                   orch=None)
    rep = {"sources_ok": 0, "sources_fail": 0, "parsed": 0, "new_nodes": 0}
    await h._fetch_and_ingest([{"url": url, "kind": "sub"}], rep)
    assert rep["sources_ok"] == 0 and rep["sources_fail"] == 1
    row = [s for s in pool.source_health(limit=10) if s["url"] == url][0]
    assert row["ok"] == 0 and row["last_error"] == "empty_sub"


def test_healthy_sources_counts_output_not_http_200(tmp_path):
    """stats 的 healthy_sources 只算「有产出」的源，不算「能返回 200」的。"""
    pool = NodePool(tmp_path / "p.sqlite3")
    pool.upsert_source("junk", "https://junk.example/x", "page")
    for _ in range(156):
        pool.record_source_fetch("junk", True, nodes_found=0)
    pool.upsert_source("good", "https://good.example/sub.txt", "sub")
    pool.record_source_fetch("good", True, nodes_found=7)

    st = pool.stats()
    assert st.source_count == 2
    assert st.healthy_sources == 1


# ══════════════════ 页面火源：页内裸 URI 直解析（2026-10-14）══════════════════


def test_extract_node_uris_from_html():
    """页内 href 里的裸节点 URI 要抠得出来（HTML 实体先反转义）。"""
    import base64
    import json as _json

    from websearch.nodes.sources import extract_node_uris

    cfg = _json.dumps({"v": "2", "ps": "t", "add": "fire.example.com",
                       "port": "443",
                       "id": "15234567-89ab-cdef-1234-567890abcdef",
                       "net": "tcp"})
    vmess = "vmess://" + base64.b64encode(cfg.encode()).decode()
    html = ('<div class="msg"><a href="' + vmess + '">n1</a></div>'
            '<code>vless://15234567-89ab-cdef-1234-567890abcdef@'
            'fire.example.com:443?type=ws#n2</code>'
            '<a href="' + vmess + '">dup</a>')
    uris = extract_node_uris(html)
    assert len(uris) == 2  # 同一个 vmess 出现两次，去重后剩 1
    assert uris[0].startswith("vmess://")
    assert uris[1].startswith("vless://")
    # query 里的 &amp; 要被反转义回 &，否则参数被截断
    esc = extract_node_uris(
        '<a href="vless://uuid@h.example.com:443?type=ws&amp;security=tls#x">')
    assert "&security=tls" in esc[0]
    # 空/无 URI 不炸
    assert extract_node_uris("") == []
    assert extract_node_uris("<html>小游戏大全</html>") == []


@pytest.mark.asyncio
async def test_page_with_embedded_node_uris_ingested(tmp_path):
    """火源页（clashgithub 日更页形态）：页内裸 URI 直接入库并记成功。

    旧逻辑只认订阅链接，这种页面会被判 no_sub_links 拉黑 —— 实测日更页
    嵌 455 个 URI，全漏。
    """
    import base64
    import json as _json

    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    cfg = _json.dumps({"v": "2", "ps": "t", "add": "fire.example.com",
                       "port": "443",
                       "id": "15234567-89ab-cdef-1234-567890abcdef",
                       "net": "tcp"})
    vmess = "vmess://" + base64.b64encode(cfg.encode()).decode()
    body = f'<div class="tgme_widget_message_text">{vmess}</div>'

    class _Stub:
        async def fetch(self, url: str):
            return type("R", (), {"ok": True, "text": body,
                                  "content_kind": "page", "error": ""})()

    pool = NodePool(tmp_path / "p.sqlite3")
    page = "https://clashgithub.com/clashnode-20261014.html"
    pool.upsert_source(source_id(page), page, "page")
    h = NodeHunter(pool=pool, fetcher=_Stub(),
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                   orch=None)
    rep = {"sources_ok": 0, "sources_fail": 0, "parsed": 0, "new_nodes": 0}
    await h._fetch_and_ingest([{"url": page, "kind": "page"}], rep)
    assert rep["sources_ok"] == 1 and rep["sources_fail"] == 0
    assert rep["parsed"] == 1 and rep["new_nodes"] == 1
    row = [s for s in pool.source_health(limit=10) if s["url"] == page][0]
    assert row["ok"] == 1 and row["nodes_found"] == 1
    nodes = pool.list_public(only_alive=False)
    assert [r["server"] for r in nodes] == ["fire.example.com"]


@pytest.mark.asyncio
async def test_dated_seed_formats_today_and_history_skips_dated(tmp_path):
    """日期种子按当天格式化；日期页不进历史轮换（旧页重抓纯耗预算）。"""
    import time as _time

    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    pool = NodePool(tmp_path / "p.sqlite3")
    h = NodeHunter(pool=pool,
                   fetcher=type("F", (), {"fetch": None})(),
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                   orch=None)
    rep = {"sources_dead_skipped": 0}
    out = await h._build_sources(discover=False, report=rep)
    urls = [s["url"] for s in out]
    today = _time.strftime("%Y%m%d")
    # 种子里的 %Y%m%d 被格式化成今天
    assert f"https://clashgithub.com/clashnode-{today}.html" in urls
    assert not any("%Y" in u for u in urls)
    # 健康度很好的历史日期页也不进轮换
    old = f"https://clashgithub.com/clashnode-20260101.html"
    pool.upsert_source(source_id(old), old, "page")
    for _ in range(50):
        pool.record_source_fetch(source_id(old), True, nodes_found=455)
    out2 = await h._build_sources(discover=False, report={"sources_dead_skipped": 0})
    assert old not in [s["url"] for s in out2]


def test_candidates_prefer_newest_untested(tmp_path):
    """未测节点必须最新优先生效——免费节点按小时死，陈库存 0% 存活。"""
    import sqlite3

    pool = NodePool(tmp_path / "p.sqlite3")
    sid = "s"
    items = [
        ("old", "trojan", {"type": "trojan", "server": "old.example.com",
                           "port": 443, "password": "p"}),
        ("mid", "trojan", {"type": "trojan", "server": "mid.example.com",
                           "port": 443, "password": "p"}),
        ("new", "trojan", {"type": "trojan", "server": "new.example.com",
                           "port": 443, "password": "p"}),
    ]
    pool.upsert_nodes(items, source_sid=sid, pool="free")
    conn = pool._ensure()
    # 手工摆 first_seen：old 最老、new 最新（都未测）
    conn.execute("UPDATE nodes SET first_seen=? WHERE server='old.example.com'",
                 (1000.0,))
    conn.execute("UPDATE nodes SET first_seen=? WHERE server='mid.example.com'",
                 (2000.0,))
    conn.execute("UPDATE nodes SET first_seen=? WHERE server='new.example.com'",
                 (3000.0,))
    conn.commit()
    got = [c["server"] for c in pool.candidates_for_probe(limit=10)]
    assert got[:3] == ["new.example.com", "mid.example.com", "old.example.com"]


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


# ══════════════════════ 节点池只读读取器（面板画灯用）══════════════════════


def _fp_of(host: str) -> str:
    """从 _node() 的同一份构造推导指纹 —— 别手写一份，改了 _node 这里会漂。"""
    _, proto, fields = _node(host)
    return fingerprint(proto, fields)


def test_read_pool_overview_missing_db_is_safe(tmp_path):
    """库还没生成 → 明确说「还没有」，绝不顺手建一个。"""
    db = tmp_path / "nodes.sqlite3"
    r = read_pool_overview(db)
    assert r["available"] is False
    assert r["nodes"] == [] and r["stats"] == {}
    assert "note" in r
    assert not db.exists(), "只读读取器不该创建节点库"


def test_read_pool_overview_reports_lights(tmp_path):
    """面板要的就是「哪个通、哪个不通」—— alive 必须如实带出来。"""
    pool = NodePool(tmp_path / "nodes.sqlite3")
    pool.upsert_nodes([_node("up.example.com")], "s1", pool="free")
    pool.upsert_nodes([_node("down.example.com")], "s2", pool="free")
    pool.record_probe(_fp_of("up.example.com"), True, 120)   # 标记存活
    pool.close()

    r = read_pool_overview(tmp_path / "nodes.sqlite3")
    assert r["available"] is True
    assert r["stats"]["total"] == 2
    assert r["stats"]["alive"] == 1
    assert r["stats"]["by_pool"]["free"]["total"] == 2
    lights = {n["server"]: n["alive"] for n in r["nodes"]}
    assert lights == {"up.example.com": True, "down.example.com": False}
    # 活的排前面 —— 用户扫一眼就看见能用的
    assert r["nodes"][0]["server"] == "up.example.com"
    # 绝不带凭据
    assert "password" not in r["nodes"][0]


def test_read_pool_overview_only_alive_filter(tmp_path):
    pool = NodePool(tmp_path / "nodes.sqlite3")
    pool.upsert_nodes([_node("up.example.com")], "s1", pool="free")
    pool.upsert_nodes([_node("down.example.com")], "s2", pool="free")
    pool.record_probe(_fp_of("up.example.com"), True, 50)
    pool.close()

    r = read_pool_overview(tmp_path / "nodes.sqlite3", only_alive=True)
    assert [n["server"] for n in r["nodes"]] == ["up.example.com"]


def test_read_pool_overview_never_writes(tmp_path):
    """只读是硬约束：面板是独立进程，读一眼不该动服务端正在用的库。"""
    db = tmp_path / "nodes.sqlite3"
    pool = NodePool(db)
    pool.upsert_nodes([_node("a.example.com")], "s1", pool="free")
    pool.close()
    before_size = db.stat().st_size
    before_mtime = db.stat().st_mtime_ns

    read_pool_overview(db, limit=10)

    assert db.stat().st_size == before_size
    assert db.stat().st_mtime_ns == before_mtime
    # 也没有额外落一个 WAL（只读连接不会触发 WAL 恢复/写入）
    assert not (tmp_path / "nodes.sqlite3-wal").exists() or \
        (tmp_path / "nodes.sqlite3-wal").stat().st_size == 0


# ══════════════ 2026-10-14 普通代理入池 ══════════════


def test_ingest_cap_truncates_proxy_list_flood(tmp_path):
    """单源入库上限：代理列表洪水（万行）只进 cap 条，库不爆。

    公开代理列表（HProxy/Proxifly/…）动辄几千上万行，不设上限会把
    库和探测预算一起撑爆。截断是「当轮丢弃」语义——源下轮还会来。
    """
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    text = "\n".join(
        f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}:1080"
        for i in range(2000))
    pool = NodePool(tmp_path / "p.sqlite3")
    h = NodeHunter(pool=pool, fetcher=None,
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                   ingest_cap=500)
    n, _added = h._ingest_text(text, "s1", url="https://x.example/socks5.txt")
    assert n == 2000                       # 解析数照实报（不隐瞒规模）
    assert pool.stats().total == 500       # 入库被 cap 截断


def test_ingest_cap_zero_means_unlimited(tmp_path):
    """cap=0 = 不限制（VPN 订阅源不受代理列表上限影响）。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    text = "\n".join(f"trojan://pw@n{i}.example.com:443#n{i}"
                     for i in range(50))
    pool = NodePool(tmp_path / "p.sqlite3")
    h = NodeHunter(pool=pool, fetcher=None,
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path),
                   ingest_cap=0)
    _n, added = h._ingest_text(text, "s1", url="https://x.example/list.txt")
    assert added == 50
    assert pool.stats().total == 50


def test_proxy_list_nodes_enter_free_pool_as_socks(tmp_path):
    """普通代理列表 → free 池，protocol=socks（与 VPN 节点同一管线）。"""
    from websearch.nodes.hunter import NodeHunter
    from websearch.nodes.probe import NodeProber

    text = "\n".join(f"198.51.100.{i}:1080" for i in range(1, 8))
    pool = NodePool(tmp_path / "p.sqlite3")
    h = NodeHunter(pool=pool, fetcher=None,
                   prober=NodeProber(singbox_bin="", work_dir=tmp_path))
    n, added = h._ingest_text(text, "s1", url="https://x.example/socks5.txt")
    assert n == 7 and added == 7
    rows = pool.list_public(only_alive=False)
    assert all(r["protocol"] == "socks" for r in rows)
    assert all(r["pool"] == "free" for r in rows)


def test_prune_deletes_dead_proxies_despite_fresh_last_seen(tmp_path):
    """死透硬删：alive=0 + 测过 + 48h 没活过 → 删，不问 last_seen。

    代理列表源每轮都列出死代理（列表自身不清理），last_seen 被无限
    刷新 —— 只依赖 last_seen 的主规则永远删不掉它们，库无限膨胀。
    """
    import time as _t

    pool = NodePool(tmp_path / "p.sqlite3")
    now = _t.time()
    # 死节点：49h 前最后一次探测成功，但 last_seen 是「现在」
    # （代理列表每轮都列出它）
    pool.upsert_nodes([("dead1", "socks",
                        {"type": "socks", "server": "10.0.0.1",
                         "server_port": 1080, "version": "5"})])
    conn = pool._ensure()
    conn.execute("UPDATE nodes SET alive=0, last_probe_at=?,"
                 " last_ok_at=?, last_seen=? WHERE tag='dead1'",
                 (now - 3600, now - 49 * 3600, now))
    # 活节点：last_ok_at 旧但活着 → 不能删
    pool.upsert_nodes([("alive1", "socks",
                        {"type": "socks", "server": "10.0.0.2",
                         "server_port": 1080, "version": "5"})])
    conn.execute("UPDATE nodes SET alive=1, last_probe_at=?,"
                 " last_ok_at=?, last_seen=? WHERE tag='alive1'",
                 (now, now - 49 * 3600, now))
    # 刚死的节点：5h 前最后一次成功 → 不删（48h 内）
    pool.upsert_nodes([("fresh-dead", "socks",
                        {"type": "socks", "server": "10.0.0.3",
                         "server_port": 1080, "version": "5"})])
    conn.execute("UPDATE nodes SET alive=0, last_probe_at=?,"
                 " last_ok_at=?, last_seen=? WHERE tag='fresh-dead'",
                 (now - 3600, now - 5 * 3600, now))
    conn.commit()

    pruned = pool.prune()
    assert pruned == 1
    left = {r["tag"] for r in pool.list_public(only_alive=False)}
    assert left == {"alive1", "fresh-dead"}


def test_prune_deletes_stale_untested_stock(tmp_path):
    """陈库存硬删：入库超过窗口且从未排到探测 → 删（探测预算排不到，纯负担）。

    窗口默认 2 天，运行期由 set_probe_throughput 按实测吞吐收敛
    （见 test_prune_untested_window_converges_to_throughput）。
    """
    import time as _t

    pool = NodePool(tmp_path / "p.sqlite3")
    now = _t.time()
    conn = pool._ensure()
    for i, age_d in ((0, 4), (1, 4), (2, 0)):   # 两个陈旧 + 一个新鲜
        pool.upsert_nodes([(f"n{i}", "socks",
                            {"type": "socks", "server": f"10.1.0.{i}",
                             "server_port": 1080, "version": "5"})])
        conn.execute("UPDATE nodes SET first_seen=?, last_seen=?"
                     " WHERE tag=?", (now - age_d * 86400, now, f"n{i}"))
    conn.commit()

    pruned = pool.prune()
    assert pruned == 2
    left = {r["tag"] for r in pool.list_public(only_alive=False)}
    assert left == {"n2"}


def test_prune_untested_window_converges_to_throughput(tmp_path):
    """陈库存窗口必须由实测探测吞吐收敛，不再写死 2 天。

    2026-10-16 实测：vivo 生产 total=33892 / untested=33528，
    单轮探 172–400、间隔 120–600s → 17 小时才扫完一遍，2 天窗口
    删的追不上进的。改由「扫完一轮的时间 × 2」算，夹在 12h–3d。
    """
    pool = NodePool(tmp_path / "p.sqlite3")
    # 塞 10000 个未测节点
    pool.upsert_nodes([
        (f"n{i}", "socks", {"type": "socks", "server": f"10.9.{i // 250}.{i % 250}",
                            "server_port": 1080, "version": "5"})
        for i in range(10000)
    ])
    default = pool.PRUNE_UNTESTED_AFTER_SEC

    # 库存 10000 个。低吞吐 200/轮 × 300s → 扫完一遍 15000s（4.2h），
    # ×2 = 30000s 低于下限 → 夹到下限 12h（43200s），比默认 2 天更紧。
    win = pool.set_probe_throughput(200, 300)
    assert win == pool.PRUNE_UNTESTED_MIN_SEC, win
    assert win < default, f"低吞吐应收紧窗口：{win} vs {default}"
    assert pool.PRUNE_UNTESTED_AFTER_SEC == win

    # 中吞吐：20/轮 × 600s → 扫一遍 300000s，×2 = 600000s
    # → 夹到上限 3 天（259200s），避免窗口无限放宽（否则库存永远清不掉）。
    win_mid = pool.set_probe_throughput(20, 600)
    assert win_mid == pool.PRUNE_UNTESTED_MAX_SEC, win_mid

    # 高吞吐：10000/轮 × 60s → 扫一遍 60s，×2 = 120s → 夹到下限 12h
    win2 = pool.set_probe_throughput(10000, 60)
    assert win2 == pool.PRUNE_UNTESTED_MIN_SEC, win2

    # 非法输入不改变现状（不崩、不乱写窗口）
    before = pool.PRUNE_UNTESTED_AFTER_SEC
    assert pool.set_probe_throughput(0, 300) == before
    assert pool.set_probe_throughput(200, 0) == before


def test_prune_never_touches_cust_pool(tmp_path):
    """硬淘汰只清 free 池；cust 客户节点一条不碰（用户自己的订阅）。"""
    import time as _t

    pool = NodePool(tmp_path / "p.sqlite3")
    now = _t.time()
    pool.upsert_nodes([("cust-dead", "socks",
                        {"type": "socks", "server": "10.2.0.1",
                         "server_port": 1080, "version": "5"})],
                      source_sid="customer", pool="cust")
    conn = pool._ensure()
    conn.execute("UPDATE nodes SET alive=0, last_probe_at=?,"
                 " last_ok_at=?, last_seen=?, first_seen=?"
                 " WHERE tag='cust-dead'",
                 (now - 3600, now - 99 * 3600, now, now - 99 * 86400))
    conn.commit()
    assert pool.prune() == 0
    assert pool.list_public(only_alive=False, pool="cust")


# ══════════════════════ 单轮入库预算闸门 ══════════════════════


def _vless_uri(i: int) -> str:
    """构造一条可解析的 vless 节点 URI（测试用，不触网）。"""
    return (f"vless://00000000-0000-0000-0000-{i:012d}"
            f"@10.0.0.{i % 250 + 1}:443"
            f"?encryption=none&security=tls&type=tcp#node-{i}")


def _make_hunter(tmp_path, ingest_cap=0, round_cap=None):
    """造一个只用到入库路径的猎手（不启循环、不触网）。"""
    from websearch.nodes.hunter import NodeHunter

    h = NodeHunter.__new__(NodeHunter)
    h.pool = NodePool(tmp_path / "n.sqlite3")
    h.ingest_cap = ingest_cap
    h.customer_subs = []
    h._round_ingest_left = round_cap
    return h


def test_round_ingest_cap_truncates_across_sources(tmp_path):
    """单轮总预算应跨源累计：多源叠加也不能突破 ROUND_INGEST_CAP。

    背景（2026-10-15 实测）：ingest_cap 是**单源**上限，多个高产源
    叠加起来单轮能入 13853 个，而单轮探测上限只有 400 —— 入库比探测
    快 34 倍，未测库存无限积压（当日全库 27265、未测 27161），
    新节点永远排不到探测窗口。总闸门就是修这个失衡。
    """
    h = _make_hunter(tmp_path, round_cap=10)
    text = "\n".join(_vless_uri(i) for i in range(50))

    # 第一源：预算 10，入 10 个
    n1, a1 = h._ingest_text(text, "src-1")
    assert n1 == 50 and a1 == 10, "首源应被截断到预算上限"
    assert h._round_ingest_left == 0

    # 第二源：预算耗尽，应整源丢弃
    n2, a2 = h._ingest_text(text, "src-2")
    assert a2 == 0, "预算耗尽后不应再入库"
    assert h._round_ingest_left == 0

    # 库中只应有首源的 10 个
    nodes = h.pool.list_public(only_alive=False)
    assert len(nodes) == 10


def test_round_ingest_cap_none_means_unlimited(tmp_path):
    """轮外直接调用（预算为 None）不受总闸门限制，只受单源上限约束。"""
    h = _make_hunter(tmp_path, ingest_cap=5, round_cap=None)
    text = "\n".join(_vless_uri(i) for i in range(50))

    n, added = h._ingest_text(text, "src")
    assert n == 50 and added == 5, "无总闸时应只受单源 ingest_cap 限制"
    assert h._round_ingest_left is None


def test_round_ingest_cap_partial_then_exhausted(tmp_path):
    """预算部分消耗：首源吃掉一部分，第二源用完剩余额度。"""
    h = _make_hunter(tmp_path, round_cap=7)
    text = "\n".join(_vless_uri(i) for i in range(20))

    _, a1 = h._ingest_text(text, "src-1")
    assert a1 == 7 and h._round_ingest_left == 0

    _, a2 = h._ingest_text(text, "src-2")
    assert a2 == 0
    assert len(h.pool.list_public(only_alive=False)) == 7


# ══════════════════════ 单轮入库预算闸门 ══════════════════════


def _vless_uri(i: int) -> str:
    """构造一条可解析的 vless 节点 URI（测试用，不触网）。"""
    return (f"vless://00000000-0000-0000-0000-{i:012d}"
            f"@10.0.0.{i % 250 + 1}:443"
            f"?encryption=none&security=tls&type=tcp#node-{i}")


def _make_hunter(tmp_path, ingest_cap=0, round_cap=None):
    """造一个只用到入库路径的猎手（不启循环、不触网）。"""
    from websearch.nodes.hunter import NodeHunter

    h = NodeHunter.__new__(NodeHunter)
    h.pool = NodePool(tmp_path / "n.sqlite3")
    h.ingest_cap = ingest_cap
    h.customer_subs = []
    h._round_ingest_left = round_cap
    return h


def test_round_ingest_cap_truncates_across_sources(tmp_path):
    """单轮总预算应跨源累计：多源叠加也不能突破 ROUND_INGEST_CAP。

    背景（2026-10-15 实测）：ingest_cap 是**单源**上限，多个高产源
    叠加起来单轮能入 13853 个，而单轮探测上限只有 400 —— 入库比探测
    快 34 倍，未测库存无限积压（当日全库 27265、未测 27161），
    新节点永远排不到探测窗口。总闸门就是修这个失衡。
    """
    h = _make_hunter(tmp_path, round_cap=10)
    text = "\n".join(_vless_uri(i) for i in range(50))

    # 第一源：预算 10，入 10 个
    n1, a1 = h._ingest_text(text, "src-1")
    assert n1 == 50 and a1 == 10, "首源应被截断到预算上限"
    assert h._round_ingest_left == 0

    # 第二源：预算耗尽，应整源丢弃
    n2, a2 = h._ingest_text(text, "src-2")
    assert a2 == 0, "预算耗尽后不应再入库"
    assert h._round_ingest_left == 0

    # 库中只应有首源的 10 个
    nodes = h.pool.list_public(only_alive=False)
    assert len(nodes) == 10


def test_round_ingest_cap_none_means_unlimited(tmp_path):
    """轮外直接调用（预算为 None）不受总闸门限制，只受单源上限约束。"""
    h = _make_hunter(tmp_path, ingest_cap=5, round_cap=None)
    text = "\n".join(_vless_uri(i) for i in range(50))

    n, added = h._ingest_text(text, "src")
    assert n == 50 and added == 5, "无总闸时应只受单源 ingest_cap 限制"
    assert h._round_ingest_left is None


def test_round_ingest_cap_partial_then_exhausted(tmp_path):
    """预算部分消耗：首源吃掉一部分，第二源用完剩余额度。"""
    h = _make_hunter(tmp_path, round_cap=7)
    text = "\n".join(_vless_uri(i) for i in range(20))

    _, a1 = h._ingest_text(text, "src-1")
    assert a1 == 7 and h._round_ingest_left == 0

    _, a2 = h._ingest_text(text, "src-2")
    assert a2 == 0
    assert len(h.pool.list_public(only_alive=False)) == 7


# ══════════════ 2026-10-15 站点可达性抽检 ══════════════


def test_site_check_candidates_and_record(tmp_path):
    """抽检候选只取 alive 延迟档；记录写入 site_ok。"""
    from websearch.nodes.pool import NodePool

    p = NodePool(tmp_path / "n.sqlite3")
    p.upsert_nodes([
        (f"n{i}", "vless", {"type": "vless", "server": f"10.0.0.{i}",
                            "server_port": 443}) for i in range(5)
    ])
    for i in range(5):
        fp = [r[0] for r in p._ensure().execute(
            "SELECT fp FROM nodes WHERE server=?", (f"10.0.0.{i}",))][0]
        p.record_probe(fp, True, 1000 + i * 100)
    cands = p.site_check_candidates(limit=3)
    assert len(cands) == 3
    # 最快的最先抽（500ms 档优先）
    assert cands[0]["outbound"]["server"] == "10.0.0.0"
    # 记录 + best 排序：全通节点压过更快但盲区的节点
    slow_fp = cands[0]["fp"]
    p.record_site_check(slow_fp, 2)          # 全通
    p.record_site_check(cands[1]["fp"], 0)   # 盲区
    best = p.best(prefer="free")
    assert best["fp"] == slow_fp, "站点全通的节点应压过更快的盲区节点"


def test_best_prefers_site_coverage_over_latency(tmp_path):
    """站点覆盖优先于延迟（实测：香港快 4% 但盲区，英国全通）。"""
    from websearch.nodes.pool import NodePool

    p = NodePool(tmp_path / "n.sqlite3")
    p.upsert_nodes([
        ("hk", "vless", {"type": "vless", "server": "10.0.0.1",
                         "server_port": 443}),
        ("gb", "vless", {"type": "vless", "server": "10.0.0.2",
                         "server_port": 443}),
    ])
    fps = {r[1]: r[0] for r in p._ensure().execute(
        "SELECT fp, server FROM nodes")}
    p.record_probe(fps["10.0.0.1"], True, 3900)   # HK 更快
    p.record_probe(fps["10.0.0.2"], True, 4100)   # GB 稍慢
    p.record_site_check(fps["10.0.0.1"], 0)        # HK 盲区
    p.record_site_check(fps["10.0.0.2"], 2)        # GB 全通
    best = p.best(prefer="free")
    assert best["fp"] == fps["10.0.0.2"], "应选站点全通的 GB 而非更快的 HK"
