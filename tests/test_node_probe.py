# -*- coding: utf-8 -*-
"""节点有效性校验与自动探测测试。

背景（2026-10-13 实测踩坑）：
用户配了机场订阅、19 个节点、代理进程也起来了，但上不了网。
根因是订阅里第一个节点的 server 是 0.0.0.0（占位条目），
而它恰好被选成 selector 的 default —— 所有流量发往 0.0.0.0:443，
报 "connect: connection refused"。表面看像「节点全不通」，
实际是**坏节点污染了整个代理**。

教训：解析阶段必须过滤无效地址；启动时必须探测选节点。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.subparse import (
    NodeParseError,
    build_singbox_config,
    parse_node,
    parse_subscription_text,
)


# ══════════════════ 坏节点必须在解析阶段被拦下 ══════════════════


@pytest.mark.parametrize("bad_server", [
    "0.0.0.0",       # 最常见的占位地址（实测踩坑的就是它）
    "::",
    "127.0.0.1",     # 指向本机没意义
    "localhost",
    "::1",
])
def test_reject_invalid_server_address(bad_server):
    """占位/回环地址必须被拒 —— 否则会污染 selector 的 default。"""
    uri = f"trojan://testpass@{bad_server}:443?sni=x.com#坏节点"
    with pytest.raises(NodeParseError) as ei:
        parse_node(uri, 0)
    assert "无效" in str(ei.value)


def test_reject_missing_server():
    uri = "trojan://testpass@:443#空地址"
    with pytest.raises(NodeParseError):
        parse_node(uri, 0)


@pytest.mark.parametrize("bad_port", ["0", "99999", "-1"])
def test_reject_invalid_port(bad_port):
    uri = f"trojan://testpass@example.com:{bad_port}#坏端口"
    with pytest.raises(NodeParseError):
        parse_node(uri, 0)


def test_bad_node_excluded_from_subscription_report():
    """坏节点进 skipped，好节点进 nodes —— 不静默丢弃也不污染。"""
    good = "trojan://testpass@example.com:443?sni=x.com#好节点"
    bad = "trojan://testpass@0.0.0.0:443#占位节点"
    report = parse_subscription_text(f"{bad}\n{good}")
    assert len(report.nodes) == 1
    assert report.nodes[0].tag == "好节点"
    assert len(report.skipped) == 1
    assert "无效" in report.skipped[0]["reason"]


def test_bad_node_does_not_become_selector_default():
    """关键回归：坏节点绝不能成为 default。

    这是实测 bug 的直接复现 —— 坏节点在列表第一位，
    原实现把 tags[0] 当 default，于是全部流量走它。
    """
    bad = "trojan://testpass@0.0.0.0:443#占位节点"
    good = "trojan://testpass@example.com:443?sni=x.com#好节点"
    report = parse_subscription_text(f"{bad}\n{good}")
    cfg = build_singbox_config(report)
    sel = [o for o in cfg["outbounds"] if o["type"] == "selector"][0]
    assert sel["default"] == "好节点", f"default 是坏节点：{sel['default']}"
    assert "占位节点" not in sel["outbounds"], "坏节点不该出现在 selector 里"


def test_all_nodes_bad_degrades_to_direct():
    """全是坏节点 → 退化成 direct，而不是生成一个必然失败的配置。"""
    report = parse_subscription_text(
        "trojan://testpass@0.0.0.0:443#坏1\ntrojan://testpass@127.0.0.1:443#坏2"
    )
    cfg = build_singbox_config(report)
    assert cfg["route"]["final"] == "direct"
    assert not [o for o in cfg["outbounds"] if o["type"] == "selector"]


# ══════════════════ 显式指定默认节点（探测后切换用） ══════════════════


def test_default_tag_respected():
    """探测出最快节点后，配置里的 default 要能换成它。"""
    a = "trojan://pw@a.example.com:443#节点A"
    b = "trojan://pw@b.example.com:443#节点B"
    report = parse_subscription_text(f"{a}\n{b}")
    cfg = build_singbox_config(report, default_tag="节点B")
    sel = [o for o in cfg["outbounds"] if o["type"] == "selector"][0]
    assert sel["default"] == "节点B"


def test_unknown_default_tag_falls_back():
    """给了不存在的 tag 时退回第一个（不能让配置非法）。"""
    report = parse_subscription_text("trojan://pw@a.example.com:443#节点A")
    cfg = build_singbox_config(report, default_tag="不存在的节点")
    sel = [o for o in cfg["outbounds"] if o["type"] == "selector"][0]
    assert sel["default"] == "节点A"


# ══════════════════ 探测结果结构（不打真网络） ══════════════════


def test_probe_result_shape_in_summary(tmp_path):
    """summary() 要带 probe 字段（面板据此展示「几个节点可用」）。"""
    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tmp_path, singbox_bin="/nonexistent/sing-box")
    s = pm.summary()
    assert "probe" in s
    assert isinstance(s["probe"], dict)


def test_probe_without_nodes_is_clear(tmp_path):
    """没有节点时探测要给可读错误，不抛异常。"""
    import asyncio

    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tmp_path, singbox_bin="/nonexistent/sing-box")
    r = asyncio.run(pm.probe_nodes())
    assert r["ok"] is False
    assert "节点" in r["error"]


def test_probe_result_has_no_credentials(tmp_path):
    """探测结果会展示在面板上，绝不能含凭据。"""
    import json as _json

    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tmp_path, singbox_bin="/nonexistent/sing-box")
    # 手工塞一个探测结果（含节点名，但不该有 server/password/uuid）
    pm.probe_result = {
        "tested": 2, "alive_count": 1, "dead_count": 1,
        "best": "香港01", "best_ms": 120,
        "alive": [{"tag": "香港01", "ms": 120}],
        "at": 0,
    }
    blob = _json.dumps(pm.summary(), ensure_ascii=False)
    assert "香港01" in blob
    for secret in ("password", "uuid", "server", "0b6e8bb4"):
        assert secret not in blob.lower(), f"探测结果泄露了 {secret}"


# ══════════════════ reality 缺 uTLS 的「毒节点」（2026-10-13 实测根因） ══════════════════
#
# 症状：节点池 892 个节点、每轮探测 100+、**永远 0 存活**。
# 根因：vless+reality 的订阅常不带 fp=，解析出的 outbound 缺 tls.utls，
#       sing-box 直接 FATAL("uTLS is required by reality client") 拒绝
#       **加载整个配置**；而探测器把上百节点塞进同一个 sing-box 实例，
#       于是一个毒节点 => 整批判死。实测 3.2% 节点命中，足以毒死每一批。


def test_vless_reality_without_fp_gets_utls():
    """reality 订阅不带 fp= 时必须补 utls，否则 sing-box 拒绝启动。"""
    uri = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
           "?security=reality&sni=x.com&pbk=PUBKEY&sid=abcd#REALITY")
    n = parse_node(uri, 0)
    tls = n.outbound["tls"]
    assert tls["reality"]["enabled"] is True
    assert tls["utls"]["enabled"] is True, "reality 缺 utls 会让 sing-box 拒绝启动"


def test_vless_reality_keeps_given_fingerprint():
    """订阅给了 fp= 时保留用户/订阅指定的指纹，不覆盖成默认。"""
    uri = ("vless://11111111-2222-3333-4444-555555555555@example.com:443"
           "?security=reality&sni=x.com&pbk=PUBKEY&sid=abcd&fp=firefox#R")
    tls = parse_node(uri, 0).outbound["tls"]
    assert tls["utls"]["fingerprint"] == "firefox"


def test_clash_reality_without_fingerprint_gets_utls():
    """clash 格式的 reality 节点同样要补 utls。"""
    yml = (
        "proxies:\n"
        "  - name: R\n"
        "    type: vless\n"
        "    server: example.com\n"
        "    port: 443\n"
        "    uuid: 11111111-2222-3333-4444-555555555555\n"
        "    tls: true\n"
        "    servername: x.com\n"
        "    reality-opts:\n"
        "      public-key: PUBKEY\n"
        "      short-id: abcd\n"
    )
    report = parse_subscription_text(yml)
    tls = report.nodes[0].outbound["tls"]
    assert tls["reality"]["enabled"] is True
    assert tls["utls"]["enabled"] is True


def test_sanitize_outbound_fixes_reality_utls():
    """探测侧兜底：存量库里已缺 utls 的节点也要被就地修好（不改原对象）。"""
    from websearch.nodes.probe import sanitize_outbound

    ob = {"type": "vless",
          "tls": {"enabled": True,
                  "reality": {"enabled": True, "public_key": "K"}}}
    out = sanitize_outbound(ob)
    assert out["tls"]["utls"]["enabled"] is True
    assert out["tls"]["utls"]["fingerprint"] == "chrome"
    assert "utls" not in ob["tls"], "不得就地修改入参"


def test_sanitize_outbound_leaves_good_node_untouched():
    """正常节点（含 trojan、已带 utls 的 reality）原样返回。"""
    from websearch.nodes.probe import sanitize_outbound

    trojan = {"type": "trojan", "tls": {"enabled": True}}
    assert sanitize_outbound(trojan) == trojan
    ok_reality = {"type": "vless",
                  "tls": {"enabled": True, "utls": {"enabled": True, "fingerprint": "firefox"},
                          "reality": {"enabled": True, "public_key": "K"}}}
    assert sanitize_outbound(ok_reality) == ok_reality


def test_drop_poison_removes_only_offending_node(tmp_path):
    """二分剔除：只丢让整批配置校验失败的节点，其余保留、顺序不变。"""
    from websearch.nodes.probe import NodeProber

    p = NodeProber(singbox_bin="/nonexistent/sing-box", work_dir=tmp_path)
    # 用假的校验器：只要配置里含 "bad" 就判失败（模拟 sing-box 拒绝加载）
    p._config_ok = lambda cfg: "bad" not in cfg["nodes"]  # type: ignore[assignment]

    def build(ns):
        return {"nodes": [n["fp"] for n in ns]}

    nodes = [{"fp": "ok1"}, {"fp": "bad"}, {"fp": "ok2"}, {"fp": "ok3"}]
    kept = [n["fp"] for n in p._drop_poison(nodes, build)]
    assert kept == ["ok1", "ok2", "ok3"]


def test_drop_poison_all_good_is_noop(tmp_path):
    """整批配置合法时零改动、零额外开销。"""
    from websearch.nodes.probe import NodeProber

    p = NodeProber(singbox_bin="/nonexistent/sing-box", work_dir=tmp_path)
    p._config_ok = lambda cfg: True  # type: ignore[assignment]
    nodes = [{"fp": "a"}, {"fp": "b"}]
    assert p._drop_poison(nodes, lambda ns: {}) is nodes



# ── 毒节点回报失败 / 系统性失败标记（2026-10-14）──────────────────
# 回归背景：探测实例（20000 段端口）因 proot 端口竞态起不来时，整批被判失败，
# 但既不记日志、又被当作「节点都差」喂进存活率 EMA → 下一轮 batch 反而缩水。
# 另：被 _drop_poison 剔除的毒节点从不记失败，永远停在「未测」，每轮重复占预算。

class _Noop:
    def __init__(self, ret=True):
        self.ret = ret
        self.calls = 0

    async def __call__(self, *a, **k):
        self.calls += 1
        return self.ret


class _FakeProc2:
    returncode = None
    pid = 999

    async def wait(self):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = 0


def test_poison_node_reported_as_failure(tmp_path, monkeypatch):
    """被剔除的毒节点也要回报 ok=False/poison_config，别让它永远「未测」。"""
    import asyncio
    from websearch.nodes.probe import NodeProber, ProbeEnv

    p = NodeProber(singbox_bin="/bin/sh", work_dir=tmp_path)
    nodes = [{"fp": "good", "outbound": {"type": "direct"}},
             {"fp": "bad", "outbound": {"type": "direct"}}]
    p._drop_poison = lambda ns, build: [n for n in ns if n["fp"] == "good"]  # type: ignore
    p._kill_stale_probe = _Noop()          # type: ignore
    p._wait_port_free = _Noop(True)        # type: ignore
    p._wait_port = _Noop(True)             # type: ignore

    async def fake_check(port, timeout, env, check_url=""):
        return True, True, ""

    p._check_via_proxy = fake_check         # type: ignore

    async def fake_exec(*a, **k):
        return _FakeProc2()
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

    res = asyncio.run(p._probe_via_singbox(nodes, 1.0, 2,
                                           ProbeEnv(checked=True)))
    by = {r.fp: r for r in res}
    assert len(res) == 2
    assert by["good"].ok is True
    assert by["bad"].ok is False
    assert by["bad"].error == "poison_config"


def _hunter_with(prober):
    from websearch.nodes.hunter import NodeHunter

    class _Pool:
        def candidates_for_probe(self, limit=200, prefer_untested=True,
                                 pool="", only_protocols=()):
            # 2026-10-15 起探测侧按协议分额（plain/tunnel 两次查询），
            # stub 用 **kwargs 兼容新参数；两个 free 查询都会拿到节点，
            # 去重后仍是 n1/n2
            if pool == "free":
                return [{"fp": "n1", "outbound": {}},
                        {"fp": "n2", "outbound": {}}]
            return []

        def record_probe(self, fp, ok, ms=0):
            pass

    h = NodeHunter.__new__(NodeHunter)      # 跳过 __init__（不建真连接池）
    h.prober = prober
    h.pool = _Pool()
    return h


def test_probe_start_failed_flag_true():
    """整批都是「探测实例启动失败」→ 标记 systemic，供上层跳过 EMA。"""
    import asyncio
    from websearch.nodes.probe import ProbeResult

    class _P:
        has_singbox = True

        async def probe_batch(self, nodes, **kw):
            return [ProbeResult(fp=n["fp"], ok=False,
                                error="探测实例启动失败") for n in nodes]

    rep = asyncio.run(_hunter_with(_P())._probe_candidates(100))
    assert rep["probe_start_failed"] is True
    assert rep["probed"] == 2
    assert rep["alive"] == 0


def test_probe_start_failed_flag_false_when_nodes_really_dead():
    """普通连接失败（节点真差）→ 不算 systemic，正常喂 EMA。"""
    import asyncio
    from websearch.nodes.probe import ProbeResult

    class _P:
        has_singbox = True

        async def probe_batch(self, nodes, **kw):
            return [ProbeResult(fp=n["fp"], ok=False,
                                error="ConnectError") for n in nodes]

    rep = asyncio.run(_hunter_with(_P())._probe_candidates(100))
    assert rep["probe_start_failed"] is False
    assert rep["probed"] == 2


# ══════════════ 2026-10-15 普通代理直测分流 ══════════════


@pytest.mark.asyncio
async def test_plain_proxy_probe_skips_singbox(tmp_path, monkeypatch):
    """socks/http 代理走 httpx 直测，不起 sing-box。

    实测背景：代理池 2533 个 socks 走 sing-box 管线因端口竞态 + 探测
    预算只能排到 5 个/轮；直测路径不受 PROBE_PORT_SPAN 约束。
    """
    from websearch.nodes.probe import NodeProber

    p = NodeProber(singbox_bin="", work_dir=tmp_path)
    # 没有 sing-box：若走 _probe_light 会全失败；直测路径应照常工作
    nodes = [
        {"fp": "s1", "protocol": "socks",
         "outbound": {"type": "socks", "server": "127.0.0.1",
                      "server_port": 1080, "version": "5"}},
        {"fp": "h1", "protocol": "http",
         "outbound": {"type": "http", "server": "127.0.0.1",
                      "server_port": 8080}},
    ]

    called = {"n": 0}

    class _Resp:
        status_code = 204

    class _Cli:
        def __init__(self, **kw):
            called["n"] += 1
            self.kw = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _Resp()

    import websearch.nodes.probe as pm
    monkeypatch.setattr(pm.httpx, "AsyncClient", _Cli)
    res = await p._probe_plain_proxies(nodes, timeout=5.0, concurrency=50)
    assert len(res) == 2
    assert all(r.ok for r in res)
    assert all(r.exit_verified for r in res)
    assert called["n"] == 2   # 每个代理一个 client（并发 50 不串扰）


@pytest.mark.asyncio
async def test_probe_batch_mixes_plain_and_tunnel(tmp_path, monkeypatch):
    """混合批次：普通代理直测 + 隧道节点走 sing-box，结果按 fp 对齐。"""
    from websearch.nodes import probe as pm
    from websearch.nodes.probe import NodeProber

    p = NodeProber(singbox_bin="", work_dir=tmp_path)
    nodes = [
        {"fp": "s1", "protocol": "socks",
         "outbound": {"type": "socks", "server": "127.0.0.1",
                      "server_port": 1080, "version": "5"}},
        {"fp": "t1", "protocol": "vless",
         "outbound": {"type": "vless", "server": "127.0.0.1",
                      "server_port": 443}},
    ]

    async def fake_plain(ns, timeout, concurrency, check_url=""):
        return [pm.ProbeResult(fp="s1", ok=True, ms=100,
                               exit_verified=True)]

    async def fake_light(ns, timeout, concurrency):
        return [pm.ProbeResult(fp="t1", ok=True, ms=200,
                               exit_verified=True)]

    monkeypatch.setattr(p, "_probe_plain_proxies", fake_plain)
    monkeypatch.setattr(p, "_probe_light", fake_light)
    res = await p.probe_batch(nodes, timeout=5.0, concurrency=12)
    by_fp = {r.fp: r for r in res}
    assert by_fp["s1"].ok and by_fp["t1"].ok
    assert len(res) == 2   # 与输入等长


# ══════════════ 2026-10-15 普通代理直测分流 ══════════════


@pytest.mark.asyncio
async def test_plain_proxy_probe_skips_singbox(tmp_path, monkeypatch):
    """socks/http 代理走 httpx 直测，不起 sing-box。

    实测背景：代理池 2533 个 socks 走 sing-box 管线因端口竞态 + 探测
    预算只能排到 5 个/轮；直测路径不受 PROBE_PORT_SPAN 约束。
    """
    from websearch.nodes.probe import NodeProber

    p = NodeProber(singbox_bin="", work_dir=tmp_path)
    # 没有 sing-box：若走 _probe_light 会全失败；直测路径应照常工作
    nodes = [
        {"fp": "s1", "protocol": "socks",
         "outbound": {"type": "socks", "server": "127.0.0.1",
                      "server_port": 1080, "version": "5"}},
        {"fp": "h1", "protocol": "http",
         "outbound": {"type": "http", "server": "127.0.0.1",
                      "server_port": 8080}},
    ]

    called = {"n": 0}

    class _Resp:
        status_code = 204

    class _Cli:
        def __init__(self, **kw):
            called["n"] += 1
            self.kw = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            return _Resp()

    import websearch.nodes.probe as pm
    monkeypatch.setattr(pm.httpx, "AsyncClient", _Cli)
    res = await p._probe_plain_proxies(nodes, timeout=5.0, concurrency=50)
    assert len(res) == 2
    assert all(r.ok for r in res)
    assert all(r.exit_verified for r in res)
    assert called["n"] == 2   # 每个代理一个 client（并发 50 不串扰）


@pytest.mark.asyncio
async def test_probe_batch_mixes_plain_and_tunnel(tmp_path, monkeypatch):
    """混合批次：普通代理直测 + 隧道节点走 sing-box，结果按 fp 对齐。"""
    from websearch.nodes import probe as pm
    from websearch.nodes.probe import NodeProber

    p = NodeProber(singbox_bin="", work_dir=tmp_path)
    nodes = [
        {"fp": "s1", "protocol": "socks",
         "outbound": {"type": "socks", "server": "127.0.0.1",
                      "server_port": 1080, "version": "5"}},
        {"fp": "t1", "protocol": "vless",
         "outbound": {"type": "vless", "server": "127.0.0.1",
                      "server_port": 443}},
    ]

    async def fake_plain(ns, timeout, concurrency, check_url=""):
        return [pm.ProbeResult(fp="s1", ok=True, ms=100,
                               exit_verified=True)]

    async def fake_light(ns, timeout, concurrency):
        return [pm.ProbeResult(fp="t1", ok=True, ms=200,
                               exit_verified=True)]

    monkeypatch.setattr(p, "_probe_plain_proxies", fake_plain)
    monkeypatch.setattr(p, "_probe_light", fake_light)
    res = await p.probe_batch(nodes, timeout=5.0, concurrency=12)
    by_fp = {r.fp: r for r in res}
    assert by_fp["s1"].ok and by_fp["t1"].ok
    assert len(res) == 2   # 与输入等长
