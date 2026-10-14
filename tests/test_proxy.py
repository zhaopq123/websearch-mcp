# -*- coding: utf-8 -*-
"""订阅解析与代理管理测试。

⚠️ 测试用的全是**假节点**（example.com、测试用 uuid），不含任何真实凭据。
   这是刻意的：测试文件会进 git，绝不能带上真节点。

覆盖重点：
  1. 各协议解析正确性（ss/vmess/trojan/vless/hysteria2/tuic）
  2. 不支持协议要**明确报告**而不是静默丢
  3. 解析失败的错误消息**不得泄露节点内容**（安全红线）
  4. sing-box 配置生成正确性
  5. 无节点时降级为 direct（不能让服务崩）
"""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.subparse import (
    NodeParseError,
    SubscriptionError,
    _sniff_proxy_proto,
    build_singbox_config,
    looks_like_proxy_list,
    parse_node,
    parse_proxy_list,
    parse_subscription_text,
)


# ── 假节点（全部指向 example.com，无真实凭据）──

FAKE_SS_SIP002 = (
    "ss://" + base64.urlsafe_b64encode(b"aes-128-gcm:testpass").decode().rstrip("=")
    + "@example.com:8388#测试ss节点"
)
FAKE_SS_LEGACY = (
    "ss://" + base64.b64encode(b"aes-256-gcm:testpass@example.com:8388").decode()
    + "#旧式ss"
)
FAKE_VMESS = "vmess://" + base64.b64encode(json.dumps({
    "v": "2", "ps": "测试vmess", "add": "example.com", "port": "443",
    "id": "11111111-2222-3333-4444-555555555555", "aid": "0",
    "scy": "auto", "net": "ws", "type": "none", "host": "example.com",
    "path": "/ws", "tls": "tls",
}).encode()).decode()
FAKE_TROJAN = "trojan://testpass@example.com:443?sni=example.com&type=tcp#测试trojan"
FAKE_VLESS = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fws&fp=chrome#测试vless"
)
FAKE_VLESS_REALITY = (
    "vless://11111111-2222-3333-4444-555555555555@example.com:443"
    "?security=reality&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "&sid=0123abcd&fp=chrome&type=tcp#reality节点"
)
FAKE_HY2 = "hysteria2://testpass@example.com:443?sni=example.com&insecure=1#测试hy2"
FAKE_TUIC = "tuic://11111111-2222-3333-4444-555555555555:testpass@example.com:443?sni=example.com&alpn=h3#测试tuic"


# ══════════════════ 协议解析 ══════════════════


def test_parse_ss_sip002():
    n = parse_node(FAKE_SS_SIP002, 0)
    assert n.protocol == "shadowsocks"
    assert n.outbound["server"] == "example.com"
    assert n.outbound["server_port"] == 8388
    assert n.outbound["method"] == "aes-128-gcm"
    assert n.outbound["password"] == "testpass"
    assert n.tag == "测试ss节点"


def test_parse_ss_legacy():
    n = parse_node(FAKE_SS_LEGACY, 0)
    assert n.protocol == "shadowsocks"
    assert n.outbound["method"] == "aes-256-gcm"
    assert n.outbound["server_port"] == 8388


def test_parse_vmess_ws_tls():
    n = parse_node(FAKE_VMESS, 0)
    assert n.protocol == "vmess"
    assert n.outbound["server"] == "example.com"
    assert n.outbound["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert n.outbound["tls"]["enabled"] is True
    assert n.outbound["tls"]["server_name"] == "example.com"
    assert n.outbound["transport"]["type"] == "ws"
    assert n.outbound["transport"]["path"] == "/ws"


def test_parse_trojan():
    n = parse_node(FAKE_TROJAN, 0)
    assert n.protocol == "trojan"
    assert n.outbound["password"] == "testpass"
    assert n.outbound["server_port"] == 443


def test_parse_vless_ws():
    n = parse_node(FAKE_VLESS, 0)
    assert n.protocol == "vless"
    assert n.outbound["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert n.outbound["tls"]["server_name"] == "example.com"
    assert n.outbound["tls"]["utls"]["fingerprint"] == "chrome"
    assert n.outbound["transport"]["path"] == "/ws"


def test_parse_vless_reality():
    """Reality 是当前抗封锁主力，必须支持。"""
    n = parse_node(FAKE_VLESS_REALITY, 0)
    assert n.protocol == "vless"
    assert n.outbound["tls"]["reality"]["enabled"] is True
    assert n.outbound["tls"]["reality"]["public_key"].startswith("AAAA")
    assert n.outbound["tls"]["reality"]["short_id"] == "0123abcd"


def test_parse_hysteria2():
    n = parse_node(FAKE_HY2, 0)
    assert n.protocol == "hysteria2"
    assert n.outbound["password"] == "testpass"
    assert n.outbound["tls"]["insecure"] is True


def test_parse_tuic():
    n = parse_node(FAKE_TUIC, 0)
    assert n.protocol == "tuic"
    assert n.outbound["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert n.outbound["tls"]["alpn"] == ["h3"]


def test_hy2_shorthand():
    """hy2:// 是 hysteria2 的常见简写。"""
    n = parse_node(FAKE_HY2.replace("hysteria2://", "hy2://"), 0)
    assert n.protocol == "hysteria2"


def test_ipv6_host():
    """IPv6 地址要能正确切出 host 与 port。"""
    n = parse_node("trojan://pw@[2001:db8::1]:443?sni=x.com#v6", 0)
    assert n.outbound["server"] == "2001:db8::1"
    assert n.outbound["server_port"] == 443


# ══════════════════ 不支持协议要明确报告 ══════════════════


def test_unsupported_protocol_reported_not_silently_dropped():
    """ssr 不支持 —— 必须出现在 skipped 里，带原因。"""
    report = parse_subscription_text(
        "ssr://dGVzdA\n" + FAKE_TROJAN
    )
    assert len(report.nodes) == 1
    assert len(report.skipped) == 1
    assert "ssr" in report.skipped[0]["scheme"]
    assert "shadowsocksr" in report.skipped[0]["reason"]


def test_summary_has_no_secrets():
    """摘要里不得出现任何节点凭据（面板会显示它）。"""
    report = parse_subscription_text("\n".join([
        FAKE_SS_SIP002, FAKE_VMESS, FAKE_TROJAN, FAKE_VLESS,
        FAKE_HY2, FAKE_TUIC,
    ]))
    blob = json.dumps(report.summary(), ensure_ascii=False)
    for secret in ("testpass", "example.com", "11111111-2222"):
        assert secret not in blob, f"摘要泄露了 {secret}"
    assert report.summary()["parsed"] == 6


# ══════════════════ 错误消息不得泄露 ══════════════════


@pytest.mark.parametrize("bad", [
    "vmess://" + base64.b64encode(b'{"v":"2"}').decode(),          # 缺 add/id
    "trojan://@example.com:443",                                    # 缺凭据
    "vless://uuid@example.com:443?security=reality",                # reality 缺 pbk
    "hysteria2://@example.com:443",                                 # 缺密码
    "ss://notbase64!!!",                                            # 坏编码
    "not-a-uri-at-all",                                             # 非链接
    "vmess://" + base64.b64encode(b"not json").decode(),            # 坏 JSON
])
def test_parse_errors_do_not_leak_values(bad):
    """失败可以，但错误消息里不能带凭据/密码/uuid。"""
    try:
        parse_node(bad, 0)
    except NodeParseError as e:
        msg = str(e)
        # 不许出现 base64 正文、不许出现假密码
        assert "testpass" not in msg
        assert bad.split("://", 1)[-1][:20] not in msg, "错误消息回显了原始内容"
    else:
        pytest.fail(f"应该解析失败：{bad[:30]}")


# ══════════════════ 订阅整体解析 ══════════════════


def test_parse_base64_subscription():
    """机场标准：整块 base64。"""
    inner = "\n".join([FAKE_SS_SIP002, FAKE_TROJAN, FAKE_VMESS])
    encoded = base64.b64encode(inner.encode()).decode()
    report = parse_subscription_text(encoded)
    assert len(report.nodes) == 3


def test_parse_plaintext_subscription():
    report = parse_subscription_text("\n".join([FAKE_SS_SIP002, FAKE_TROJAN]))
    assert len(report.nodes) == 2


def test_empty_subscription_raises():
    with pytest.raises(SubscriptionError):
        parse_subscription_text("   ")


def test_garbage_subscription_raises():
    with pytest.raises(SubscriptionError):
        parse_subscription_text("这是纯文本没有任何节点")


# ══════════════════ sing-box 配置生成 ══════════════════


def test_build_config_has_selector_and_direct():
    report = parse_subscription_text("\n".join([FAKE_TROJAN, FAKE_VLESS]))
    cfg = build_singbox_config(report, http_port=17890, socks_port=17891)
    types = [o["type"] for o in cfg["outbounds"]]
    assert "trojan" in types and "vless" in types
    assert "selector" in types
    assert "direct" in types
    assert cfg["route"]["final"] == "proxy"
    ports = {i["listen_port"] for i in cfg["inbounds"]}
    assert ports == {17890, 17891}
    # 只监听回环 —— 代理端口绝不能暴露给局域网
    for i in cfg["inbounds"]:
        assert i["listen"] == "127.0.0.1"


def test_build_config_no_nodes_degrades_to_direct():
    """没有任何可用节点时退化成 direct，而不是生成一个起不来的配置。"""
    report = parse_subscription_text("ssr://dGVzdA")
    cfg = build_singbox_config(report)
    assert cfg["route"]["final"] == "direct"
    types = [o["type"] for o in cfg["outbounds"]]
    assert "selector" not in types
    assert "direct" in types


def test_config_private_ip_bypasses_proxy():
    """内网流量必须直连，避免自环。"""
    report = parse_subscription_text(FAKE_TROJAN)
    cfg = build_singbox_config(report)
    rules = cfg["route"]["rules"]
    assert any(r.get("ip_is_private") and r.get("outbound") == "direct" for r in rules)


# ══════════════════ 管理器（不打真网络） ══════════════════


def test_manager_available_flag():
    from websearch.proxy.manager import ProxyManager
    import tempfile

    pm = ProxyManager(tempfile.mkdtemp(), singbox_bin="/nonexistent/sing-box")
    assert pm.available is False
    # 未运行时 proxy_url 为空 —— 调用方据此直连，实现降级
    assert pm.proxy_url() == ""


def test_manager_stop_is_idempotent():
    import asyncio
    import tempfile

    from websearch.proxy.manager import ProxyManager

    pm = ProxyManager(tempfile.mkdtemp())
    asyncio.run(pm.stop())
    asyncio.run(pm.stop())   # 再调一次不应抛
    assert pm.state.running is False


def test_manager_config_file_mode_is_600():
    """写出的配置必须是 600（含凭据）。"""
    import asyncio
    import os
    import stat
    import tempfile

    from websearch.proxy.manager import ProxyManager

    d = tempfile.mkdtemp()
    pm = ProxyManager(d)
    if not pm.available:
        pytest.skip("本机没有 sing-box，跳过真实启动校验")
    asyncio.run(pm._start_with_report(
        parse_subscription_text(FAKE_TROJAN), replace_running=False
    ))
    try:
        assert pm.cfg_path.exists()
        mode = stat.S_IMODE(os.stat(pm.cfg_path).st_mode)
        assert mode == 0o600, f"配置文件权限 {oct(mode)}，应为 600"
    finally:
        asyncio.run(pm.stop())


# ══════════════ 2026-10-14 优化文档复盘新增 ══════════════


def test_hysteria2_ipv6_trailing_slash_not_fatal():
    """[IPv6]:port/ 畸形行只跳自己，不炸整份订阅。

    实测 morpheusadam/hysteria2.txt（1690 节点）里混了
    hysteria2://pw@[2001:xx::1]:34602/?sni=... 行，旧 _split_hostport
    对 "34602/" 抛裸 ValueError 炸穿 parse_subscription_text ——
    整份订阅解析失败，1690 个节点全丢。
    """
    text = (
        "hysteria2://testpass@example.com:443?sni=example.com#good1\n"
        "hysteria2://testpass@[2001:db8::1]:34602/?sni=example.com#ipv6\n"
        "hysteria2://testpass@example.net:443?sni=example.net#good2\n"
    )
    # 修复后 IPv6 行也能正确解析（rstrip("/") + IPv6 分支 try）——
    # 三个节点都进来，一个不丢
    rep = parse_subscription_text(text)
    assert len(rep.nodes) == 3
    assert not rep.skipped
    v6 = [n for n in rep.nodes if n.outbound["server"] == "2001:db8::1"]
    assert v6 and v6[0].outbound["server_port"] == 34602


def test_unexpected_parse_error_skips_one_line_only():
    """未预期异常只跳过单行 —— 兜底防「一个坏行丢整份订阅」。"""
    from unittest import mock

    text = ("trojan://p@example.com:443?sni=example.com#a\n"
            "trojan://p@example.net:443?sni=example.net#b\n")
    with mock.patch(
        "websearch.proxy.subparse.parse_node",
        side_effect=[ValueError("boom"),  # 第一个炸
                     __import__("websearch.proxy.subparse", fromlist=["Node"]).Node(
                         tag="b", protocol="trojan", outbound={})],
    ):
        rep = parse_subscription_text(text)
    assert len(rep.nodes) == 1
    assert rep.skipped[0]["reason"].startswith("未预期错误")


# ── 普通代理列表（IP:PORT 行）──


def test_parse_proxy_list_plain():
    text = ("# 注释\n"
            "198.199.86.11:1080\n"
            "209.97.150.167:1080\n"
            "192.252.209.155:14455\n")
    rep = parse_proxy_list(text, "socks5")
    assert len(rep.nodes) == 3
    n = rep.nodes[0]
    assert n.protocol == "socks"
    assert n.outbound["version"] == "5"
    assert n.outbound["server"] == "198.199.86.11"
    assert n.outbound["server_port"] == 1080


def test_parse_proxy_list_country_suffix_and_scheme_prefix():
    """@CC / |CC / socks5:// 前缀都只抠 IP:PORT。"""
    text = ("1.2.3.4:1080@US\n"
            "US|5.6.7.8:1080\n"
            "socks5://9.10.11.12:1080\n")
    rep = parse_proxy_list(text)
    assert [n.outbound["server"] for n in rep.nodes] == [
        "1.2.3.4", "5.6.7.8", "9.10.11.12"]


def test_parse_proxy_list_rejects_invalid():
    text = ("999.999.999.999:1080\n"     # 段超 255
            "1.2.3.4:99999\n"            # 端口超范围
            "1.2.3.4:abc\n"              # 端口非数字
            "1.2.3.4:1080\n")            # 唯一合法的
    rep = parse_proxy_list(text)
    assert len(rep.nodes) == 1
    assert len(rep.skipped) == 3


def test_parse_proxy_list_socks4_and_http():
    r4 = parse_proxy_list("1.2.3.4:1080\n", "socks4")
    assert r4.nodes[0].outbound["version"] == "4"
    rh = parse_proxy_list("1.2.3.4:8080\n", "http")
    assert rh.nodes[0].protocol == "http"
    assert "version" not in rh.nodes[0].outbound


def test_socks5_and_http_uri_forms():
    n = parse_node("socks5://user:pass@198.51.100.7:1080#p5", 0)
    assert n.protocol == "socks"
    assert n.outbound["version"] == "5"
    assert n.outbound["username"] == "user"
    assert n.outbound["password"] == "pass"
    n2 = parse_node("http://198.51.100.8:8080#phttp", 0)
    assert n2.protocol == "http"
    assert n2.outbound["server_port"] == 8080


def test_looks_like_proxy_list():
    assert looks_like_proxy_list("1.2.3.4:1080\n5.6.7.8:1080\n9.10.11.12:1080\n"
                                 "13.14.15.16:1080\n17.18.19.20:1080\n")
    assert not looks_like_proxy_list("vmess://abc\nvmess://def\nvmess://ghi\n"
                                     "vmess://jkl\nvmess://mno\n")


def test_sniff_proxy_proto():
    assert _sniff_proxy_proto("https://x/main/socks5.txt") == "socks5"
    assert _sniff_proxy_proto("https://x/main/socks4.txt") == "socks4"
    assert _sniff_proxy_proto("https://x/main/http.txt") == "http"
    assert _sniff_proxy_proto("https://x/main/all.txt") == "socks5"  # 默认


def test_subscription_text_falls_back_to_proxy_list():
    """URI 体系零节点 + 像代理列表 + default_proto → 走代理解析。"""
    text = ("198.199.86.11:1080\n209.97.150.167:1080\n192.252.209.155:14455\n"
            "67.207.92.87:1088\n138.68.60.8:1080\n142.54.236.97:4145\n")
    rep = parse_subscription_text(text, default_proto="socks5")
    assert len(rep.nodes) == 6
    assert all(n.protocol == "socks" for n in rep.nodes)


def test_subscription_text_without_proto_still_raises():
    """没给 default_proto 时不猜 —— 保持「不像订阅就报错」的旧口径。"""
    with pytest.raises(SubscriptionError):
        parse_subscription_text("198.199.86.11:1080\n209.97.150.167:1080\n")
