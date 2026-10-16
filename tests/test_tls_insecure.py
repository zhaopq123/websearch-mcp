# -*- coding: utf-8 -*-
"""TLS 跳过校验参数（allowInsecure）解析测试。

背景（2026-10-13 实测踩坑）：
用户配了机场订阅（19 个节点，含 vless/trojan），节点服务器 TCP 层能连上，
但经代理访问一律 000。逐层排查后发现根因是**解析时把 allowInsecure
硬编码成 false**，导致 TLS 握手校验失败。

关键点：同一个参数，hysteria2/tuic 分支本来就读了，
vless/trojan/vmess 分支却漏了 —— 典型的复制粘贴漏改。
这类「同一语义参数在不同分支处理不一致」的 bug 极难靠读代码发现，
只能靠实测撞出来，所以每条协议都要有测试钉住。

注意：allowInsecure=true 会关闭证书校验，存在中间人风险。
但机场节点大量使用「证书与 SNI 不匹配」的伪装（这是它们的常态），
不设就一律连不上。这里**遵从订阅的显式声明**，
不擅自开启（订阅没写就是 false）。
"""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.subparse import parse_node


# ══════════════════ vless / trojan（本次修复的重点） ══════════════════


@pytest.mark.parametrize("allow", ["1", "true", "yes"])
def test_vless_allowinsecure_true(allow):
    """订阅声明 allowInsecure 时必须如实反映。"""
    n = parse_node(
        f"vless://uuid-1234@example.com:443?security=tls&sni=x.com&"
        f"type=tcp&allowInsecure={allow}#节点", 0)
    assert n.outbound["tls"]["insecure"] is True, \
        "allowInsecure=1 却没生效 —— 这就是连不上的原因"


def test_vless_allowinsecure_absent_defaults_false():
    """订阅没写就不开（不擅自关闭证书校验）。"""
    n = parse_node(
        "vless://uuid-1234@example.com:443?security=tls&sni=x.com&type=tcp#节点", 0)
    assert n.outbound["tls"]["insecure"] is False


def test_vless_skip_cert_verify_alias():
    """skip-cert-verify 是另一个常见别名，要认。"""
    n = parse_node(
        "vless://uuid@example.com:443?security=tls&skip-cert-verify=1#节点", 0)
    assert n.outbound["tls"]["insecure"] is True


def test_trojan_allowinsecure_true():
    n = parse_node(
        "trojan://pw@example.com:443?sni=x.com&allowInsecure=1#节点", 0)
    assert n.outbound["tls"]["insecure"] is True


def test_reality_allowinsecure_true():
    """Reality 节点同样要认这个参数。"""
    n = parse_node(
        "vless://uuid@example.com:443?security=reality&sni=x.com&"
        "pbk=AAAA&sid=ab12&allowInsecure=1#reality节点", 0)
    assert n.outbound["tls"]["insecure"] is True
    assert n.outbound["tls"]["reality"]["enabled"] is True


# ══════════════════ vmess（JSON 形态，字段名不同） ══════════════════


def test_vmess_skip_cert_verify():
    n = parse_node(_vmess_uri({"add": "example.com", "id": "u-1",
                               "port": "443", "tls": "tls",
                               "skip-cert-verify": True}), 0)
    assert n.outbound["tls"]["insecure"] is True


def test_vmess_allowinsecure_alias():
    n = parse_node(_vmess_uri({"add": "example.com", "id": "u-1",
                               "port": "443", "tls": "tls",
                               "allowInsecure": True}), 0)
    assert n.outbound["tls"]["insecure"] is True


def test_vmess_default_secure():
    n = parse_node(_vmess_uri({"add": "example.com", "id": "u-1",
                               "port": "443", "tls": "tls"}), 0)
    assert n.outbound["tls"]["insecure"] is False


def test_vmess_utls_fingerprint():
    n = parse_node(_vmess_uri({"add": "example.com", "id": "u-1",
                               "port": "443", "tls": "tls", "fp": "chrome"}), 0)
    assert n.outbound["tls"]["utls"]["fingerprint"] == "chrome"


# ══════════════════ hysteria2 / tuic（本来就对，防回归） ══════════════════


def test_hysteria2_allowinsecure():
    n = parse_node(
        "hysteria2://pw@example.com:443?sni=x.com&allowInsecure=1#节点", 0)
    assert n.outbound["tls"]["insecure"] is True


def test_tuic_allow_insecure():
    n = parse_node(
        "tuic://uuid:pw@example.com:443?sni=x.com&allow_insecure=1#节点", 0)
    assert n.outbound["tls"]["insecure"] is True


# ══════════════════ 跨协议一致性（这是本测试的核心意图） ══════════════════


def test_all_protocols_consistent_on_insecure():
    """同一语义参数，各协议行为必须一致。

    这条测试就是为「复制粘贴漏改」而设 ——
    只要某个分支再漏掉，这里立刻红。
    """
    cases = {
        "vless": "vless://u@example.com:443?security=tls&allowInsecure=1#n",
        "trojan": "trojan://pw@example.com:443?security=tls&allowInsecure=1#n",
        "hysteria2": "hysteria2://pw@example.com:443?allowInsecure=1#n",
        "tuic": "tuic://u:pw@example.com:443?allow_insecure=1#n",
    }
    for name, uri in cases.items():
        n = parse_node(uri, 0)
        assert n.outbound["tls"]["insecure"] is True, \
            f"{name} 没读 allowInsecure —— 各协议处理不一致"


def _vmess_uri(d: dict) -> str:
    """把 vmess JSON 字典包成 vmess:// URI。"""
    payload = base64.b64encode(json.dumps(d).encode()).decode()
    return f"vmess://{payload}"