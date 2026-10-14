"""订阅解析 —— 把机场订阅/节点链接转成 sing-box outbound 配置。

⚠️ 安全约定（本模块是红线区）：
  1. **绝不记录节点信息** —— 本模块不写任何日志，不打印 URL/password/uuid。
     异常信息只带「第几个节点、什么协议、什么原因」，不带值。
  2. **绝不落盘** —— 解析结果只在内存里传给调用方；持久化由调用方
     写进 600 权限的 .env，且那个文件在 .gitignore 里。
  3. **失败要能定位但不能泄密** —— 报 "第 3 个节点：vmess 缺 add 字段"，
     而不是把整个 JSON 打出来。

支持的协议（按国内机场常见度排序）：
  ss://         shadowsocks（SIP002 与旧式两种编码）
  vmess://      base64(JSON)
  trojan://     trojan
  vless://      vless（含 reality）
  hysteria2://  hysteria2（含 hy2:// 简写）
  tuic://       tuic v5
  socks5:// / socks4:// / http://   普通代理（IP:PORT 或裸列表行）

普通代理与 VPN 隧道节点是两种东西（无 UUID/密码，形态就是 IP:PORT），
但 sing-box 原生支持 socks/http outbound，所以它们与 VPN 节点走同一条
探测/选路/local_proxy 管线，只是 outbound type 不同。公开代理列表源
（HProxy/Proxifly/monosans/…）是低延迟候选的重要补充 —— 公网代理多在
欧美 VPS 上，实测 RTT 150-300ms，比免费 VPN 节点的 4.7s 快一个数量级。
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


class SubscriptionError(Exception):
    """订阅本身不可用（拉取失败、格式完全无法识别）。"""


class NodeParseError(Exception):
    """单个节点解析失败。异常消息里**不含**节点敏感值。"""


@dataclass
class Node:
    """一个解析成功的节点。

    注意 raw 字段保存原始 URI —— 只在内存里用于诊断，
    **不要**把它写进日志或响应体。
    """

    tag: str                    # 显示名（sing-box 里的 tag）
    protocol: str               # sing-box outbound type
    outbound: dict[str, Any] = field(default_factory=dict)
    raw: str = ""               # 原始 URI，仅内存诊断用

    def to_outbound(self) -> dict[str, Any]:
        """转成 sing-box outbound（自动带上 tag）。"""
        return {"tag": self.tag, **self.outbound}


@dataclass
class ParseReport:
    """解析结果报告 —— 只含数量与错误原因，**不含节点敏感值**。"""

    nodes: list[Node] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.nodes) + len(self.skipped)

    def summary(self) -> dict[str, Any]:
        """给面板/API 用的摘要。故意不含任何节点内容。"""
        by_proto: dict[str, int] = {}
        for n in self.nodes:
            by_proto[n.protocol] = by_proto.get(n.protocol, 0) + 1
        return {
            "total": self.total,
            "parsed": len(self.nodes),
            "skipped": len(self.skipped),
            "by_protocol": by_proto,
            "skip_reasons": self.skipped,
        }


# ══════════════════════ 解码工具 ══════════════════════


def _b64pad(s: str) -> str:
    """补齐 base64 的 padding（机场经常省略）。"""
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def _b64decode_text(s: str) -> str:
    """宽松 base64 解码：容忍缺 padding 与 URL-safe 字符。"""
    try:
        return base64.b64decode(_b64pad(s)).decode("utf-8", "replace")
    except Exception as e:
        raise NodeParseError(f"base64 解码失败: {type(e).__name__}") from e


def _split_hostport(s: str, default_port: int = 443) -> tuple[str, int]:
    """解析 host:port，兼容 IPv6 的 [::1]:443 形式。

    2026-10-14 修（实测 morpheusadam/hysteria2.txt 触发）：真实订阅里
    有 `hysteria2://pw@[2001:xx::1]:34602/?sni=...` 这种带尾斜杠的
    IPv6 行，旧代码 `int(rest.lstrip(":"))` 对 "34602/" 抛裸
    ValueError —— 它不在 NodeParseError 体系里，会炸穿
    parse_subscription_text 主循环，**一整份 1690 节点的订阅因为
    一个畸形行全丢**。现在：入口先剥尾斜杠，IPv6 分支 int() 包 try。
    """
    s = s.strip().rstrip("/")
    if not s:
        raise NodeParseError("缺少服务器地址")
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port_s = rest.lstrip(":")
        if not port_s:
            return host, default_port
        try:
            return host, int(port_s)
        except ValueError as e:
            raise NodeParseError("端口不是数字") from e
    if ":" in s:
        host, _, port_s = s.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError as e:
            raise NodeParseError("端口不是数字") from e
    return s, default_port


def _qs_one(q: dict[str, list[str]], key: str, default: str = "") -> str:
    v = q.get(key)
    return v[0] if v else default


def _qs_bool(q: dict[str, list[str]], key: str) -> bool:
    return _qs_one(q, key, "").lower() in ("1", "true", "yes")


# ══════════════════════ 各协议解析 ══════════════════════


def _parse_ss(uri: str, idx: int) -> dict[str, Any]:
    """shadowsocks。两种形态：

    旧式：ss://base64(method:password@host:port)
    SIP002：ss://base64(method:password)@host:port/?plugin=...
    """
    body = uri[len("ss://"):]
    # 去掉 fragment（#备注）
    body = body.split("#", 1)[0]

    # SIP002：有 @ 说明是分开的
    if "@" in body:
        userinfo, _, hostpart = body.rpartition("@")
        try:
            decoded = _b64decode_text(userinfo)
        except NodeParseError:
            decoded = unquote(userinfo)
        if ":" not in decoded:
            raise NodeParseError("ss 用户信息格式错误")
        method, _, password = decoded.partition(":")
        hostport, _, query = hostpart.partition("?")
        host, port = _split_hostport(hostport)
        ob: dict[str, Any] = {
            "type": "shadowsocks",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password,
        }
        # plugin（如 obfs-local / v2ray-plugin）sing-box 用 plugin 字段
        q = parse_qs(query)
        plugin = _qs_one(q, "plugin")
        if plugin:
            # sing-box 1.11+ 用 plugin / plugin_opts
            parts = plugin.split(";")
            ob["plugin"] = parts[0]
            if len(parts) > 1:
                ob["plugin_opts"] = ";".join(parts[1:])
        return ob

    # 旧式：整体 base64
    decoded = _b64decode_text(body)
    if "@" not in decoded:
        raise NodeParseError("ss 旧式编码里没有 @")
    userinfo, _, hostport = decoded.rpartition("@")
    if ":" not in userinfo:
        raise NodeParseError("ss 用户信息格式错误")
    method, _, password = userinfo.partition(":")
    host, port = _split_hostport(hostport)
    return {
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": method,
        "password": password,
    }


def _parse_vmess(uri: str, idx: int) -> dict[str, Any]:
    """vmess：vmess://base64(JSON)。"""
    payload = uri[len("vmess://"):].split("#", 1)[0]
    text = _b64decode_text(payload)
    try:
        d = json.loads(text)
    except Exception as e:
        raise NodeParseError("vmess 的 JSON 无效") from e
    if not isinstance(d, dict):
        raise NodeParseError("vmess 的 JSON 不是对象")
    if not d.get("add"):
        raise NodeParseError("vmess 缺 add 字段")
    if not d.get("id"):
        raise NodeParseError("vmess 缺 id 字段")

    net = (d.get("net") or "tcp").lower()
    tls = (d.get("tls") or "").lower()

    ob: dict[str, Any] = {
        "type": "vmess",
        "server": str(d["add"]),
        "server_port": int(d.get("port") or 443),
        "uuid": str(d["id"]),
        "security": str(d.get("scy") or "auto"),
        "alter_id": int(d.get("aid") or 0),
    }
    if tls in ("tls", "reality"):
        # 同样要读 skip-cert-verify / allowInsecure（vmess JSON 里字段名是
        # skip-cert-verify，见 v2rayN 系导出的约定）
        insecure = bool(d.get("skip-cert-verify") or d.get("allowInsecure")
                        or d.get("insecure"))
        ob["tls"] = {
            "enabled": True,
            "server_name": str(d.get("sni") or d.get("host") or d["add"]),
            "insecure": insecure,
        }
        fp = d.get("fp")
        if fp:
            ob["tls"]["utls"] = {"enabled": True, "fingerprint": str(fp)}
    # 传输层
    if net == "ws":
        ws: dict[str, Any] = {"type": "ws", "path": str(d.get("path") or "/")}
        host = d.get("host")
        if host:
            ws["headers"] = {"Host": str(host)}
        ob["transport"] = ws
    elif net == "grpc":
        ob["transport"] = {"type": "grpc", "service_name": str(d.get("path") or "")}
    elif net == "h2":
        ob["transport"] = {"type": "http", "host": [str(d.get("host") or d["add"])]}
    return ob


def _parse_trojan_like(uri: str, scheme: str, idx: int) -> dict[str, Any]:
    """trojan / vless 共用 URL 结构。

    trojan://password@host:port?sni=&type=&path=&host=
    vless://uuid@host:port?sni=&type=&flow=&security=reality&pbk=&sid=
    """
    rest = uri[len(scheme) + 3:]
    rest = rest.split("#", 1)[0]
    if "@" not in rest:
        raise NodeParseError(f"{scheme} 缺少 @ 分隔的凭据")
    userinfo, _, hostpart = rest.rpartition("@")
    credential = unquote(userinfo)
    if not credential:
        raise NodeParseError(f"{scheme} 缺少凭据")

    hostpart, _, query = hostpart.partition("?")
    host, port = _split_hostport(hostpart)
    q = parse_qs(query)

    net = _qs_one(q, "type", "tcp").lower()
    security = _qs_one(q, "security", "none").lower()
    sni = _qs_one(q, "sni") or _qs_one(q, "peer") or host
    fp = _qs_one(q, "fp")

    ob: dict[str, Any] = {
        "type": "trojan" if scheme == "trojan" else "vless",
        "server": host,
        "server_port": port,
    }
    if scheme == "trojan":
        ob["password"] = credential
    else:
        ob["uuid"] = credential
        flow = _qs_one(q, "flow")
        if flow:
            ob["flow"] = flow

    # TLS / Reality
    # ⚠️ trojan 协议本身就是「全 TLS 传输」—— 即使订阅不写 security=tls，
    # 也**必须**开 TLS。之前写成 `if security in (...)` 才生成 tls 段，
    # 导致不写 security 的 trojan 节点完全没有 TLS，既连不上也不安全。
    # vless 则相反：只有明确声明 security=tls/reality 才开。
    need_tls = (scheme == "trojan") or security in ("tls", "reality", "xtls")
    if need_tls:
        # ⚠️ insecure 必须读订阅里的 allowInsecure，**不能硬编码 false**。
        # 实测踩坑（2026-10-13）：订阅里 allowInsecure=1 的节点，
        # 硬编码 insecure:false 会导致 TLS 校验失败 → 连接建不起来 →
        # 表现为「所有节点都不通」，而 TCP 层明明能连上节点服务器。
        # 这个参数在 hysteria2 分支里本来就读了，vless/trojan 却漏了 ——
        # 同一个参数两种协议处理不一致，是典型的复制粘贴漏改。
        insecure = (_qs_bool(q, "allowInsecure")
                    or _qs_bool(q, "insecure")
                    or _qs_bool(q, "skip-cert-verify"))
        tls: dict[str, Any] = {
            "enabled": True, "server_name": sni, "insecure": insecure,
        }
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
            # ⚠️ sing-box 的 reality 客户端**强制要求 uTLS**：缺了直接 FATAL
            # "uTLS is required by reality client" 拒绝启动。订阅里 fp= 常缺省，
            # 缺了就整个节点连带同批探测实例一起起不来 → 探测全线 0 存活
            # （2026-10-13 实测定位，3.2% 节点命中，足以毒死每一批）。
            tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
            pbk = _qs_one(q, "pbk")
            if not pbk:
                raise NodeParseError("reality 缺 pbk 公钥")
            tls["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": _qs_one(q, "sid"),
            }
        ob["tls"] = tls

    # 传输层
    if net == "ws":
        ws: dict[str, Any] = {"type": "ws", "path": _qs_one(q, "path", "/")}
        h = _qs_one(q, "host")
        if h:
            ws["headers"] = {"Host": h}
        ob["transport"] = ws
    elif net == "grpc":
        ob["transport"] = {
            "type": "grpc",
            "service_name": _qs_one(q, "serviceName") or _qs_one(q, "path"),
        }
    elif net in ("h2", "http"):
        h = _qs_one(q, "host")
        ob["transport"] = {"type": "http", "host": [h] if h else [sni]}
    return ob


def _parse_hysteria2(uri: str, idx: int) -> dict[str, Any]:
    """hysteria2://password@host:port?sni=&insecure=1&obfs=salamander&obfs-password="""
    rest = uri.split("://", 1)[1].split("#", 1)[0]
    if "@" not in rest:
        raise NodeParseError("hysteria2 缺少 @ 分隔的凭据")
    userinfo, _, hostpart = rest.rpartition("@")
    password = unquote(userinfo)
    if not password:
        raise NodeParseError("hysteria2 缺少密码")

    hostpart, _, query = hostpart.partition("?")
    host, port = _split_hostport(hostpart)
    q = parse_qs(query)

    ob: dict[str, Any] = {
        "type": "hysteria2",
        "server": host,
        "server_port": port,
        "password": password,
    }
    sni = _qs_one(q, "sni") or _qs_one(q, "peer") or host
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": sni,
        "insecure": _qs_bool(q, "insecure") or _qs_bool(q, "allowInsecure"),
    }
    ob["tls"] = tls
    obfs = _qs_one(q, "obfs")
    if obfs:
        ob["obfs"] = {"type": obfs, "password": _qs_one(q, "obfs-password")}
    return ob


def _parse_tuic(uri: str, idx: int) -> dict[str, Any]:
    """tuic://uuid:password@host:port?sni=&alpn=h3"""
    rest = uri[len("tuic://"):].split("#", 1)[0]
    if "@" not in rest:
        raise NodeParseError("tuic 缺少 @ 分隔的凭据")
    userinfo, _, hostpart = rest.rpartition("@")
    userinfo = unquote(userinfo)
    if ":" not in userinfo:
        raise NodeParseError("tuic 凭据需为 uuid:password")
    uuid, _, password = userinfo.partition(":")

    hostpart, _, query = hostpart.partition("?")
    host, port = _split_hostport(hostpart)
    q = parse_qs(query)

    ob: dict[str, Any] = {
        "type": "tuic",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "password": password,
        "tls": {
            "enabled": True,
            "server_name": _qs_one(q, "sni") or host,
            "insecure": _qs_bool(q, "allow_insecure") or _qs_bool(q, "insecure"),
            "alpn": [_qs_one(q, "alpn")] if _qs_one(q, "alpn") else ["h3"],
        },
    }
    return ob


def _parse_socks(uri: str, idx: int) -> dict[str, Any]:
    """socks5://host:port / socks4://host:port（可能带 user:pass@）。"""
    scheme, _, rest = uri.partition("://")
    rest = rest.split("#", 1)[0]
    version = "4" if scheme.lower() == "socks4" else "5"
    user = pw = ""
    if "@" in rest:
        userinfo, _, rest = rest.rpartition("@")
        if ":" in userinfo:
            user, _, pw = userinfo.partition(":")
        else:
            user = unquote(userinfo)
    host, port = _split_hostport(rest)
    ob: dict[str, Any] = {
        "type": "socks",
        "server": host,
        "server_port": port,
        "version": version,
    }
    if version == "5" and user:
        ob["username"] = unquote(user)
        ob["password"] = unquote(pw)
    return ob


def _parse_http_proxy(uri: str, idx: int) -> dict[str, Any]:
    """http://host:port / https://host:port（可能带 user:pass@）。"""
    scheme, _, rest = uri.partition("://")
    rest = rest.split("#", 1)[0]
    user = pw = ""
    if "@" in rest:
        userinfo, _, rest = rest.rpartition("@")
        if ":" in userinfo:
            user, _, pw = userinfo.partition(":")
        else:
            user = unquote(userinfo)
    host, port = _split_hostport(rest, default_port=8080)
    ob: dict[str, Any] = {
        "type": "http",
        "server": host,
        "server_port": port,
    }
    if user:
        ob["username"] = unquote(user)
        ob["password"] = unquote(pw)
    return ob


_PARSERS = {
    "ss": _parse_ss,
    "vmess": _parse_vmess,
    "trojan": lambda u, i: _parse_trojan_like(u, "trojan", i),
    "vless": lambda u, i: _parse_trojan_like(u, "vless", i),
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
    "socks5": lambda u, i: _parse_socks(u, i),
    "socks4": lambda u, i: _parse_socks(u, i),
    "socks": lambda u, i: _parse_socks(u, i),
    "http": _parse_http_proxy,
    "https": _parse_http_proxy,
}

# 明确识别但不支持 —— 报给用户，不静默丢
_UNSUPPORTED = {
    "ssr": "shadowsocksr（sing-box 已不再支持，建议换 ss/ss2022 节点）",
    "hysteria": "hysteria v1（建议用 hysteria2）",
    "snell": "snell（sing-box 不支持）",
}

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")


def parse_node(uri: str, idx: int = 0) -> Node:
    """解析单个节点 URI。失败抛 NodeParseError（消息不含敏感值）。"""
    uri = uri.strip()
    if not uri or uri.startswith("#"):
        raise NodeParseError("空行或注释")

    m = _SCHEME_RE.match(uri)
    if not m:
        raise NodeParseError("不是标准节点链接（缺少 scheme://）")
    scheme = m.group(1).lower()

    if scheme in _UNSUPPORTED:
        raise NodeParseError(f"不支持的协议 {scheme}：{_UNSUPPORTED[scheme]}")

    parser = _PARSERS.get(scheme)
    if parser is None:
        raise NodeParseError(f"未知协议 {scheme}")

    ob = parser(uri, idx)

    # ⚠️ 校验服务器地址有效性 —— 这一步不能省。
    # 实测踩坑（2026-10-13）：机场订阅里混了占位节点，server 是
    # 0.0.0.0。不过滤的后果：
    #   1. 它被选进 selector 并成为 default（因为是列表第一个）
    #   2. 所有流量发往 0.0.0.0:443 → "connect: connection refused"
    #   3. 表面看是「节点全不通」，实际是坏节点污染了整个代理
    # 报错要能定位但不能泄密：只说地址无效，不回显完整凭据。
    server = str(ob.get("server", "")).strip()
    if not server:
        raise NodeParseError("节点缺少服务器地址")
    if server in ("0.0.0.0", "::", "127.0.0.1", "localhost", "::1"):
        raise NodeParseError(f"节点服务器地址无效（{server}）—— 多为订阅里的占位条目")
    port = ob.get("server_port")
    if not isinstance(port, int) or not (0 < port < 65536):
        raise NodeParseError(f"节点端口无效：{port!r}")

    # 备注名：fragment 里的 #名字
    tag = ""
    if "#" in uri:
        tag = unquote(uri.split("#", 1)[1]).strip()
    if not tag:
        tag = f"{scheme}-{idx + 1}"
    # sing-box 的 tag 不允许奇怪字符，做一次清洗
    tag = re.sub(r"[^\w\u4e00-\u9fff.@_-]+", "_", tag)[:60] or f"{scheme}-{idx + 1}"

    return Node(tag=tag, protocol=ob["type"], outbound=ob, raw=uri)


# ══════════════════════ Clash YAML 解析 ══════════════════════
#
# 为什么需要：免费节点源里 clash.yaml 与 v2ray.txt 各占半壁（如
# manifest.dpdns.org 两种都提供）。只支持 URI 订阅会丢掉一半来源。
# 字段映射按 clash → sing-box 的官方约定，与上面 URI 解析保持同一
# 目标结构（同样的 tls/transport 形状）。

_CLASH_TYPE_MAP = {
    "ss": "shadowsocks",
    "trojan": "trojan",
    "vmess": "vmess",
    "vless": "vless",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
}


def _clash_transport(p: dict[str, Any]) -> dict[str, Any] | None:
    """clash 的 network + *-opts → sing-box transport。无则返回 None。"""
    net = str(p.get("network") or "").lower()
    if net == "ws":
        opts = p.get("ws-opts") or {}
        ws: dict[str, Any] = {"type": "ws", "path": str(opts.get("path") or "/")}
        headers = opts.get("headers") or {}
        if headers:
            ws["headers"] = {str(k): str(v) for k, v in headers.items()}
        return ws
    if net == "grpc":
        opts = p.get("grpc-opts") or {}
        return {"type": "grpc",
                "service_name": str(opts.get("grpc-service-name") or "")}
    if net in ("h2", "http"):
        opts = p.get("h2-opts") or {}
        hosts = opts.get("host")
        if isinstance(hosts, list):
            return {"type": "http", "host": [str(h) for h in hosts]}
        return {"type": "http", "host": [str(hosts)] if hosts else []}
    return None


def _clash_tls(p: dict[str, Any], *, default_sni: str = "",
               force: bool = False) -> dict[str, Any] | None:
    """clash 的 tls/servername/skip-cert-verify/reality-opts → sing-box tls。

    force=True 用于 trojan（协议本身即全 TLS，即使没写 tls: true）。
    """
    enabled = bool(p.get("tls")) or force
    if not enabled:
        return None
    sni = str(p.get("servername") or p.get("sni") or default_sni or "")
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": sni,
        "insecure": bool(p.get("skip-cert-verify")),
    }
    alpn = p.get("alpn")
    if isinstance(alpn, list) and alpn:
        tls["alpn"] = [str(a) for a in alpn]
    fp = p.get("client-fingerprint")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": str(fp)}
    ro = p.get("reality-opts") or {}
    if ro.get("public-key"):
        # reality 客户端必须带 uTLS，缺 client-fingerprint 时补默认（同 _parse_vless）
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
        tls["reality"] = {
            "enabled": True,
            "public_key": str(ro["public-key"]),
            "short_id": str(ro.get("short-id") or ""),
        }
    return tls


def _clash_proxy_to_outbound(p: dict[str, Any], idx: int) -> dict[str, Any]:
    """单个 clash proxy 条目 → sing-box outbound。

    异常消息**不含**任何凭据值（只带类型与字段名）。
    """
    if not isinstance(p, dict):
        raise NodeParseError("条目不是对象")
    ctype = str(p.get("type") or "").lower()
    stype = _CLASH_TYPE_MAP.get(ctype)
    if not stype:
        raise NodeParseError(f"不支持的 clash 类型 {ctype or '?'}")
    server = str(p.get("server") or "").strip()
    try:
        port = int(p.get("port") or 0)
    except (TypeError, ValueError):
        raise NodeParseError("port 不是数字") from None
    if not server or not port:
        raise NodeParseError("缺 server 或 port")

    ob: dict[str, Any] = {"type": stype, "server": server, "server_port": port}

    if stype == "shadowsocks":
        method = str(p.get("cipher") or "")
        if not method or "password" not in p:
            raise NodeParseError("ss 缺 cipher 或 password")
        ob["method"] = method
        ob["password"] = str(p["password"])
        plugin = p.get("plugin")
        if plugin:
            ob["plugin"] = str(plugin)
            opts = p.get("plugin-opts") or {}
            if isinstance(opts, dict) and opts:
                ob["plugin_opts"] = ";".join(f"{k}={v}" for k, v in opts.items())

    elif stype == "trojan":
        if "password" not in p:
            raise NodeParseError("trojan 缺 password")
        ob["password"] = str(p["password"])
        tls = _clash_tls(p, default_sni=server, force=True)
        if tls:
            ob["tls"] = tls

    elif stype == "vmess":
        if not p.get("uuid"):
            raise NodeParseError("vmess 缺 uuid")
        ob["uuid"] = str(p["uuid"])
        ob["security"] = str(p.get("cipher") or "auto")
        try:
            ob["alter_id"] = int(p.get("alterId") or 0)
        except (TypeError, ValueError):
            ob["alter_id"] = 0
        tls = _clash_tls(p, default_sni=server)
        if tls:
            ob["tls"] = tls

    elif stype == "vless":
        if not p.get("uuid"):
            raise NodeParseError("vless 缺 uuid")
        ob["uuid"] = str(p["uuid"])
        if p.get("flow"):
            ob["flow"] = str(p["flow"])
        tls = _clash_tls(p, default_sni=server)
        if tls:
            ob["tls"] = tls

    elif stype == "hysteria2":
        if "password" not in p:
            raise NodeParseError("hysteria2 缺 password")
        ob["password"] = str(p["password"])
        if p.get("obfs"):
            ob["obfs"] = {"type": str(p["obfs"]),
                          "password": str(p.get("obfs-password") or "")}
        tls = _clash_tls(p, default_sni=server, force=True)
        if tls:
            ob["tls"] = tls

    transport = _clash_transport(p)
    if transport:
        ob["transport"] = transport
    return ob


def parse_clash_yaml(text: str) -> ParseReport:
    """解析 Clash/Mihomo 的 yaml 配置（取 proxies 段）。

    需要 pyyaml。没装则抛 SubscriptionError（明确告诉调用方装什么），
    不静默返回空。
    """
    try:
        import yaml
    except ImportError as e:
        raise SubscriptionError(
            "解析 clash yaml 需要 pyyaml：pip install pyyaml") from e

    try:
        doc = yaml.safe_load(text)
    except Exception as e:
        raise SubscriptionError(f"yaml 解析失败: {type(e).__name__}") from e
    if not isinstance(doc, dict):
        raise SubscriptionError("clash 配置不是对象")
    proxies = doc.get("proxies")
    if not isinstance(proxies, list):
        raise SubscriptionError("clash 配置里没有 proxies 列表")

    report = ParseReport()
    for i, p in enumerate(proxies):
        try:
            ob = _clash_proxy_to_outbound(p, i)
        except NodeParseError as e:
            report.skipped.append({
                "index": i,
                "scheme": str((p or {}).get("type") or "?") if isinstance(p, dict) else "?",
                "reason": str(e),
            })
            continue
        name = str((p or {}).get("name") or f"clash-{i}")
        report.nodes.append(Node(tag=name, protocol=ob["type"], outbound=ob))
    if not report.nodes and not report.skipped:
        raise SubscriptionError("clash 配置的 proxies 是空的")
    return report


def looks_like_clash_yaml(text: str) -> bool:
    """粗判文本是否为 clash yaml 配置。"""
    head = (text or "")[:4000]
    if "proxies:" not in head:
        return False
    # 排除 HTML 与纯 URI 列表
    if head.lstrip().lower().startswith(("<!doctype", "<html")):
        return False
    return True


# ══════════════════════ 订阅正文解析 ══════════════════════


# ══════════════════════ 普通代理列表解析 ══════════════════════
#
# HProxy/Proxifly/monosans/litport/Thordata/proxio/databay 等公开代理
# 列表的形态：一行一个 IP:PORT（无任何 scheme）。各站噪声格式不一：
#   1.2.3.4:1080            纯（多数站）
#   1.2.3.4:1080@US         带国家码（hproxy all.json 导出）
#   US|1.2.3.4:1080         国家码前缀
#   socks5://1.2.3.4:1080   个别站带 scheme
# 统一只抠 IP:PORT，行内其他内容忽略；协议由调用方按源声明/URL 嗅探。

_IPPORT_LINE_RE = re.compile(
    r"^(?:[a-z0-9]+://)?"            # 可选 scheme 前缀（socks5://）
    r"(?:[a-z]{2}[|@])?"             # 可选国家码前缀（US| / US@）
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"  # IPv4
    r":(?P<port>\d{1,5})"            # 端口
    r"(?:[@|,].*)?$",                # 可带 @CC / |CC 后缀
    re.I,
)
_IPV4_OCTET_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

_PROXY_DEFAULT_PORTS = {"socks5": 1080, "socks4": 1080, "http": 8080}


def _valid_ipv4(ip: str) -> bool:
    """四段都在 0-255（防止把 999.999.999.999 当节点，白耗探测预算）。"""
    m = _IPV4_OCTET_RE.match(ip)
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def parse_proxy_list(text: str,
                     default_proto: str = "socks5") -> ParseReport:
    """解析普通代理列表（一行一个 IP:PORT）。

    default_proto：列表的协议（socks5 / socks4 / http）—— 调用方按
    源 URL 或页面声明给出（socks5.txt → socks5）。缺省 socks5 是这类
    列表的最大公约数。

    产出 Node.protocol = sing-box outbound type（socks/http），
    与 VPN 节点同一套探测/选路管线。
    """
    proto = (default_proto or "socks5").lower()
    if proto in ("socks4", "socks"):
        stype, version = "socks", "4"
    elif proto == "socks5":
        stype, version = "socks", "5"
    elif proto in ("http", "https"):
        stype, version = "http", ""
    else:
        raise SubscriptionError(f"不支持的代理列表协议 {default_proto}")

    report = ParseReport()
    idx = 0
    for ln in (text or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        m = _IPPORT_LINE_RE.match(ln)
        if not m:
            # 不像 IP:PORT 的行：能解析出 scheme:// 的交给 URI 体系，
            # 否则记 skip（保持「不静默丢」的约定）
            if "://" in ln:
                try:
                    report.nodes.append(parse_node(ln, idx))
                    idx += 1
                    continue
                except NodeParseError:
                    pass
            report.skipped.append({"index": idx, "scheme": "?",
                                   "reason": "不是 IP:PORT 行"})
            idx += 1
            continue
        ip, port_s = m.group("ip"), m.group("port")
        if not _valid_ipv4(ip):
            report.skipped.append({"index": idx, "scheme": proto,
                                   "reason": "IPv4 地址无效"})
            idx += 1
            continue
        try:
            port = int(port_s)
        except ValueError:
            report.skipped.append({"index": idx, "scheme": proto,
                                   "reason": "端口不是数字"})
            idx += 1
            continue
        if not (0 < port < 65536):
            report.skipped.append({"index": idx, "scheme": proto,
                                   "reason": "端口超出范围"})
            idx += 1
            continue
        ob: dict[str, Any] = {"type": stype, "server": ip,
                              "server_port": port}
        if stype == "socks":
            ob["version"] = version
        report.nodes.append(Node(tag=f"{proto}-{idx}", protocol=stype,
                                 outbound=ob))
        idx += 1
    if not report.nodes and not report.skipped:
        raise SubscriptionError("代理列表为空")
    return report


def looks_like_proxy_list(text: str) -> bool:
    """粗判文本是否为普通代理列表（IP:PORT 行占非空行一半以上）。"""
    lines = [l.strip() for l in (text or "").splitlines()
             if l.strip() and not l.strip().startswith("#")]
    if len(lines) < 5:
        return False
    hit = sum(1 for l in lines if _IPPORT_LINE_RE.match(l))
    return hit * 2 >= len(lines)


def _sniff_proxy_proto(url: str) -> str:
    """按 URL 路径/查询嗅探列表协议。认不出来的默认 socks5。

    ⚠️ 只看 path/query，**不看 URL 自身的 scheme** ——
    https://…/all.txt 是 https 页面，列表内容多半是 socks。2026-10-14
    第一版把 scheme 也算进去，结果所有 https 源都被判成 http 代理。
    """
    try:
        parts = urlsplit(url or "")
        hay = (parts.path + " " + parts.query).lower()
    except ValueError:
        hay = (url or "").lower()
    if "socks4" in hay:
        return "socks4"
    if "socks5" in hay or "socks" in hay:
        return "socks5"
    if "http" in hay:
        return "http"
    return "socks5"


def parse_subscription_text(text: str,
                            default_proto: str = "") -> ParseReport:
    """解析订阅正文。

    四种常见形态：
      · base64 编码的整块（机场标准）—— 里面每行一个节点
      · 明文每行一个节点（部分自建/分享用）
      · Clash/Mihomo yaml（免费聚合源常见，取 proxies 段）
      · 普通代理列表（一行一个 IP:PORT，无 scheme）—— default_proto
        非空且 URI 解析零节点时走 parse_proxy_list

    自动判别：整块能 base64 解出含 "://" 的文本就当编码块；
    含 proxies: 的 yaml 走 clash 解析。
    """
    raw = text.strip()
    if not raw:
        raise SubscriptionError("订阅内容为空")

    # Clash yaml 优先判别（它一定不是 base64，也不含 :// 节点行）
    if looks_like_clash_yaml(raw):
        return parse_clash_yaml(raw)

    body = raw
    # 判别是不是整块 base64
    if "://" not in raw[:200]:
        try:
            decoded = _b64decode_text(raw)
            if "://" in decoded:
                body = decoded
        except NodeParseError:
            pass  # 不是 base64，按明文处理

    lines = [ln.strip() for ln in body.splitlines()]
    report = ParseReport()
    for i, ln in enumerate(lines):
        if not ln or ln.startswith("#"):
            continue
        try:
            report.nodes.append(parse_node(ln, i))
        except NodeParseError as e:
            report.skipped.append({
                "index": i,
                "scheme": (_SCHEME_RE.match(ln).group(1).lower()
                           if _SCHEME_RE.match(ln) else "?"),
                "reason": str(e),   # 已确保不含敏感值
            })
        except Exception as e:  # noqa: BLE001
            # 兜底：未预期异常（解析器 bug、畸形行）只跳过这一行，
            # 绝不炸掉整份订阅。2026-10-14 实测：一个带尾斜杠的 IPv6
            # 行曾让 1690 节点的 hysteria2.txt 整份解析失败。
            # reason 只记异常类型名（可能含地址等敏感值，不记消息）。
            report.skipped.append({
                "index": i,
                "scheme": (_SCHEME_RE.match(ln).group(1).lower()
                           if _SCHEME_RE.match(ln) else "?"),
                "reason": f"未预期错误 {type(e).__name__}",
            })
    if report.nodes:
        return report
    # URI 体系零节点：文本像普通代理列表（IP:PORT 行过半）且调用方
    # 声明了协议 → 走代理解析（HProxy/Proxifly 这类源的全部价值）。
    if default_proto and looks_like_proxy_list(raw):
        try:
            return parse_proxy_list(raw, default_proto)
        except SubscriptionError:
            pass  # 解析不出就按下面的口径报错，不掩盖
    if not report.skipped:
        raise SubscriptionError("订阅里没有识别到任何节点")
    # 区分两种「零节点」：
    #   · 一行都不像节点链接（HTML 错误页、纯说明文字）→ 这压根不是订阅，报错
    #   · 有像节点链接的行但都解析失败/不支持（如整份都是 ssr）→ 返回报告，
    #     让用户看到具体原因，而不是一句含糊的「没有节点」
    if not any(s["scheme"] != "?" for s in report.skipped):
        raise SubscriptionError(
            "订阅内容不像节点列表（可能链接失效、返回了网页或错误信息）"
        )
    return report


# ══════════════════════ sing-box 配置生成 ══════════════════════


def build_singbox_config(
    report: ParseReport,
    *,
    http_port: int = 17890,
    socks_port: int = 17891,
    listen: str = "127.0.0.1",
    log_level: str = "warn",
    clash_api_port: int = 0,
    default_tag: str = "",
) -> dict[str, Any]:
    """生成 sing-box 配置。

    ⚠️ 生成的配置**含节点凭据**，调用方负责：
      · 写入 600 权限文件
      · 不落日志、不进 git

    路由：默认走 selector，由调用方指定默认节点（见 default_tag 参数）。
    若没有任何节点，退化成 direct（这样服务不会因为没节点而崩）。
    """
    outbounds: list[dict[str, Any]] = []
    for n in report.nodes:
        outbounds.append(n.to_outbound())

    tags = [n.tag for n in report.nodes]
    if tags:
        # selector 让用户能切换节点（面板/Clash API）
        # default 由调用方给（通常是探测出来的最快节点）；
        # 没给就用第一个，但**不能是坏节点**（parse_node 已过滤掉 0.0.0.0 之类）
        chosen = default_tag if default_tag in tags else tags[0]
        outbounds.append({
            "type": "selector",
            "tag": "proxy",
            "outbounds": tags,
            "default": chosen,
        })
        final = "proxy"
    else:
        final = "direct"

    outbounds.append({"type": "direct", "tag": "direct"})

    cfg: dict[str, Any] = {
        "log": {"level": log_level, "timestamp": True},
        "inbounds": [
            {"type": "http", "tag": "http-in",
             "listen": listen, "listen_port": http_port},
            {"type": "socks", "tag": "socks-in",
             "listen": listen, "listen_port": socks_port},
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                # 本地/内网直连，不走代理（避免自环与无谓流量）
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": final,
        },
    }
    if clash_api_port:
        cfg["experimental"] = {
            "clash_api": {"external_controller": f"127.0.0.1:{clash_api_port}"}
        }
    return cfg
