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

不支持的协议会**明确列出并跳过**，不静默丢弃 —— 用户要能看到
「你 20 个节点里有 3 个是 ssr，没接进来」，而不是莫名其妙少几个。
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
    """解析 host:port，兼容 IPv6 的 [::1]:443 形式。"""
    s = s.strip()
    if not s:
        raise NodeParseError("缺少服务器地址")
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = int(rest.lstrip(":") or default_port)
        return host, port
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
        ob["tls"] = {
            "enabled": True,
            "server_name": str(d.get("sni") or d.get("host") or d["add"]),
            "insecure": False,
        }
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
    if security in ("tls", "reality", "xtls"):
        tls: dict[str, Any] = {"enabled": True, "server_name": sni, "insecure": False}
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        if security == "reality":
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


_PARSERS = {
    "ss": _parse_ss,
    "vmess": _parse_vmess,
    "trojan": lambda u, i: _parse_trojan_like(u, "trojan", i),
    "vless": lambda u, i: _parse_trojan_like(u, "vless", i),
    "hysteria2": _parse_hysteria2,
    "hy2": _parse_hysteria2,
    "tuic": _parse_tuic,
}

# 明确识别但不支持 —— 报给用户，不静默丢
_UNSUPPORTED = {
    "ssr": "shadowsocksr（sing-box 已不再支持，建议换 ss/ss2022 节点）",
    "hysteria": "hysteria v1（建议用 hysteria2）",
    "snell": "snell（sing-box 不支持）",
    "http": "http 代理节点",
    "socks": "socks 代理节点",
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


def parse_subscription_text(text: str) -> ParseReport:
    """解析订阅正文。

    两种常见形态：
      · base64 编码的整块（机场标准）—— 里面每行一个节点
      · 明文每行一个节点（部分自建/分享用）

    自动判别：整块能 base64 解出含 "://" 的文本就当编码块。
    """
    raw = text.strip()
    if not raw:
        raise SubscriptionError("订阅内容为空")

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
    if not report.nodes and not report.skipped:
        raise SubscriptionError("订阅里没有识别到任何节点")
    # 区分两种「零节点」：
    #   · 一行都不像节点链接（HTML 错误页、纯说明文字）→ 这压根不是订阅，报错
    #   · 有像节点链接的行但都解析失败/不支持（如整份都是 ssr）→ 返回报告，
    #     让用户看到具体原因，而不是一句含糊的「没有节点」
    if not report.nodes and not any(s["scheme"] != "?" for s in report.skipped):
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
