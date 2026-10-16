"""配置存储 —— 面板与代理的持久化层。

⚠️ 安全红线（本模块是凭据落盘的唯一入口）：
  1. **文件权限强制 600**，目录 700。每次写入后都 chmod，
     不依赖 umask（umask 在不同环境差异大，不能指望）。
  2. **不回显**：read_public() 只返回「是否已配置」与长度掩码，
     绝不返回凭据本身。面板用它渲染「已配置 ●●●●」。
  3. **原子写**：先写 .tmp 再 replace，避免写一半断电留下坏文件。
  4. **不进 git**：.env 已在 .gitignore；本模块额外提供 check_gitignored()
     供启动时自检，防止有人改了 .gitignore 后把凭据提交上去。

存储格式：key=value 的 .env（兼容 shell source，便于运维）
  WS_SUBSCRIPTION_URL=...     机场订阅链接
  WS_PROXY_ENABLED=1          是否启用代理
  WS_PANEL_TOKEN=...          面板访问口令（首次启动自动生成）
  WS_HTTP_PROXY_PORT=17890
  WS_SOCKS_PROXY_PORT=17891
"""

from __future__ import annotations

import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path

# 允许通过面板写入的键（白名单 —— 防止面板被利用来注入任意环境变量）
WRITABLE_KEYS = {
    "WS_SUBSCRIPTION_URL",
    "WS_PROXY_ENABLED",
    "WS_HTTP_PROXY_PORT",
    "WS_SOCKS_PROXY_PORT",
    "WS_PANEL_TOKEN",
    "WS_PROXY_AUTO_START",
    "WS_PROXY_HEALTH_INTERVAL",
    # 一键登录票据（服务端签发，不来自面板输入；放白名单是因为
    # 它要经 set_many 落盘 —— 白名单拦的是「面板能写什么」，
    # 不是「哪些键存在」）
    "WS_LOGIN_TICKET_HASH",
    "WS_LOGIN_TICKET_EXP",
}

# 敏感键：read_public 绝不返回其值
SECRET_KEYS = {
    "WS_SUBSCRIPTION_URL",
    "WS_PANEL_TOKEN",
    "WS_LOGIN_TICKET_HASH",   # 票据哈希也不该外泄（可用于碰撞尝试）
}

DEFAULTS: dict[str, str] = {
    "WS_PROXY_ENABLED": "0",
    "WS_HTTP_PROXY_PORT": "17890",
    "WS_SOCKS_PROXY_PORT": "17891",
    "WS_PROXY_AUTO_START": "1",
    "WS_PROXY_HEALTH_INTERVAL": "300",
    "WS_PANEL_HOST": "127.0.0.1",
    "WS_PANEL_PORT": "8500",
    # MCP 搜索服务端口（面板生成客户端配置时要用）
    "WS_PORT": "8300",
}


class ConfigError(Exception):
    """配置读写错误。消息里**不含**凭据值。"""


def _mask(value: str) -> str:
    """把凭据变成可安全展示的掩码。

    只暴露「长度量级」与首尾各 2 字符，中间全遮。
    长度太短的（<12）直接全遮，避免泄露过多信息。
    """
    if not value:
        return ""
    if len(value) < 12:
        return "●" * len(value)
    return f"{value[:2]}{'●' * min(len(value) - 4, 24)}{value[-2:]} ({len(value)} 字符)"


@dataclass
class Store:
    """凭据/配置存储。一个实例绑定一个 .env 文件。

    ⚠️ 跨进程一致性（踩过一次真 bug）：
    面板进程持有 Store 实例，而 `ticket` 工具是**另一个进程**，
    它签发票据时改的是磁盘文件。面板进程的内存缓存不会自动更新，
    导致「工具说链接有效、面板说票据无效」——用户点开链接进不去。

    修法：每次读之前检查文件 mtime，变了就重载（见 _maybe_reload）。
    开销极小（一次 stat），但消除了这类跨进程不一致。
    """

    path: Path
    _cache: dict[str, str] = field(default_factory=dict, repr=False)
    _mtime: float = field(default=0.0, repr=False)
    _last_stat: float = field(default=0.0, repr=False)

    # 最多多久 stat 一次（秒）。设 0 = 每次读都 stat。
    # 取 0.5 是因为：面板是低频交互，stat 成本可忽略；
    # 而用户「刚跑完命令就点链接」的场景必须立刻生效。
    STAT_INTERVAL = 0.5

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self._ensure_dir()
        if self.path.exists():
            self.reload()

    def _maybe_reload(self) -> None:
        """文件被外部改动时自动重载（跨进程一致性）。

        为什么要节流：一次搜索可能读十几个配置项，每次都 stat 没必要。
        0.5 秒窗口足够覆盖「用户刚跑完命令就点链接」的场景。
        """
        now = time.monotonic()
        if now - self._last_stat < self.STAT_INTERVAL:
            return
        self._last_stat = now
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return
        if mtime != self._mtime:
            self.reload()

    # ── 目录/权限 ──

    def _ensure_dir(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    def _secure_file(self) -> None:
        """强制 600。每次写完都调。"""
        try:
            os.chmod(self.path, 0o600)
        except OSError as e:
            raise ConfigError(f"无法设置文件权限: {type(e).__name__}") from None

    def check_permissions(self) -> tuple[bool, str]:
        """自检：文件权限是否为 600。返回 (是否安全, 说明)。"""
        if not self.path.exists():
            return True, "文件尚未创建"
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        if mode & 0o077:
            return False, f"权限过宽 {oct(mode)}（其他用户可读），应为 600"
        return True, f"权限 {oct(mode)}"

    # ── 读写 ──

    def reload(self) -> None:
        """从磁盘重新加载。"""
        try:
            text = self.path.read_text(encoding="utf-8")
            self._mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            self._cache = {}
            self._mtime = 0.0
            return
        except Exception as e:
            raise ConfigError(f"读取失败: {type(e).__name__}") from None

        data: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            data[key.strip()] = value.strip()
        self._cache = data

    def get(self, key: str, default: str = "") -> str:
        """读一个值。环境变量优先（便于运维临时覆盖）。

        读之前先看文件有没有被外部改过（跨进程一致性）。
        """
        self._maybe_reload()
        env = os.environ.get(key)
        if env:
            return env
        return self._cache.get(key, DEFAULTS.get(key, default))

    def get_bool(self, key: str, default: bool = False) -> bool:
        v = self.get(key, "1" if default else "0").strip().lower()
        return v in ("1", "true", "yes", "on")

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, str(default)))
        except ValueError:
            return default

    def set_many(self, values: dict[str, str], *, allow_secret: bool = True) -> None:
        """批量写值（原子写 + 600 权限）。

        只接受白名单键 —— 面板被攻破也不能借此注入任意环境变量。
        """
        clean: dict[str, str] = {}
        for k, v in values.items():
            if k not in WRITABLE_KEYS:
                raise ConfigError(f"不允许写入的配置项: {k}")
            if k in SECRET_KEYS and not allow_secret:
                continue
            # 值里不能有换行（防注入额外配置行）
            if "\n" in v or "\r" in v:
                raise ConfigError(f"{k} 的值不能包含换行")
            clean[k] = v.strip()

        merged = dict(self._cache)
        merged.update(clean)
        self._write(merged)
        self._cache = merged

    def delete(self, keys: list[str]) -> None:
        """删除配置项（用于「清除订阅」）。"""
        merged = {k: v for k, v in self._cache.items() if k not in keys}
        self._write(merged)
        self._cache = merged

    def _write(self, data: dict[str, str]) -> None:
        """原子写 + 强制 600。"""
        self._ensure_dir()
        lines = [
            "# websearch-mcp 本地配置 —— 含凭据，权限 600，已在 .gitignore",
            "# 本文件由管理面板读写。手工编辑后需重启服务或用面板「重新加载」。",
            "",
        ]
        for k in sorted(data):
            lines.append(f"{k}={data[k]}")
        body = "\n".join(lines) + "\n"

        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(body, encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)
        self._secure_file()
        # 记录新 mtime —— 否则自己写的改动会被 _maybe_reload 当成
        # 「外部改动」再重载一次（无害但多余），且可能读到写一半的状态
        try:
            self._mtime = self.path.stat().st_mtime
        except OSError:
            self._mtime = 0.0
        self._last_stat = time.monotonic()

    # ── 面板展示用（无凭据） ──

    def read_public(self) -> dict[str, object]:
        """给面板/API 的安全视图。

        **绝不返回凭据值** —— 只告诉调用方「配了没、多长」。
        这样即使面板页面被截图、被分享，也不会泄露订阅链接。
        """
        sub = self.get("WS_SUBSCRIPTION_URL", "")
        panel = self.get("WS_PANEL_TOKEN", "")
        perm_ok, perm_note = self.check_permissions()
        return {
            "subscription": {
                "configured": bool(sub),
                "masked": _mask(sub),
                "host": _safe_host(sub),
            },
            "panel_token": {
                "configured": bool(panel),
                "masked": _mask(panel),
            },
            "proxy_enabled": self.get_bool("WS_PROXY_ENABLED"),
            "http_port": self.get_int("WS_HTTP_PROXY_PORT", 17890),
            "socks_port": self.get_int("WS_SOCKS_PROXY_PORT", 17891),
            "auto_start": self.get_bool("WS_PROXY_AUTO_START", True),
            "health_interval": self.get_int("WS_PROXY_HEALTH_INTERVAL", 300),
            "file_permissions": {"secure": perm_ok, "detail": perm_note},
            "path": str(self.path),
        }

    # ── 面板口令 ──

    def ensure_panel_token(self) -> str:
        """确保面板口令存在。不存在则生成并落盘。

        返回明文 —— 调用方只在**首次生成时**打印一次，之后不再展示。
        """
        existing = self._cache.get("WS_PANEL_TOKEN", "")
        if existing:
            return ""
        token = secrets.token_urlsafe(32)
        self.set_many({"WS_PANEL_TOKEN": token})
        return token

    def verify_panel_token(self, given: str) -> bool:
        """常数时间比对，防时序侧信道。"""
        real = self.get("WS_PANEL_TOKEN", "")
        if not real or not given:
            return False
        return secrets.compare_digest(real, given)

    # ── 一键登录票据（免手工复制口令）──

    def issue_login_ticket(self, ttl_sec: int = 300) -> str:
        """签发一次性登录票据，用于生成「点开即登录」的链接。

        为什么需要它：让用户去 grep 口令再手工粘贴，是典型的
        「运维视角」而非「产品视角」——非技术用户第一步就卡死。
        票据把口令藏进 URL，点一下就进面板。

        安全设计：
          · 一次性（用过即废，见 consume_login_ticket）
          · 短时效（默认 5 分钟）
          · 存的是**哈希**不是明文 —— 即使 .env 泄露也拿不到票据
          · 与面板口令分离：票据泄露不能改口令
        """
        import hashlib
        import time

        raw = secrets.token_urlsafe(32)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        expiry = int(time.time()) + ttl_sec
        self.set_many({
            "WS_LOGIN_TICKET_HASH": digest,
            "WS_LOGIN_TICKET_EXP": str(expiry),
        })
        return raw

    def consume_login_ticket(self, ticket: str) -> bool:
        """校验并**作废**登录票据。返回是否有效。

        安全与可用性的取舍（这里踩过一次坑）：
          · 「校验失败就作废」能防暴力尝试 —— 但**不能无条件作废**，
            否则拿一个旧票据来试，会把刚签发的新票据一起删掉，
            表现为「点了链接进不去」（可用性事故）。
          · 正确做法：**只有校验通过（成功消费）才作废**。
            票据本身是 32 字节随机数 + 5 分钟时效，暴力猜测不现实，
            不需要靠「失败即废」来兜。
        """
        import hashlib
        import time

        if not ticket:
            return False
        # 关键：票据可能是**另一个进程**（ticket 工具）刚写入的，
        # 不重载就永远校验不过 —— 这正是「链接点了进不去」的根因。
        self._maybe_reload()
        stored = self._cache.get("WS_LOGIN_TICKET_HASH", "")
        if not stored:
            return False
        try:
            exp = int(self._cache.get("WS_LOGIN_TICKET_EXP", "0"))
        except ValueError:
            exp = 0

        digest = hashlib.sha256(ticket.encode()).hexdigest()
        matched = secrets.compare_digest(stored, digest)
        expired = bool(exp) and time.time() > exp

        if matched and not expired:
            # 只在成功消费时作废（一次性）
            self.delete(["WS_LOGIN_TICKET_HASH", "WS_LOGIN_TICKET_EXP"])
            return True
        if matched and expired:
            # 票据对但过期：清掉它，避免继续占位
            self.delete(["WS_LOGIN_TICKET_HASH", "WS_LOGIN_TICKET_EXP"])
        return False

    # ── 安全自检 ──

    def check_gitignored(self, repo_root: Path | str | None = None) -> tuple[bool, str]:
        """自检：本文件是否被 git 忽略。

        为什么要这个：一旦有人改坏 .gitignore，凭据会被提交上去，
        而 git 历史里的东西删不干净。启动时自检比事后补救便宜得多。

        默认仓库根 = .env 所在目录（本项目的 .env 就放在仓库根）。
        若你的 .env 放在子目录（如 secrets/.env），传 repo_root 指定。
        """
        root = Path(repo_root) if repo_root else self.path.parent
        gi = root / ".gitignore"
        if not gi.exists():
            return False, f"未找到 {gi}，无法确认凭据不会被提交"
        try:
            text = gi.read_text(encoding="utf-8")
        except Exception as e:
            return False, f"读取 .gitignore 失败: {type(e).__name__}"
        name = self.path.name
        # 粗判：文件名或 .env* 模式在忽略列表里
        if name in text or ".env" in text:
            return True, f"{name} 已被 .gitignore 覆盖"
        return False, f"{name} 未出现在 .gitignore，有被提交风险"


def _safe_host(url: str) -> str:
    """只取订阅链接的 host，**去掉 path 与 query**（token 通常在 query 里）。

    这样面板能显示「你配的是 sub3.smallstrawberry.com」帮用户确认，
    但不会泄露 token。
    """
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit

        p = urlsplit(url)
        return p.hostname or ""
    except Exception:
        return ""
