# -*- coding: utf-8 -*-
"""一键登录链接签发工具测试（用户视角）。

这个工具解决的是「用户视角」的真实问题：
  1. 用户不该去 grep 口令
  2. 在**看门狗托管**的部署里，面板启动日志里打印的链接可能是废的
     （看门狗重启面板 → 新实例签发新票据 → 旧票据失效）
     所以链接必须由独立工具在面板稳定后签发

测试重点：链接真能用、能覆盖「面板被重启后旧链接失效」这个坑。
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.proxy.store import Store

SRC = Path(__file__).resolve().parents[1] / "src"


def run_ticket(cfg_path: Path, *args: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    """以子进程方式跑 ticket 工具（模拟用户敲命令）。"""
    env = {"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "websearch.proxy.ticket",
         "--config", str(cfg_path), *args],
        capture_output=True, text=True, timeout=30, env=env,
    )


@pytest.fixture
def cfg(tmp_path):
    """建一个配置文件。

    ⚠️ 只写**面板可写**的键（WS_PANEL_TOKEN）。
    WS_PANEL_HOST / WS_PANEL_PORT 是只读配置 —— 面板不该能改自己的
    监听地址（改了会导致面板重启后失联）。它们由 DEFAULTS 或环境变量提供。
    这个约束踩过三次（票据键、WS_PORT、WS_PANEL_HOST），写测试时注意。
    """
    p = tmp_path / ".env"
    s = Store(p)
    s.set_many({"WS_PANEL_TOKEN": "panel-token-for-test-only-0123456789"})
    return p


def test_ticket_tool_prints_url(cfg):
    r = run_ticket(cfg)
    assert r.returncode == 0, f"退出码 {r.returncode}: {r.stderr}"
    assert "/_open?t=" in r.stdout, f"没打印链接：{r.stdout}"


def test_ticket_tool_link_is_actually_usable(cfg):
    """打印出来的链接，其票据必须真的能消费（不是摆设）。"""
    import re

    r = run_ticket(cfg)
    m = re.search(r"/_open\?t=([A-Za-z0-9_-]+)", r.stdout)
    assert m, f"提取不到票据：{r.stdout}"
    ticket = m.group(1)
    # 用同一个 store 校验（模拟面板收到请求）
    s = Store(cfg)
    assert s.consume_login_ticket(ticket) is True, "工具打印的票据不可用"


def test_ticket_tool_uses_saved_host_and_port(cfg):
    """用环境变量提供 host/port（它们是只读配置，只能这样注入）。"""
    r = run_ticket(cfg, extra_env={
        "WS_PANEL_HOST": "0.0.0.0", "WS_PANEL_PORT": "8500",
    })
    assert r.returncode == 0, r.stderr
    assert ":8500" in r.stdout, "没用配置里的端口"
    assert "/_open" in r.stdout


def test_ticket_tool_respects_ttl(cfg):
    """--ttl 要生效（打印的说明里体现）。"""
    r = run_ticket(cfg, "--ttl", "1800")
    assert r.returncode == 0
    assert "1800" in r.stdout or "30 分钟" in r.stdout


def test_ticket_tool_missing_config_is_clear(tmp_path):
    """配置不存在时给人话提示，不是堆栈。"""
    r = run_ticket(tmp_path / "nope.env")
    assert r.returncode == 2
    assert "install.sh" in r.stderr, "应提示去跑安装脚本"
    assert "Traceback" not in r.stderr, "不该抛堆栈给用户看"


def test_ticket_tool_warns_on_unsafe_permissions(cfg):
    """权限不安全时拒绝签发并说明怎么修。"""
    import os

    os.chmod(cfg, 0o644)
    r = run_ticket(cfg)
    assert r.returncode == 2
    assert "chmod 600" in r.stderr, "应给出修复命令"


def test_new_ticket_invalidates_old(cfg):
    """重跑命令会作废旧链接 —— 这是刻意的（防重放）。

    但也正因为这个行为，面板启动日志里的链接在看门狗重启后可能失效，
    所以必须用独立工具签发。这条测试把这个因果钉住。
    """
    import re

    r1 = run_ticket(cfg)
    t1 = re.search(r"/_open\?t=([A-Za-z0-9_-]+)", r1.stdout).group(1)
    r2 = run_ticket(cfg)
    t2 = re.search(r"/_open\?t=([A-Za-z0-9_-]+)", r2.stdout).group(1)

    assert t1 != t2
    s = Store(cfg)
    assert s.consume_login_ticket(t1) is False, "旧票据应已失效"
    assert s.consume_login_ticket(t2) is True, "新票据应可用"


def test_ticket_tool_does_not_leak_panel_token(cfg):
    """打印内容不能含面板口令本身。"""
    r = run_ticket(cfg)
    assert "panel-token-for-test-only" not in r.stdout
    assert "panel-token-for-test-only" not in r.stderr


# ══════════════════ 跨进程一致性（真 bug 回归） ══════════════════


def test_store_sees_external_write(cfg):
    """另一个进程写了文件，本实例必须能读到。

    这是踩过的真 bug：ticket 工具（独立进程）签发票据写入 .env，
    但面板进程的 Store 还拿着启动时的内存缓存，
    于是「工具说链接有效、面板说票据无效」——用户点开链接进不去。

    修法是按 mtime 自动重载。这条测试钉住它。

    注意断言方式：走**公开读接口**（get / consume_login_ticket），
    而不是直接读 _cache —— 后者是内部实现，且不触发重载检查。
    真实面板代码也是走公开接口的。
    """
    import time as _t

    panel_store = Store(cfg)          # 模拟面板进程持有的实例
    panel_store.set_many({"WS_PANEL_TOKEN": "panel-token-for-test-only-0123456789"})
    # 确认此刻没有票据
    assert panel_store.get("WS_LOGIN_TICKET_HASH", "") == ""

    # 另一个进程写票据（直接改文件，不经过 panel_store）
    r = run_ticket(cfg)
    assert r.returncode == 0, r.stderr

    # 让节流窗口过期（STAT_INTERVAL = 0.5s）
    _t.sleep(0.6)
    # panel_store 必须能看到新票据
    assert panel_store.get("WS_LOGIN_TICKET_HASH", "") != "", \
        "Store 没感知到外部写入 —— 跨进程缓存不一致"


def test_consume_ticket_written_by_other_process(cfg):
    """完整复现用户路径：工具签发 → 面板校验通过。"""
    import re
    import time as _t

    panel_store = Store(cfg)
    panel_store.set_many({"WS_PANEL_TOKEN": "panel-token-for-test-only-0123456789"})

    r = run_ticket(cfg)
    ticket = re.search(r"/_open\?t=([A-Za-z0-9_-]+)", r.stdout).group(1)

    _t.sleep(0.6)   # 越过节流窗口
    assert panel_store.consume_login_ticket(ticket) is True, \
        "面板没能校验另一个进程签发的票据（用户会看到链接失效）"


def test_reload_is_throttled(cfg):
    """节流生效：短时间内的多次读不该反复 stat。"""
    s = Store(cfg)
    s._last_stat = 0.0
    s.get("WS_PANEL_TOKEN")          # 第一次会 stat
    first = s._last_stat
    s.get("WS_PANEL_TOKEN")          # 立刻再读，应被节流
    assert s._last_stat == first, "节流没生效（每次读都 stat）"
