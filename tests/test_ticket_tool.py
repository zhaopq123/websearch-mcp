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


def run_ticket(cfg_path: Path, *args: str) -> subprocess.CompletedProcess:
    """以子进程方式跑 ticket 工具（模拟用户敲命令）。"""
    return subprocess.run(
        [sys.executable, "-m", "websearch.proxy.ticket",
         "--config", str(cfg_path), *args],
        capture_output=True, text=True, timeout=30,
        env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
    )


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".env"
    s = Store(p)
    s.set_many({
        "WS_PANEL_TOKEN": "panel-token-for-test-only-0123456789",
        "WS_PANEL_HOST": "0.0.0.0",
        "WS_PANEL_PORT": "8500",
    })
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
    r = run_ticket(cfg)
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
