# -*- coding: utf-8 -*-
"""LocalNodeProxy 启动端口竞态自愈。

回归背景（2026-10-14）：服务重启时旧实例的 sing-box 可能还没被 proot 收掉，
17892 仍被占用 → 新实例 bind 失败 → **静默掉回直连**（用户诉求是「只用节点池」，
静默降级不可接受）。修法：起前清孤儿 + 等端口释放 + 失败重试一次。
本测试用 mock 模拟「第一次起不来、第二次起来」的竞态。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.nodes.local_proxy import LocalNodeProxy  # noqa: E402


class _FakeProc:
    def __init__(self):
        self.returncode = None
        self.pid = 4242

    async def wait(self):
        self.returncode = 0
        return 0

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = 0


def _make(tmp_path, monkeypatch, ready_seq):
    lp = LocalNodeProxy(singbox_bin="/bin/sh", work_dir=tmp_path,
                        http_port=17892, socks_port=17893)

    async def fake_check(path):
        return True

    async def fake_wait_free(port, timeout=8.0):
        return True

    seq = list(ready_seq)

    async def fake_wait_port(port, timeout=8.0):
        return seq.pop(0) if seq else False

    lp._check_config = fake_check
    lp._wait_port_free = fake_wait_free
    lp._wait_port = fake_wait_port
    lp.stale_calls = 0

    async def fake_kill_stale():
        lp.stale_calls += 1

    lp._kill_stale = fake_kill_stale

    async def fake_exec(*a, **k):
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return lp


_OB = {"type": "vless", "tag": "t1",
       "server": "1.2.3.4", "server_port": 443,
       "uuid": "00000000-0000-0000-0000-000000000000"}


def test_restart_retries_and_succeeds(tmp_path, monkeypatch):
    """第一次端口未就绪 → 重试 → 第二次成功。"""
    lp = _make(tmp_path, monkeypatch, [False, True])
    ok = asyncio.run(lp._restart_with(dict(_OB), "desc"))
    assert ok is True
    assert lp.state.running is True
    assert lp.state.node_fp == "t1"
    assert lp.stale_calls == 2          # 每次尝试前都清了孤儿


def test_restart_fails_after_two_attempts(tmp_path, monkeypatch):
    """两次都起不来 → 返回 False 且 running=False（不谎报成功）。"""
    lp = _make(tmp_path, monkeypatch, [False, False])
    ok = asyncio.run(lp._restart_with(dict(_OB), "desc"))
    assert ok is False
    assert lp.state.running is False
    assert lp.stale_calls == 2


def test_kill_stale_pattern_escapes_dot(tmp_path):
    """pkill 模式必须把 . 转义成 [.]，否则会自匹配杀掉自己。"""
    lp = LocalNodeProxy(singbox_bin="/bin/sh", work_dir=tmp_path)
    pat = str(lp._cfg_path).replace(".", "[.]")
    assert "[.]json" in pat
    assert ".json" not in pat.replace("[.]json", "")   # 没有裸露的 .json
