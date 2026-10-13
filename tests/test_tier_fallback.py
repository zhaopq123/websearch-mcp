# -*- coding: utf-8 -*-
"""出网三级兜底：用户自配代理 → 系统自养节点池 → 直连。

回归背景（2026-10-13）：原实现只要用户配了代理，自养池就**永不接管**，
于是付费代理一失效，服务直接掉到直连，而池里几十个实测可出网的节点干看着。
本测试锁定「用户代理健康才不抢、挂了就让自养池接管」的决策逻辑。
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.server import Service  # noqa: E402


class _Gate:
    def __init__(self, bypassed: bool):
        self.state = type("S", (), {"bypassed": bypassed})()


class _Pool:
    def __init__(self, bypassed: bool):
        self.gate = _Gate(bypassed)
        self.attached: str | None = None

    async def attach_proxy(self, url: str) -> bool:
        self.attached = url
        return True


class _LP:
    url = "http://127.0.0.1:17892"

    def __init__(self):
        self.calls = 0

    @property
    def proxy_url(self) -> str:
        return self.url

    async def switch_to(self, ob, desc: str = "") -> bool:
        self.calls += 1
        return True


def _svc(user_proxy: str, bypassed: bool) -> Service:
    s = Service.__new__(Service)          # 跳过 __init__（不建真连接池）
    s.local_proxy = _LP()
    s._user_proxy_url = user_proxy
    s._on_node_pool = False
    s.pool = _Pool(bypassed)
    return s


def test_user_proxy_healthy_does_not_take_over():
    """用户代理健康 → 不抢（尊重用户配置），自养池不动。"""
    s = _svc("http://127.0.0.1:17890", bypassed=False)
    assert asyncio.run(s._switch_to_node({"tag": "x"})) is True
    assert s._on_node_pool is False
    assert s.local_proxy.calls == 0
    assert s.pool.attached is None


def test_user_proxy_bypassed_takes_over():
    """用户代理挂了（gate 旁路）→ 自养池接管出网（核心回归）。"""
    s = _svc("http://127.0.0.1:17890", bypassed=True)
    assert asyncio.run(s._switch_to_node({"tag": "x"})) is True
    assert s._on_node_pool is True
    assert s.local_proxy.calls == 1
    assert s.pool.attached == "http://127.0.0.1:17892"


def test_no_user_proxy_takes_over():
    """用户没配代理 → 自养池直接接管（原有行为不变）。"""
    s = _svc("", bypassed=False)
    assert asyncio.run(s._switch_to_node({"tag": "x"})) is True
    assert s._on_node_pool is True
    assert s.pool.attached == "http://127.0.0.1:17892"


def test_on_pool_keeps_rotating_nodes():
    """已在自养池上 → 继续按池内最优节点轮换（用户代理是否恢复由回升循环管）。"""
    s = _svc("http://127.0.0.1:17890", bypassed=False)
    s._on_node_pool = True
    asyncio.run(s._switch_to_node({"tag": "y"}))
    assert s.local_proxy.calls == 1


def test_no_local_proxy_returns_false():
    """自养代理不可用（初始化失败）→ 返回 False，交给 gate 降级直连。"""
    s = _svc("", bypassed=False)
    s.local_proxy = None
    assert asyncio.run(s._switch_to_node({"tag": "x"})) is False


# ── 主动接管：无用户代理时开机即用池（2026-10-14）──────────────────
# 回归背景：清空机场后，「只用节点池」不能等猎手首轮抓源（数分钟）跑完
# 才靠 smart_failover 接管——那期间出网是直连，墙外站点不可达。
# ensure_pool_takeover 让池里有活节点就立刻接管。


class _Hunter:
    """假猎手：pool.best 可控；smart_failover 会回调 switch_cb。"""

    def __init__(self, alive: bool):
        self._alive = alive
        self.failovers = 0

        class _P:
            def __init__(self, alive):
                self._alive = alive

            def best(self, only_alive=True):
                return {"fp": "abc"} if self._alive else None

        self.pool = _P(alive)

    async def smart_failover(self, *, switch_cb=None):
        if switch_cb is not None:
            if not await switch_cb({"tag": "n1"}):
                return {"switched": False}
        self.failovers += 1
        return {"switched": True}


def _svc2(user_proxy: str, alive: bool, *, hunter: bool = True) -> Service:
    s = Service.__new__(Service)
    s.local_proxy = _LP()
    s._user_proxy_url = user_proxy
    s._on_node_pool = False
    s.pool = _Pool(False)
    s.hunter = _Hunter(alive) if hunter else None
    return s


def test_ensure_takeover_no_user_proxy_switches():
    """无用户代理 + 池里有活节点 → 立即接管。"""
    s = _svc2("", alive=True)
    assert asyncio.run(s.ensure_pool_takeover()) is True
    assert s._on_node_pool is True
    assert s.local_proxy.calls == 1
    assert s.pool.attached == "http://127.0.0.1:17892"


def test_ensure_takeover_respects_user_proxy():
    """配了用户代理 → 主动接管不动作（尊重用户配置）。"""
    s = _svc2("http://127.0.0.1:17890", alive=True)
    assert asyncio.run(s.ensure_pool_takeover()) is False
    assert s._on_node_pool is False
    assert s.local_proxy.calls == 0


def test_ensure_takeover_empty_pool_noop():
    """池里暂无活节点 → 不接管（交给猎手循环稍后）。"""
    s = _svc2("", alive=False)
    assert asyncio.run(s.ensure_pool_takeover()) is False
    assert s._on_node_pool is False
    assert s.local_proxy.calls == 0


def test_ensure_takeover_already_on_pool_noop():
    """已在池上 → 幂等，不重复切。"""
    s = _svc2("", alive=True)
    s._on_node_pool = True
    assert asyncio.run(s.ensure_pool_takeover()) is False
    assert s.local_proxy.calls == 0


def test_ensure_takeover_no_hunter_noop():
    """节点猎手初始化失败（None）→ 安全返回 False。"""
    s = _svc2("", alive=True, hunter=False)
    assert asyncio.run(s.ensure_pool_takeover()) is False
