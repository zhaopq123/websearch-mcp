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


# ── 死节点自愈：当前节点死了就换（2026-10-14）──────────────────────
# 回归背景：实测节点 6a03d7d5（韩国）在池里仍 alive=1 且均延迟最优，
# 但它已死 —— smart_failover 认为「当前仍最优」不换，服务卡死节点上，
# 所有走代理的墙外引擎全挂 → 用户拿到 server_busy。重选原本只发生
# 在 hunt 轮（数百秒一次），太慢。这里锁定 recover_dead_node 的行为。


class _Gate3:
    def __init__(self, bypassed: bool, enabled: bool = True):
        self.enabled = enabled
        self.state = type("S", (), {"bypassed": bypassed})()
        self.restored = 0

    def restore(self):
        self.restored += 1
        self.state.bypassed = False


class _NodePool3:
    DEAD_STREAK = 3

    def __init__(self):
        self.recorded: list[tuple[str, bool]] = []

    def record_probe(self, fp, ok, ms=0):
        self.recorded.append((fp, bool(ok)))

    def best(self, only_alive=True):
        return {"fp": "new1"}


class _Pool3:
    def __init__(self, bypassed: bool, enabled: bool = True,
                 probe_ok: bool = False):
        self.gate = _Gate3(bypassed, enabled)
        self.attached: str | None = None
        self.probe_ok = probe_ok
        self.probed = 0

    async def attach_proxy(self, url: str) -> bool:
        self.attached = url
        return True

    async def probe_proxy(self) -> bool:
        self.probed += 1
        return self.probe_ok


class _Hunter3:
    def __init__(self, cur: str | None, switch_ok: bool = True):
        self.pool = _NodePool3()
        self.state = type("S", (), {"current_node_fp": cur})()
        self.switched = False
        self._switch_ok = switch_ok

    async def smart_failover(self, *, switch_cb=None):
        if switch_cb is not None and not await switch_cb({"tag": "n"}):
            return {"switched": False, "reason": "切换失败"}
        self.switched = True
        return {"switched": True, "fp": "new1", "reason": "切到 香港 5227ms"}


def _svc3(*, bypassed: bool, on_pool: bool = True, cur: str | None = "dead1",
           hunter: bool = True, enabled: bool = True,
           probe_ok: bool = False) -> Service:
    s = Service.__new__(Service)
    s.local_proxy = _LP()
    s._user_proxy_url = ""
    s._on_node_pool = on_pool
    s._last_node_recover_mono = 0.0
    s.pool = _Pool3(bypassed, enabled, probe_ok)
    s.hunter = _Hunter3(cur) if hunter else None
    return s


def test_recover_dead_node_switches_when_bypassed():
    """探针确认当前节点已死 → 标死旧节点并换新节点。"""
    s = _svc3(bypassed=True, cur="dead1", probe_ok=False)
    assert asyncio.run(s.recover_dead_node()) is True
    assert s.hunter.switched is True
    # 旧节点被标死 DEAD_STREAK 次，否则 best() 仍会选它
    assert s.hunter.pool.recorded == [("dead1", False)] * 3
    assert s.pool.attached == "http://127.0.0.1:17892"


def test_recover_dead_node_false_positive_restores():
    """旁路是误报（探针经代理可达）→ 撤销旁路，不换节点。

    实测：慢目标站的 ReadTimeout 也命中 _is_proxy_failure，代理明明通
    却攒够 5 次进了旁路。若按旁路信号直接换节点，会把好节点误标死。
    """
    s = _svc3(bypassed=True, probe_ok=True)
    assert asyncio.run(s.recover_dead_node()) is False
    assert s.hunter.switched is False
    assert s.hunter.pool.recorded == []
    assert s.pool.gate.restored == 1


def test_recover_dead_node_noop_when_healthy():
    """代理健康（未旁路）→ 不动，避免无谓重启代理。"""
    s = _svc3(bypassed=False)
    assert asyncio.run(s.recover_dead_node()) is False
    assert s.hunter.switched is False
    assert s.hunter.pool.recorded == []


def test_recover_dead_node_noop_when_not_on_pool():
    """未挂在节点池上（例如走用户代理）→ 不动作。"""
    s = _svc3(bypassed=True, on_pool=False)
    assert asyncio.run(s.recover_dead_node()) is False
    assert s.hunter.switched is False


def test_recover_dead_node_noop_when_gate_disabled():
    """gate 未启用（没配任何代理）→ 不动作。"""
    s = _svc3(bypassed=True, enabled=False)
    assert asyncio.run(s.recover_dead_node()) is False


def test_recover_dead_node_cooldown():
    """同一坏节点在冷却窗口内不反复换节点（防抖）。"""
    s = _svc3(bypassed=True, probe_ok=False)
    assert asyncio.run(s.recover_dead_node()) is True
    s.hunter.switched = False
    assert asyncio.run(s.recover_dead_node()) is False   # 冷却内
    assert s.hunter.switched is False


def test_recover_dead_node_no_hunter_noop():
    """猎手初始化失败 → 安全返回 False。"""
    s = _svc3(bypassed=True, hunter=False)
    assert asyncio.run(s.recover_dead_node()) is False
