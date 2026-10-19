"""数据模型 —— 层与层之间只传这几个结构，不传裸 dict。

设计取舍：全部用 dataclass 而非 pydantic。
  理由：这是 IO 密集服务，每秒可能处理几十条结果，pydantic 的校验开销没必要；
  且这些结构只在进程内流转，出进程时 to_dict() 转成 JSON 即可。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class SearchResult:
    """单条搜索结果（引擎原始产出，未融合）。"""

    title: str
    url: str
    snippet: str = ""
    engine: str = ""
    rank: int = 0                 # 在该引擎结果中的位次（0 基）
    published: str = ""           # 引擎给的时间信息（raw，不解析，避免格式猜错）
    site: str = ""                # 展示用站点名（如「知乎」）
    # ── 融合阶段填充 ──
    score: float = 0.0
    engines: list[str] = field(default_factory=list)  # 命中它的所有引擎（交叉验证）
    _url_key: str = ""            # 规范化后的 URL（去重键）

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("_url_key", None)
        return d


@dataclass
class EngineOutcome:
    """一个引擎一次搜索的完整结果 —— 成败都要有据可查（痛点 #4：静默失败）。"""

    engine: str
    ok: bool
    results: list[SearchResult] = field(default_factory=list)
    error: str = ""               # 人类可读错误
    error_kind: str = ""          # timeout | blocked | parse | network | http | cancelled | unknown
    elapsed_ms: int = 0
    from_cache: bool = False
    blocked: bool = False         # 命中反爬（403/429/captcha）

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "ok": self.ok,
            "count": len(self.results),
            "error": self.error,
            "error_kind": self.error_kind,
            "elapsed_ms": self.elapsed_ms,
            "from_cache": self.from_cache,
            "blocked": self.blocked,
        }


@dataclass
class FetchResult:
    """一次网页正文抓取的结果。"""

    url: str
    ok: bool
    final_url: str = ""
    title: str = ""
    text: str = ""                # 提取后的 markdown/纯文本
    error: str = ""
    error_kind: str = ""
    status_code: int = 0
    elapsed_ms: int = 0
    bytes_read: int = 0
    from_cache: bool = False
    truncated: bool = False
    extractor: str = ""
    fetched_at: str = ""          # 抓取时刻           # trafilatura | builtin

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Budget:
    """全局时间预算。

    为什么单独抽一个类：编排层、引擎层、抓取层都要问「还剩多少时间」，
    各自算 time.time() 会漂移，而且容易漏掉「单引擎超时不能超过剩余总预算」这条约束。
    """

    __slots__ = ("total_ms", "_start")

    def __init__(self, total_ms: int):
        self.total_ms = total_ms
        self._start = time.monotonic()

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self._start) * 1000)

    @property
    def remaining_ms(self) -> int:
        return max(0, self.total_ms - self.elapsed_ms)

    @property
    def remaining_sec(self) -> float:
        return max(0.0, self.remaining_ms / 1000.0)

    @property
    def exhausted(self) -> bool:
        return self.remaining_ms <= 0

    def clamp(self, ms: int, floor_ms: int = 50) -> float:
        """把某个子超时收敛到「不超过剩余总预算」。

        floor_ms 保证不会返回 0——asyncio.wait(timeout=0) 会立刻返回空，
        导致最后一点时间窗口被浪费掉。
        """
        return max(floor_ms, min(ms, self.remaining_ms)) / 1000.0
