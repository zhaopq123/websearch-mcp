# -*- coding: utf-8 -*-
"""引擎解析器测试（离线，用合成 HTML）。

网站结构会变，但解析器「该提取什么」的契约不变。
这些测试保证改版/重构时不会静默退化。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.engines import (
    REGISTRY, BingEngine, BaiduMobileEngine, So360MobileEngine,
    SogouMobileEngine, WeixinEngine, DuckDuckGoEngine, MojeekEngine,
    generic_parse,
)

BING_HTML = """
<html><body><ol id="b_results">
<li class="b_algo"><h2><a href="https://ex.com/1">结果标题一</a></h2>
<p>这是摘要一的内容。</p></li>
<li class="b_algo"><h2><a href="https://ex.com/2">结果标题二</a></h2>
<p>这是摘要二的内容。</p></li>
<li class="b_ad"><h2><a href="https://ad.com">广告</a></h2></li>
</ol></body></html>
"""

BAIDU_M_HTML = """
<html><body>
<div class="c-result result" data-log='{"mu":"https://real1.com/a"}'>
<div class="c-result-content"><span class="content-link_2AXFK">百度结果一</span></div></div>
<div class="c-result result" data-log='{"mu":"https://real2.com/b"}'>
<div class="c-result-content"><span class="content-link_2AXFK">百度结果二</span></div></div>
</body></html>
"""

SO360_M_HTML = """
<html><body>
<div class="g-card res-list og" data-pcurl="https://sohu.com/a/1">
<div class="res-title">360结果一</div><p class="res-desc">摘要一</p></div>
<div class="g-card res-list og" data-pcurl="https://sohu.com/a/2">
<div class="res-title">360结果二</div><p class="res-desc">摘要二</p></div>
</body></html>
"""

SOGOU_M_HTML = """
<html><body>
<p>搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，搜狗移动版结果页的说明文字，真实页面这一段很长，</p>
<div class="vrResult"><div class="title__saTitle_287f">搜狗结果一</div>
<a href="https://sogou-target.com/1">x</a><div class="text-layout">搜狗摘要一</div></div>
<div class="vrResult"><div class="vr-tit clamp2">搜狗结果二</div>
<a href="/link?url=abc123">y</a><div class="text-layout">搜狗摘要二</div></div>
</body></html>
"""

WEIXIN_HTML = """
<html><body>
<div class="txt-box"><h3><a href="/link?url=xyz">公众号文章一</a></h3>
<p class="s-p">摘要内容一</p></div>
<div class="txt-box"><h3><a href="/link?url=abc">公众号文章二</a></h3>
<p class="txt-info">摘要内容二</p></div>
</body></html>
"""

DDG_HTML = """
<html><body>
<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fddg1.com%2Fp">DDG结果一</a>
<a class="result__snippet">DDG摘要一</a>
<a class="result__a" href="https://ddg2.com/q">DDG结果二</a>
<a class="result__snippet">DDG摘要二</a>
</body></html>
"""


def test_bing_parse():
    rs = REGISTRY["bing"].parse(BING_HTML, limit=10)
    assert len(rs) == 2, f"应解析出 2 条（广告不计），实际 {len(rs)}"
    assert rs[0].title == "结果标题一"
    assert rs[0].url == "https://ex.com/1"
    assert "摘要一" in rs[0].snippet
    assert rs[0].engine == "bing"


def test_baidu_mobile_unwraps_real_url():
    rs = REGISTRY["baidu_m"].parse(BAIDU_M_HTML, limit=10)
    assert len(rs) == 2, f"实际 {len(rs)}"
    assert rs[0].url == "https://real1.com/a", f"没解开真实 URL: {rs[0].url}"
    assert rs[0].title == "百度结果一"


def test_so360_mobile_uses_pcurl():
    rs = REGISTRY["so360_m"].parse(SO360_M_HTML, limit=10)
    assert len(rs) == 2
    assert rs[0].url == "https://sohu.com/a/1"
    assert rs[0].title == "360结果一"
    assert rs[0].snippet == "摘要一"


def test_sogou_mobile_relative_link():
    rs = REGISTRY["sogou_m"].parse(SOGOU_M_HTML, limit=10)
    assert len(rs) == 2
    assert rs[0].url == "https://sogou-target.com/1"
    assert rs[1].url == "https://m.sogou.com/link?url=abc123", rs[1].url


def test_weixin_parse():
    rs = REGISTRY["weixin"].parse(WEIXIN_HTML, limit=10)
    assert len(rs) == 2
    assert rs[0].title == "公众号文章一"
    assert rs[0].url.startswith("https://weixin.sogou.com/link")


def test_ddg_unwraps_uddg():
    rs = REGISTRY["duckduckgo"].parse(DDG_HTML, limit=10)
    assert len(rs) == 2
    assert rs[0].url == "https://ddg1.com/p", f"uddg 没解包: {rs[0].url}"
    assert rs[0].snippet == "DDG摘要一"


def test_generic_parse_needs_visible_text():
    """反爬验证页可见文本极少 → 兜底解析器必须拒绝产出（否则是把导航当结果）。"""
    thin = '<html><body><a href="https://x.com/a">关于我们</a></body></html>'
    assert generic_parse(thin, "test", 10) == []

    rich = ("<html><body><p>" + "这是一个足够长的正文内容可以用来通过可见文本门槛" * 30 +
            '</p><a href="https://real.com/article">一篇真实文章的标题在这里</a>'
            "</body></html>")
    rs = generic_parse(rich, "test", 10)
    assert len(rs) >= 1


def test_generic_parse_skips_self_noise():
    """引擎自己站点上的登录页/首页链接不能当结果。"""
    html = ("<html><body><p>" + "足够长的正文内容" * 60 +
            '</p><a href="https://passport.baidu.com/v2/?login">登录</a>'
            '<a href="https://real.com/x">真实结果标题内容足够长</a>'
            "</body></html>")
    rs = generic_parse(html, "test", 10)
    urls = [r.url for r in rs]
    assert all("passport.baidu.com" not in u for u in urls), urls


def test_all_engines_have_build_and_parse():
    for name, e in REGISTRY.items():
        spec = e.build("测试查询", count=5)
        assert spec.url.startswith("http"), f"{name} 的 URL 不合法: {spec.url}"
        assert e.weight > 0
        assert e.label
        # 空 HTML 不能崩
        assert e.parse("", limit=5) == []


def test_registry_complete():
    for expect in ("bing", "so360", "baidu_m", "sogou_m", "so360_m", "weixin",
                   "toutiao", "duckduckgo", "mojeek", "brave"):
        assert expect in REGISTRY, f"缺少引擎 {expect}"


# ══════════════ 2026-10-14 结果后过滤（全量测试复盘）══════════════


def test_is_noise_result_categories():
    """self 噪声 / 验证挑战页 / 已知仿冒站都要拦；正常结果不误伤。"""
    from websearch.engines import _is_noise_result

    # 拦：引擎自身站点非跳转壳（登录页/热搜榜）
    assert _is_noise_result("https://passport.baidu.com/v2/?login")
    assert _is_noise_result("https://top.baidu.com/board?tab=realtime")
    assert _is_noise_result("https://www.sogou.com/web?query=x")
    # 拦：cloudflare 挑战页与 cdn-cgi 路径
    assert _is_noise_result("https://challenges.cloudflare.com/turnstile")
    assert _is_noise_result("https://openai.com/_cdn-cgi/challenge-platform/x")
    # 拦：实测抓到过的仿冒站
    assert _is_noise_result("https://chatgpt-ai.com/")
    # 不拦：真实结果 + 引擎跳转壳（/link?url= 是真结果）
    assert not _is_noise_result("https://openai.com/chatgpt")
    assert not _is_noise_result("https://www.baidu.com/link?url=abc123")
    assert not _is_noise_result("https://example.com/login-help")  # 第三方登录帮助页是内容


def test_baidu_parse_output_is_filtered_by_orchestrator_layer():
    """parse 层保持纯净，噪声过滤在 orchestrator 层统一做（一处覆盖全引擎）。

    设计取舍：过滤下沉到 17 个 parse 方法里必然漏；放在 orchestrator
    解析后一步，所有引擎（含未来新增）自动获得过滤。
    """
    from websearch.engines import BaiduEngine, _is_noise_result

    e = BaiduEngine()

    def block(url: str, title: str) -> str:
        return (f'<div class="result c-container"><h3 class="t">'
                f'<a href="{url}">{title}</a></h3></div>')

    html = ("<html><body>"
            + block("https://passport.baidu.com/v2/?login", "登录百度")
            + block("https://top.baidu.com/board?tab=realtime", "百度热搜")
            + block("https://openai.com/chatgpt", "ChatGPT 官网")
            + "</body></html>")
    raw = e.parse(html, limit=10)
    # parse 层原样返回（不内置过滤）
    assert len(raw) == 3
    # orchestrator 层的过滤把噪声清掉，只留真实结果
    kept = [r for r in raw if not _is_noise_result(r.url)]
    assert [r.url for r in kept] == ["https://openai.com/chatgpt"]


def test_orchestrator_noise_filter_wiring():
    """orchestrator 模块确实 import 并使用了噪声过滤（防回归掉线）。"""
    import websearch.orchestrator as orch_mod
    from websearch.engines import _is_noise_result

    # 接线存在：模块级名字可用
    assert orch_mod._is_noise_result is _is_noise_result
    # 源码里确实出现在解析之后（而不是只 import 不用的死 import）
    src = Path(orch_mod.__file__).read_text(encoding="utf-8")
    assert "_is_noise_result(r.url)" in src


# ══════════════ 2026-10-15 国内引擎直连路由 ══════════════


def test_domestic_engines_go_direct():
    """国内引擎 needs_proxy=False（直连）——实测国内站经海外代理恒被拒。"""
    from websearch.engines import get_engine

    for name in ("baidu", "baidu_m", "so360", "so360_m", "sogou",
                 "sogou_m", "weixin", "toutiao", "bing"):
        e = get_engine(name)
        assert e is not None, f"{name} 未注册"
        assert e.needs_proxy is False, f"{name} 应直连（needs_proxy=False）"


def test_foreign_engines_need_proxy():
    """国外引擎必须走代理；bing_intl 继承 BingEngine 但不得误继承 False。"""
    from websearch.engines import get_engine

    for name in ("duckduckgo", "bing_intl"):
        e = get_engine(name)
        assert e is not None, f"{name} 未注册"
        assert e.needs_proxy is True, f"{name} 必须走代理"
