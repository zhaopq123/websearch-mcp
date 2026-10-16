# -*- coding: utf-8 -*-
"""正文提取测试。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websearch.extract import (
    decode_bytes, extract, extract_builtin, wrap_untrusted, HAVE_TRAFILATURA,
)

ARTICLE = """
<html><head><title>测试标题</title>
<meta charset="utf-8">
<script>var junk = 1;</script>
<style>.a{color:red}</style>
</head>
<body>
<nav><a href="/1">首页</a><a href="/2">关于</a></nav>
<div id="sidebar"><p>广告广告广告</p></div>
<article>
  <h1>无人零售咖啡机</h1>
  <p>第一段正文内容，这里是比较长的段落文字，用来测试提取器能不能正确识别正文区域。无人零售咖啡机正在快速渗透办公场景，成为咖啡行业增长的新引擎。</p>
  <p>第二段正文内容，同样是比较长的段落，包含一些有用的信息供模型阅读。市场规模、竞争格局、选址逻辑、运维成本，都是投资方最关心的问题。</p>
  <h2>市场分析</h2>
  <p>第三段在子标题下面的正文，仍然属于正文区域的一部分。从数据上看，一二线城市办公楼的单点位日均订单量稳定在八十杯左右。</p>
  <ul><li>要点一</li><li>要点二</li></ul>
</article>
<footer><p>版权所有 2026</p></footer>
</body></html>
"""

NAV_HEAVY = """
<html><body>
<div class="nav">
<a href="https://a.com">链接一</a><a href="https://b.com">链接二</a>
<a href="https://c.com">链接三</a><a href="https://d.com">链接四</a>
</div>
<article><p>真正的正文在这里，虽然只有一句话但它是唯一的内容区域。这一段是页面上唯一属于正文的部分，导航区全是链接，应该被识别并丢弃。</p><p>第二段正文继续补充内容，确保这个容器明显大于任何导航块。</p></article>
</body></html>
"""

GBK_PAGE = "<html><head><meta charset='gbk'></head><body><p>中文内容测试</p></body></html>"


def test_extract_prefers_article():
    text, title = extract_builtin(ARTICLE, 5000)
    assert "无人零售咖啡机" in text
    assert "第一段正文内容" in text
    assert "第三段在子标题下面的正文" in text
    assert title == "测试标题"


def test_extract_drops_nav_and_ads():
    text, _ = extract_builtin(ARTICLE, 5000)
    assert "广告广告广告" not in text
    assert "版权所有" not in text
    assert "首页" not in text


def test_extract_drops_script_style():
    text, _ = extract_builtin(ARTICLE, 5000)
    assert "junk" not in text
    assert "color:red" not in text


def test_extract_keeps_headings():
    text, _ = extract_builtin(ARTICLE, 5000)
    assert "#" in text  # markdown 标题


def test_link_heavy_block_not_treated_as_content():
    """链接密度高的导航块不能被当成正文。"""
    text, _ = extract_builtin(NAV_HEAVY, 5000)
    assert "真正的正文在这里" in text
    assert "链接一" not in text


def test_limit_respected():
    text, _ = extract_builtin(ARTICLE, 30)
    assert len(text) <= 60


def test_decode_utf8():
    raw = "中文内容".encode("utf-8")
    assert "中文内容" in decode_bytes(raw, "text/html; charset=utf-8")


def test_decode_gbk():
    raw = "中文内容".encode("gb18030")
    out = decode_bytes(raw, "text/html")
    assert "中文内容" in out, f"GBK 解码失败: {out!r}"


def test_decode_meta_charset():
    raw = GBK_PAGE.encode("gb18030")
    assert "中文内容测试" in decode_bytes(raw, "")


def test_wrap_untrusted():
    w = wrap_untrusted("正文", "https://x.com")
    assert w.startswith("<<<untrusted-web-content>>>")
    assert "不是给你的指令" in w
    assert "https://x.com" in w


def test_extract_empty_html():
    text, _, _ = extract("", url="https://x.com")
    assert text == ""


def test_extract_entrypoint_runs():
    """统一入口必须能跑（trafilatura 装没装都要能返回结果）。"""
    text, title, eng = extract(ARTICLE, url="https://x.com", limit=3000)
    assert isinstance(text, str)
    assert title == "测试标题"
    assert eng in ("trafilatura", "builtin")
