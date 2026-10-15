# -*- coding: utf-8 -*-
"""来源权威度分级测试（2026-10-15）。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from websearch.authority import domain_authority


@pytest.mark.parametrize("url,lo,hi", [
    # 高权威
    ("https://www.gov.cn/zhengce/x.html", 0.9, 1.01),
    ("https://www.tsinghua.edu.cn/xx", 0.9, 1.01),
    ("http://www.xinhuanet.com/politics/2026.html", 0.9, 1.01),
    ("https://arxiv.org/abs/2401.00001", 0.9, 1.01),
    ("https://www.nature.com/articles/x", 0.9, 1.01),
    # 权威
    ("https://www.thepaper.cn/newsDetail_forward_1", 0.5, 0.7),
    ("https://36kr.com/p/123", 0.5, 0.7),
    ("https://news.qq.com/rain/a/20261014A0CS8100", 0.5, 0.7),
    ("https://zh.wikipedia.org/wiki/x", 0.5, 0.7),
    ("https://docs.python.org/3/", 0.5, 0.7),
    ("https://github.com/psf/requests", 0.5, 0.7),
    # 低质
    ("https://blog.csdn.net/x/article/details/1", -0.7, -0.5),
    ("https://juejin.cn/post/767", -0.7, -0.5),
    ("https://www.zhihu.com/question/1", -0.7, -0.5),
    ("https://aikitapp.com/zh/weekly/china-ai/", -0.7, -0.5),
    ("https://wenku.baidu.com/view/x.html", -0.7, -0.5),
    ("https://someshop.top/item/1", -0.7, -0.5),
    # 中性
    ("https://example.com/page", -0.01, 0.01),
])
def test_authority_levels(url, lo, hi):
    v = domain_authority(url)
    assert lo <= v <= hi, f"{url} -> {v}（期望 {lo}~{hi}）"


def test_authority_accepts_bare_host():
    assert domain_authority("xinhuanet.com") >= 0.9
    assert domain_authority("csdn.net") <= -0.5


def test_authority_never_crashes_on_junk():
    for bad in ("", "not a url", "http://", "https://"):
        assert isinstance(domain_authority(bad), float)
