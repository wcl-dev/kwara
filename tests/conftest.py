"""讓測試以 `kwara` 套件的方式匯入模組。

放的是 repo 根目錄，不是 `kwara/` 本身。舊版把套件目錄塞進 sys.path，讓
`from config import ...` 這種平坦 import 能運作——那是為了配合
`streamlit run kwara/app.py` 的執行方式。UI 移除後那個理由不存在了，而平坦
import 會把 config、db、graph 這些通名污染到全域 sys.path。

安裝過（`pip install -e .`）的話這裡其實不必要，但保留讓 clone 後直接跑
pytest 也能動。
"""
import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


import pytest


@pytest.fixture(autouse=True)
def _isolate_reference_prevalence(monkeypatch):
    """Keep the machine's reference-prevalence table out of the test run.

    prevalence.load() reads an optional multi-megabyte artifact that some
    machines have and others do not. Left alone, a tier assertion would pass or
    fail depending on whether this laptop happens to hold a table containing
    the fixture's account names — a test that depends on local data is not a
    test. Tests that exercise the table point the path at their own fixture.
    """
    from kwara import prevalence
    monkeypatch.setattr(prevalence, "ADS_TXT_PREVALENCE_PATH",
                        "/nonexistent/kwara-test-prevalence.json")
