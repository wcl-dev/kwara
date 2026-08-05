"""讓測試能以 `kwara/` 為套件根目錄匯入模組。"""
import sys
from pathlib import Path

_KWARA = Path(__file__).resolve().parent.parent / "kwara"
_p = str(_KWARA)
if _p not in sys.path:
    sys.path.insert(0, _p)


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
    import prevalence
    monkeypatch.setattr(prevalence, "ADS_TXT_PREVALENCE_PATH",
                        "/nonexistent/kwara-test-prevalence.json")
