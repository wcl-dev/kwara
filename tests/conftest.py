"""讓測試以 `kwara` 套件的方式匯入模組。

放的是 repo 根目錄，不是 `kwara/` 本身。舊版把套件目錄塞進 sys.path，讓
`from config import ...` 這種平坦 import 能運作——那是為了配合
`streamlit run kwara/app.py` 的執行方式。UI 移除後那個理由不存在了，而平坦
import 會把 config、db、graph 這些通名污染到全域 sys.path。

安裝過（`pip install -e .`）的話這裡其實不必要，但保留讓 clone 後直接跑
pytest 也能動。
"""
import os
import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


import pytest


def _enable_subprocess_coverage() -> None:
    """Make the Playwright worker's coverage countable, but only when measuring.

    _snapshot_worker.py runs in a subprocess, so its 224 statements reported 0%
    even with ten tests driving it — a number that flattered the gap and lied
    about the covered part. coverage's startup hook needs COVERAGE_PROCESS_START
    pointing at a config file; without it the child simply does not record, and
    silently. Setting it unconditionally would start coverage in every
    subprocess of every ordinary run, so it is set only when the parent is
    already measuring.
    """
    try:
        import coverage
    except ImportError:
        return
    if coverage.Coverage.current() is None:
        return
    os.environ.setdefault(
        "COVERAGE_PROCESS_START",
        str(Path(__file__).resolve().parent.parent / "pyproject.toml"))


_enable_subprocess_coverage()


# The local HTTP origin every collection test runs against. Registered here so
# `site` is available everywhere without an import: the alternative to a real
# server is mocking requests.get, which exercises the call site but never the
# behaviour that actually breaks — redirect chains, timeouts, truncation,
# content that differs by query string.
from fixtures.server import site  # noqa: F401


@pytest.fixture(autouse=True)
def _isolate_evidence_store(monkeypatch, tmp_path):
    """No test may write into the operator's real capture store.

    Before this, tests that exercised _per_capture_dir() wrote straight into
    kwara/data/snapshots/ — the live evidence tree. Measured 2026-08-07:
    13,785 capture directories on disk against 983 with a database row, and
    snapshots/99 alone held 9,807 from roughly 98 accumulated runs of a
    100-iteration loop. Their contents are fixture data — capture.json naming
    https://target.com/, HTML carrying a made-up Meta Pixel ID — sitting in
    buckets numbered like real scan_run_ids and indistinguishable on disk from
    genuine captures. delete_case only removes directories the DB lists, so
    nothing ever cleaned them up.

    Fabricated evidence in an evidence store is the one failure this tool
    cannot tolerate, so the isolation is autouse: opt-out, never opt-in.
    """
    from kwara import config
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "data" / "snapshots"))
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "data" / "exports"))


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


# ---------------------------------------------------------------------------
# The live evidence store must be exactly as we found it
# ---------------------------------------------------------------------------
#
# The suite could write into the analyst's real case store, and for months it
# did — 1,300 fabricated captures, including 14-byte files named screenshot.png
# containing the string PLAYWRIGHT_PNG. The per-test redirects below are a
# convention, and this codebase keeps discovering conventions it had quietly
# broken. So the store is measured before and after the whole session.
#
# Session-scoped rather than a test, because a test only runs where it is
# collected; a fixture finaliser runs after everything.

@pytest.fixture(scope="session")
def live_store_baseline():
    from test_live_store_untouched import _snapshot_state
    return _snapshot_state()


@pytest.fixture(scope="session", autouse=True)
def _fail_if_the_live_store_moves():
    from test_live_store_untouched import _real_paths, _snapshot_state

    paths = _real_paths()
    # No early return when the database is absent. A test that CREATES a live
    # store where there was none escapes exactly as badly as one that modifies
    # an existing one, and skipping here let that through.
    before = _snapshot_state()
    yield
    after = _snapshot_state()
    drifted = [k for k in after if before[k] != after[k]]
    if drifted:
        raise AssertionError(
            "THE TEST SUITE MODIFIED THE LIVE EVIDENCE STORE: "
            + ", ".join(drifted)
            + f"\nPaths: {paths}\n"
            "Some test wrote outside its tmp_path. Find it before committing.")
