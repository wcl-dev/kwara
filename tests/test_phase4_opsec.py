"""Phase 4.3 — OPSEC profile (lightweight vs Playwright success-rate diff).

QSH 2026-04-28 patterns:
  visitor-landing.example    100% lw / 100% pw  → low
  hub-site.example    16% lw / 100% pw  → strong (UA gate)
  satellite-site.example   0% lw / 100% pw  → strong (UA gate, samples sparse)
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import datetime, timezone

import pytest

from kwara.db import get_conn, init_db, migrate_db
from kwara.opsec import compute_opsec_profile


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _seed_case(conn) -> int:
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES ('t', '', ?, ?)",
        (_now(), _now()),
    )
    return cur.lastrowid


def _add_snapshot(conn, case_id: int, domain: str, method: str, status: str):
    """Convenience: message → url_artifact → scan_run → snapshot, all wired
    by foreign keys, so compute_opsec_profile sees a real row."""
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, _now()),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, ?, 0, ?)",
        (pid, case_id, f"http://{domain}/", domain, _now()),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, _now(), f"http://{domain}/"),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_method, capture_status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sr_id, f"http://{domain}/", domain, _now(), method, status),
    )
    conn.commit()


def _row_for(out, domain):
    matches = [r for r in out if r["domain"] == domain]
    assert len(matches) == 1, f"expected exactly one row for {domain}"
    return matches[0]


# ---------------------------------------------------------------------------
# QSH-style positive cases
# ---------------------------------------------------------------------------

def test_strong_ua_gate_when_playwright_succeeds_lightweight_fails():
    """The hubsite / satellitesite pattern: lightweight blocked, Playwright works."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    # 10 Playwright captures all OK, 10 lightweight all error
    for _ in range(10):
        _add_snapshot(conn, case_id, "hub-site.example", "playwright", "ok")
        _add_snapshot(conn, case_id, "hub-site.example", "http_only", "error")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "hub-site.example")
    assert row["pw_ok"] == 10 and row["pw_total"] == 10
    assert row["lw_ok"] == 0 and row["lw_total"] == 10
    assert row["level"] == "strong"
    assert row["diff_above_50"] is True


def test_low_when_both_paths_succeed():
    """visitor-landing.example pattern: site doesn't gate UA at all."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    for _ in range(5):
        _add_snapshot(conn, case_id, "visitor-landing.example", "playwright", "ok")
        _add_snapshot(conn, case_id, "visitor-landing.example", "http_only", "ok")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "visitor-landing.example")
    assert row["level"] == "low"
    assert row["diff_above_50"] is False


def test_medium_when_lightweight_partially_succeeds():
    """20-70% lightweight success rate and >=70% Playwright = medium."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    # Playwright: 5/5 ok; lightweight: 2/5 ok (40%)
    for _ in range(5):
        _add_snapshot(conn, case_id, "partial.com", "playwright", "ok")
    for status in ("ok", "ok", "error", "error", "error"):
        _add_snapshot(conn, case_id, "partial.com", "http_only", status)
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "partial.com")
    assert row["level"] == "medium"


def test_indeterminate_when_only_one_path_has_data():
    conn = _fresh_db()
    case_id = _seed_case(conn)
    for _ in range(5):
        _add_snapshot(conn, case_id, "onepath.com", "playwright", "ok")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "onepath.com")
    assert row["level"] == "indeterminate"
    assert row["lw_total"] == 0


def test_indeterminate_when_playwright_itself_fails():
    """If Playwright itself only succeeds <70%, we can't read OPSEC level
    off the lightweight side — environmental flakiness dominates."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    # pw 4/10 = 40% (below 70 threshold)
    for status in (["ok"] * 4 + ["error"] * 6):
        _add_snapshot(conn, case_id, "flaky.com", "playwright", status)
    for _ in range(10):
        _add_snapshot(conn, case_id, "flaky.com", "http_only", "ok")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "flaky.com")
    assert row["level"] == "indeterminate"


# ---------------------------------------------------------------------------
# OK_STATES coverage
# ---------------------------------------------------------------------------

def test_wayback_and_manual_count_as_ok():
    """Analyst rescued via Wayback / manual upload — those still count
    as OPSEC=passed for the purpose of this view (the URL is reachable
    in some form)."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _add_snapshot(conn, case_id, "rescued.com", "playwright", "wayback")
    _add_snapshot(conn, case_id, "rescued.com", "playwright", "manual")
    _add_snapshot(conn, case_id, "rescued.com", "playwright", "ok")
    _add_snapshot(conn, case_id, "rescued.com", "http_only", "ok")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "rescued.com")
    assert row["pw_ok"] == 3 and row["pw_total"] == 3
    assert row["lw_ok"] == 1 and row["lw_total"] == 1


def test_capture_method_manual_is_excluded_from_counters():
    """Manual upload doesn't carry UA-gate signal — must be excluded
    from both lw and pw counters."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _add_snapshot(conn, case_id, "x.com", "manual", "manual")
    _add_snapshot(conn, case_id, "x.com", "playwright", "ok")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "x.com")
    assert row["pw_total"] == 1
    assert row["lw_total"] == 0


def test_no_snapshots_returns_empty_list():
    conn = _fresh_db()
    case_id = _seed_case(conn)
    assert compute_opsec_profile(conn, case_id) == []


def test_output_is_sorted_by_domain():
    conn = _fresh_db()
    case_id = _seed_case(conn)
    for d in ("z.com", "a.com", "m.com"):
        _add_snapshot(conn, case_id, d, "playwright", "ok")
    out = compute_opsec_profile(conn, case_id)
    assert [r["domain"] for r in out] == ["a.com", "m.com", "z.com"]


# ── why a verdict is missing ───────────────────────────────────────────────
# OPSEC compares two collection paths that are filled by DIFFERENT commands:
# `run attribute` does the lightweight fetch, `run snapshot` drives Playwright.
# A case that ran only one can never produce a level, and measured 2026-08-06,
# five of six cases in the QSH DB were entirely indeterminate for exactly that
# reason with nothing anywhere saying so. A silent "indeterminate" reads as
# "we looked and found nothing" when the truth is "we never collected half".

def test_missing_playwright_is_reported_as_the_reason():
    conn = _fresh_db(); cid = _seed_case(conn)
    _add_snapshot(conn, cid, "a.com", "http_only", "ok")
    row = compute_opsec_profile(conn, cid)[0]
    assert row["level"] == "indeterminate"
    assert row["indeterminate_reason"] == "no_playwright"


def test_missing_lightweight_is_reported_as_the_reason():
    conn = _fresh_db(); cid = _seed_case(conn)
    _add_snapshot(conn, cid, "a.com", "playwright", "ok")
    row = compute_opsec_profile(conn, cid)[0]
    assert row["indeterminate_reason"] == "no_lightweight"


def test_unreliable_playwright_is_a_collection_problem_not_an_observation():
    """When the browser path itself fails there is no baseline to compare
    against, so the verdict says nothing about the site."""
    conn = _fresh_db(); cid = _seed_case(conn)
    _add_snapshot(conn, cid, "a.com", "http_only", "ok")
    for _ in range(3):
        _add_snapshot(conn, cid, "a.com", "playwright", "error")
    row = compute_opsec_profile(conn, cid)[0]
    assert row["level"] == "indeterminate"
    assert row["indeterminate_reason"] == "playwright_unreliable"


def test_a_real_verdict_carries_no_reason():
    conn = _fresh_db(); cid = _seed_case(conn)
    _add_snapshot(conn, cid, "a.com", "http_only", "ok")
    _add_snapshot(conn, cid, "a.com", "playwright", "ok")
    row = compute_opsec_profile(conn, cid)[0]
    assert row["level"] == "low"
    assert row["indeterminate_reason"] is None


def test_insights_reports_the_uncollected_path_as_a_gap():
    """The reason has to reach the analyst, not just the OPSEC rows."""
    from kwara.insights import case_insights
    conn = _fresh_db(); cid = _seed_case(conn)
    _add_snapshot(conn, cid, "a.com", "http_only", "ok")
    _add_snapshot(conn, cid, "b.com", "http_only", "ok")
    gaps = " ".join(case_insights(conn, cid)["gaps"])
    assert "OPSEC" in gaps and "**2**" in gaps


def test_no_opsec_gap_when_both_paths_ran():
    from kwara.insights import case_insights
    conn = _fresh_db(); cid = _seed_case(conn)
    _add_snapshot(conn, cid, "a.com", "http_only", "ok")
    _add_snapshot(conn, cid, "a.com", "playwright", "ok")
    assert not [g for g in case_insights(conn, cid)["gaps"] if "OPSEC" in g]
