"""Phase 4.3 — OPSEC profile (lightweight vs Playwright success-rate diff).

QSH 2026-04-28 patterns:
  maimai.pro    100% lw / 100% pw  → low
  picelse.com    16% lw / 100% pw  → strong (UA gate)
  luckyelse.com   0% lw / 100% pw  → strong (UA gate, samples sparse)
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import datetime, timezone

import pytest

from db import get_conn, init_db, migrate_db
from opsec import compute_opsec_profile


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
    """The picelse / luckyelse pattern: lightweight blocked, Playwright works."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    # 10 Playwright captures all OK, 10 lightweight all error
    for _ in range(10):
        _add_snapshot(conn, case_id, "picelse.com", "playwright", "ok")
        _add_snapshot(conn, case_id, "picelse.com", "http_only", "error")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "picelse.com")
    assert row["pw_ok"] == 10 and row["pw_total"] == 10
    assert row["lw_ok"] == 0 and row["lw_total"] == 10
    assert row["level"] == "strong"
    assert row["diff_above_50"] is True


def test_low_when_both_paths_succeed():
    """maimai.pro pattern: site doesn't gate UA at all."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    for _ in range(5):
        _add_snapshot(conn, case_id, "maimai.pro", "playwright", "ok")
        _add_snapshot(conn, case_id, "maimai.pro", "http_only", "ok")
    out = compute_opsec_profile(conn, case_id)
    row = _row_for(out, "maimai.pro")
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
