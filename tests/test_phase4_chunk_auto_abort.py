"""Phase 4.4 — chunk failure-rate auto-abort.

If N consecutive batches of >=MIN_CHUNK_SIZE URLs all fail above the
configured threshold, the run aborts (exit 3) so the analyst can
diagnose the environment instead of letting a 16-min batch silently
fail end-to-end (the QSH 2026-04-28 incident).
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from kwara import _run_pending as rp
from kwara.db import get_conn, init_db, migrate_db


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _seed_case_with_n_urls(conn, n: int) -> tuple[int, list[int]]:
    """Returns (case_id, [scan_run_id, ...]) — scan_runs marked 'done'
    with no snapshot yet (so they're 'pending'). Snapshot rows will be
    inserted by the test directly to control capture_status outcomes."""
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES ('t', '', ?, ?)",
        (_now(), _now()),
    )
    case_id = cur.lastrowid
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, _now()),
    )
    pid = cur.lastrowid
    sr_ids = []
    for i in range(n):
        cur = conn.execute(
            "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
            "url_order, created_at) VALUES (?, ?, ?, '', ?, ?)",
            (pid, case_id, f"http://x/{i}", i, _now()),
        )
        ua_id = cur.lastrowid
        cur = conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
            "VALUES (?, ?, ?, 0, 'done')",
            (ua_id, _now(), f"https://target.com/{i}"),
        )
        sr_ids.append(cur.lastrowid)
    conn.commit()
    return case_id, sr_ids


def _insert_snapshot(conn, sr_id: int, capture_status: str) -> int:
    cur = conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, captured_at, capture_status)
           VALUES (?, 'https://target.com/', ?, ?)""",
        (sr_id, _now(), capture_status),
    )
    conn.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# _chunk_failure_rate
# ---------------------------------------------------------------------------

def test_chunk_failure_rate_all_ok():
    conn = _fresh_db()
    _, sr_ids = _seed_case_with_n_urls(conn, 5)
    sids = [_insert_snapshot(conn, sr, "ok") for sr in sr_ids]
    ok, total, rate = rp._chunk_failure_rate(conn, sids)
    assert (ok, total, rate) == (5, 5, 0.0)


def test_chunk_failure_rate_majority_failed():
    conn = _fresh_db()
    _, sr_ids = _seed_case_with_n_urls(conn, 5)
    sids = []
    sids.append(_insert_snapshot(conn, sr_ids[0], "ok"))
    for sr in sr_ids[1:]:
        sids.append(_insert_snapshot(conn, sr, "error"))
    ok, total, rate = rp._chunk_failure_rate(conn, sids)
    assert ok == 1
    assert total == 5
    assert rate == 0.8


def test_chunk_failure_rate_wayback_counts_as_ok():
    """Wayback fallback rescued the URL — analyst still gets evidence."""
    conn = _fresh_db()
    _, sr_ids = _seed_case_with_n_urls(conn, 3)
    sids = [_insert_snapshot(conn, sr_ids[0], "ok"),
            _insert_snapshot(conn, sr_ids[1], "wayback"),
            _insert_snapshot(conn, sr_ids[2], "manual")]
    ok, total, rate = rp._chunk_failure_rate(conn, sids)
    assert (ok, total, rate) == (3, 3, 0.0)


def test_chunk_failure_rate_empty_list():
    conn = _fresh_db()
    assert rp._chunk_failure_rate(conn, []) == (0, 0, 0.0)


# ---------------------------------------------------------------------------
# _drain_case abort behaviour
# ---------------------------------------------------------------------------

@patch("kwara._run_pending.run_snapshot_batch")
def test_drain_case_aborts_after_n_consecutive_bad_chunks(mock_batch, monkeypatch):
    """Two chunks of 5 URLs each, both fail at 100% → SystemExit(3)."""
    monkeypatch.setattr(rp, "FAILURE_THRESHOLD", 0.5)
    monkeypatch.setattr(rp, "FAILURE_CHUNKS", 2)
    monkeypatch.setattr(rp, "MIN_CHUNK_SIZE", 5)

    conn = _fresh_db()
    case_id, sr_ids = _seed_case_with_n_urls(conn, 10)

    # Each call to run_snapshot_batch inserts 5 'error' snapshots and
    # returns their ids (matches the real function's contract).
    def fake_batch(_conn, batch):
        return [_insert_snapshot(_conn, sr, "error") for sr in batch]
    mock_batch.side_effect = fake_batch

    with pytest.raises(SystemExit) as exc:
        rp._drain_case(conn, case_id, batch_budget=10)
    assert exc.value.code == rp.ENV_ABORTED_EXIT_CODE


@patch("kwara._run_pending.run_snapshot_batch")
def test_drain_case_does_not_abort_when_one_bad_followed_by_ok(mock_batch, monkeypatch):
    """Single bad chunk then a recovery chunk → must NOT abort
    (consecutive_bad resets to 0)."""
    monkeypatch.setattr(rp, "FAILURE_THRESHOLD", 0.5)
    monkeypatch.setattr(rp, "FAILURE_CHUNKS", 2)
    monkeypatch.setattr(rp, "MIN_CHUNK_SIZE", 5)

    conn = _fresh_db()
    case_id, sr_ids = _seed_case_with_n_urls(conn, 10)

    call_state = {"n": 0}
    def fake_batch(_conn, batch):
        call_state["n"] += 1
        # First batch all error, second batch all ok
        status = "error" if call_state["n"] == 1 else "ok"
        return [_insert_snapshot(_conn, sr, status) for sr in batch]
    mock_batch.side_effect = fake_batch

    snap_count, used, consecutive_bad = rp._drain_case(
        conn, case_id, batch_budget=10,
    )
    assert used == 2
    assert snap_count == 10
    assert consecutive_bad == 0  # second chunk was clean → reset


@patch("kwara._run_pending.run_snapshot_batch")
def test_drain_case_ignores_small_chunks_for_threshold(mock_batch, monkeypatch):
    """A small tail batch (< MIN_CHUNK_SIZE) failing must NOT count
    toward consecutive_bad — covers the 'leftover 2 URLs' tail case."""
    monkeypatch.setattr(rp, "FAILURE_THRESHOLD", 0.5)
    monkeypatch.setattr(rp, "FAILURE_CHUNKS", 1)  # very strict
    monkeypatch.setattr(rp, "MIN_CHUNK_SIZE", 5)

    conn = _fresh_db()
    case_id, sr_ids = _seed_case_with_n_urls(conn, 2)  # only 2 URLs

    def fake_batch(_conn, batch):
        return [_insert_snapshot(_conn, sr, "error") for sr in batch]
    mock_batch.side_effect = fake_batch

    # Should NOT raise, even though all 2 URLs failed (chunk too small)
    snap_count, used, consecutive_bad = rp._drain_case(
        conn, case_id, batch_budget=10,
    )
    assert used == 1
    assert snap_count == 2
    assert consecutive_bad == 0
