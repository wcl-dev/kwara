"""Round-6 codex review #4 — `running` scan_runs left behind by crashed
workers must be reclaimable so the URL can re-enter the pending queue."""
from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from kwara.db import get_conn, init_db, migrate_db
from kwara.scanner import reclaim_stuck_scans


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _seed_running_scan(conn, run_at: str) -> int:
    """Insert a `running` scan_run with the given run_at timestamp.
    Returns scan_run_id."""
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
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'http://x/a', '', 0, ?)",
        (pid, case_id, _now()),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, status) VALUES (?, ?, 'running')",
        (ua_id, run_at),
    )
    conn.commit()
    return cur.lastrowid


def test_reclaim_stuck_scans_marks_expired_rows():
    """A scan_run with run_at older than the lease window is reclaimed."""
    conn = _fresh_db()
    stale = (datetime.now(tz=timezone.utc) - timedelta(hours=2)).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    sr_id = _seed_running_scan(conn, stale)

    n = reclaim_stuck_scans(conn, lease_seconds=60 * 60)
    assert n == 1
    row = conn.execute(
        "SELECT status, notes FROM scan_runs WHERE id = ?", (sr_id,),
    ).fetchone()
    assert row["status"] == "lease_expired"
    assert "auto-reclaim" in (row["notes"] or "")


def test_reclaim_stuck_scans_skips_fresh_rows():
    """A scan_run that just started must not be reclaimed."""
    conn = _fresh_db()
    fresh = _now()
    sr_id = _seed_running_scan(conn, fresh)

    n = reclaim_stuck_scans(conn, lease_seconds=60 * 60)
    assert n == 0
    row = conn.execute(
        "SELECT status FROM scan_runs WHERE id = ?", (sr_id,),
    ).fetchone()
    assert row["status"] == "running"


def test_reclaim_skips_already_finished_rows():
    """A `done` row with the same age as the lease window must not be touched."""
    conn = _fresh_db()
    stale = (datetime.now(tz=timezone.utc) - timedelta(hours=2)).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    sr_id = _seed_running_scan(conn, stale)
    conn.execute("UPDATE scan_runs SET status = 'done' WHERE id = ?", (sr_id,))
    conn.commit()

    n = reclaim_stuck_scans(conn, lease_seconds=60 * 60)
    assert n == 0
    row = conn.execute(
        "SELECT status FROM scan_runs WHERE id = ?", (sr_id,),
    ).fetchone()
    assert row["status"] == "done"


# ---------------------------------------------------------------------------
# Transport metadata (round 6 #3) — sanity that the new keys are emitted
# ---------------------------------------------------------------------------

def test_grab_tls_info_dict_shape_includes_transport_keys():
    """Round-6 #3: peer_ip, tls_version, cipher_suite, scanner_user_agent
    must be part of the tls_info_json shape. We assert only on the keys
    (full SSL handshake is exercised in QSH end-to-end testing)."""
    import inspect

    from kwara import scanner
    src = inspect.getsource(scanner._grab_tls_info)
    # The structure of the return dict — pin the new keys so a future
    # rewrite cannot silently drop transport metadata again.
    for key in ("peer_ip", "tls_version", "cipher_suite", "cipher_protocol",
                "scanner_user_agent"):
        assert f'"{key}"' in src, f"_grab_tls_info missing return key {key}"
