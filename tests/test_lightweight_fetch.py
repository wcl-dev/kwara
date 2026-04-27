"""Tests for lightweight_fetch.fetch_html_only().

Mocks ``requests.get`` so unit tests run offline. Real-world behaviour
is verified by the end-to-end QSH smoke after this commit lands.
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from db import get_conn, init_db, migrate_db
from lightweight_fetch import (
    CAPTURE_METHOD_HTTP_ONLY,
    MAX_HTML_BYTES,
    fetch_html_only,
    fetch_html_only_batch,
)


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _make_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _make_case(conn):
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("t", "", now, now),
    )
    return cur.lastrowid


def _add_scan_run(conn, case_id, original_url, final_url) -> int:
    """Add post + url_artifact + done scan_run; return scan_run_id."""
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, original_url, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, original_url, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, now, final_url),
    )
    conn.commit()
    return cur.lastrowid


def _fake_response(body: bytes, status_code: int = 200):
    """Build a MagicMock that imitates requests.Response for streaming reads."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.iter_content = MagicMock(return_value=iter([body]))
    resp.raise_for_status = MagicMock(
        side_effect=(requests.exceptions.HTTPError(response=resp) if status_code >= 400 else None)
    )
    return resp


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

@patch("lightweight_fetch.requests.get")
def test_successful_fetch_writes_html_and_extracts_pixel(mock_get):
    conn = _make_db()
    case_id = _make_case(conn)
    sr_id = _add_scan_run(conn, case_id, "http://x/a", "https://target.com/")

    html = b"<script>fbq('init', '1234567890123456');</script>"
    mock_get.return_value.__enter__ = lambda s: s
    mock_get.return_value.__exit__  = lambda *_: None
    mock_get.return_value = _fake_response(html)

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute(
        "SELECT html_path, capture_status, capture_method, "
        "tracking_ids_json, screenshot_path, har_path "
        "FROM snapshots WHERE id = ?", (sid,),
    ).fetchone()
    assert row["capture_status"]   == "ok"
    assert row["capture_method"]   == CAPTURE_METHOD_HTTP_ONLY
    assert row["screenshot_path"]  is None  # no Playwright
    assert row["har_path"]         is None  # no HAR
    assert row["html_path"]        is not None
    assert os.path.isfile(row["html_path"])
    ids = json.loads(row["tracking_ids_json"])
    assert ids == {"Meta Pixel": ["1234567890123456"]}


@patch("lightweight_fetch.requests.get")
def test_no_pixel_in_html_writes_null_tracking_ids(mock_get):
    conn = _make_db()
    case_id = _make_case(conn)
    sr_id = _add_scan_run(conn, case_id, "http://x/a", "https://target.com/")
    mock_get.return_value = _fake_response(b"<html><body>No tracking</body></html>")

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute(
        "SELECT capture_status, tracking_ids_json FROM snapshots WHERE id = ?",
        (sid,),
    ).fetchone()
    assert row["capture_status"] == "ok"
    assert row["tracking_ids_json"] is None


# ---------------------------------------------------------------------------
# Failure paths — each should still create a snapshot row recording the failure
# ---------------------------------------------------------------------------

@patch("lightweight_fetch.requests.get")
def test_timeout_records_timeout_status(mock_get):
    conn = _make_db()
    case_id = _make_case(conn)
    sr_id = _add_scan_run(conn, case_id, "http://x/a", "https://target.com/")
    mock_get.side_effect = requests.exceptions.Timeout()

    sid = fetch_html_only(conn, sr_id, timeout=5)
    row = conn.execute(
        "SELECT capture_status, capture_detail, html_path, tracking_ids_json "
        "FROM snapshots WHERE id = ?", (sid,),
    ).fetchone()
    assert row["capture_status"] == "timeout"
    assert "5s" in (row["capture_detail"] or "")
    assert row["html_path"]        is None
    assert row["tracking_ids_json"] is None


@patch("lightweight_fetch.requests.get")
def test_http_error_records_error_status(mock_get):
    conn = _make_db()
    case_id = _make_case(conn)
    sr_id = _add_scan_run(conn, case_id, "http://x/a", "https://target.com/")
    mock_get.return_value = _fake_response(b"forbidden", status_code=403)

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute(
        "SELECT capture_status, capture_detail FROM snapshots WHERE id = ?",
        (sid,),
    ).fetchone()
    assert row["capture_status"] == "error"
    assert "403" in (row["capture_detail"] or "")


@patch("lightweight_fetch.requests.get")
def test_connection_error_records_error_status(mock_get):
    conn = _make_db()
    case_id = _make_case(conn)
    sr_id = _add_scan_run(conn, case_id, "http://x/a", "https://target.com/")
    mock_get.side_effect = requests.exceptions.ConnectionError("DNS failed")

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute(
        "SELECT capture_status, capture_detail FROM snapshots WHERE id = ?",
        (sid,),
    ).fetchone()
    assert row["capture_status"] == "error"
    assert "DNS" in (row["capture_detail"] or "")


# ---------------------------------------------------------------------------
# Body cap
# ---------------------------------------------------------------------------

@patch("lightweight_fetch.requests.get")
def test_response_capped_at_max_bytes(mock_get):
    conn = _make_db()
    case_id = _make_case(conn)
    sr_id = _add_scan_run(conn, case_id, "http://x/a", "https://target.com/")
    # Stream returns 3 chunks adding up to MAX + 100 KB
    huge = b"x" * (MAX_HTML_BYTES + 100 * 1024)
    resp = MagicMock(spec=requests.Response)
    resp.iter_content = MagicMock(return_value=iter([
        huge[:MAX_HTML_BYTES // 2],
        huge[MAX_HTML_BYTES // 2:MAX_HTML_BYTES],
        huge[MAX_HTML_BYTES:],
    ]))
    resp.raise_for_status = MagicMock(return_value=None)
    mock_get.return_value = resp

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute("SELECT html_path FROM snapshots WHERE id = ?", (sid,)).fetchone()
    assert os.path.getsize(row["html_path"]) == MAX_HTML_BYTES


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_missing_scan_run_id_raises():
    conn = _make_db()
    _make_case(conn)
    with pytest.raises(ValueError, match="not found"):
        fetch_html_only(conn, 99999)


def test_scan_run_with_null_final_url_raises():
    conn = _make_db()
    case_id = _make_case(conn)
    # Insert a scan_run with final_url=NULL
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'http://x/a', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, NULL, 0, 'running')",
        (ua_id, now),
    )
    conn.commit()
    sr_id = cur.lastrowid
    with pytest.raises(ValueError, match="no final_url"):
        fetch_html_only(conn, sr_id)


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

@patch("lightweight_fetch.requests.get")
def test_batch_continues_after_per_url_failure(mock_get):
    """One URL fails (timeout), others succeed — batch returns all snapshot
    ids and doesn't abort."""
    conn = _make_db()
    case_id = _make_case(conn)
    sr_a = _add_scan_run(conn, case_id, "http://x/a", "https://a.com/")
    sr_b = _add_scan_run(conn, case_id, "http://x/b", "https://b.com/")
    sr_c = _add_scan_run(conn, case_id, "http://x/c", "https://c.com/")

    def fake(url, **kw):
        if "b.com" in url:
            raise requests.exceptions.Timeout()
        return _fake_response(b"<p>ok</p>")
    mock_get.side_effect = fake

    sids = fetch_html_only_batch(conn, [sr_a, sr_b, sr_c])
    assert len(sids) == 3  # all three rows created (b's is a status='timeout' row)
    statuses = {
        conn.execute("SELECT capture_status FROM snapshots WHERE id = ?", (s,)).fetchone()["capture_status"]
        for s in sids
    }
    assert statuses == {"ok", "timeout"}


# ---------------------------------------------------------------------------
# Migration regression
# ---------------------------------------------------------------------------

def test_capture_method_column_exists_and_backfilled():
    """db.migrate_db should add capture_method and backfill old rows to 'playwright'."""
    conn = _make_db()
    case_id = _make_case(conn)
    # Insert a 'legacy' snapshot with no capture_method
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'http://x/a', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, 'https://a.com/', 0, 'done')",
        (ua_id, now),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, captured_at, capture_status)
           VALUES (?, 'https://a.com/', ?, 'ok')""",
        (sr_id, now),
    )
    # Force capture_method back to NULL to simulate pre-migration row
    conn.execute("UPDATE snapshots SET capture_method = NULL")
    conn.commit()

    # Re-run migrate
    migrate_db(conn)

    row = conn.execute("SELECT capture_method FROM snapshots").fetchone()
    assert row["capture_method"] == "playwright"
