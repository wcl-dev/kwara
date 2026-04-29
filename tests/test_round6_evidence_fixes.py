"""Round-6 codex review fixes — three evidence-completeness gaps.

Each fix has one targeted regression test:

  1. scanner._headers_to_json must preserve duplicate Set-Cookie pairs
     by reading from urllib3's HTTPHeaderDict (resp.raw.headers).
     CaseInsensitiveDict folds duplicates into one comma-joined value
     and destroys per-cookie boundaries needed for cookie-domain leak
     analysis.

  2. lightweight_fetch must save body for 4xx/5xx responses (not just
     2xx). Error pages — custom 404, PHP 500 with debug info, branded
     WAF blocks — are themselves evidence for FIMI investigations.

  3. pipeline._try_corroborate must record a failure stub when
     corroborate_url() raises, instead of leaving corroboration_json
     NULL. Otherwise "never attempted" and "tried but pipeline aborted"
     are indistinguishable downstream.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from db import get_conn, init_db, migrate_db
from lightweight_fetch import fetch_html_only
from pipeline import _try_corroborate
from scanner import _headers_to_json


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _make_db() -> sqlite3.Connection:
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _add_done_scan_run(conn: sqlite3.Connection, final_url: str) -> int:
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, '', ?, ?)",
        ("t", now, now),
    )
    case_id = cur.lastrowid
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, final_url, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, now, final_url),
    )
    conn.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Fix 1: duplicate Set-Cookie survives serialization
# ---------------------------------------------------------------------------

class _MultiValueHeaders:
    """Stand-in for urllib3.HTTPHeaderDict.items() — preserves duplicates and order."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def items(self):
        return iter(self._pairs)


def test_headers_to_json_preserves_duplicate_set_cookie():
    resp = MagicMock(spec=requests.Response)
    resp.raw = MagicMock()
    resp.raw.headers = _MultiValueHeaders([
        ("Server", "nginx"),
        ("Set-Cookie", "sid=abc; Domain=.realorigin.example; HttpOnly"),
        ("Set-Cookie", "lang=zh-TW; Path=/"),
        ("X-Powered-By", "PHP/8.2"),
    ])
    # CaseInsensitiveDict path (would merge into one Set-Cookie)
    resp.headers = {"Server": "nginx", "Set-Cookie": "sid=abc, lang=zh-TW",
                    "X-Powered-By": "PHP/8.2"}

    out = _headers_to_json(resp)
    pairs = json.loads(out)
    set_cookies = [v for k, v in pairs if k.lower() == "set-cookie"]
    assert len(set_cookies) == 2, f"expected 2 separate Set-Cookie pairs, got {set_cookies}"
    assert any("Domain=.realorigin.example" in v for v in set_cookies)
    assert any("Path=/" in v for v in set_cookies)


def test_headers_to_json_falls_back_when_raw_unavailable():
    """Older test fixtures that don't set resp.raw still work via CaseInsensitiveDict."""
    resp = MagicMock(spec=requests.Response)
    resp.raw = None
    resp.headers = {"Server": "nginx"}
    out = _headers_to_json(resp)
    assert json.loads(out) == [["Server", "nginx"]]


# ---------------------------------------------------------------------------
# Fix 2: 4xx/5xx body is preserved as evidence
# ---------------------------------------------------------------------------

def _fake_response(body: bytes, status_code: int = 200):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = {}
    resp.iter_content = MagicMock(return_value=iter([body]))
    return resp


@patch("lightweight_fetch.requests.get")
def test_500_error_page_body_is_saved_as_evidence(mock_get):
    """PHP 500 with branded debug template — body must survive even though
    capture_status='error'."""
    conn = _make_db()
    sr_id = _add_done_scan_run(conn, "https://target.example/")
    body = b"<html><body>Fatal error: /var/www/realorigin/inc/db.php line 42</body></html>"
    mock_get.return_value = _fake_response(body, status_code=500)

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute(
        "SELECT capture_status, capture_detail, html_path FROM snapshots WHERE id = ?",
        (sid,),
    ).fetchone()
    assert row["capture_status"] == "error"
    assert "500" in (row["capture_detail"] or "")
    assert row["html_path"] is not None
    with open(row["html_path"], "rb") as f:
        saved = f.read()
    assert saved == body, "error-page body must be saved verbatim"


@patch("lightweight_fetch.requests.get")
def test_403_error_body_extracts_tracking_ids(mock_get):
    """Some operators leave GA loaded on the WAF block page — that's still
    a tracking-ID hit linking the block page to the same operator."""
    conn = _make_db()
    sr_id = _add_done_scan_run(conn, "https://target.example/")
    body = b'<html><script>fbq("init", "1234567890123456");</script>blocked</html>'
    mock_get.return_value = _fake_response(body, status_code=403)

    sid = fetch_html_only(conn, sr_id)
    row = conn.execute(
        "SELECT capture_status, html_path, tracking_ids_json FROM snapshots WHERE id = ?",
        (sid,),
    ).fetchone()
    assert row["capture_status"] == "error"
    assert row["html_path"] is not None
    ids = json.loads(row["tracking_ids_json"])
    assert ids == {"Meta Pixel": ["1234567890123456"]}


# ---------------------------------------------------------------------------
# Fix 3: corroboration pipeline failure leaves an audit trail
# ---------------------------------------------------------------------------

@patch("pipeline.corroborate_url")
def test_corroborate_pipeline_crash_writes_failure_stub(mock_corr):
    """When corroborate_url() itself raises (e.g. import-time crash),
    the previous code silently swallowed the exception and left
    corroboration_json NULL — indistinguishable from 'never attempted'."""
    mock_corr.side_effect = RuntimeError("network stack unavailable")
    conn = _make_db()
    sr_id = _add_done_scan_run(conn, "https://target.example/")

    _try_corroborate(conn, sr_id)

    row = conn.execute(
        "SELECT corroboration_json FROM scan_runs WHERE id = ?", (sr_id,)
    ).fetchone()
    assert row["corroboration_json"] is not None, "must record attempt, not NULL"
    payload = json.loads(row["corroboration_json"])
    assert "_pipeline_error" in payload
    assert "RuntimeError" in payload["urlscan"]["error"]
    assert "RuntimeError" in payload["wayback"]["error"]
    assert "RuntimeError" in payload["timestamp"]["error"]
    assert payload["_attempted_at"]


@patch("pipeline.corroborate_url")
def test_corroborate_success_path_unchanged(mock_corr):
    """Sanity: success path still writes the unmodified corroborate_url() return."""
    mock_corr.return_value = {
        "urlscan":   {"service": "urlscan.io",  "permalink": "https://urlscan.io/x"},
        "wayback":   {"service": "archive.org", "permalink": "https://web.archive.org/y"},
        "timestamp": {"service": "rfc3161",     "token_b64": "AAAA"},
        "corroborated_at": _now(),
    }
    conn = _make_db()
    sr_id = _add_done_scan_run(conn, "https://target.example/")

    _try_corroborate(conn, sr_id)

    row = conn.execute(
        "SELECT corroboration_json FROM scan_runs WHERE id = ?", (sr_id,)
    ).fetchone()
    payload = json.loads(row["corroboration_json"])
    assert "_pipeline_error" not in payload
    assert payload["urlscan"]["permalink"] == "https://urlscan.io/x"


def test_corroborate_skips_if_already_corroborated():
    conn = _make_db()
    sr_id = _add_done_scan_run(conn, "https://target.example/")
    conn.execute(
        "UPDATE scan_runs SET corroboration_json = ? WHERE id = ?",
        (json.dumps({"urlscan": {"permalink": "x"}}), sr_id),
    )
    conn.commit()

    with patch("pipeline.corroborate_url") as mock_corr:
        _try_corroborate(conn, sr_id)
        mock_corr.assert_not_called()
