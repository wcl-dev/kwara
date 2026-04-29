"""Phase 4.1 — cloaking detection.

picread.net case from QSH 2026-04-28: ?uid=638 → 302 to maimai.pro;
no uid → 200 with 25KB real article. Tool now compares the two and
flags the gating logic.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

from db import get_conn, init_db, migrate_db
from cloaking import (
    BODY_SIZE_DIFF_THRESHOLD,
    _strip_tracking_params,
    detect_and_store_cloaking,
    detect_cloaking,
)


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _seed_scan_run(conn, original_url: str) -> int:
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
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, original_url, _now()),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, _now(), original_url),
    )
    conn.commit()
    return cur.lastrowid


def _resp(body: bytes, status_code: int = 200, final_url: str | None = None):
    """Mock for requests.Response yielded by requests.get(stream=True)."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.url = final_url
    resp.iter_content = MagicMock(return_value=iter([body]))
    return resp


# ---------------------------------------------------------------------------
# _strip_tracking_params
# ---------------------------------------------------------------------------

def test_strip_removes_known_tracking_params():
    url = "http://picread.net/article/277290?uid=638&page=1"
    stripped, keys = _strip_tracking_params(url)
    assert stripped == "http://picread.net/article/277290?page=1"
    assert keys == ["uid"]


def test_strip_removes_utm_prefix_keys():
    url = "http://example.com/?utm_source=fb&utm_campaign=qsh&id=42"
    stripped, keys = _strip_tracking_params(url)
    assert "utm_source" in keys and "utm_campaign" in keys
    assert "id=42" in stripped
    assert "utm_" not in stripped


def test_strip_returns_unchanged_url_when_no_tracking_params():
    url = "http://example.com/?page=1"
    stripped, keys = _strip_tracking_params(url)
    assert stripped == url
    assert keys == []


# ---------------------------------------------------------------------------
# detect_cloaking — verdicts
# ---------------------------------------------------------------------------

def test_detect_no_tracking_params_skips_comparison():
    out = detect_cloaking("http://example.com/")
    assert out == {"verdict": "no_tracking_params"}


@patch("cloaking.requests.get")
def test_detect_picread_style_redirect_cloaking(mock_get):
    """The QSH 2026-04-28 case: ?uid → 302 to maimai, no uid → 200 article."""
    def fake(url, **_):
        if "uid=" in url:
            return _resp(b"", status_code=302, final_url="https://maimai.pro/article/x")
        return _resp(b"<html>Real article content " + b"x" * 20000 + b"</html>",
                     status_code=200, final_url=url)
    mock_get.side_effect = fake

    out = detect_cloaking("http://picread.net/article/277290?uid=638")
    assert out["verdict"] == "cloaking_suspect"
    assert "status_code" in out["diffs"]
    assert "final_domain" in out["diffs"]
    assert out["with_params"]["status_code"] == 302
    assert out["with_params"]["final_domain"] == "maimai.pro"
    assert out["without_params"]["status_code"] == 200
    assert out["without_params"]["final_domain"] == "picread.net"


@patch("cloaking.requests.get")
def test_detect_no_cloaking_when_responses_match(mock_get):
    """Both fetches return identical body — must be flagged no_cloaking."""
    body = b"<html>same content</html>"
    # Each fetch needs its own iter_content iterator (a single one is
    # exhausted after the first call), so use side_effect to build a
    # fresh response per call.
    mock_get.side_effect = lambda *a, **kw: _resp(
        body, status_code=200, final_url="http://example.com/"
    )
    out = detect_cloaking("http://example.com/?utm_source=fb")
    assert out["verdict"] == "no_cloaking"
    assert out["diffs"] == []


@patch("cloaking.requests.get")
def test_detect_body_size_diff_above_threshold(mock_get):
    """Same status, same domain, but content size differs >30%."""
    def fake(url, **_):
        if "uid=" in url:
            return _resp(b"x" * 1000, status_code=200, final_url=url)
        return _resp(b"x" * 5000, status_code=200, final_url=url.replace("?uid=1", ""))
    mock_get.side_effect = fake
    out = detect_cloaking("http://example.com/?uid=1")
    assert out["verdict"] == "cloaking_suspect"
    assert "body_size" in out["diffs"]
    assert "body_content" in out["diffs"]


@patch("cloaking.requests.get")
def test_detect_body_size_diff_below_threshold_not_flagged(mock_get):
    """Tiny size variation (e.g. timestamp in HTML) shouldn't fire body_size,
    even if body_content (hash) differs."""
    def fake(url, **_):
        if "uid=" in url:
            return _resp(b"a" * 1000, status_code=200, final_url=url)
        return _resp(b"b" * 1010, status_code=200, final_url=url.replace("?uid=1", ""))
    mock_get.side_effect = fake
    out = detect_cloaking("http://example.com/?uid=1")
    assert "body_size" not in out["diffs"]
    # body_content still flagged because hashes differ
    assert "body_content" in out["diffs"]


@patch("cloaking.requests.get")
def test_detect_fetch_error_records_verdict_not_raises(mock_get):
    mock_get.side_effect = requests.exceptions.ConnectionError("DNS failed")
    out = detect_cloaking("http://example.com/?uid=1")
    assert out["verdict"] == "fetch_error"
    assert "DNS" in out["with_params"]["error"]
    assert "DNS" in out["without_params"]["error"]


# ---------------------------------------------------------------------------
# detect_and_store_cloaking — DB + audit + idempotency
# ---------------------------------------------------------------------------

@patch("cloaking.requests.get")
def test_detect_and_store_writes_json_to_scan_runs(mock_get):
    mock_get.side_effect = lambda *a, **kw: _resp(
        b"<html>", status_code=200, final_url="http://example.com/"
    )
    conn = _fresh_db()
    sr_id = _seed_scan_run(conn, "http://example.com/?uid=1")

    result = detect_and_store_cloaking(conn, sr_id)
    assert result["verdict"] in ("no_cloaking", "cloaking_suspect")

    row = conn.execute(
        "SELECT cloaking_signal_json FROM scan_runs WHERE id = ?", (sr_id,),
    ).fetchone()
    assert row["cloaking_signal_json"]
    assert json.loads(row["cloaking_signal_json"])["verdict"] == result["verdict"]


@patch("cloaking.requests.get")
def test_detect_and_store_skips_when_already_done(mock_get):
    """Pre-existing cloaking_signal_json must not be overwritten unless force=True."""
    mock_get.return_value = _resp(b"x", status_code=200, final_url="x")
    conn = _fresh_db()
    sr_id = _seed_scan_run(conn, "http://example.com/?uid=1")
    conn.execute(
        "UPDATE scan_runs SET cloaking_signal_json = ? WHERE id = ?",
        (json.dumps({"verdict": "previously_run"}), sr_id),
    )
    conn.commit()

    out = detect_and_store_cloaking(conn, sr_id)
    assert out == {"verdict": "previously_run"}
    mock_get.assert_not_called()


@patch("cloaking.requests.get")
def test_detect_and_store_force_reruns(mock_get):
    mock_get.side_effect = lambda *a, **kw: _resp(
        b"x", status_code=200, final_url="http://example.com/"
    )
    conn = _fresh_db()
    sr_id = _seed_scan_run(conn, "http://example.com/?uid=1")
    conn.execute(
        "UPDATE scan_runs SET cloaking_signal_json = ? WHERE id = ?",
        (json.dumps({"verdict": "stale"}), sr_id),
    )
    conn.commit()

    detect_and_store_cloaking(conn, sr_id, force=True)
    assert mock_get.called
    new_payload = json.loads(conn.execute(
        "SELECT cloaking_signal_json FROM scan_runs WHERE id = ?", (sr_id,),
    ).fetchone()["cloaking_signal_json"])
    assert new_payload["verdict"] != "stale"


def test_detect_and_store_returns_none_for_missing_scan_run():
    conn = _fresh_db()
    assert detect_and_store_cloaking(conn, 99999) is None
