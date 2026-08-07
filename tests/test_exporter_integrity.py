"""Tests for evidence-pack export integrity (codex review #2 + #3).

Pins the post-fix archive layout (snapshots keyed by snapshot_id, not
scan_run_id) and the manifest self-protection / warning behaviour.
"""
import hashlib
import hmac as _hmac
import json
import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from unittest.mock import patch

import pytest


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.fixture
def kwara_env(monkeypatch):
    """Spin up a fresh kwara DB in a temp dir; redirect EXPORTS_DIR there too.

    Returns (conn, exports_dir).
    """
    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "kwara.db")
    exports_dir = os.path.join(td, "exports")
    os.makedirs(exports_dir, exist_ok=True)

    # Patch EXPORTS_DIR to the temp path so we don't pollute the repo
    from kwara import exporter as _exporter
    # exports go to a temp dir via the autouse _isolate_evidence_store fixture

    from kwara.db import get_conn, init_db, migrate_db
    conn = get_conn(db_path)
    init_db(conn)
    migrate_db(conn)
    yield conn, exports_dir, td

    conn.close()
    shutil.rmtree(td, ignore_errors=True)


def _make_case_with_snapshot(conn, td, *, snapshot_count: int = 1):
    """Create case + 1 message + 1 url + 1 scan_run + N snapshots.

    Each snapshot writes distinct screenshot.png + page.html bytes
    so we can verify the archive layout doesn't lose data.

    Returns (case_id, scan_run_id, [snapshot_id, ...], expected_files).
    """
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("t", "", now, now),
    )
    case_id = cur.lastrowid
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, "post body", now),
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
        "VALUES (?, ?, 'https://target.com/', 0, 'done')",
        (ua_id, now),
    )
    sr_id = cur.lastrowid

    snapshot_dir = os.path.join(td, "snap_files")
    os.makedirs(snapshot_dir, exist_ok=True)

    snap_ids = []
    expected = {}
    for i in range(snapshot_count):
        per_dir = os.path.join(snapshot_dir, f"snap_{i}")
        os.makedirs(per_dir, exist_ok=True)
        ss_path = os.path.join(per_dir, "screenshot.png")
        html_path = os.path.join(per_dir, "page.html")
        ss_bytes = f"PNG_BYTES_FOR_SNAP_{i}".encode()
        html_bytes = f"<html>page snapshot {i}</html>".encode()
        with open(ss_path, "wb") as f:
            f.write(ss_bytes)
        with open(html_path, "wb") as f:
            f.write(html_bytes)
        cur = conn.execute(
            """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
               screenshot_path, html_path,
               captured_at, capture_status, capture_method)
               VALUES (?, 'https://target.com/', 'target.com', ?, ?, ?, 'ok', 'playwright')""",
            (sr_id, ss_path, html_path, now),
        )
        snap_id = cur.lastrowid
        snap_ids.append(snap_id)
        expected[snap_id] = (ss_bytes, html_bytes)
    conn.commit()
    return case_id, sr_id, snap_ids, expected


# ---------------------------------------------------------------------------
# Archive layout — codex review #2
# ---------------------------------------------------------------------------

def test_export_archive_keys_snapshots_by_snapshot_id_not_scan_run(kwara_env):
    """Two snapshots on the same scan_run must each get their own archive
    directory keyed by snapshot.id — older content cannot be overwritten."""
    from kwara.exporter import export_case
    conn, exports_dir, td = kwara_env
    case_id, sr_id, snap_ids, expected = _make_case_with_snapshot(
        conn, td, snapshot_count=2,
    )
    zip_path = export_case(conn, case_id)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        # Each snapshot must be at snapshots/{snapshot_id}/
        for snap_id, (expected_ss, expected_html) in expected.items():
            ss_arc = f"snapshots/{snap_id}/screenshot.png"
            html_arc = f"snapshots/{snap_id}/page.html"
            assert ss_arc in names, f"missing {ss_arc} in {names}"
            assert html_arc in names, f"missing {html_arc}"
            with zf.open(ss_arc) as f:
                assert f.read() == expected_ss
            with zf.open(html_arc) as f:
                assert f.read() == expected_html


def test_export_csv_includes_snapshot_id_column(kwara_env):
    """snapshots.csv must expose snapshot_id so CSV rows can be cross-
    referenced to the per-snapshot archive directory."""
    from kwara.exporter import export_case
    conn, exports_dir, td = kwara_env
    case_id, _sr, snap_ids, _ = _make_case_with_snapshot(
        conn, td, snapshot_count=2,
    )
    zip_path = export_case(conn, case_id)
    with zipfile.ZipFile(zip_path) as zf:
        csv_bytes = zf.read("snapshots/snapshots.csv").decode("utf-8")
    header = csv_bytes.splitlines()[0]
    assert "snapshot_id" in header
    # Both snapshot ids should appear in the body
    body = "\n".join(csv_bytes.splitlines()[1:])
    for snap_id in snap_ids:
        assert str(snap_id) in body


# ---------------------------------------------------------------------------
# Manifest self-protection — codex review #3
# ---------------------------------------------------------------------------

def test_manifest_sha256_companion_file_present_and_correct(kwara_env):
    """Every export ZIP must include manifest.sha256 with the correct hash
    of manifest.json so reviewers can verify the manifest out-of-band."""
    from kwara.exporter import export_case
    conn, exports_dir, td = kwara_env
    case_id, _sr, _snaps, _ = _make_case_with_snapshot(conn, td)
    zip_path = export_case(conn, case_id)
    with zipfile.ZipFile(zip_path) as zf:
        manifest_bytes = zf.read("manifest.json")
        sha_line = zf.read("manifest.sha256").decode("utf-8")
    expected_sha = hashlib.sha256(manifest_bytes).hexdigest()
    assert sha_line.startswith(expected_sha)
    assert "manifest.json" in sha_line


def test_manifest_includes_integrity_warning_when_no_hmac_key(kwara_env, monkeypatch):
    """When KWARA_HMAC_KEY is unset, the manifest must say so explicitly."""
    from kwara import exporter
    monkeypatch.setattr(exporter, "HMAC_KEY", None)
    from kwara.exporter import export_case
    conn, exports_dir, td = kwara_env
    case_id, _sr, _snaps, _ = _make_case_with_snapshot(conn, td)
    zip_path = export_case(conn, case_id)
    with zipfile.ZipFile(zip_path) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        names = set(zf.namelist())
    assert "integrity_warning" in manifest
    assert "KWARA_HMAC_KEY" in manifest["integrity_warning"]
    # No sig file when key absent
    assert "manifest.sig" not in names


def test_manifest_sig_present_and_no_warning_when_hmac_key_set(kwara_env, monkeypatch):
    from kwara import exporter
    monkeypatch.setattr(exporter, "HMAC_KEY", "secret-test-key")
    from kwara.exporter import export_case
    conn, exports_dir, td = kwara_env
    case_id, _sr, _snaps, _ = _make_case_with_snapshot(conn, td)
    zip_path = export_case(conn, case_id)
    with zipfile.ZipFile(zip_path) as zf:
        manifest_bytes = zf.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        sig_payload = json.loads(zf.read("manifest.sig"))
    # Warning should NOT be present
    assert "integrity_warning" not in manifest
    # Sig should verify against manifest_bytes with the test key
    expected_sig = _hmac.new(
        b"secret-test-key", manifest_bytes, hashlib.sha256
    ).hexdigest()
    assert sig_payload["signature"] == expected_sig
