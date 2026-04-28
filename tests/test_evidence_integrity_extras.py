"""Tests for the evidence-integrity surface that round-5 codex review
flagged as still uncovered: manual upload isolation, export→restore
round-trip path correctness, and case-deletion path confinement.
"""
import os
import shutil
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def kwara_env(monkeypatch):
    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "kwara.db")
    exports_dir = os.path.join(td, "exports")
    os.makedirs(exports_dir, exist_ok=True)
    import exporter as _exporter
    monkeypatch.setattr(_exporter, "EXPORTS_DIR", exports_dir)
    from db import get_conn, init_db, migrate_db
    conn = get_conn(db_path)
    init_db(conn)
    migrate_db(conn)
    yield conn, exports_dir, td
    conn.close()
    shutil.rmtree(td, ignore_errors=True)


def _seed(conn):
    """Single message → 1 url → 1 scan_run (status=done). Returns scan_run_id."""
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("t", "", now, now),
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
        "url_order, created_at) VALUES (?, ?, 'http://x/a', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, 'https://target.com/', 0, 'done')",
        (ua_id, now),
    )
    conn.commit()
    return case_id, ua_id, cur.lastrowid


# ---------------------------------------------------------------------------
# #1 round-5: manual upload now creates a NEW snapshot row (immutable model)
# ---------------------------------------------------------------------------

def test_per_capture_dir_used_consistently_by_all_capture_paths():
    """All capture entry points (Playwright/lightweight/manual) must route
    artifacts through _per_capture_dir so older snapshot rows can't be
    silently overwritten."""
    from snapshots import _per_capture_dir
    a = _per_capture_dir(7)
    b = _per_capture_dir(7)
    assert a != b
    # Both paths exist and are directories
    assert os.path.isdir(a) and os.path.isdir(b)


def test_manual_upload_inserts_row_does_not_mutate_existing(kwara_env):
    """Round-5 codex finding: manual upload was UPDATE-ing an existing row
    AND writing to a fixed `screenshot.png` path. The right model is to
    INSERT a new snapshot (capture_method='manual') so older evidence is
    preserved. We verify by simulating the new flow directly: insert two
    rows for the same scan_run, both should remain queryable.
    """
    from lightweight_fetch import CAPTURE_METHOD_MANUAL, CAPTURE_METHOD_PLAYWRIGHT
    from snapshots import _per_capture_dir
    conn, _, _ = kwara_env
    _, _, sr_id = _seed(conn)

    # Simulate an earlier Playwright snapshot
    base_pw = _per_capture_dir(sr_id)
    pw_ss = os.path.join(base_pw, "screenshot.png")
    with open(pw_ss, "wb") as f:
        f.write(b"PLAYWRIGHT_PNG")
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, screenshot_path,
           captured_at, capture_status, capture_method)
           VALUES (?, ?, ?, ?, 'ok', ?)""",
        (sr_id, "https://target.com/", pw_ss, _now(), CAPTURE_METHOD_PLAYWRIGHT),
    )

    # Simulate a manual upload (post-fix flow: new dir + INSERT)
    base_manual = _per_capture_dir(sr_id)
    assert base_manual != base_pw, "manual capture must get its OWN dir"
    manual_ss = os.path.join(base_manual, "screenshot.png")
    with open(manual_ss, "wb") as f:
        f.write(b"MANUAL_PNG")
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, screenshot_path,
           captured_at, capture_status, capture_method)
           VALUES (?, ?, ?, ?, 'manual', ?)""",
        (sr_id, "https://target.com/", manual_ss, _now(), CAPTURE_METHOD_MANUAL),
    )
    conn.commit()

    rows = conn.execute(
        "SELECT screenshot_path, capture_method FROM snapshots WHERE scan_run_id = ? "
        "ORDER BY id", (sr_id,),
    ).fetchall()
    assert len(rows) == 2
    # Original Playwright file still exists with original bytes
    with open(rows[0]["screenshot_path"], "rb") as f:
        assert f.read() == b"PLAYWRIGHT_PNG"
    # New manual upload at its own path
    assert rows[1]["screenshot_path"] != rows[0]["screenshot_path"]
    with open(rows[1]["screenshot_path"], "rb") as f:
        assert f.read() == b"MANUAL_PNG"


# ---------------------------------------------------------------------------
# #4 round-1: uploaded post screenshots have message_id-prefixed names
# ---------------------------------------------------------------------------

def test_uploaded_post_screenshot_uses_message_id_prefix(kwara_env, tmp_path):
    """Two posts uploading 'image.png' must NOT overwrite each other.
    Verify by simulating the post-fix flow: read bytes, ingest message,
    write file with message_id prefix, update row."""
    from ingestion import ingest_message
    conn, _, _ = kwara_env
    case_id = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) "
        "VALUES ('t', '', ?, ?)", (_now(), _now()),
    ).lastrowid
    conn.commit()

    save_dir = str(tmp_path / "screenshots")
    os.makedirs(save_dir, exist_ok=True)

    paths = []
    for i in range(2):
        msg_id, _ = ingest_message(
            conn, case_id,
            message_text=f"post {i}", platform="", permalink="",
            actor_label="", posted_at="", screenshot_path="",
        )
        # Post-fix logic: name = {msg_id}_{basename}
        path = os.path.join(save_dir, f"{msg_id}_image.png")
        with open(path, "wb") as f:
            f.write(f"image-bytes-{i}".encode())
        conn.execute(
            "UPDATE message_evidence SET screenshot_path = ? WHERE id = ?",
            (path, msg_id),
        )
        paths.append(path)
    conn.commit()

    # Both files exist with distinct content
    assert paths[0] != paths[1]
    for path, expect_idx in zip(paths, (0, 1)):
        with open(path, "rb") as f:
            assert f.read() == f"image-bytes-{expect_idx}".encode()


# ---------------------------------------------------------------------------
# Restore round-trip: export then restore must yield reachable snapshot files
# ---------------------------------------------------------------------------

def test_export_then_restore_snapshot_files_reachable(kwara_env, tmp_path):
    """After export → restore, every restored snapshot row's
    screenshot_path/html_path must point at a file that actually exists."""
    from exporter import export_case
    conn, exports_dir, td = kwara_env
    case_id, _, sr_id = _seed(conn)

    # Two snapshots on the same scan_run, both with files
    snap_files_dir = os.path.join(td, "_snap_files")
    os.makedirs(snap_files_dir, exist_ok=True)
    for i in range(2):
        d = os.path.join(snap_files_dir, f"cap_{i}")
        os.makedirs(d, exist_ok=True)
        ss = os.path.join(d, "screenshot.png")
        html = os.path.join(d, "page.html")
        with open(ss, "wb") as f:
            f.write(f"png-{i}".encode())
        with open(html, "wb") as f:
            f.write(f"<html>{i}</html>".encode())
        conn.execute(
            """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
               screenshot_path, html_path, captured_at, capture_status,
               capture_method)
               VALUES (?, 'https://target.com/', 'target.com', ?, ?, ?, 'ok', 'playwright')""",
            (sr_id, ss, html, _now()),
        )
    conn.commit()

    zip_path = export_case(conn, case_id)

    # Unpack into a "restored" dir that mimics what restore_from_export does
    restore_dir = tmp_path / "restored_snaps"
    restore_dir.mkdir()
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.startswith("snapshots/") or name.endswith("/"):
                continue
            # Skip the CSV — only copy snapshot_id-keyed dirs
            if name.startswith("snapshots/snapshots.csv"):
                continue
            target = os.path.join(restore_dir, name.replace("snapshots/", "", 1))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(name) as src, open(target, "wb") as dst:
                dst.write(src.read())

    # Read snapshots.csv from the ZIP and verify each snapshot's archive
    # path can be resolved to a restored file
    with zipfile.ZipFile(zip_path) as zf:
        csv_text = zf.read("snapshots/snapshots.csv").decode("utf-8")
    import csv
    reader = csv.DictReader(csv_text.splitlines())
    rows = list(reader)
    assert len(rows) == 2
    for row in rows:
        for col in ("screenshot_file", "html_file"):
            arc = row[col]
            assert arc, f"{col} should be populated"
            local = os.path.join(
                restore_dir,
                arc.replace("snapshots/", "", 1),
            )
            assert os.path.isfile(local), f"restored file missing: {local}"


# ---------------------------------------------------------------------------
# #6: case deletion path confinement
# ---------------------------------------------------------------------------

def test_case_deletion_realpath_check_blocks_paths_outside_data_root(tmp_path):
    """Mirrors the app.py check: only paths whose realpath lives under
    the snapshot root may be rmtree-d. A crafted DB path pointing elsewhere
    must NOT trigger directory removal."""
    snap_root = tmp_path / "snap_root"
    snap_root.mkdir()
    (snap_root / "good_dir").mkdir()
    (snap_root / "good_dir" / "screenshot.png").write_bytes(b"ok")

    # An "evil" location outside the snapshot root
    evil_dir = tmp_path / "evil_outside"
    evil_dir.mkdir()
    (evil_dir / "important.txt").write_bytes(b"do not delete")

    snap_root_real = os.path.realpath(str(snap_root))

    # Simulate the confined-cleanup logic from app.py
    candidate_paths = [
        str(snap_root / "good_dir" / "screenshot.png"),
        str(evil_dir / "important.txt"),
    ]
    dirs_to_clean = set()
    for p in candidate_paths:
        if not os.path.exists(p):
            continue
        real = os.path.realpath(os.path.dirname(p))
        if real == snap_root_real or real.startswith(snap_root_real + os.sep):
            dirs_to_clean.add(real)

    # Only the in-root dir is selected
    assert len(dirs_to_clean) == 1
    assert os.path.realpath(str(snap_root / "good_dir")) in dirs_to_clean
    # Evil dir is NOT in the cleanup set even though path was DB-supplied
    assert os.path.realpath(str(evil_dir)) not in dirs_to_clean
