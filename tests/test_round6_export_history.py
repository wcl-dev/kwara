"""Round-6 codex review — exporter must preserve full scan_run history.

The bug: a URL that has been rescanned has multiple scan_runs in the DB,
but the old exporter only flattened the *latest* scan_run into urls.csv.
Snapshots from earlier scan_runs were still included in the ZIP — they
referenced scan_run_ids that the restore step would never insert. With
PRAGMA foreign_keys=ON the restore would fail; even without FK
enforcement, the older redirect chains and HAR / tracking IDs were
silently lost.

These tests pin the v2 export schema:
  - urls/scan_runs.csv contains every scan_run for the case
  - urls/chains/scan_run_{sr_id}_hops.csv (one per scan_run, not per url)
  - snapshots.csv carries tracking_ids_json + capture_method + har_file
  - HAR file packed at snapshots/{snapshot_id}/network.har

Plus the actual round-trip: export → restore → no FK violations,
every scan_run / redirect chain / snapshot survives intact.
"""
from __future__ import annotations

import csv
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

import pytest


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.fixture
def kwara_env(monkeypatch):
    td = tempfile.mkdtemp()
    db_path = os.path.join(td, "kwara.db")
    exports_dir = os.path.join(td, "exports")
    os.makedirs(exports_dir, exist_ok=True)
    from kwara import exporter as _exporter
    monkeypatch.setattr(_exporter, "EXPORTS_DIR", exports_dir)
    from kwara.db import get_conn, init_db, migrate_db
    conn = get_conn(db_path)
    init_db(conn)
    migrate_db(conn)
    yield conn, exports_dir, td
    conn.close()
    shutil.rmtree(td, ignore_errors=True)


def _seed_rescan(conn, td):
    """Single URL, two scan_runs (old + new rescan), each with its own
    redirect chain + snapshot. Returns (case_id, [sr_id_old, sr_id_new],
    [snap_id_old, snap_id_new]).
    """
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, '', ?, ?)",
        ("rescan-case", now, now),
    )
    case_id = cur.lastrowid
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, 'fb', '', 'actor', '', 'msg', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'http://x/a', 'x', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid

    sr_ids = []
    snap_ids = []
    snap_files_dir = os.path.join(td, "_snap")
    os.makedirs(snap_files_dir, exist_ok=True)
    for i, (final_url, ga_id) in enumerate(
        [("https://target.example/v1", "G-OLD123"),
         ("https://target.example/v2", "G-NEW456")]
    ):
        cur = conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
            "VALUES (?, ?, ?, 1, 'done')",
            (ua_id, now, final_url),
        )
        sr_id = cur.lastrowid
        sr_ids.append(sr_id)
        # Distinct redirect chain per scan_run
        conn.execute(
            """INSERT INTO redirect_hops
               (scan_run_id, hop_order, url, status_code, location, resolved_url, fetched_at)
               VALUES (?, 0, ?, 302, ?, ?, ?)""",
            (sr_id, "http://x/a", final_url, final_url, now),
        )
        # Distinct snapshot per scan_run with HAR + tracking ID
        d = os.path.join(snap_files_dir, f"sr_{sr_id}")
        os.makedirs(d, exist_ok=True)
        ss = os.path.join(d, "screenshot.png")
        html = os.path.join(d, "page.html")
        har = os.path.join(d, "network.har")
        with open(ss, "wb") as f:
            f.write(f"png-{i}".encode())
        with open(html, "wb") as f:
            f.write(f"<html>{ga_id}</html>".encode())
        with open(har, "wb") as f:
            f.write(f'{{"har":"sr-{sr_id}"}}'.encode())
        cur = conn.execute(
            """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
               screenshot_path, html_path, har_path,
               tracking_ids_json, capture_method,
               captured_at, capture_status)
               VALUES (?, ?, 'target.example', ?, ?, ?, ?, 'playwright', ?, 'ok')""",
            (sr_id, final_url, ss, html, har,
             f'{{"google_analytics": ["{ga_id}"]}}', now),
        )
        snap_ids.append(cur.lastrowid)
    conn.commit()
    return case_id, sr_ids, snap_ids


# ---------------------------------------------------------------------------
# Schema pins — what v2 exports look like
# ---------------------------------------------------------------------------

def test_export_writes_scan_runs_csv_with_full_history(kwara_env):
    from kwara.exporter import export_case
    conn, _exports, td = kwara_env
    case_id, sr_ids, _snaps = _seed_rescan(conn, td)
    zip_path = export_case(conn, case_id)

    with zipfile.ZipFile(zip_path) as zf:
        assert "urls/scan_runs.csv" in zf.namelist()
        rows = list(csv.DictReader(
            zf.read("urls/scan_runs.csv").decode("utf-8-sig").splitlines()
        ))
    ids_in_csv = {int(r["id"]) for r in rows}
    assert ids_in_csv == set(sr_ids), \
        f"expected both scan_runs in csv, got {ids_in_csv}"


def test_export_writes_per_scan_run_redirect_chains(kwara_env):
    from kwara.exporter import export_case
    conn, _exports, td = kwara_env
    _case, sr_ids, _snaps = _seed_rescan(conn, td)
    zip_path = export_case(conn, _case)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
    for sr_id in sr_ids:
        arc = f"urls/chains/scan_run_{sr_id}_hops.csv"
        assert arc in names, f"missing {arc}; have {[n for n in names if 'chains' in n]}"


def test_snapshots_csv_includes_tracking_capture_method_har(kwara_env):
    from kwara.exporter import export_case
    conn, _exports, td = kwara_env
    _case, _sr, snap_ids = _seed_rescan(conn, td)
    zip_path = export_case(conn, _case)

    with zipfile.ZipFile(zip_path) as zf:
        text = zf.read("snapshots/snapshots.csv").decode("utf-8-sig")
    rows = list(csv.DictReader(text.splitlines()))
    header = rows[0].keys() if rows else []
    assert "tracking_ids_json" in header
    assert "capture_method" in header
    assert "har_file" in header
    for r in rows:
        assert r["capture_method"] == "playwright"
        assert "google_analytics" in r["tracking_ids_json"]
        assert r["har_file"], "har_file must be populated when har_path exists"


def test_har_file_packed_under_snapshot_id_dir(kwara_env):
    from kwara.exporter import export_case
    conn, _exports, td = kwara_env
    _case, _sr, snap_ids = _seed_rescan(conn, td)
    zip_path = export_case(conn, _case)

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        for snap_id in snap_ids:
            arc = f"snapshots/{snap_id}/network.har"
            assert arc in names, f"missing {arc}"
            assert zf.read(arc).startswith(b'{"har":"sr-')


# ---------------------------------------------------------------------------
# Round-trip — the actual fix
# ---------------------------------------------------------------------------

def _restore_zip_into(zip_path: str, target_dir: str) -> str:
    """Unpack ZIP into target_dir/restored/ and run restore_from_export.py
    pointing kwara/data/ inside target_dir. Returns the restored DB path."""
    extracted = os.path.join(target_dir, "extracted")
    os.makedirs(extracted, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extracted)

    # Patch SCRIPT_DIR / DB_PATH / SNAP_DST to land inside target_dir
    import importlib
    spec = importlib.util.spec_from_file_location(
        "_restore_mod",
        os.path.join(os.path.dirname(__file__), "..", "restore_from_export.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.KWARA_DIR = os.path.join(target_dir, "kwara")
    mod.DB_PATH   = os.path.join(target_dir, "kwara", "data", "kwara.db")
    mod.SNAP_DST  = os.path.join(target_dir, "kwara", "data", "snapshots")
    mod.restore(extracted, "round-trip-test")
    return mod.DB_PATH


def test_round_trip_rescan_history_survives(kwara_env):
    """A URL with two scan_runs survives export→restore: both scan_runs,
    both redirect chains, both snapshots all reachable; FK constraint
    holds (no orphan snapshot.scan_run_id)."""
    from kwara.exporter import export_case
    conn, _exports, td = kwara_env
    case_id, sr_ids, snap_ids = _seed_rescan(conn, td)
    zip_path = export_case(conn, case_id)

    target = tempfile.mkdtemp()
    try:
        db_path = _restore_zip_into(zip_path, target)

        rconn = sqlite3.connect(db_path)
        rconn.row_factory = sqlite3.Row
        rconn.execute("PRAGMA foreign_keys = ON")

        # Both scan_runs survived
        sr_rows = rconn.execute(
            "SELECT id, final_url FROM scan_runs ORDER BY id"
        ).fetchall()
        assert {r["id"] for r in sr_rows} == set(sr_ids)
        finals = {r["final_url"] for r in sr_rows}
        assert "https://target.example/v1" in finals
        assert "https://target.example/v2" in finals

        # Both redirect chains survived, attributed to correct scan_run
        for sr_id in sr_ids:
            hops = rconn.execute(
                "SELECT url, resolved_url FROM redirect_hops WHERE scan_run_id = ?",
                (sr_id,),
            ).fetchall()
            assert len(hops) == 1, f"expected 1 hop for scan_run {sr_id}"

        # Both snapshots survived, each with its own tracking ID + capture_method
        # + valid scan_run_id (FK satisfied by definition since query succeeded)
        snap_rows = rconn.execute(
            """SELECT id, scan_run_id, tracking_ids_json, capture_method, har_path
               FROM snapshots ORDER BY id"""
        ).fetchall()
        assert len(snap_rows) == 2
        ga_ids = []
        for row in snap_rows:
            assert row["capture_method"] == "playwright"
            assert "google_analytics" in (row["tracking_ids_json"] or "")
            ga_ids.append(row["tracking_ids_json"])
            # Each snapshot's scan_run_id must point at a real scan_run row
            assert rconn.execute(
                "SELECT 1 FROM scan_runs WHERE id = ?", (row["scan_run_id"],),
            ).fetchone(), "snapshot.scan_run_id orphaned — FK would have failed"
        assert any("G-OLD123" in s for s in ga_ids)
        assert any("G-NEW456" in s for s in ga_ids)

        # HAR file copied into the restored snapshot dir
        for snap_id in snap_ids:
            har_path = os.path.join(
                target, "kwara", "data", "snapshots", str(snap_id), "network.har"
            )
            assert os.path.isfile(har_path), f"HAR not restored: {har_path}"

        rconn.close()
    finally:
        shutil.rmtree(target, ignore_errors=True)
