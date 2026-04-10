"""CLI: run pending snapshots for first case.

Usage:
  python _run_pending.py
  KWARA_MAX_SNAPSHOT_BATCHES=1 python _run_pending.py   # first batch only (smoke test)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from config import DB_PATH as DB
from db import get_conn, migrate_db
from pipeline import run_snapshot_batch
from snapshots import (
    CAPTURE_OK, CAPTURE_MANUAL, CAPTURE_WAYBACK,
    CAPTURE_CF, CAPTURE_ERROR, CAPTURE_TIMEOUT, CAPTURE_FILE_MISSING,
)

MAX_BATCHES = int(os.environ.get("KWARA_MAX_SNAPSHOT_BATCHES", "999999"))


def main():
    conn = get_conn(DB)
    migrate_db(conn)
    case_id = conn.execute("SELECT id FROM cases ORDER BY id LIMIT 1").fetchone()
    if not case_id:
        print("No cases.")
        return
    case_id = case_id[0]
    # Latest snapshot per scan_run only. Pending = no row, explicit failure status,
    # or legacy row (capture_status NULL) with missing/empty screenshot file.
    rows = conn.execute(
        """
        SELECT sr.id AS scan_run_id, s.id AS snap_id, s.capture_status, s.screenshot_path
        FROM url_artifacts ua
        JOIN scan_runs sr ON sr.id = (
            SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1
        )
        LEFT JOIN snapshots s ON s.scan_run_id = sr.id
            AND s.id = (
                SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1
            )
        WHERE ua.case_id = ?
        ORDER BY sr.id
        """,
        (case_id,),
    ).fetchall()
    pending = []
    for r in rows:
        st = r["capture_status"]
        sp = r["screenshot_path"]
        if r["snap_id"] is None:
            pending.append(r["scan_run_id"])
            continue
        if st in (CAPTURE_OK, CAPTURE_MANUAL, CAPTURE_WAYBACK):
            continue
        if st in (CAPTURE_CF, CAPTURE_ERROR, CAPTURE_TIMEOUT, CAPTURE_FILE_MISSING):
            pending.append(r["scan_run_id"])
            continue
        # legacy NULL status: need resnapshot only if file missing
        if st is None or st == "":
            if sp and os.path.isfile(sp) and os.path.getsize(sp) > 0:
                continue
            pending.append(r["scan_run_id"])
            continue
        pending.append(r["scan_run_id"])
    print(f"Case {case_id}: {len(pending)} pending snapshot(s)", flush=True)
    if not pending:
        return
    if MAX_BATCHES < 999999:
        print(f"(limit: first {MAX_BATCHES} batch(es) only)", flush=True)
    BATCH = 5
    all_ids = []
    batch_num = 0
    for i in range(0, len(pending), BATCH):
        if batch_num >= MAX_BATCHES:
            print("Stopped at batch limit.", flush=True)
            break
        batch_num += 1
        batch = pending[i : i + BATCH]
        print(
            f"Batch {i // BATCH + 1}: scan_run_ids {batch[0]}..{batch[-1]} ({len(batch)} URLs)",
            flush=True,
        )
        sids = run_snapshot_batch(conn, batch)
        all_ids.extend(sids)
        print(f"  -> {len(sids)} snapshot row(s) inserted", flush=True)
    print(f"Done. Total snapshots this run: {len(all_ids)}", flush=True)


if __name__ == "__main__":
    main()
