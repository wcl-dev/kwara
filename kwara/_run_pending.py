"""CLI: drain pending snapshots across all cases.

Usage:
  python _run_pending.py
  python _run_pending.py --case-id 3                   # one specific case
  KWARA_MAX_SNAPSHOT_BATCHES=1 python _run_pending.py  # first batch only (smoke test)

Round-6 codex finding: the prior version only handled the first case
(`ORDER BY id LIMIT 1`); subsequent cases were never drained. It also
didn't reclaim 'running' scan_runs left behind by crashed workers, so
URLs blocked on those rows could never advance.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from config import DB_PATH as DB
from db import get_conn, migrate_db
from pipeline import run_snapshot_batch
from scanner import reclaim_stuck_scans
from snapshots import (
    CAPTURE_OK, CAPTURE_MANUAL, CAPTURE_WAYBACK,
    CAPTURE_CF, CAPTURE_ERROR, CAPTURE_TIMEOUT, CAPTURE_FILE_MISSING,
)

MAX_BATCHES = int(os.environ.get("KWARA_MAX_SNAPSHOT_BATCHES", "999999"))


def _pending_scan_run_ids(conn, case_id: int) -> list[int]:
    """Latest snapshot per scan_run only. Pending = no row, explicit
    failure status, or legacy row (capture_status NULL) with missing/empty
    screenshot file."""
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
    pending: list[int] = []
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
    return pending


def _drain_case(conn, case_id: int, batch_budget: int) -> tuple[int, int]:
    """Drain pending snapshots for one case. Returns (snapshot_count,
    batches_used). batch_budget caps how many batches this case may use."""
    pending = _pending_scan_run_ids(conn, case_id)
    print(f"Case {case_id}: {len(pending)} pending snapshot(s)", flush=True)
    if not pending or batch_budget <= 0:
        return (0, 0)
    BATCH = 5
    snap_count = 0
    batches_used = 0
    for i in range(0, len(pending), BATCH):
        if batches_used >= batch_budget:
            print(f"  case {case_id}: stopped at batch budget {batch_budget}", flush=True)
            break
        batches_used += 1
        batch = pending[i : i + BATCH]
        print(
            f"  case {case_id} batch {batches_used}: scan_run_ids "
            f"{batch[0]}..{batch[-1]} ({len(batch)} URLs)",
            flush=True,
        )
        sids = run_snapshot_batch(conn, batch)
        snap_count += len(sids)
        print(f"    -> {len(sids)} snapshot row(s) inserted", flush=True)
    return (snap_count, batches_used)


def main():
    conn = get_conn(DB)
    migrate_db(conn)

    # Reclaim crashed-worker rows so blocked URLs become eligible again
    reclaimed = reclaim_stuck_scans(conn)
    if reclaimed:
        print(f"Reclaimed {reclaimed} stuck scan_run(s) (lease expired)", flush=True)

    # Optional: --case-id N to only drain one case
    target_case_id: int | None = None
    if "--case-id" in sys.argv:
        idx = sys.argv.index("--case-id")
        try:
            target_case_id = int(sys.argv[idx + 1])
        except (IndexError, ValueError):
            print("usage: --case-id <int>")
            sys.exit(2)

    if target_case_id is not None:
        case_ids = [target_case_id]
    else:
        case_ids = [
            r["id"] for r in conn.execute(
                "SELECT id FROM cases ORDER BY id"
            ).fetchall()
        ]
    if not case_ids:
        print("No cases.")
        return
    if MAX_BATCHES < 999999:
        print(f"(limit: first {MAX_BATCHES} batch(es) total across all cases)", flush=True)

    total_snapshots = 0
    remaining = MAX_BATCHES
    for cid in case_ids:
        snap_count, used = _drain_case(conn, cid, batch_budget=remaining)
        total_snapshots += snap_count
        remaining -= used
        if remaining <= 0:
            print("Stopped at total batch limit.", flush=True)
            break
    print(f"Done. Total snapshots this run: {total_snapshots}", flush=True)


if __name__ == "__main__":
    main()
