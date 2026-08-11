"""CLI: drain pending snapshots across all cases.

Usage:
  python _run_pending.py
  python _run_pending.py --case-id 3                   # one specific case
  KWARA_MAX_SNAPSHOT_BATCHES=1 python _run_pending.py  # first batch only (smoke test)

Environment:
  KWARA_FAILURE_THRESHOLD  per-batch failure-rate ceiling (default 0.5)
  KWARA_FAILURE_CHUNKS     consecutive bad chunks before abort (default 2)
  KWARA_MIN_CHUNK_SIZE     batch must have at least N URLs to count
                           toward the failure-rate budget (default 5)

Round-6 codex finding: the prior version only handled the first case
(`ORDER BY id LIMIT 1`); subsequent cases were never drained. It also
didn't reclaim 'running' scan_runs left behind by crashed workers, so
URLs blocked on those rows could never advance.

ROADMAP 4.4: chunk failure-rate auto-abort. If N consecutive chunks all
fail at >threshold rate, the run aborts (exit 3) so the analyst can
diagnose the environment instead of letting a 16-min batch silently
fail end-to-end.
"""
import os
import sys


from .config import DB_PATH as DB
from .db import get_conn, migrate_db
from .pipeline import run_snapshot_batch
from .scanner import reclaim_stuck_scans
from .snapshots import CAPTURE_OK, CAPTURE_MANUAL, CAPTURE_WAYBACK

MAX_BATCHES       = int(os.environ.get("KWARA_MAX_SNAPSHOT_BATCHES", "999999"))
FAILURE_THRESHOLD = float(os.environ.get("KWARA_FAILURE_THRESHOLD", "0.5"))
FAILURE_CHUNKS    = int(os.environ.get("KWARA_FAILURE_CHUNKS", "2"))
MIN_CHUNK_SIZE    = int(os.environ.get("KWARA_MIN_CHUNK_SIZE", "5"))

ENV_ABORTED_EXIT_CODE = 3


def _pending_scan_run_ids(conn, case_id: int) -> list[int]:
    """Pending = `sql.browser_capture_exists` is not satisfied, plus the one
    case SQL cannot decide: a legacy row (capture_status NULL) that satisfies
    the predicate on paper but whose screenshot file is missing or empty on
    disk. Only this module can check that, because only this module is allowed
    to touch the filesystem.

    2026-08-08: the browser-free pass writes an http_only row with
    capture_status='ok' and no screenshot; as the newest row it made every
    scanned URL look captured and drained nothing.
    2026-08-11: the definition moved to sql.py. This module had excluded only
    'http_only', so `cloaking_alt` — the crawler-facing persona — satisfied it
    here while failing the same check in cli.py.
    """
    rows = conn.execute(
        """
        SELECT sr.id AS scan_run_id,
               s.capture_method, s.capture_status, s.screenshot_path
        FROM url_artifacts ua
        JOIN scan_runs sr ON sr.id = (
            SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1
        )
        LEFT JOIN snapshots s ON s.scan_run_id = sr.id
        WHERE ua.case_id = ?
        ORDER BY sr.id, s.id
        """,
        (case_id,),
    ).fetchall()

    order: list[int] = []
    seen: set[int] = set()
    satisfied: set[int] = set()
    for r in rows:
        sid = r["scan_run_id"]
        if sid not in seen:
            seen.add(sid)
            order.append(sid)
        if _row_satisfies(r["capture_method"], r["capture_status"],
                          r["screenshot_path"]):
            satisfied.add(sid)
    return [sid for sid in order if sid not in satisfied]


def _row_satisfies(method, status, screenshot_path) -> bool:
    """One snapshot row's answer to `sql.browser_capture_exists`.

    A strict refinement of it: identical except that a legacy row (written
    before capture_status existed) is trusted only when its screenshot is
    really on disk. SQL can check that a path was recorded; it cannot check
    that the file survived. test_capture_predicate.py pins the two together
    so the refinement stays a refinement and does not drift into a difference.
    """
    if status in (CAPTURE_MANUAL, CAPTURE_WAYBACK):
        return True
    if method == "playwright" and status == CAPTURE_OK:
        return True
    # Unmigrated row: db.py backfills a NULL method to 'playwright'.
    if method is None and status == CAPTURE_OK:
        return True
    if status in (None, "") and method not in ("http_only", "cloaking_alt"):
        return bool(screenshot_path
                    and os.path.isfile(screenshot_path)
                    and os.path.getsize(screenshot_path) > 0)
    return False




def _chunk_failure_rate(conn, snapshot_ids: list[int]) -> tuple[int, int, float]:
    """Returns (success_count, total_count, failure_rate) for the given
    just-inserted snapshot rows. capture_status='ok' (or wayback/manual,
    which are analyst-recoverable) counts as success."""
    if not snapshot_ids:
        return (0, 0, 0.0)
    placeholders = ",".join("?" * len(snapshot_ids))
    rows = conn.execute(
        f"SELECT capture_status FROM snapshots WHERE id IN ({placeholders})",
        snapshot_ids,
    ).fetchall()
    total = len(rows)
    if total == 0:
        return (0, 0, 0.0)
    ok_states = {CAPTURE_OK, CAPTURE_WAYBACK, CAPTURE_MANUAL}
    success = sum(1 for r in rows if r["capture_status"] in ok_states)
    return (success, total, (total - success) / total)


def _drain_case(conn, case_id: int, batch_budget: int,
                consecutive_bad_in: int = 0) -> tuple[int, int, int]:
    """Drain pending snapshots for one case.

    Returns (snapshot_count, batches_used, consecutive_bad_out).
    batch_budget caps how many batches this case may use.
    consecutive_bad carries across cases so a single shared environment
    failure (e.g. network down) trips the abort regardless of which case
    is currently being drained.

    Raises SystemExit(ENV_ABORTED_EXIT_CODE) when N consecutive eligible
    chunks all exceed FAILURE_THRESHOLD.
    """
    pending = _pending_scan_run_ids(conn, case_id)
    print(f"Case {case_id}: {len(pending)} pending snapshot(s)", flush=True)
    if not pending or batch_budget <= 0:
        return (0, 0, consecutive_bad_in)
    BATCH = 5
    snap_count = 0
    batches_used = 0
    consecutive_bad = consecutive_bad_in
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
        ok, total, rate = _chunk_failure_rate(conn, sids)
        print(f"    -> {ok}/{total} ok ({rate:.0%} fail)", flush=True)
        # Only chunks at or above MIN_CHUNK_SIZE count toward the budget;
        # a tail batch of 1-2 URLs hitting transient failure shouldn't
        # trip the abort.
        if total >= MIN_CHUNK_SIZE and rate > FAILURE_THRESHOLD:
            consecutive_bad += 1
            print(
                f"    warn: chunk above failure threshold "
                f"({rate:.0%} > {FAILURE_THRESHOLD:.0%}); "
                f"consecutive bad chunks = {consecutive_bad}/{FAILURE_CHUNKS}",
                flush=True,
            )
            if consecutive_bad >= FAILURE_CHUNKS:
                print(
                    f"\n[ENV_ABORTED] {FAILURE_CHUNKS} consecutive chunks "
                    f"failed above {FAILURE_THRESHOLD:.0%}. Likely environment "
                    f"issue (network, browser, disk). Investigate before "
                    f"continuing — remaining URLs are intact and will retry "
                    f"on next run.",
                    flush=True,
                )
                sys.exit(ENV_ABORTED_EXIT_CODE)
        else:
            consecutive_bad = 0
    return (snap_count, batches_used, consecutive_bad)


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
    consecutive_bad = 0
    for cid in case_ids:
        snap_count, used, consecutive_bad = _drain_case(
            conn, cid, batch_budget=remaining,
            consecutive_bad_in=consecutive_bad,
        )
        total_snapshots += snap_count
        remaining -= used
        if remaining <= 0:
            print("Stopped at total batch limit.", flush=True)
            break
    print(f"Done. Total snapshots this run: {total_snapshots}", flush=True)


if __name__ == "__main__":
    main()
