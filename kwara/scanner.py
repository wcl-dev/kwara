import sqlite3
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests
import requests.exceptions

from audit import write_audit

MAX_HOPS   = 20
TIMEOUT    = 10
USER_AGENT = "Mozilla/5.0 (compatible; kwara-scanner/1.0)"


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _insert_hop(conn, scan_run_id, hop_order, url, status_code, location, resolved_url):
    conn.execute(
        """INSERT INTO redirect_hops
               (scan_run_id, hop_order, url, status_code, location, resolved_url, fetched_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (scan_run_id, hop_order, url, status_code, location, resolved_url, _now()),
    )


def scan_url(
    conn: sqlite3.Connection,
    url_artifact_id: int,
    timeout: int = TIMEOUT,
    max_hops: int = MAX_HOPS,
) -> int:
    row = conn.execute(
        "SELECT original_url, case_id FROM url_artifacts WHERE id = ?",
        (url_artifact_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"url_artifact_id {url_artifact_id} not found")

    original_url = row["original_url"]
    case_id      = row["case_id"]

    # INSERT scan_run with status="running"
    conn.execute(
        """INSERT INTO scan_runs (url_artifact_id, run_at, status)
           VALUES (?, ?, 'running')""",
        (url_artifact_id, _now()),
    )
    conn.commit()
    scan_run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    current_url = original_url
    visited     = set()
    hop_order   = 0
    final_url   = original_url
    status      = "done"
    notes       = None

    try:
        while hop_order < max_hops:
            if current_url in visited:
                status = "loop_detected"
                notes  = f"Loop at hop {hop_order}: {current_url}"
                _insert_hop(conn, scan_run_id, hop_order, current_url, None, None, None)
                break

            visited.add(current_url)

            try:
                resp = session.get(current_url, timeout=timeout, allow_redirects=False,
                                   verify=True)
            except requests.exceptions.SSLError as exc:
                status = "ssl_error"
                notes  = str(exc)[:500]
                _insert_hop(conn, scan_run_id, hop_order, current_url, None, None, None)
                break
            except requests.exceptions.Timeout as exc:
                status = "timeout"
                notes  = str(exc)[:500]
                _insert_hop(conn, scan_run_id, hop_order, current_url, None, None, None)
                break
            except Exception as exc:
                status = "error"
                notes  = str(exc)[:500]
                _insert_hop(conn, scan_run_id, hop_order, current_url, None, None, None)
                break

            sc       = resp.status_code
            location = resp.headers.get("Location")

            if 300 <= sc < 400 and location:
                resolved = urljoin(current_url, location)
                _insert_hop(conn, scan_run_id, hop_order, current_url, sc, location, resolved)
                conn.commit()
                hop_order  += 1
                final_url   = resolved
                current_url = resolved
            else:
                # Non-3xx → end of chain
                _insert_hop(conn, scan_run_id, hop_order, current_url, sc, location, None)
                final_url = current_url
                hop_order += 1
                break
        else:
            # Exited while loop without break → max_hops reached
            status = "max_hops"
            notes  = f"Exceeded {max_hops} hops"

    except Exception as exc:
        status = "error"
        notes  = str(exc)[:500]

    conn.execute(
        """UPDATE scan_runs
           SET final_url = ?, hop_count = ?, status = ?, notes = ?
           WHERE id = ?""",
        (final_url, hop_order, status, notes, scan_run_id),
    )

    write_audit(
        conn,
        "scan_url",
        case_id=case_id,
        meta={
            "url_artifact_id": url_artifact_id,
            "scan_run_id":     scan_run_id,
            "original_url":    original_url,
            "final_url":       final_url,
            "hop_count":       hop_order,
            "status":          status,
        },
    )

    return scan_run_id
