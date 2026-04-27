"""Lightweight HTML-only fetch path (Phase 3 ticket C).

Alternative to ``snapshots.snapshot_url()``: pulls a landing page's HTML
via ``requests.get`` and runs the same fingerprint extraction, without
launching Playwright. ~10x faster, no browser dependency, no screenshot
or HAR — useful when an analyst wants quick attribution analysis on a
large URL list and is willing to accept the trade-offs:

  - JS-injected tracking (GTM-loaded GA4, SPA-hydrated Pixels) is invisible
  - No screenshot evidence — only HTML + extracted IDs survive
  - No request_domains_json (HAR-derived; absent here)
  - No 'high_tracker_count' risk flag for these snapshots

Snapshots created here are tagged ``capture_method = 'http_only'``;
existing Playwright captures are ``capture_method = 'playwright'``.
"""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from audit import write_audit
from config import HTTP_TIMEOUT, SCANNER_USER_AGENT
from fingerprints import extract_tracking_ids_from_file


CAPTURE_METHOD_PLAYWRIGHT = "playwright"
CAPTURE_METHOD_HTTP_ONLY  = "http_only"

# Cap response size so a misbehaving server can't exhaust memory.
# 5 MB covers virtually every legitimate landing page (the QSH dataset's
# largest captured HTML is ~120 KB).
MAX_HTML_BYTES = 5 * 1024 * 1024


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fetch_html_only(
    conn: sqlite3.Connection,
    scan_run_id: int,
    timeout: int = HTTP_TIMEOUT,
) -> int:
    """Fetch the scan_run's final_url over HTTP, save HTML, extract pixel IDs.

    Creates a new snapshot row tagged capture_method='http_only'. Returns
    the snapshot_id.

    Failures (timeout, HTTP error, connection error) still create a
    snapshot row with capture_status set accordingly so the analyst can
    see what was attempted.
    """
    row = conn.execute(
        """SELECT sr.final_url, ua.case_id
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"scan_run_id {scan_run_id} not found")
    final_url = row["final_url"]
    if not final_url:
        raise ValueError(f"scan_run_id {scan_run_id} has no final_url")
    case_id = row["case_id"]
    final_domain = urlparse(final_url).hostname or ""

    base_dir = os.path.join(os.path.dirname(__file__), "data", "snapshots", str(scan_run_id))
    os.makedirs(base_dir, exist_ok=True)
    html_path = os.path.join(base_dir, "page_http_only.html")

    capture_status: str = "ok"
    capture_detail: str | None = None
    body_written = False

    try:
        resp = requests.get(
            final_url,
            timeout=timeout,
            headers={"User-Agent": SCANNER_USER_AGENT},
            stream=True,
            allow_redirects=True,
        )
        resp.raise_for_status()
        content = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = MAX_HTML_BYTES - len(content)
            if remaining <= 0:
                break
            content.extend(chunk[:remaining])
        with open(html_path, "wb") as f:
            f.write(content)
        body_written = True
    except requests.exceptions.Timeout:
        capture_status = "timeout"
        capture_detail = f"requests timeout after {timeout}s"
    except requests.exceptions.HTTPError as exc:
        capture_status = "error"
        sc = exc.response.status_code if exc.response is not None else "?"
        capture_detail = f"HTTP {sc}"
    except requests.exceptions.RequestException as exc:
        capture_status = "error"
        capture_detail = str(exc)[:500]

    tracking_ids = (
        extract_tracking_ids_from_file(html_path) if body_written else {}
    )
    tracking_ids_json = (
        json.dumps(tracking_ids, ensure_ascii=False) if tracking_ids else None
    )

    conn.execute(
        """INSERT INTO snapshots
               (scan_run_id, final_url, final_domain,
                screenshot_path, html_path, har_path,
                request_domains_json, risk_tags, captured_at,
                capture_status, capture_detail, tracking_ids_json,
                capture_method)
           VALUES (?, ?, ?, NULL, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?)""",
        (
            scan_run_id, final_url, final_domain,
            html_path if body_written else None,
            _now(), capture_status, capture_detail, tracking_ids_json,
            CAPTURE_METHOD_HTTP_ONLY,
        ),
    )
    conn.commit()
    snapshot_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    write_audit(
        conn, "fetch_html_only", case_id=case_id,
        meta={
            "scan_run_id":            scan_run_id,
            "snapshot_id":            snapshot_id,
            "final_url":              final_url,
            "final_domain":           final_domain,
            "capture_status":         capture_status,
            "capture_detail":         capture_detail,
            "tracking_id_platforms":  sorted(tracking_ids.keys()),
            "method":                 CAPTURE_METHOD_HTTP_ONLY,
        },
    )
    return snapshot_id


def fetch_html_only_batch(
    conn: sqlite3.Connection,
    scan_run_ids: list[int],
    timeout: int = HTTP_TIMEOUT,
) -> list[int]:
    """Sequential batch — no parallelism (kept simple, no thread pool).

    Continues on per-URL failure so one bad URL doesn't abort the batch.
    """
    out: list[int] = []
    for sr_id in scan_run_ids:
        try:
            out.append(fetch_html_only(conn, sr_id, timeout=timeout))
        except Exception:
            # Skip — the underlying function records a status='error'
            # snapshot itself; we only land here on schema-level surprise
            # like missing scan_run_id.
            continue
    return out
