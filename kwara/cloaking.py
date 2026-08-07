"""Cloaking detection — Phase 4.1.

Compares the response a URL gives 'with tracking params' vs 'without
tracking params'. Operators that gate behaviour on a tracking parameter
(crawlerlanding.example's ?uid case from QSH-2026-04-28) leak their conditional
logic via:

  - status_code differs   (e.g. 302 with uid → 200 without)
  - final_domain differs  (one redirects out, the other doesn't)
  - body sha256 differs   (same status, different content served)
  - body size differs     (>30% — same content vs SEO-fattened landing)

Cloaking is an *active* anti-investigation signal: the operator wrote
PHP/middleware logic specifically to vary behaviour by visitor type.
Evidence weight ≥ GA4-sharing (which is unconscious infrastructure
leakage). One cloaking domain alone justifies "operator is intentionally
evading investigation".

Result is stored as scan_runs.cloaking_signal_json. The verdict field
is one of:
  no_tracking_params  — input URL has no recognisable tracking params,
                         comparison was not possible
  fetch_error         — at least one of the two fetches failed
  no_cloaking         — both fetches succeeded with no observable diff
  cloaking_suspect    — at least one diff observed (see "diffs" field)
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from .audit import write_audit
from .config import CLOAKING_BODY_SIZE_DIFF, HTTP_TIMEOUT, SCANNER_USER_AGENT
from .lightweight_fetch import CAPTURE_METHOD_CLOAKING_ALT
from .param_attribution import identify_param

# Body sizes within this fraction are treated as the same — accommodates
# ad-script variability without firing on minor template diffs. Sourced from
# config (KWARA_CLOAKING_BODY_SIZE_DIFF) so reports can cite it; the
# module-level name is retained as the canonical reference used in tests.
BODY_SIZE_DIFF_THRESHOLD = CLOAKING_BODY_SIZE_DIFF

# Cap response read; mirrors lightweight_fetch's MAX_HTML_BYTES so the
# sha256 inputs are bounded.
MAX_BODY_BYTES = 5 * 1024 * 1024


def _strip_tracking_params(url: str) -> tuple[str, list[str]]:
    """Return (url_without_tracking_params, [stripped_keys]).

    A param is "tracking" if `identify_param` returns a non-empty
    platform_id (recognised vendor or generic bucket like uid/aff_id).
    """
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    kept: list[tuple[str, str]] = []
    stripped: list[str] = []
    for k, v in pairs:
        platform_id, _ = identify_param(k)
        if platform_id:
            stripped.append(k)
        else:
            kept.append((k, v))
    new_query = urlencode(kept)
    return urlunparse(p._replace(query=new_query)), stripped


def _fetch_summary(
    url: str, timeout: int,
) -> tuple[dict[str, Any], bytes | None]:
    """Single-shot fetch returning (summary_dict, body_bytes).

    On success the summary has status_code/final_url/final_domain/
    body_size/body_sha256 and body_bytes is the (capped) response body.
    On failure the dict is {"error": "..."} and body_bytes is None.
    """
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": SCANNER_USER_AGENT},
            allow_redirects=True,
            stream=True,
        )
        body = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = MAX_BODY_BYTES - len(body)
            if remaining <= 0:
                break
            body.extend(chunk[:remaining])
    except requests.exceptions.RequestException as exc:
        return {"error": str(exc)[:300]}, None
    body_bytes = bytes(body)
    return {
        "status_code":  resp.status_code,
        "final_url":    resp.url,
        "final_domain": urlparse(resp.url).hostname or "",
        "body_size":    len(body_bytes),
        "body_sha256":  hashlib.sha256(body_bytes).hexdigest(),
    }, body_bytes


def _detect_cloaking_with_bodies(
    url: str, timeout: int,
) -> tuple[dict[str, Any], bytes | None, bytes | None]:
    """Internal: fetch with-params + without-params and return
    (verdict_dict, with_body, without_body). Bodies are None when the
    corresponding fetch failed or comparison was skipped.

    `detect_cloaking` exposes only the verdict; `detect_and_store_cloaking`
    additionally needs the without-params body to create a cloaking_alt
    snapshot, so it calls this private helper directly.
    """
    stripped_url, stripped_keys = _strip_tracking_params(url)
    if not stripped_keys or stripped_url == url:
        return {"verdict": "no_tracking_params"}, None, None

    with_summary, with_body       = _fetch_summary(url, timeout)
    without_summary, without_body = _fetch_summary(stripped_url, timeout)

    if with_summary.get("error") or without_summary.get("error"):
        return ({
            "verdict": "fetch_error",
            "stripped_params": stripped_keys,
            "stripped_url": stripped_url,
            "with_params": with_summary,
            "without_params": without_summary,
        }, with_body, without_body)

    diffs: list[str] = []
    if with_summary["status_code"] != without_summary["status_code"]:
        diffs.append("status_code")
    if with_summary["final_domain"] != without_summary["final_domain"]:
        diffs.append("final_domain")
    if with_summary["body_sha256"] != without_summary["body_sha256"]:
        diffs.append("body_content")
    a, b = with_summary["body_size"], without_summary["body_size"]
    biggest = max(a, b)
    if biggest > 0 and abs(a - b) / biggest > BODY_SIZE_DIFF_THRESHOLD:
        diffs.append("body_size")

    return ({
        "verdict": "cloaking_suspect" if diffs else "no_cloaking",
        "diffs": diffs,
        "stripped_params": stripped_keys,
        "stripped_url": stripped_url,
        "with_params": with_summary,
        "without_params": without_summary,
    }, with_body, without_body)


def detect_cloaking(url: str, timeout: int = HTTP_TIMEOUT) -> dict[str, Any]:
    """Compare 'with tracking params' vs 'without' for `url`.

    Always returns a dict with a `verdict` field. Safe to JSON-serialise
    and store as scan_runs.cloaking_signal_json.
    """
    verdict, _wb, _wob = _detect_cloaking_with_bodies(url, timeout=timeout)
    return verdict


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _save_cloaking_alt_snapshot(
    conn: sqlite3.Connection,
    scan_run_id: int,
    *,
    without_summary: dict[str, Any],
    body: bytes,
    force: bool,
) -> int | None:
    """Persist the without-params body as a snapshots row keyed on
    capture_method='cloaking_alt'. Idempotent: skips when a row already
    exists for this scan_run unless `force=True` (in which case the
    existing row is updated in place to preserve cross-references).

    Runs fingerprint extraction so the alt-persona's tracking IDs flow
    into existing clustering (`shared_tracking_ids`,
    `ad_tracking_platforms`) without any change to those modules — the
    point of routing this through a normal snapshot row.
    """
    # Late imports avoid a circular dep:
    #   snapshots imports cloaking nothing → safe
    #   fingerprints imports nothing app-level → safe
    from .fingerprints import extract_tracking_ids_from_file
    from .snapshots import _per_capture_dir

    existing = conn.execute(
        """SELECT id FROM snapshots
           WHERE scan_run_id = ? AND capture_method = ?""",
        (scan_run_id, CAPTURE_METHOD_CLOAKING_ALT),
    ).fetchone()
    if existing and not force:
        return existing["id"]

    base_dir = _per_capture_dir(
        scan_run_id, final_url=without_summary.get("final_url"),
        capture_method=CAPTURE_METHOD_CLOAKING_ALT)
    html_path = os.path.join(base_dir, "page_cloaking_alt.html")
    with open(html_path, "wb") as f:
        f.write(body)

    tracking_ids = extract_tracking_ids_from_file(html_path)
    tracking_ids_json = (
        json.dumps(tracking_ids, ensure_ascii=False) if tracking_ids else None
    )

    final_url    = without_summary.get("final_url")    or ""
    final_domain = without_summary.get("final_domain") or ""

    if existing and force:
        conn.execute(
            """UPDATE snapshots
                  SET final_url = ?, final_domain = ?,
                      html_path = ?, captured_at = ?,
                      capture_status = 'ok', tracking_ids_json = ?
                WHERE id = ?""",
            (final_url, final_domain, html_path, _now(),
             tracking_ids_json, existing["id"]),
        )
        snapshot_id = existing["id"]
    else:
        cur = conn.execute(
            """INSERT INTO snapshots
                  (scan_run_id, final_url, final_domain,
                   screenshot_path, html_path, har_path,
                   request_domains_json, risk_tags, captured_at,
                   capture_status, capture_detail, tracking_ids_json,
                   capture_method)
               VALUES (?, ?, ?, NULL, ?, NULL, NULL, NULL, ?, 'ok', NULL, ?, ?)""",
            (scan_run_id, final_url, final_domain, html_path, _now(),
             tracking_ids_json, CAPTURE_METHOD_CLOAKING_ALT),
        )
        snapshot_id = cur.lastrowid
    conn.commit()
    return snapshot_id


def detect_and_store_cloaking(
    conn: sqlite3.Connection,
    scan_run_id: int,
    *,
    timeout: int = HTTP_TIMEOUT,
    force: bool = False,
) -> dict[str, Any] | None:
    """Run cloaking detection on a scan_run's URL and store the result.

    By default skips if `cloaking_signal_json` is already populated;
    `force=True` re-runs (e.g. analyst clicks Retry in the UI).
    Returns the verdict dict, or None when no scan_run row exists.

    When the verdict is `cloaking_suspect`, the without-params body is
    additionally saved as a `capture_method='cloaking_alt'` snapshot row
    so HTML fingerprint extraction (GA4, Pixel, GTM, etc.) can run on
    the cloaker's SEO-facing persona that the normal scan path never
    sees (because scan follows the redirect to the with-params
    destination).
    """
    row = conn.execute(
        """SELECT ua.original_url, ua.case_id, sr.cloaking_signal_json
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    if row is None:
        return None
    if row["cloaking_signal_json"] and not force:
        return json.loads(row["cloaking_signal_json"])

    result, _with_body, without_body = _detect_cloaking_with_bodies(
        row["original_url"], timeout=timeout,
    )
    conn.execute(
        "UPDATE scan_runs SET cloaking_signal_json = ? WHERE id = ?",
        (json.dumps(result, ensure_ascii=False), scan_run_id),
    )
    conn.commit()

    alt_snapshot_id: int | None = None
    if result.get("verdict") == "cloaking_suspect" and without_body is not None:
        alt_snapshot_id = _save_cloaking_alt_snapshot(
            conn, scan_run_id,
            without_summary=result["without_params"],
            body=without_body,
            force=force,
        )

    write_audit(
        conn, "detect_cloaking", case_id=row["case_id"],
        meta={
            "scan_run_id":       scan_run_id,
            "verdict":           result.get("verdict"),
            "diffs":             result.get("diffs", []),
            "alt_snapshot_id":   alt_snapshot_id,
        },
    )
    return result
