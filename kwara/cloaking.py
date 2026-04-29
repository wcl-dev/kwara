"""Cloaking detection — Phase 4.1.

Compares the response a URL gives 'with tracking params' vs 'without
tracking params'. Operators that gate behaviour on a tracking parameter
(picread.net's ?uid case from QSH-2026-04-28) leak their conditional
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
import sqlite3
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from audit import write_audit
from config import HTTP_TIMEOUT, SCANNER_USER_AGENT
from param_attribution import identify_param

# Body sizes within ±30% are treated as the same — accommodates ad-script
# variability without firing on every minor template difference.
BODY_SIZE_DIFF_THRESHOLD = 0.30

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


def _fetch_summary(url: str, timeout: int) -> dict[str, Any]:
    """Single-shot fetch returning a comparable summary, or {"error": ...}."""
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
        return {"error": str(exc)[:300]}
    return {
        "status_code": resp.status_code,
        "final_url": resp.url,
        "final_domain": urlparse(resp.url).hostname or "",
        "body_size": len(body),
        "body_sha256": hashlib.sha256(bytes(body)).hexdigest(),
    }


def detect_cloaking(url: str, timeout: int = HTTP_TIMEOUT) -> dict[str, Any]:
    """Compare 'with tracking params' vs 'without' for `url`.

    Always returns a dict with a `verdict` field. Safe to JSON-serialise
    and store as scan_runs.cloaking_signal_json.
    """
    stripped_url, stripped_keys = _strip_tracking_params(url)
    if not stripped_keys or stripped_url == url:
        return {"verdict": "no_tracking_params"}

    with_params = _fetch_summary(url, timeout)
    without_params = _fetch_summary(stripped_url, timeout)

    if with_params.get("error") or without_params.get("error"):
        return {
            "verdict": "fetch_error",
            "stripped_params": stripped_keys,
            "stripped_url": stripped_url,
            "with_params": with_params,
            "without_params": without_params,
        }

    diffs: list[str] = []
    if with_params["status_code"] != without_params["status_code"]:
        diffs.append("status_code")
    if with_params["final_domain"] != without_params["final_domain"]:
        diffs.append("final_domain")
    if with_params["body_sha256"] != without_params["body_sha256"]:
        diffs.append("body_content")
    a, b = with_params["body_size"], without_params["body_size"]
    biggest = max(a, b)
    if biggest > 0 and abs(a - b) / biggest > BODY_SIZE_DIFF_THRESHOLD:
        diffs.append("body_size")

    return {
        "verdict": "cloaking_suspect" if diffs else "no_cloaking",
        "diffs": diffs,
        "stripped_params": stripped_keys,
        "stripped_url": stripped_url,
        "with_params": with_params,
        "without_params": without_params,
    }


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

    result = detect_cloaking(row["original_url"], timeout=timeout)
    conn.execute(
        "UPDATE scan_runs SET cloaking_signal_json = ? WHERE id = ?",
        (json.dumps(result, ensure_ascii=False), scan_run_id),
    )
    conn.commit()
    write_audit(
        conn, "detect_cloaking", case_id=row["case_id"],
        meta={
            "scan_run_id": scan_run_id,
            "verdict":     result.get("verdict"),
            "diffs":       result.get("diffs", []),
        },
    )
    return result
