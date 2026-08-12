"""ads.txt monetization forensics — Phase 8.

Fetches each landing domain's `/ads.txt` — the IAB Tech Lab transparency
file in which a publisher *itself* declares which ad systems it authorises
and under which seller account. A `DIRECT` line means "this account
collects the money for this domain"; it is a money-trail attribution
signal, arguably harder than GA4-sharing (which is unconscious tracking
leakage — ads.txt is a deliberate monetisation declaration).

Two operator signals fall out of it:
  - shared DIRECT accounts across domains (frequency-weighted — see
    clustering_infra.shared_ad_accounts; a handful of accounts shared by
    *every* domain is a shared monetisation manager, NOT one operator)
  - byte-identical ads.txt files (same raw sha256) → shared template,
    strongest operator signal

ads.txt 1.1 added OWNERDOMAIN / MANAGERDOMAIN variables — the publisher's
self-declared owner / manager. Parsed as first-class declared-attribution
fields (forgeable, but the forgery is itself a signal).

Result is stored as scan_runs.ads_txt_json. A non-200 fetch (403 in
particular — several QSH cloakers WAF-block the ads.txt path too) is
recorded rather than dropped: the status is itself a cloaking-adjacent
OPSEC signal.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests

from .audit import write_audit
from .config import ADS_TXT_MAX_BYTES, ADS_TXT_TIMEOUT, SCANNER_USER_AGENT

# Relationship tokens defined by the ads.txt spec. Anything else in the
# 3rd field is normalised to the upper-cased raw token (kept, not dropped,
# so anomalies stay visible).
REL_DIRECT = "DIRECT"
REL_RESELLER = "RESELLER"


def _ads_txt_url(final_url: str) -> str | None:
    """Build the https://{host}/ads.txt URL for a scanned final_url.

    ads.txt is always served from the root of the domain over the same
    scheme. Returns None when final_url has no host.
    """
    p = urlparse(final_url or "")
    if not p.hostname:
        return None
    scheme = p.scheme or "https"
    return urlunparse((scheme, p.netloc, "/ads.txt", "", "", ""))


def parse_ads_txt(text: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Parse ads.txt content into (records, variables).

    records: one dict per data row —
      {adsystem, seller_id, relationship, cert_authority_id}
    variables: OWNERDOMAIN / MANAGERDOMAIN (ads.txt 1.1), lower-cased keys
      → 'owner_domain' / 'manager_domain'.

    Comments (`#` to end of line) and blank lines are ignored. A data row
    needs at least adsystem + seller_id + relationship; rows with fewer
    fields are skipped.
    """
    records: list[dict[str, Any]] = []
    variables: dict[str, str] = {}
    for raw_line in text.splitlines():
        # Strip inline comments and surrounding whitespace.
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        # Variable lines: KEY=value (no comma). OWNERDOMAIN / MANAGERDOMAIN.
        if "=" in line and "," not in line.split("=", 1)[0]:
            key, _, val = line.partition("=")
            key = key.strip().upper()
            val = val.strip()
            if key == "OWNERDOMAIN" and val:
                variables["owner_domain"] = val.lower()
            elif key == "MANAGERDOMAIN" and val:
                # MANAGERDOMAIN may carry an optional ", exchange" suffix.
                variables["manager_domain"] = val.split(",")[0].strip().lower()
            continue

        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 3 or not fields[0] or not fields[1]:
            continue
        adsystem = fields[0].lower()
        seller_id = fields[1]
        relationship = fields[2].upper()
        cert_authority_id = fields[3] if len(fields) >= 4 and fields[3] else None
        records.append({
            "adsystem":          adsystem,
            "seller_id":         seller_id,
            "relationship":      relationship,
            "cert_authority_id": cert_authority_id,
        })
    return records, variables


def _fetch_ads_txt(final_url: str, timeout: int) -> dict[str, Any]:
    """Fetch and parse {domain}/ads.txt for a scanned final_url.

    Uses allow_redirects=False (contract 9): the scan path already
    resolved the canonical final_url, so following further redirects here
    would capture an ads.txt from a *different* host. A redirect, a
    non-200, or a network error is recorded (not dropped) — the status is
    itself an OPSEC signal.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    url = _ads_txt_url(final_url)
    if url is None:
        return {"status": "error", "error": "no host in final_url",
                "fetched_at": now}

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": SCANNER_USER_AGENT},
            allow_redirects=False,
            stream=True,
        )
        body = bytearray()
        truncated = False
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = ADS_TXT_MAX_BYTES - len(body)
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                truncated = True
            body.extend(chunk[:remaining])
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": str(exc)[:300],
                "url": url, "fetched_at": now,
                # A network error is a real acquisition outcome with no body.
                # Recorded, not dropped — see kwara/acquisition.py.
                "_acquisition": {"requested_url": url, "status": "error",
                                 "error": str(exc)[:300], "fetched_at": now,
                                 "user_agent": SCANNER_USER_AGENT}}

    body_bytes = bytes(body)
    out: dict[str, Any] = {
        "url":         url,
        "status_code": resp.status_code,
        "fetched_at":  now,
        # None when the read hit ADS_TXT_MAX_BYTES: a prefix hash would be
        # matched as byte-identity by the template clustering downstream.
        "truncated":   truncated,
        "raw_sha256":  (None if truncated
                        else hashlib.sha256(body_bytes).hexdigest()),
    }
    # The bytes are handed on so the caller can persist them. A 403 challenge
    # page and a 302 are bodies too, and they are exactly the ones worth
    # keeping — they record what the site served an investigator.
    from .acquisition import headers_as_pairs
    out["_acquisition"] = {
        "requested_url": url,
        "final_url": url,                      # allow_redirects=False here
        "status": "non_200" if resp.status_code != 200 else "ok",
        "status_code": resp.status_code,
        "fetched_at": now,
        "response_headers": headers_as_pairs(
            getattr(getattr(resp, "raw", None), "headers", None) or resp.headers),
        "user_agent": SCANNER_USER_AGENT,
        "truncated": truncated,
        "body": body_bytes,
    }

    if resp.status_code != 200:
        # 403 / 3xx / 404 etc. — record status, no records to parse.
        out["status"] = "non_200"
        out["records"] = []
        out["record_count"] = 0
        return out

    # Deliberately NOT parsed here. The records must come from the bytes that
    # were actually persisted, not from a sibling copy in memory — otherwise
    # "we parsed what we kept" is an intention rather than a fact. The caller
    # writes the body, reads it back, and calls parse_body() on that.
    out["status"] = "ok"
    out["records"] = []
    out["record_count"] = 0
    out["_needs_parse"] = True
    return out


def parse_body(body: bytes) -> dict[str, Any]:
    """Parse ads.txt bytes into the derived record fields."""
    records, variables = parse_ads_txt(body.decode("utf-8", errors="replace"))
    return {"records": records, "record_count": len(records),
            "owner_domain": variables.get("owner_domain"),
            "manager_domain": variables.get("manager_domain")}


def fetch_and_store_ads_txt(
    conn: sqlite3.Connection,
    scan_run_id: int,
    *,
    timeout: int = ADS_TXT_TIMEOUT,
    force: bool = False,
) -> dict[str, Any] | None:
    """Fetch a scan_run's domain ads.txt and store it on the scan_run.

    By default skips if `ads_txt_json` is already populated; `force=True`
    re-fetches (analyst clicks Re-run in the UI). Returns the result dict,
    or None when no scan_run row exists or it has no usable final_url.
    """
    row = conn.execute(
        """SELECT sr.final_url, sr.ads_txt_json, ua.case_id
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    if row is None:
        return None
    if row["ads_txt_json"] and not force:
        return json.loads(row["ads_txt_json"])
    if not row["final_url"]:
        return None

    result = _fetch_ads_txt(row["final_url"], timeout=timeout)

    # Persist the response BEFORE the derived JSON, and carry the row id on
    # the derived record. A forced re-fetch inserts a new acquisition; the
    # previous body and its row are never touched, so an earlier observation
    # stays checkable after the site changes or starts refusing.
    from .acquisition import read_back, record_fetch
    acq = result.pop("_acquisition", None)
    needs_parse = result.pop("_needs_parse", False)
    if acq is not None:
        try:
            aid = record_fetch(conn, scan_run_id=scan_run_id, **acq)
            result["acquisition_id"] = aid
            if needs_parse:
                # Read the artifact back and parse THAT. After this the
                # records demonstrably came from the bytes on disk, and
                # captured_sha256 is literally that file's hash.
                path = conn.execute(
                    "SELECT body_path FROM acquisitions WHERE id = ?",
                    (aid,)).fetchone()["body_path"]
                result.update(parse_body(read_back(path)))
        except (OSError, RuntimeError) as exc:
            # Retention failing must not lose the analysis, but it must be
            # visible: an unrecorded fetch cannot support an identity claim.
            result["acquisition_error"] = str(exc)[:300]
            if needs_parse and acq.get("body") is not None:
                result.update(parse_body(acq["body"]))
                result["parsed_from"] = "memory (artifact unavailable)"

    conn.execute(
        "UPDATE scan_runs SET ads_txt_json = ? WHERE id = ?",
        (json.dumps(result, ensure_ascii=False), scan_run_id),
    )
    conn.commit()

    write_audit(
        conn, "fetch_ads_txt", case_id=row["case_id"],
        meta={
            "scan_run_id":  scan_run_id,
            "status":       result.get("status"),
            "status_code":  result.get("status_code"),
            "record_count": result.get("record_count", 0),
        },
    )
    return result
