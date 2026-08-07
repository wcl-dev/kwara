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

from audit import write_audit
from config import ADS_TXT_MAX_BYTES, ADS_TXT_TIMEOUT, SCANNER_USER_AGENT

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
                "url": url, "fetched_at": now}

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
    if resp.status_code != 200:
        # 403 / 3xx / 404 etc. — record status, no records to parse.
        out["status"] = "non_200"
        out["records"] = []
        out["record_count"] = 0
        return out

    text = body_bytes.decode("utf-8", errors="replace")
    records, variables = parse_ads_txt(text)
    out["status"] = "ok"
    out["records"] = records
    out["record_count"] = len(records)
    out["owner_domain"] = variables.get("owner_domain")
    out["manager_domain"] = variables.get("manager_domain")
    return out


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
