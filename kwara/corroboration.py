"""
corroboration.py — Third-party evidence corroboration services.

Each function is best-effort: failure returns a dict with an "error" key
instead of raising. This lets the pipeline continue even when an external
service is down or rate-limited.

Services:
  submit_urlscan(url)       → permalink on urlscan.io (community tier)
  save_to_wayback(url)      → archive.org permalink
  get_rfc3161_timestamp(data) → base64 DER timestamp token from a TSA

All results are stored as JSON in scan_runs.corroboration_json.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
from datetime import datetime, timezone

import requests

from config import URLSCAN_API_KEY, TSA_URL


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── Rate limiter ─────────────────────────────────────────────────────────
# Per-service minimum interval between requests. Prevents getting banned
# when batch-scanning 100+ URLs.
_RATE_LIMITS: dict[str, float] = {
    "urlscan":  3.0,   # urlscan.io community tier: ~100/day ≈ 1 per 15s, we use 3s
    "wayback":  5.0,   # archive.org is polite-crawl, 5s between saves
    "rfc3161":  1.0,   # FreeTSA is generous but don't hammer
}
_last_call: dict[str, float] = {}
_rate_lock = threading.Lock()


def _rate_wait(service: str) -> None:
    """Block until the minimum interval for this service has elapsed."""
    min_interval = _RATE_LIMITS.get(service, 1.0)
    with _rate_lock:
        last = _last_call.get(service, 0.0)
        elapsed = time.monotonic() - last
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        _last_call[service] = time.monotonic()


# ── urlscan.io ───────────────────────────────────────────────────────────

def submit_urlscan(url: str, *, visibility: str = "unlisted") -> dict:
    """Submit a URL to urlscan.io and return the result permalink.

    Requires KWARA_URLSCAN_API_KEY to be set. Community tier allows
    100 scans/day. Visibility defaults to "unlisted" (not shown in
    public search, but accessible via direct link — suitable for
    evidence corroboration without exposing case details).

    Returns {"service": "urlscan.io", "permalink": "...", "uuid": "...",
             "submitted_at": "..."} on success, or
            {"service": "urlscan.io", "error": "..."} on failure.
    """
    if not URLSCAN_API_KEY:
        return {"service": "urlscan.io", "error": "KWARA_URLSCAN_API_KEY not set", "skipped": True}

    _rate_wait("urlscan")
    try:
        resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={
                "API-Key": URLSCAN_API_KEY,
                "Content-Type": "application/json",
            },
            json={"url": url, "visibility": visibility},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "service": "urlscan.io",
            "permalink": data.get("result"),
            "api_url": data.get("api"),
            "uuid": data.get("uuid"),
            "submitted_at": _now(),
        }
    except Exception as exc:
        return {"service": "urlscan.io", "error": str(exc)[:300]}


# ── Wayback Machine Save Page Now ────────────────────────────────────────

def save_to_wayback(url: str) -> dict:
    """Request Internet Archive to save a fresh snapshot of the URL.

    Uses the SPN2 simple endpoint (no auth needed for basic saves).
    Returns a permalink to the archived page on success.

    Returns {"service": "archive.org", "permalink": "...", "saved_at": "..."}
    on success, or {"service": "archive.org", "error": "..."} on failure.
    """
    _rate_wait("wayback")
    try:
        # SPN (Save Page Now) simple endpoint — rate limited but no key needed
        resp = requests.get(
            f"https://web.archive.org/save/{url}",
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; kwara/1.0; +https://github.com/wcl-dev/kwara)",
            },
            timeout=60,
            allow_redirects=True,
        )
        # archive.org redirects to the archived URL on success
        if "web.archive.org/web/" in resp.url:
            return {
                "service": "archive.org",
                "permalink": resp.url,
                "saved_at": _now(),
            }
        # Sometimes returns 200 with the archived URL in headers
        content_location = resp.headers.get("Content-Location", "")
        if content_location:
            permalink = f"https://web.archive.org{content_location}"
            return {
                "service": "archive.org",
                "permalink": permalink,
                "saved_at": _now(),
            }
        return {"service": "archive.org", "error": f"unexpected response: status={resp.status_code}, url={resp.url[:200]}"}
    except Exception as exc:
        return {"service": "archive.org", "error": str(exc)[:300]}


# ── RFC 3161 Timestamp ───────────────────────────────────────────────────

def get_rfc3161_timestamp(data: bytes) -> dict:
    """Request a trusted timestamp from an RFC 3161 Time Stamp Authority.

    The timestamp proves that `data` existed at a specific point in time,
    as attested by the TSA (default: FreeTSA.org).

    The timestamp token (DER-encoded) is returned as base64. It can be
    verified independently with OpenSSL:
      openssl ts -verify -data <file> -in token.tsr -CAfile cacert.pem

    Returns {"service": "rfc3161", "tsa_url": "...", "token_b64": "...",
             "digest_sha256": "...", "requested_at": "..."}
    on success, or {"service": "rfc3161", "error": "..."} on failure.
    """
    digest = hashlib.sha256(data).digest()

    # Build a minimal TimeStampReq (DER) for SHA-256
    # RFC 3161 §2.4.1 — we construct it manually to avoid requiring
    # pyasn1 or other heavy dependencies.
    tsq = _build_timestamp_request(digest)

    _rate_wait("rfc3161")
    try:
        resp = requests.post(
            TSA_URL,
            data=tsq,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=30,
        )
        resp.raise_for_status()

        if resp.headers.get("Content-Type", "").startswith("application/timestamp-reply"):
            token_b64 = base64.b64encode(resp.content).decode("ascii")
            return {
                "service": "rfc3161",
                "tsa_url": TSA_URL,
                "token_b64": token_b64,
                "digest_sha256": hashlib.sha256(data).hexdigest(),
                "requested_at": _now(),
            }
        return {"service": "rfc3161", "error": f"unexpected content-type: {resp.headers.get('Content-Type')}"}
    except Exception as exc:
        return {"service": "rfc3161", "error": str(exc)[:300]}


def _build_timestamp_request(sha256_digest: bytes) -> bytes:
    """Build a minimal DER-encoded RFC 3161 TimeStampReq for SHA-256.

    Structure (ASN.1):
      TimeStampReq ::= SEQUENCE {
        version          INTEGER { v1(1) },
        messageImprint   MessageImprint,
        certReq          BOOLEAN DEFAULT FALSE
      }
      MessageImprint ::= SEQUENCE {
        hashAlgorithm    AlgorithmIdentifier (SHA-256 OID),
        hashedMessage    OCTET STRING
      }

    We set certReq=TRUE so the TSA includes its certificate in the response
    for independent verification.
    """
    # SHA-256 AlgorithmIdentifier (OID 2.16.840.1.101.3.4.2.1, NULL params)
    sha256_oid = bytes([
        0x30, 0x0d,  # SEQUENCE
        0x06, 0x09,  # OID
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,  # NULL
    ])

    # hashedMessage OCTET STRING
    hashed_msg = bytes([0x04, len(sha256_digest)]) + sha256_digest

    # MessageImprint SEQUENCE
    mi_body = sha256_oid + hashed_msg
    mi = bytes([0x30, len(mi_body)]) + mi_body

    # version INTEGER 1
    version = bytes([0x02, 0x01, 0x01])

    # certReq BOOLEAN TRUE
    cert_req = bytes([0x01, 0x01, 0xff])

    # TimeStampReq SEQUENCE
    body = version + mi + cert_req
    tsq = bytes([0x30, len(body)]) + body

    return tsq


# ── Orchestrator ─────────────────────────────────────────────────────────

def corroborate_url(url: str) -> dict:
    """Run all available corroboration services for a single URL.

    Returns a dict with keys for each service attempted. Services that
    are not configured (e.g. no API key) are marked as skipped.

    The urlscan + wayback results provide independent third-party evidence
    that the URL content existed. The RFC 3161 timestamp is attached to
    the combined result to prove when the corroboration was performed.
    """
    results = {}

    # 1. urlscan.io (if API key configured)
    results["urlscan"] = submit_urlscan(url)

    # 2. Wayback Machine (always available, rate limited)
    results["wayback"] = save_to_wayback(url)

    # 3. RFC 3161 timestamp on the combined results so far
    # This proves "at time T, these corroboration results existed"
    snapshot_data = json.dumps(results, sort_keys=True).encode("utf-8")
    results["timestamp"] = get_rfc3161_timestamp(snapshot_data)

    results["corroborated_at"] = _now()
    return results
