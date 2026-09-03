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

from .config import URLSCAN_API_KEY, TSA_URL


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

# PKIStatus (RFC 3161 §2.4.2). Only granted/grantedWithMods carry a token.
_TSA_STATUS = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}
_TSA_STATUS_OK = frozenset({0, 1})

# PKIFailureInfo bit positions (RFC 3161 §2.4.2).
_TSA_FAILURE_INFO = {
    0:  "badAlg",
    2:  "badRequest",
    5:  "badDataFormat",
    14: "timeNotAvailable",
    15: "unacceptedPolicy",
    16: "unacceptedExtension",
    17: "addInfoNotAvailable",
    25: "systemFailure",
}

# These name our request as the problem, so re-sending it changes nothing.
# Anything else — including a rejection with no failInfo at all, which is how
# FreeTSA reports "Error during serial number generation" — is the TSA having
# a bad moment and clears on retry.
_TSA_PERMANENT_FAILURES = frozenset({
    "badAlg", "badRequest", "badDataFormat",
    "unacceptedPolicy", "unacceptedExtension",
})

_TSA_MAX_ATTEMPTS = 3


def get_rfc3161_timestamp(data: bytes, *, attempts: int = _TSA_MAX_ATTEMPTS) -> dict:
    """Request a trusted timestamp from an RFC 3161 Time Stamp Authority.

    The timestamp proves that `data` existed at a specific point in time,
    as attested by the TSA (default: FreeTSA.org).

    A TSA that refuses still answers HTTP 200 with a well-formed
    application/timestamp-reply — a ~55-byte TimeStampResp whose PKIStatusInfo
    says rejection and which contains no token at all. Storing that as evidence
    would put something in the record that looks timestamped and proves
    nothing, so the reply's status is parsed and only granted (0) and
    grantedWithMods (1) are returned as a token; everything else comes back as
    an error. Transient refusals are retried up to `attempts` times.

    The timestamp token (DER-encoded) is returned as base64. It can be
    verified independently with OpenSSL:
      openssl ts -verify -data <file> -in token.tsr -CAfile cacert.pem
    and its status read back with:
      openssl ts -reply -in token.tsr -text | grep Status:

    Returns {"service": "rfc3161", "tsa_url": "...", "token_b64": "...",
             "digest_sha256": "...", "status": "granted", "requested_at": "..."}
    on success, or {"service": "rfc3161", "error": "...", "attempts": n}
    on failure.
    """
    digest = hashlib.sha256(data).digest()

    # Build a minimal TimeStampReq (DER) for SHA-256
    # RFC 3161 §2.4.1 — we construct it manually to avoid requiring
    # pyasn1 or other heavy dependencies.
    tsq = _build_timestamp_request(digest)

    attempt = 0
    last_error = "no attempt made"
    for attempt in range(1, max(1, attempts) + 1):
        _rate_wait("rfc3161")
        try:
            resp = requests.post(
                TSA_URL,
                data=tsq,
                headers={"Content-Type": "application/timestamp-query"},
                timeout=30,
            )
            resp.raise_for_status()

            content_type = resp.headers.get("Content-Type", "")
            if not content_type.startswith("application/timestamp-reply"):
                return {"service": "rfc3161",
                        "error": f"unexpected content-type: {content_type}",
                        "attempts": attempt}

            try:
                info = _parse_timestamp_response(resp.content)
            except ValueError as exc:
                return {"service": "rfc3161",
                        "error": f"unparseable TSA reply: {exc}"[:300],
                        "attempts": attempt}

            if info["status"] in _TSA_STATUS_OK:
                if info["has_token"]:
                    return {
                        "service": "rfc3161",
                        "tsa_url": TSA_URL,
                        "token_b64": base64.b64encode(resp.content).decode("ascii"),
                        "digest_sha256": hashlib.sha256(data).hexdigest(),
                        "status": info["status_text"],
                        "requested_at": _now(),
                    }
                # Accepted but empty: nothing to store, and worth another go.
                last_error = f"TSA returned {info['status_text']} with no timeStampToken"
            else:
                last_error = _describe_tsa_failure(info)
                if not _tsa_failure_is_transient(info):
                    break
        except Exception as exc:
            last_error = str(exc)[:300]

    return {"service": "rfc3161", "error": last_error, "attempts": attempt}


def _describe_tsa_failure(info: dict) -> str:
    """One line naming what the TSA refused and why, so the caller can tell a
    malformed request from a server-side hiccup without re-parsing the DER."""
    parts = [f"TSA rejected: {info['status_text']}({info['status']})"]
    if info["fail_info"]:
        parts.append(f"failInfo={info['fail_info']}")
    if info["status_string"]:
        parts.append(info["status_string"])
    return " ".join(parts)[:300]


def _tsa_failure_is_transient(info: dict) -> bool:
    """Whether re-sending the identical request could plausibly succeed."""
    named = {name for name in info["fail_info"].split(",") if name}
    return not (named & _TSA_PERMANENT_FAILURES)


def _parse_timestamp_response(der: bytes) -> dict:
    """Read the PKIStatusInfo out of a DER TimeStampResp (RFC 3161 §2.4.2).

      TimeStampResp ::= SEQUENCE {
        status           PKIStatusInfo,
        timeStampToken   TimeStampToken OPTIONAL }
      PKIStatusInfo ::= SEQUENCE {
        status           INTEGER,
        statusString     PKIFreeText     OPTIONAL,
        failInfo         PKIFailureInfo  OPTIONAL }

    Only the outermost layers are decoded — the token itself is kept as
    opaque bytes and verified with OpenSSL, not here.

    Returns {"status": int, "status_text": str, "status_string": str,
             "fail_info": str, "has_token": bool}.
    Raises ValueError if the reply is not a parseable TimeStampResp.
    """
    tag, body, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError(f"TimeStampResp is not a SEQUENCE (tag 0x{tag:02x})")

    tag, status_info, pos = _der_read(body, 0)
    if tag != 0x30:
        raise ValueError(f"PKIStatusInfo is not a SEQUENCE (tag 0x{tag:02x})")
    has_token = pos < len(body)

    tag, value, sub = _der_read(status_info, 0)
    if tag != 0x02 or not value:
        raise ValueError("PKIStatus is not an INTEGER")
    status = int.from_bytes(value, "big", signed=True)

    status_string = ""
    fail_info = ""
    while sub < len(status_info):
        tag, value, sub = _der_read(status_info, sub)
        if tag == 0x30:        # PKIFreeText ::= SEQUENCE OF UTF8String
            texts, inner = [], 0
            while inner < len(value):
                _, text, inner = _der_read(value, inner)
                texts.append(text.decode("utf-8", "replace"))
            status_string = " ".join(texts)
        elif tag == 0x03:      # PKIFailureInfo ::= BIT STRING
            fail_info = _decode_failure_info(value)

    return {
        "status": status,
        "status_text": _TSA_STATUS.get(status, f"unknown({status})"),
        "status_string": status_string,
        "fail_info": fail_info,
        "has_token": has_token,
    }


def _decode_failure_info(bit_string: bytes) -> str:
    """Names of the set bits in a DER BIT STRING, comma-separated."""
    if len(bit_string) < 2:
        return ""
    unused, data = bit_string[0], bit_string[1:]
    n_bits = len(data) * 8 - (unused if 0 <= unused < 8 else 0)
    names = [
        _TSA_FAILURE_INFO.get(i, f"bit{i}")
        for i in range(n_bits)
        if data[i // 8] >> (7 - i % 8) & 1
    ]
    return ",".join(names)


def _der_read(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one DER TLV at `pos`; return (tag, value, next_pos).

    Low-tag-number form only — every field of a PKIStatusInfo is a universal
    primitive or a SEQUENCE.
    """
    if pos + 2 > len(buf):
        raise ValueError("truncated DER header")
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        n_bytes = length & 0x7F
        if not 1 <= n_bytes <= 4:
            raise ValueError("unsupported DER length form")
        if pos + n_bytes > len(buf):
            raise ValueError("truncated DER length")
        length = int.from_bytes(buf[pos:pos + n_bytes], "big")
        pos += n_bytes
    if pos + length > len(buf):
        raise ValueError("truncated DER value")
    return tag, bytes(buf[pos:pos + length]), pos + length


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
