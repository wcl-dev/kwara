import json
import socket
import sqlite3
import ssl
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

import requests
import requests.exceptions

from audit import write_audit
from config import HTTP_TIMEOUT as TIMEOUT, MAX_HOPS, SCANNER_USER_AGENT as USER_AGENT


# A scan_run that's been 'running' beyond this window has lost its worker
# (process crashed, terminal closed, OS reboot). Without reclaim, the row
# sits forever and the URL never re-scans. 60 min covers a slow scan +
# corroboration + WHOIS comfortably; legitimate runs finish in seconds.
SCAN_LEASE_SECONDS = 60 * 60


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def reclaim_stuck_scans(conn: sqlite3.Connection,
                        *, lease_seconds: int = SCAN_LEASE_SECONDS) -> int:
    """Mark scan_runs that have outlived their lease as 'lease_expired'.

    Returns the number of rows reclaimed. Call once at worker startup
    (e.g. _run_pending.py) so abandoned 'running' rows don't block the
    URL from being rescanned.
    """
    threshold = (
        datetime.now(tz=timezone.utc) - timedelta(seconds=lease_seconds)
    ).strftime("%Y-%m-%d %H:%M:%S UTC")
    cur = conn.execute(
        """UPDATE scan_runs
              SET status = 'lease_expired',
                  notes = COALESCE(notes, '')
                          || ' [auto-reclaim: lease > ' || ? || 's]'
            WHERE status = 'running'
              AND run_at IS NOT NULL
              AND run_at < ?""",
        (lease_seconds, threshold),
    )
    conn.commit()
    return cur.rowcount


def _insert_hop(conn, scan_run_id, hop_order, url, status_code, location,
                resolved_url, response_headers_json: str | None = None):
    conn.execute(
        """INSERT INTO redirect_hops
               (scan_run_id, hop_order, url, status_code, location, resolved_url,
                fetched_at, response_headers_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_run_id, hop_order, url, status_code, location, resolved_url,
         _now(), response_headers_json),
    )


def _grab_tls_info(url: str, timeout: int) -> dict | None:
    """Fetch TLS certificate + transport metadata from the final landing URL.

    Returns a dict with cert fields (issuer/subject/notBefore/notAfter/
    serialNumber/subjectAltName/version) plus transport metadata captured
    from the live socket: peer_ip (origin behind any CDN proxy at the IP
    layer), tls_version, tls_cipher. These transport details are part of
    the request-persona record needed to reproduce a scan and to spot
    cloaking divergence — codex round-6 medium finding flagged that we
    were dropping them on the floor.

    Returns None if the URL is not HTTPS or if the handshake fails.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return None

    ctx = ssl.create_default_context()
    peer_ip: str | None = None
    tls_version: str | None = None
    tls_cipher: tuple | None = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                try:
                    peer_ip = ssock.getpeername()[0]
                except Exception:
                    peer_ip = None
                tls_version = ssock.version()
                tls_cipher = ssock.cipher()
    except Exception:
        return None

    if not cert:
        return None

    def _dn_to_str(dn_tuple):
        """Convert a ((('commonName', 'example.com'),),) structure to a dict."""
        out = {}
        for rdn in dn_tuple:
            for attr_type, attr_value in rdn:
                if attr_type in out:
                    existing = out[attr_type]
                    if isinstance(existing, list):
                        existing.append(attr_value)
                    else:
                        out[attr_type] = [existing, attr_value]
                else:
                    out[attr_type] = attr_value
        return out

    san_list = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        san_list.append(f"{san_type}:{san_value}")

    return {
        "subject": _dn_to_str(cert.get("subject", ())),
        "issuer": _dn_to_str(cert.get("issuer", ())),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "serialNumber": cert.get("serialNumber"),
        "subjectAltName": san_list,
        "version": cert.get("version"),
        # Transport-layer fingerprints (round 6 medium): peer_ip lets you
        # see the origin IP behind a CDN, tls_version + cipher_suite spot
        # operator template reuse across domains.
        "peer_ip": peer_ip,
        "tls_version": tls_version,
        "cipher_suite": tls_cipher[0] if tls_cipher else None,
        "cipher_protocol": tls_cipher[1] if tls_cipher else None,
        "scanner_user_agent": USER_AGENT,
    }


def _headers_to_json(resp: requests.Response) -> str | None:
    """Serialize response headers as a JSON list of [key, value] pairs.

    `resp.headers` (CaseInsensitiveDict) folds duplicate keys into one
    comma-joined value, which destroys per-`Set-Cookie` boundaries needed
    for cookie-domain leak / per-cookie flag analysis. Read from the
    underlying urllib3 HTTPHeaderDict (`resp.raw.headers`) when available
    so each `Set-Cookie` survives as its own pair.
    """
    raw = getattr(resp, "raw", None)
    raw_headers = getattr(raw, "headers", None) if raw is not None else None
    pairs: list[list[str]] | None = None
    if raw_headers is not None:
        try:
            pairs = [[k, v] for k, v in raw_headers.items()]
        except Exception:
            pairs = None
    if pairs is None:
        pairs = [[k, v] for k, v in resp.headers.items()]
    return json.dumps(pairs, ensure_ascii=False) if pairs else None


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
    final_resp  = None      # last non-3xx response

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

            hop_headers_json = _headers_to_json(resp)
            if 300 <= sc < 400 and location:
                resolved = urljoin(current_url, location)
                _insert_hop(conn, scan_run_id, hop_order, current_url, sc, location,
                            resolved, response_headers_json=hop_headers_json)
                conn.commit()
                hop_order  += 1
                final_url   = resolved
                current_url = resolved
            else:
                # Non-3xx → end of chain
                _insert_hop(conn, scan_run_id, hop_order, current_url, sc, location, None,
                            response_headers_json=hop_headers_json)
                final_url = current_url
                final_resp = resp
                hop_order += 1
                break
        else:
            # Exited while loop without break → max_hops reached
            status = "max_hops"
            notes  = f"Exceeded {max_hops} hops"

    except Exception as exc:
        status = "error"
        notes  = str(exc)[:500]

    # ── TLS certificate + response headers (best-effort) ─────────────
    tls_json = None
    headers_json = None

    if final_resp is not None:
        headers_json = _headers_to_json(final_resp)

    if status == "done" and final_url:
        tls_info = _grab_tls_info(final_url, timeout)
        if tls_info:
            tls_json = json.dumps(tls_info, ensure_ascii=False)

    conn.execute(
        """UPDATE scan_runs
           SET final_url = ?, hop_count = ?, status = ?, notes = ?,
               tls_info_json = ?, final_response_headers_json = ?
           WHERE id = ?""",
        (final_url, hop_order, status, notes, tls_json, headers_json, scan_run_id),
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
