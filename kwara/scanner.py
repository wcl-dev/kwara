import json
import socket
import sqlite3
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import requests.exceptions

from audit import write_audit
from config import HTTP_TIMEOUT as TIMEOUT, MAX_HOPS, SCANNER_USER_AGENT as USER_AGENT


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _insert_hop(conn, scan_run_id, hop_order, url, status_code, location, resolved_url):
    conn.execute(
        """INSERT INTO redirect_hops
               (scan_run_id, hop_order, url, status_code, location, resolved_url, fetched_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (scan_run_id, hop_order, url, status_code, location, resolved_url, _now()),
    )


def _grab_tls_info(url: str, timeout: int) -> dict | None:
    """Fetch TLS certificate from the final landing URL via a fresh TLS handshake.

    Returns a dict with issuer, subject, notBefore, notAfter, serialNumber,
    subjectAltName, and the raw PEM-decoded fields. Returns None if the URL
    is not HTTPS or if the handshake fails.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return None

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
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
