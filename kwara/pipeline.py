"""
pipeline.py — 統一調度 scan → snapshot → whois
app.py 只呼叫這裡，不直接碰底層模組。
網域情資（WHOIS／ASN）可獨立於截圖寫入 scan_runs。
"""
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import NEW_DOMAIN_DAYS
from corroboration import corroborate_url
from scanner import scan_url as _scan
from snapshots import snapshot_url as _snapshot, snapshot_batch as _snapshot_batch
from whois_lookup import query_whois, UNKNOWN
from ip_lookup import lookup_ip

_POSTED_AT_FMTS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d-%m-%Y",
    "%m/%d/%Y",
]


def _parse_posted_at(raw: str):
    raw = (raw or "").strip().replace(" UTC", "")
    for fmt in _POSTED_AT_FMTS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _intel_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def run_scan_only(conn: sqlite3.Connection, url_artifact_id: int) -> int:
    """Pure scan — redirect chain + TLS + headers. No third-party network calls.

    Use run_scan_with_corroboration() to additionally submit to Wayback /
    urlscan / RFC 3161 in the same step, or call run_corroborate() later.
    """
    return _scan(conn, url_artifact_id)


def run_scan_with_corroboration(conn: sqlite3.Connection, url_artifact_id: int) -> int:
    """Scan, then best-effort third-party corroboration. Failures in
    corroboration do not surface — see _try_corroborate()."""
    scan_run_id = _scan(conn, url_artifact_id)
    _try_corroborate(conn, scan_run_id)
    return scan_run_id


def run_lightweight_fetch_batch(
    conn: sqlite3.Connection,
    scan_run_ids: list[int],
) -> list[int]:
    """Lightweight HTML-only fetch — no Playwright, no screenshot, no HAR.

    Wraps lightweight_fetch.fetch_html_only_batch(). See that module's
    docstring for trade-offs vs the full Playwright snapshot path.
    """
    from lightweight_fetch import fetch_html_only_batch
    return fetch_html_only_batch(conn, scan_run_ids)


def _try_corroborate(conn: sqlite3.Connection, scan_run_id: int) -> None:
    """Best-effort third-party corroboration after a successful scan."""
    row = conn.execute(
        "SELECT final_url, status, corroboration_json FROM scan_runs WHERE id = ?",
        (scan_run_id,),
    ).fetchone()
    if not row or row["status"] != "done" or not row["final_url"]:
        return
    if row["corroboration_json"]:
        return  # already corroborated
    try:
        results = corroborate_url(row["final_url"])
        conn.execute(
            "UPDATE scan_runs SET corroboration_json = ? WHERE id = ?",
            (json.dumps(results, ensure_ascii=False), scan_run_id),
        )
        conn.commit()
    except Exception:
        pass  # best-effort — never block the scan pipeline


def run_corroborate(conn: sqlite3.Connection, scan_run_id: int) -> dict | None:
    """Force (re-)corroborate a scan run. Called from UI retry button."""
    row = conn.execute(
        "SELECT final_url, status FROM scan_runs WHERE id = ?",
        (scan_run_id,),
    ).fetchone()
    if not row or row["status"] != "done" or not row["final_url"]:
        return None
    results = corroborate_url(row["final_url"])
    conn.execute(
        "UPDATE scan_runs SET corroboration_json = ? WHERE id = ?",
        (json.dumps(results, ensure_ascii=False), scan_run_id),
    )
    conn.commit()
    return results


def _latest_snapshot_id(conn: sqlite3.Connection, scan_run_id: int) -> int | None:
    row = conn.execute(
        """SELECT id FROM snapshots WHERE scan_run_id = ?
           ORDER BY id DESC LIMIT 1""",
        (scan_run_id,),
    ).fetchone()
    return row["id"] if row else None


def _enrich_domain_for_scan_run(
    conn: sqlite3.Connection,
    scan_run_id: int,
    snapshot_id: int | None = None,
) -> None:
    sr = conn.execute(
        "SELECT id, final_url, status FROM scan_runs WHERE id = ?",
        (scan_run_id,),
    ).fetchone()
    if not sr or (sr["status"] or "") != "done" or not sr["final_url"]:
        return

    final_domain = urlparse(sr["final_url"]).hostname or ""
    if not final_domain:
        return

    posted_row = conn.execute(
        """SELECT me.posted_at FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           JOIN message_evidence me ON me.id = ua.message_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    posted_at = posted_row["posted_at"] if posted_row else None

    registrar, creation_date, _ = query_whois(final_domain)
    data = lookup_ip(final_domain)
    ref_date = _parse_posted_at(posted_at) if posted_at else None
    if ref_date is None:
        ref_date = datetime.now()

    intel_tags: list[str] = []
    if creation_date and creation_date != UNKNOWN:
        try:
            age = (ref_date - datetime.strptime(creation_date, "%Y-%m-%d")).days
            if age < NEW_DOMAIN_DAYS:
                intel_tags.append("new_domain")
        except ValueError:
            pass

    enriched_at = _intel_now()

    if snapshot_id is not None:
        snap = conn.execute(
            "SELECT id, risk_tags FROM snapshots WHERE id = ? AND scan_run_id = ?",
            (snapshot_id, scan_run_id),
        ).fetchone()
        if snap:
            tags = json.loads(snap["risk_tags"] or "[]")
            for t in intel_tags:
                if t not in tags:
                    tags.append(t)
            conn.execute(
                """UPDATE snapshots SET whois_registrar = ?, whois_creation_date = ?,
                       ip_address = ?, asn = ?, as_org = ?, as_country = ?, risk_tags = ?
                   WHERE id = ?""",
                (
                    registrar,
                    creation_date,
                    data["ip"],
                    data["asn"],
                    data["as_org"],
                    data["as_country"],
                    json.dumps(tags),
                    snapshot_id,
                ),
            )

    conn.execute(
        """UPDATE scan_runs SET whois_registrar = ?, whois_creation_date = ?,
               ip_address = ?, asn = ?, as_org = ?, as_country = ?,
               intel_risk_tags = ?, domain_enriched_at = ?
           WHERE id = ?""",
        (
            registrar,
            creation_date,
            data["ip"],
            data["asn"],
            data["as_org"],
            data["as_country"],
            json.dumps(intel_tags),
            enriched_at,
            scan_run_id,
        ),
    )
    conn.commit()


def run_domain_intel_only(conn: sqlite3.Connection, scan_run_id: int) -> None:
    """WHOIS / ASN only; no browser. Updates scan_runs; merges into snapshot row if present."""
    sid = _latest_snapshot_id(conn, scan_run_id)
    _enrich_domain_for_scan_run(conn, scan_run_id, snapshot_id=sid)


def run_domain_intel_batch(conn: sqlite3.Connection, scan_run_ids: list[int]) -> None:
    for sr_id in scan_run_ids:
        run_domain_intel_only(conn, sr_id)


def run_snapshot(conn: sqlite3.Connection, scan_run_id: int,
                 env_override: dict[str, str] | None = None) -> int:
    snapshot_id = _snapshot(conn, scan_run_id, env_override=env_override)
    _enrich_domain_for_scan_run(conn, scan_run_id, snapshot_id=snapshot_id)
    _try_corroborate(conn, scan_run_id)
    return snapshot_id


def run_snapshot_batch(conn: sqlite3.Connection, scan_run_ids: list[int],
                       env_override: dict[str, str] | None = None) -> list[int]:
    """Capture screenshots for multiple URLs in one subprocess, then enrich."""
    snapshot_ids = _snapshot_batch(conn, scan_run_ids, env_override=env_override)
    for sid in snapshot_ids:
        row = conn.execute(
            "SELECT scan_run_id FROM snapshots WHERE id = ?", (sid,)
        ).fetchone()
        if row:
            _enrich_domain_for_scan_run(conn, row["scan_run_id"], snapshot_id=sid)
    return snapshot_ids
