"""
pipeline.py — 統一調度 scan → snapshot → whois
app.py 只呼叫這裡，不直接碰底層模組。
"""
import json
import sqlite3
from datetime import datetime

from scanner import scan_url as _scan
from snapshots import snapshot_url as _snapshot
from whois_lookup import query_whois, UNKNOWN
from ip_lookup import lookup_ip

NEW_DOMAIN_DAYS = 180

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


def run_scan_only(conn: sqlite3.Connection, url_artifact_id: int) -> int:
    return _scan(conn, url_artifact_id)


def run_snapshot(conn: sqlite3.Connection, scan_run_id: int) -> int:
    snapshot_id = _snapshot(conn, scan_run_id)
    _apply_whois(conn, snapshot_id)
    _apply_ip_asn(conn, snapshot_id)
    return snapshot_id


def _apply_ip_asn(conn: sqlite3.Connection, snapshot_id: int) -> None:
    row = conn.execute(
        "SELECT final_domain FROM snapshots WHERE id = ?", (snapshot_id,)
    ).fetchone()
    if not row or not row["final_domain"]:
        return

    data = lookup_ip(row["final_domain"])
    conn.execute(
        """UPDATE snapshots
           SET ip_address = ?, asn = ?, as_org = ?, as_country = ?
           WHERE id = ?""",
        (data["ip"], data["asn"], data["as_org"], data["as_country"], snapshot_id),
    )
    conn.commit()


def _apply_whois(conn: sqlite3.Connection, snapshot_id: int) -> None:
    row = conn.execute(
        """SELECT s.final_domain, s.risk_tags, me.posted_at
           FROM snapshots s
           JOIN scan_runs sr ON sr.id = s.scan_run_id
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           JOIN message_evidence me ON me.id = ua.message_id
           WHERE s.id = ?""",
        (snapshot_id,),
    ).fetchone()
    if not row or not row["final_domain"]:
        return

    registrar, creation_date, _ = query_whois(row["final_domain"])

    # Use posted_at as reference date; fall back to today if unparseable
    ref_date = _parse_posted_at(row["posted_at"]) or datetime.now()

    tags = json.loads(row["risk_tags"] or "[]")
    if creation_date and creation_date != UNKNOWN:
        try:
            age = (ref_date - datetime.strptime(creation_date, "%Y-%m-%d")).days
            if age < NEW_DOMAIN_DAYS and "new_domain" not in tags:
                tags.append("new_domain")
        except ValueError:
            pass

    conn.execute(
        """UPDATE snapshots
           SET whois_registrar = ?, whois_creation_date = ?, risk_tags = ?
           WHERE id = ?""",
        (registrar, creation_date, json.dumps(tags), snapshot_id),
    )
    conn.commit()
