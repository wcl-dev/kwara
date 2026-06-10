"""Cross-case signal index (index_db.py).

Builds small case DBs, indexes them into a central index DB, and checks the
cross-case questions it exists to answer: the same GA4 ID / cert / registrar
surfacing across separate cases — including across separate source DB files.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

from db import get_conn, init_db, migrate_db
from index_db import (
    SIGNAL_ASN,
    SIGNAL_CERT_SERIAL,
    SIGNAL_FINAL_DOMAIN,
    SIGNAL_REGISTRAR,
    SIGNAL_TRACKING_ID,
    extract_case_signals,
    get_index_conn,
    index_case,
    lookup,
    recurring_signals,
)


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_case_db():
    td = tempfile.mkdtemp()
    path = os.path.join(td, "case.db")
    conn = get_conn(path)
    init_db(conn)
    migrate_db(conn)
    return conn, path


def _fresh_index():
    td = tempfile.mkdtemp()
    return get_index_conn(os.path.join(td, "index.db"))


def _seed_case(conn, title="t") -> int:
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, '', ?, ?)",
        (title, _now(), _now()),
    )
    return cur.lastrowid


def _seed_scanned_url(conn, case_id, url, *, final_url=None, final_domain=None,
                      tracking_ids=None, cert_serial=None, cert_issuer=None,
                      registrar=None, asn=None, as_org=None):
    """message → url_artifact → done scan_run → ok snapshot, with signals."""
    final_url = final_url or url
    final_domain = final_domain or url.split("//")[-1].split("/")[0]
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, _now()),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, url, _now()),
    )
    ua_id = cur.lastrowid
    tls_json = None
    if cert_serial:
        tls_json = json.dumps({
            "serialNumber": cert_serial,
            "issuer": {"organizationName": cert_issuer or "Test CA"},
        })
    cur = conn.execute(
        """INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,
           status, tls_info_json, whois_registrar, asn, as_org)
           VALUES (?, ?, ?, 0, 'done', ?, ?, ?, ?)""",
        (ua_id, _now(), final_url, tls_json, registrar, asn, as_org),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           capture_status, tracking_ids_json, captured_at)
           VALUES (?, ?, ?, 'ok', ?, ?)""",
        (sr_id, final_url, final_domain,
         json.dumps(tracking_ids) if tracking_ids else None, _now()),
    )
    conn.commit()
    return sr_id


# ── extraction ────────────────────────────────────────────────────────────

def test_extract_pulls_all_signal_types():
    conn, path = _fresh_case_db()
    cid = _seed_case(conn, "case-A")
    _seed_scanned_url(conn, cid, "https://picelse.com/a",
                      final_domain="picelse.com",
                      tracking_ids={"Google Analytics 4": ["G-BG0P58H1GN"]},
                      cert_serial="0A1B2C", cert_issuer="Google Trust Services",
                      registrar="NameSilo", asn="13335", as_org="Cloudflare")
    sigs = extract_case_signals(conn, cid, path, "case-A")
    types = {s["signal_type"] for s in sigs}
    assert types == {SIGNAL_TRACKING_ID, SIGNAL_CERT_SERIAL, SIGNAL_REGISTRAR,
                     SIGNAL_ASN, SIGNAL_FINAL_DOMAIN}
    ga = next(s for s in sigs if s["signal_type"] == SIGNAL_TRACKING_ID)
    assert ga["signal_value"] == "G-BG0P58H1GN"
    assert ga["platform"] == "Google Analytics 4"
    assert ga["source_db"] == path


def test_extract_skips_failed_snapshot_tracking_ids():
    conn, path = _fresh_case_db()
    cid = _seed_case(conn)
    sr = _seed_scanned_url(conn, cid, "https://x.com/a",
                           tracking_ids={"Meta Pixel": ["123456789012345"]})
    # A later FAILED re-capture must not shadow the good snapshot.
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           capture_status, tracking_ids_json, captured_at)
           VALUES (?, '', 'x.com', 'cloudflare_challenge', NULL, ?)""",
        (sr, _now()),
    )
    conn.commit()
    sigs = extract_case_signals(conn, cid, path)
    assert any(s["signal_value"] == "123456789012345" for s in sigs)


# ── indexing + lookup ──────────────────────────────────────────────────────

def test_index_and_lookup_round_trip():
    conn, path = _fresh_case_db()
    cid = _seed_case(conn, "case-A")
    _seed_scanned_url(conn, cid, "https://picelse.com/a",
                      tracking_ids={"Google Analytics 4": ["G-BG0P58H1GN"]})
    idx = _fresh_index()
    n = index_case(idx, conn, path, cid, "case-A")
    assert n >= 1
    hits = lookup(idx, "G-BG0P58H1GN")
    assert len(hits) == 1
    assert hits[0]["case_title"] == "case-A"
    assert hits[0]["signal_type"] == SIGNAL_TRACKING_ID


def test_reindex_is_idempotent():
    conn, path = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_scanned_url(conn, cid, "https://x.com/a",
                      tracking_ids={"Google Analytics 4": ["G-AAA111"]})
    idx = _fresh_index()
    n1 = index_case(idx, conn, path, cid)
    n2 = index_case(idx, conn, path, cid)
    assert n1 == n2
    # No duplicate rows after re-index.
    total = idx.execute("SELECT COUNT(*) AS c FROM signals").fetchone()["c"]
    assert total == n1


# ── recurring across cases (the headline) ───────────────────────────────────

def test_recurring_signal_across_two_cases_same_db():
    conn, path = _fresh_case_db()
    a = _seed_case(conn, "case-A")
    b = _seed_case(conn, "case-B")
    _seed_scanned_url(conn, a, "https://picelse.com/x",
                      tracking_ids={"Google Analytics 4": ["G-SHARED"]})
    _seed_scanned_url(conn, b, "https://luckyelse.com/y",
                      tracking_ids={"Google Analytics 4": ["G-SHARED"]})
    idx = _fresh_index()
    index_case(idx, conn, path, a, "case-A")
    index_case(idx, conn, path, b, "case-B")
    rec = recurring_signals(idx, min_cases=2)
    shared = [r for r in rec if r["signal_value"] == "G-SHARED"]
    assert len(shared) == 1
    assert shared[0]["case_count"] == 2
    assert {c["case_id"] for c in shared[0]["cases"]} == {a, b}


def test_recurring_signal_across_separate_db_files():
    # Two investigations in DIFFERENT db files sharing one registrar.
    conn1, path1 = _fresh_case_db()
    conn2, path2 = _fresh_case_db()
    c1 = _seed_case(conn1, "inv-1")
    c2 = _seed_case(conn2, "inv-2")
    _seed_scanned_url(conn1, c1, "https://a.com/x", registrar="PDR Ltd")
    _seed_scanned_url(conn2, c2, "https://b.com/y", registrar="PDR Ltd")
    idx = _fresh_index()
    index_case(idx, conn1, path1, c1, "inv-1")
    index_case(idx, conn2, path2, c2, "inv-2")
    rec = recurring_signals(idx, min_cases=2)
    reg = [r for r in rec if r["signal_value"] == "PDR Ltd"
           and r["signal_type"] == SIGNAL_REGISTRAR]
    assert len(reg) == 1
    assert reg[0]["case_count"] == 2
    assert {c["source_db"] for c in reg[0]["cases"]} == {path1, path2}


def test_singleton_not_reported_as_recurring():
    conn, path = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_scanned_url(conn, cid, "https://only.com/a",
                      tracking_ids={"Google Analytics 4": ["G-ONCE"]})
    idx = _fresh_index()
    index_case(idx, conn, path, cid)
    rec = recurring_signals(idx, min_cases=2)
    assert not any(r["signal_value"] == "G-ONCE" for r in rec)
    # ...but a direct lookup still finds the singleton.
    assert len(lookup(idx, "G-ONCE")) == 1
