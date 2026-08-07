"""Tests for clustering.certificate_authorities()."""
import json
import os
import tempfile
from datetime import datetime, timezone

from kwara.clustering_infra import certificate_authorities
from kwara.db import get_conn, init_db, migrate_db


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _make_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _make_case(conn):
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("t", "", now, now),
    )
    return cur.lastrowid


def _add_scan(conn, case_id, original_url, final_url, tls_info: dict | None):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, original_url, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, original_url, now),
    )
    ua_id = cur.lastrowid
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status, tls_info_json) VALUES (?, ?, ?, 0, 'done', ?)",
        (ua_id, now, final_url, json.dumps(tls_info) if tls_info else None),
    )
    conn.commit()


def test_empty_case():
    conn = _make_db()
    case_id = _make_case(conn)
    assert certificate_authorities(conn, case_id) == []


def test_single_ca_multiple_domains():
    conn = _make_db()
    case_id = _make_case(conn)
    cert_a = {
        "issuer":       {"organizationName": "Let's Encrypt", "commonName": "R3"},
        "notBefore":    "Apr 15 00:00:00 2026 GMT",
        "serialNumber": "AAA",
    }
    cert_b = {
        "issuer":       {"organizationName": "Let's Encrypt", "commonName": "R3"},
        "notBefore":    "Apr 16 00:00:00 2026 GMT",
        "serialNumber": "BBB",
    }
    _add_scan(conn, case_id, "http://x/a", "https://aaa.com/", cert_a)
    _add_scan(conn, case_id, "http://x/b", "https://bbb.com/", cert_b)

    res = certificate_authorities(conn, case_id)
    assert len(res) == 1
    r = res[0]
    assert "Let's Encrypt" in r["issuer"]
    assert r["domain_count"] == 2
    assert r["cert_count"] == 2
    assert r["earliest_notBefore"] == "2026-04-15"


def test_multiple_cas_sorted_by_domain_count():
    conn = _make_db()
    case_id = _make_case(conn)
    le = {"issuer": {"commonName": "Let's Encrypt"}, "notBefore": "Apr 15 00:00:00 2026 GMT", "serialNumber": "L1"}
    le2 = {"issuer": {"commonName": "Let's Encrypt"}, "notBefore": "Apr 15 00:00:00 2026 GMT", "serialNumber": "L2"}
    google = {"issuer": {"commonName": "Google Trust Services"}, "notBefore": "Apr 15 00:00:00 2026 GMT", "serialNumber": "G1"}
    _add_scan(conn, case_id, "http://x/1", "https://a.com/", le)
    _add_scan(conn, case_id, "http://x/2", "https://b.com/", le2)
    _add_scan(conn, case_id, "http://x/3", "https://c.com/", google)
    res = certificate_authorities(conn, case_id)
    assert res[0]["issuer"] == "Let's Encrypt"
    assert res[0]["domain_count"] == 2
    assert res[1]["issuer"] == "Google Trust Services"


def test_malformed_tls_skipped():
    conn = _make_db()
    case_id = _make_case(conn)
    _add_scan(conn, case_id, "http://x/a", "https://a.com/", None)
    res = certificate_authorities(conn, case_id)
    assert res == []
