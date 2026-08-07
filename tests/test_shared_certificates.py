"""Tests for clustering.shared_certificates()."""
import json
import os
import tempfile
from datetime import datetime, timezone

from kwara.clustering_infra import shared_certificates
from kwara.db import get_conn, init_db, migrate_db


def _now_iso():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _make_case(conn, title="Test"):
    now = _now_iso()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
        (title, "", now, now),
    )
    return cur.lastrowid


def _add_scan(conn, case_id, original_url, final_url, tls_info: dict | None,
              post_id: int | None = None):
    """Insert message_evidence + url_artifact + scan_run with TLS info attached."""
    now = _now_iso()
    if post_id is None:
        cur = conn.execute(
            """INSERT INTO message_evidence
               (case_id, platform, permalink, actor_label, posted_at, message_text,
                screenshot_path, ingested_at)
               VALUES (?, '', '', '', '', ?, '', ?)""",
            (case_id, original_url, now),
        )
        post_id = cur.lastrowid

    cur = conn.execute(
        """INSERT INTO url_artifacts
           (message_id, case_id, original_url, domain, url_order, created_at)
           VALUES (?, ?, ?, '', 0, ?)""",
        (post_id, case_id, original_url, now),
    )
    ua_id = cur.lastrowid

    tls_json = json.dumps(tls_info) if tls_info is not None else None
    conn.execute(
        """INSERT INTO scan_runs
           (url_artifact_id, run_at, final_url, hop_count, status, tls_info_json)
           VALUES (?, ?, ?, 0, 'done', ?)""",
        (ua_id, now, final_url, tls_json),
    )
    conn.commit()
    return post_id, ua_id


def _make_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def test_empty_case_returns_empty_clusters():
    conn = _make_db()
    case_id = _make_case(conn)
    result = shared_certificates(conn, case_id)
    assert result == {"by_cert": [], "by_issuance": []}


def test_same_cert_covering_two_domains_is_clustered():
    conn = _make_db()
    case_id = _make_case(conn)
    cert = {
        "subject":       {"commonName": "scam-a.com"},
        "issuer":        {"organizationName": "Let's Encrypt", "commonName": "R3"},
        "notBefore":     "Apr 15 00:00:00 2026 GMT",
        "notAfter":      "Jul 14 00:00:00 2026 GMT",
        "serialNumber":  "ABC123",
        "subjectAltName": ["DNS:scam-a.com", "DNS:scam-b.com"],
    }
    _add_scan(conn, case_id, "http://x/a", "https://scam-a.com/", cert)
    _add_scan(conn, case_id, "http://x/b", "https://scam-b.com/", cert)

    result = shared_certificates(conn, case_id)
    assert len(result["by_cert"]) == 1
    cluster = result["by_cert"][0]
    assert cluster["serial"] == "ABC123"
    assert cluster["domain_count"] == 2
    assert sorted(cluster["domains"]) == ["scam-a.com", "scam-b.com"]
    assert cluster["san_count"] == 2
    assert "Let's Encrypt" in cluster["issuer"]


def test_single_domain_on_cert_is_not_clustered():
    """A cert observed only on one domain in this case should not appear in by_cert."""
    conn = _make_db()
    case_id = _make_case(conn)
    cert = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr 15 00:00:00 2026 GMT",
        "notAfter":     "Jul 14 00:00:00 2026 GMT",
        "serialNumber": "SOLO",
    }
    _add_scan(conn, case_id, "http://x/a", "https://only.com/", cert)
    _add_scan(conn, case_id, "http://x/b", "https://only.com/page2", cert)
    result = shared_certificates(conn, case_id)
    assert result["by_cert"] == []


def test_certs_issued_within_24h_cluster_in_by_issuance():
    conn = _make_db()
    case_id = _make_case(conn)
    cert_a = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr 15 00:00:00 2026 GMT",
        "notAfter":     "Jul 14 00:00:00 2026 GMT",
        "serialNumber": "SERIAL_A",
    }
    cert_b = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr 15 18:00:00 2026 GMT",
        "notAfter":     "Jul 14 18:00:00 2026 GMT",
        "serialNumber": "SERIAL_B",
    }
    _add_scan(conn, case_id, "http://x/a", "https://aaa.com/", cert_a)
    _add_scan(conn, case_id, "http://x/b", "https://bbb.com/", cert_b)

    result = shared_certificates(conn, case_id)
    assert result["by_cert"] == []  # different serials, neither covers 2 domains
    assert len(result["by_issuance"]) == 1
    win = result["by_issuance"][0]
    assert win["cert_count"] == 2
    assert win["domain_count"] == 2
    assert sorted(win["domains"]) == ["aaa.com", "bbb.com"]


def test_certs_issued_more_than_24h_apart_do_not_cluster():
    conn = _make_db()
    case_id = _make_case(conn)
    cert_a = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr 15 00:00:00 2026 GMT",
        "notAfter":     "Jul 14 00:00:00 2026 GMT",
        "serialNumber": "SERIAL_A",
    }
    cert_b = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr 17 00:00:00 2026 GMT",
        "notAfter":     "Jul 16 00:00:00 2026 GMT",
        "serialNumber": "SERIAL_B",
    }
    _add_scan(conn, case_id, "http://x/a", "https://aaa.com/", cert_a)
    _add_scan(conn, case_id, "http://x/b", "https://bbb.com/", cert_b)
    result = shared_certificates(conn, case_id)
    assert result["by_issuance"] == []


def test_single_digit_day_with_double_space_parses():
    """OpenSSL renders single-digit days with a leading space: 'Apr  7 ...'."""
    conn = _make_db()
    case_id = _make_case(conn)
    cert_a = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr  7 00:00:00 2026 GMT",
        "notAfter":     "Jul  6 00:00:00 2026 GMT",
        "serialNumber": "SERIAL_A",
    }
    cert_b = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr  7 12:00:00 2026 GMT",
        "notAfter":     "Jul  6 12:00:00 2026 GMT",
        "serialNumber": "SERIAL_B",
    }
    _add_scan(conn, case_id, "http://x/a", "https://aaa.com/", cert_a)
    _add_scan(conn, case_id, "http://x/b", "https://bbb.com/", cert_b)
    result = shared_certificates(conn, case_id)
    assert len(result["by_issuance"]) == 1


def test_missing_or_malformed_tls_is_skipped():
    conn = _make_db()
    case_id = _make_case(conn)
    _add_scan(conn, case_id, "http://x/a", "https://aaa.com/", None)
    # malformed tls (will fail json.loads via direct insert)
    now = _now_iso()
    cur = conn.execute(
        "INSERT INTO message_evidence (case_id, platform, permalink, actor_label, "
        "posted_at, message_text, screenshot_path, ingested_at) VALUES (?, '', '', '', '', '', '', ?)",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, url_order, created_at) "
        "VALUES (?, ?, 'http://x/b', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status, tls_info_json) "
        "VALUES (?, ?, 'https://bbb.com/', 0, 'done', '{not json')",
        (ua_id, now),
    )
    conn.commit()

    result = shared_certificates(conn, case_id)
    assert result == {"by_cert": [], "by_issuance": []}


def test_only_latest_done_scan_is_used():
    """If a URL has multiple scan_runs, only the most recent done one is considered."""
    conn = _make_db()
    case_id = _make_case(conn)
    old_cert = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Jan 01 00:00:00 2025 GMT",
        "notAfter":     "Apr 01 00:00:00 2025 GMT",
        "serialNumber": "OLD",
    }
    new_cert = {
        "issuer":       {"commonName": "Let's Encrypt"},
        "notBefore":    "Apr 15 00:00:00 2026 GMT",
        "notAfter":     "Jul 14 00:00:00 2026 GMT",
        "serialNumber": "NEW",
    }
    _, ua_id = _add_scan(conn, case_id, "http://x/a", "https://aaa.com/", old_cert)
    # add a newer scan_run for the same url_artifact with NEW cert
    now = _now_iso()
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status, tls_info_json) "
        "VALUES (?, ?, 'https://aaa.com/', 0, 'done', ?)",
        (ua_id, now, json.dumps(new_cert)),
    )
    conn.commit()

    _add_scan(conn, case_id, "http://x/b", "https://bbb.com/", new_cert)

    result = shared_certificates(conn, case_id)
    # Both URLs should now be tied to NEW cert via the latest scan_run.
    assert len(result["by_cert"]) == 1
    assert result["by_cert"][0]["serial"] == "NEW"
    assert result["by_cert"][0]["domain_count"] == 2
