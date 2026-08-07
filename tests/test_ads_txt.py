"""Tests for adstxt.py — parsing + fetch/store (Phase 8)."""
import json
import os
import tempfile
from datetime import datetime, timezone

from kwara import adstxt
from kwara.adstxt import _ads_txt_url, fetch_and_store_ads_txt, parse_ads_txt
from kwara.db import get_conn, init_db, migrate_db


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── parse_ads_txt ──────────────────────────────────────────────────────────

def test_parse_direct_and_reseller_split():
    text = (
        "google.com, pub-1234567890, DIRECT, f08c47fec0942fa0\n"
        "pubmatic.com, 160987, RESELLER, 5d62403b186f2ace\n"
    )
    records, variables = parse_ads_txt(text)
    assert len(records) == 2
    assert records[0] == {
        "adsystem": "google.com",
        "seller_id": "pub-1234567890",
        "relationship": "DIRECT",
        "cert_authority_id": "f08c47fec0942fa0",
    }
    assert records[1]["relationship"] == "RESELLER"
    assert variables == {}


def test_parse_relationship_normalised_uppercase():
    records, _ = parse_ads_txt("taboola.com, 1054426, direct\n")
    assert records[0]["relationship"] == "DIRECT"


def test_parse_optional_cert_authority_id_absent():
    records, _ = parse_ads_txt("genieegroup.com, 23045857909, DIRECT\n")
    assert records[0]["cert_authority_id"] is None


def test_parse_owner_and_manager_domain_variables():
    text = (
        "OWNERDOMAIN=example.com\n"
        "MANAGERDOMAIN=manager.example, EXCHANGE\n"
        "google.com, pub-1, DIRECT\n"
    )
    records, variables = parse_ads_txt(text)
    assert variables["owner_domain"] == "example.com"
    # the optional ", exchange" suffix is stripped
    assert variables["manager_domain"] == "manager.example"
    assert len(records) == 1


def test_parse_ignores_comments_and_blanks():
    text = (
        "# this is a contact comment\n"
        "\n"
        "google.com, pub-1, DIRECT  # inline comment\n"
        "   \n"
    )
    records, _ = parse_ads_txt(text)
    assert len(records) == 1
    assert records[0]["seller_id"] == "pub-1"


def test_parse_negative_garbage_rows_skipped():
    """Contract 4 analogue: rows that aren't valid ads.txt data are dropped,
    not coerced into phantom records."""
    text = (
        "not a real ads txt line\n"          # < 3 fields
        "onlytwo, fields\n"                  # < 3 fields
        ", , DIRECT\n"                       # empty adsystem + seller
        "<html><body>404</body></html>\n"    # an error page, not ads.txt
    )
    records, variables = parse_ads_txt(text)
    assert records == []
    assert variables == {}


def test_parse_empty_string():
    assert parse_ads_txt("") == ([], {})


# ── _ads_txt_url ───────────────────────────────────────────────────────────

def test_ads_txt_url_built_from_root():
    assert _ads_txt_url("https://a.com/landing?x=1") == "https://a.com/ads.txt"


def test_ads_txt_url_preserves_scheme_and_port():
    assert _ads_txt_url("http://a.com:8080/p") == "http://a.com:8080/ads.txt"


def test_ads_txt_url_none_without_host():
    assert _ads_txt_url("") is None
    assert _ads_txt_url("not-a-url") is None


# ── fetch_and_store_ads_txt (stubbed network) ──────────────────────────────

def _make_scan_run(conn, final_url):
    now = _now()
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
        ("t", "", now, now),
    )
    case_id = cur.lastrowid
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'http://x/a', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, now, final_url),
    )
    conn.commit()
    return case_id, cur.lastrowid


def _make_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def test_fetch_and_store_writes_scan_run_and_skips_when_present(monkeypatch):
    conn = _make_db()
    _, sr_id = _make_scan_run(conn, "https://a.com/")

    calls = {"n": 0}

    def fake_fetch(final_url, timeout):
        calls["n"] += 1
        return {"status": "ok", "status_code": 200, "raw_sha256": "abc",
                "records": [{"adsystem": "google.com", "seller_id": "pub-1",
                             "relationship": "DIRECT", "cert_authority_id": None}],
                "record_count": 1, "owner_domain": None, "manager_domain": None}

    monkeypatch.setattr(adstxt, "_fetch_ads_txt", fake_fetch)

    result = fetch_and_store_ads_txt(conn, sr_id)
    assert result["status"] == "ok"
    stored = conn.execute(
        "SELECT ads_txt_json FROM scan_runs WHERE id = ?", (sr_id,)
    ).fetchone()["ads_txt_json"]
    assert json.loads(stored)["records"][0]["seller_id"] == "pub-1"

    # Second call without force is a no-op (no new fetch).
    fetch_and_store_ads_txt(conn, sr_id)
    assert calls["n"] == 1

    # force=True re-fetches.
    fetch_and_store_ads_txt(conn, sr_id, force=True)
    assert calls["n"] == 2


def test_fetch_and_store_records_non_200(monkeypatch):
    conn = _make_db()
    _, sr_id = _make_scan_run(conn, "https://blocked.com/")

    def fake_fetch(final_url, timeout):
        return {"status": "non_200", "status_code": 403, "raw_sha256": "0" * 64,
                "records": [], "record_count": 0}

    monkeypatch.setattr(adstxt, "_fetch_ads_txt", fake_fetch)
    result = fetch_and_store_ads_txt(conn, sr_id)
    assert result["status_code"] == 403  # 403 is itself an OPSEC signal, recorded


def test_fetch_and_store_none_when_no_scan_run():
    conn = _make_db()
    assert fetch_and_store_ads_txt(conn, 99999) is None


def test_fetch_and_store_none_when_no_final_url(monkeypatch):
    conn = _make_db()
    _, sr_id = _make_scan_run(conn, None)
    monkeypatch.setattr(adstxt, "_fetch_ads_txt",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not fetch")))
    assert fetch_and_store_ads_txt(conn, sr_id) is None
