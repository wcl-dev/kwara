"""Tests for clustering_infra.shared_ad_accounts() + index_db ads.txt signals."""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone

from clustering_infra import shared_ad_accounts
from db import get_conn, init_db, migrate_db
from index_db import (
    SIGNAL_ADS_TXT_SELLER,
    SIGNAL_ADS_TXT_TEMPLATE,
    extract_case_signals,
)
from param_attribution import PLATFORM_ADS_TXT_SELLER


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


def _ads_json(direct_sellers, *, sha=None, status="ok", raw_text=None):
    """Build a stored ads_txt_json dict. direct_sellers: list of
    (adsystem, seller_id). sha defaults to a hash of the seller list unless
    raw_text is given (use raw_text to force identical/different templates)."""
    records = [
        {"adsystem": a, "seller_id": s, "relationship": "DIRECT",
         "cert_authority_id": None}
        for a, s in direct_sellers
    ]
    if sha is None:
        basis = raw_text if raw_text is not None else json.dumps(direct_sellers)
        sha = hashlib.sha256(basis.encode()).hexdigest()
    return {
        "url": "https://x/ads.txt",
        "status": status,
        "status_code": 200 if status == "ok" else 403,
        "raw_sha256": sha,
        "records": records,
        "record_count": len(records),
        "owner_domain": None,
        "manager_domain": None,
    }


def _add(conn, case_id, final_url, final_domain, ads_dict):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, final_url, now),
    )
    ua_id = cur.lastrowid
    ads_json = json.dumps(ads_dict) if ads_dict is not None else None
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status, ads_txt_json) VALUES (?, ?, ?, 0, 'done', ?)",
        (ua_id, now, final_url, ads_json),
    )
    conn.commit()


# ── shared_ad_accounts: by_account ─────────────────────────────────────────

def test_empty_case():
    conn = _make_db()
    case_id = _make_case(conn)
    res = shared_ad_accounts(conn, case_id)
    assert res == {"by_account": [], "by_template": []}


def test_shared_direct_account_clusters_two_domains():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://a.com/", "a.com",
         _ads_json([("clickforce.com.tw", "873")], raw_text="a"))
    _add(conn, case_id, "https://b.com/", "b.com",
         _ads_json([("clickforce.com.tw", "873")], raw_text="b"))
    res = shared_ad_accounts(conn, case_id)
    assert len(res["by_account"]) == 1
    a = res["by_account"][0]
    assert a["platform_id"] == PLATFORM_ADS_TXT_SELLER
    assert a["adsystem"] == "clickforce.com.tw"
    assert a["seller_id"] == "873"
    assert a["domain_count"] == 2
    assert sorted(a["domains"]) == ["a.com", "b.com"]


def test_singleton_account_excluded():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://a.com/", "a.com",
         _ads_json([("tenmax.io", "fadcc2")], raw_text="a"))
    assert shared_ad_accounts(conn, case_id)["by_account"] == []


def test_breadth_weighting_operator_vs_manager():
    """An account on a rare subset is operator-tier; one on every domain is
    manager-tier."""
    conn = _make_db()
    case_id = _make_case(conn)
    # 5 domains, each unique template (different raw_text).
    domains = ["a.com", "b.com", "c.com", "d.com", "e.com"]
    # manager account appears on ALL 5; operator account on only 2.
    for i, d in enumerate(domains):
        sellers = [("google.com", "pub-MANAGER")]
        if d in ("a.com", "b.com"):
            sellers.append(("clickforce.com.tw", "pub-OPERATOR"))
        _add(conn, case_id, f"https://{d}/", d,
             _ads_json(sellers, raw_text=f"unique-{i}"))
    res = shared_ad_accounts(conn, case_id)
    tiers = {(a["adsystem"], a["seller_id"]): a["tier"] for a in res["by_account"]}
    assert tiers[("google.com", "pub-MANAGER")] == "manager"   # 5/5 = 1.0 >= 0.8
    assert tiers[("clickforce.com.tw", "pub-OPERATOR")] == "operator"  # 2/5 = 0.4
    # operator-tier sorts first
    assert res["by_account"][0]["tier"] == "operator"


def test_only_direct_lines_feed_accounts():
    """RESELLER lines must not create account clusters."""
    conn = _make_db()
    case_id = _make_case(conn)
    ads = {
        "url": "https://a/ads.txt", "status": "ok", "status_code": 200,
        "raw_sha256": "h1",
        "records": [{"adsystem": "pubmatic.com", "seller_id": "160987",
                     "relationship": "RESELLER", "cert_authority_id": None}],
        "record_count": 1, "owner_domain": None, "manager_domain": None,
    }
    ads2 = dict(ads, raw_sha256="h2")
    _add(conn, case_id, "https://a.com/", "a.com", ads)
    _add(conn, case_id, "https://b.com/", "b.com", ads2)
    assert shared_ad_accounts(conn, case_id)["by_account"] == []


def test_malformed_ads_json_skipped():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://a.com/", "a.com", _ads_json([("g.com", "1")], raw_text="a"))
    # second row with bad JSON
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'https://b.com/', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status, ads_txt_json) VALUES (?, ?, 'https://b.com/', 0, 'done', '{bad json')",
        (ua_id, now),
    )
    conn.commit()
    # only a.com parses → singleton → no cluster, no crash
    assert shared_ad_accounts(conn, case_id)["by_account"] == []


# ── shared_ad_accounts: by_template ────────────────────────────────────────

def test_identical_template_clusters():
    conn = _make_db()
    case_id = _make_case(conn)
    # three domains serve a byte-identical ads.txt (same sha) but DIFFERENT
    # sellers wouldn't matter — sha is the key.
    same = _ads_json([("g.com", "pub-x")], sha="IDENTICALSHA256")
    _add(conn, case_id, "https://a.com/", "a.com", same)
    _add(conn, case_id, "https://b.com/", "b.com", same)
    _add(conn, case_id, "https://c.com/", "c.com",
         _ads_json([("g.com", "pub-y")], sha="DIFFERENT"))
    res = shared_ad_accounts(conn, case_id)
    assert len(res["by_template"]) == 1
    t = res["by_template"][0]
    assert t["domain_count"] == 3 - 1  # a + b share; c is alone
    assert sorted(t["domains"]) == ["a.com", "b.com"]


def test_non_200_excluded_from_template_and_breadth():
    """A 403 ads.txt has a body hash but no records — it must not count as an
    ads.txt-bearing domain."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://a.com/", "a.com",
         _ads_json([("g.com", "1")], raw_text="a"))
    _add(conn, case_id, "https://blocked.com/", "blocked.com",
         _ads_json([], sha="403sha", status="non_200"))
    res = shared_ad_accounts(conn, case_id)
    assert res["by_template"] == []  # blocked.com doesn't count
    assert res["by_account"] == []   # a.com is a singleton


# ── index_db ads.txt extraction (operator-only) ────────────────────────────

def test_index_emits_operator_seller_not_manager():
    conn = _make_db()
    case_id = _make_case(conn)
    domains = ["a.com", "b.com", "c.com", "d.com", "e.com"]
    for i, d in enumerate(domains):
        sellers = [("google.com", "pub-MANAGER")]
        if d in ("a.com", "b.com"):
            sellers.append(("clickforce.com.tw", "pub-OPERATOR"))
        _add(conn, case_id, f"https://{d}/", d,
             _ads_json(sellers, raw_text=f"unique-{i}"))

    signals = extract_case_signals(conn, case_id, source_db="/tmp/x.db")
    sellers = {(s["signal_value"], s["platform"]) for s in signals
               if s["signal_type"] == SIGNAL_ADS_TXT_SELLER}
    # operator account indexed, manager account excluded
    assert ("pub-OPERATOR", "clickforce.com.tw") in sellers
    assert not any(v == "pub-MANAGER" for v, _ in sellers)


def test_index_emits_template_hashes():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://a.com/", "a.com",
         _ads_json([("g.com", "1")], sha="SHA_A"))
    _add(conn, case_id, "https://b.com/", "b.com",
         _ads_json([("g.com", "1")], sha="SHA_A"))
    signals = extract_case_signals(conn, case_id, source_db="/tmp/x.db")
    tmpl = [s["signal_value"] for s in signals
            if s["signal_type"] == SIGNAL_ADS_TXT_TEMPLATE]
    assert tmpl.count("SHA_A") == 2  # one per domain — cross-case match fodder
