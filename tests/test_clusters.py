"""Tests for clusters.py — the group-centric model.

Locks the core guarantee: hard signals partition domains into groups, and
nothing (weak header templates, generic values) silently merges them.
"""
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone

from kwara import clusters
from kwara.clusters import (
    TIER_CONFIRMED,
    _channel,
    _components,
    _is_generic_weak,
    case_clusters,
    group_color,
    node_id,
)
from kwara.db import get_conn, init_db, migrate_db


# ── Pure graph logic ──────────────────────────────────────────────────────
def test_components_disjoint_signals_stay_separate():
    sigs = [{"domains": ["a", "b"]}, {"domains": ["c", "d"]}]
    comps = _components(sigs)
    assert sorted(sorted(c) for c in comps) == [["a", "b"], ["c", "d"]]


def test_components_shared_domain_merges_transitively():
    # a-b via signal 1, b-c via signal 2  ->  one component {a,b,c}
    sigs = [{"domains": ["a", "b"]}, {"domains": ["b", "c"]}]
    comps = _components(sigs)
    assert len(comps) == 1
    assert sorted(comps[0]) == ["a", "b", "c"]


def test_components_empty():
    assert _components([]) == []


def test_node_id_stable_and_safe():
    # Reproducible across calls (unlike Python hash()), DOT-safe.
    a = node_id("dom", "hubsite.example")
    b = node_id("dom", "hubsite.example")
    assert a == b
    assert a.startswith("dom_")
    assert node_id("dom", "x.com") != node_id("dom", "y.com")


def test_group_color_cycles_and_is_stable():
    assert group_color(1) == group_color(1)
    assert group_color(1) != group_color(2)


def test_universal_infra_dropped_even_on_small_case():
    # Regression for the 2026-06-11 independent-batch validation: on a 4-domain
    # case "server: cloudflare" sat at 3/4 = 0.75 < 0.8 breadth and leaked
    # through. The universal-infra floor must catch it regardless of breadth.
    assert _is_generic_weak("cloudflare", 0.75) is True
    assert _is_generic_weak("nginx", 0.5) is True
    # A distinctive value at the SAME breadth must be kept (not over-dropped).
    assert _is_generic_weak("Malaysia Cloud Pte Ltd", 0.75) is False
    # Breadth still drops any ubiquitous (even non-listed) value.
    assert _is_generic_weak("custom-stack-x", 0.85) is True
    assert _is_generic_weak("custom-stack-x", 0.30) is False


def test_channel_maps_platform_to_disposition():
    assert "Google" in _channel("tracking", "Google Analytics 4")
    assert "AdSense" in _channel("tracking", "Google AdSense")
    assert "Meta" in _channel("tracking", "Meta Facebook Page")
    assert "Cloudflare" in _channel("cert")
    assert "SSP" in _channel("ads_account")


# ── Integration over a seeded DB ──────────────────────────────────────────
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


def _add(conn, case_id, final_url, final_domain, tracking_ids=None,
         tls=None, ads=None):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, final_url, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, final_url, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, now, final_url),
    )
    sr_id = cur.lastrowid
    if tls is not None:
        conn.execute("UPDATE scan_runs SET tls_info_json = ? WHERE id = ?",
                     (json.dumps(tls), sr_id))
    if ads is not None:
        conn.execute("UPDATE scan_runs SET ads_txt_json = ? WHERE id = ?",
                     (json.dumps(ads), sr_id))
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, tracking_ids_json)
           VALUES (?, ?, ?, ?, 'ok', ?)""",
        (sr_id, final_url, final_domain, now,
         json.dumps(tracking_ids) if tracking_ids is not None else None),
    )
    conn.commit()


def test_empty_case_has_no_groups():
    conn = _make_db()
    cid = _make_case(conn)
    m = case_clusters(conn, cid)
    assert m["groups"] == []
    assert m["n_urls"] == 0


def test_two_disjoint_operators_yield_two_groups():
    conn = _make_db()
    cid = _make_case(conn)
    # Group A: GA4 G-AAA across a.com, b.com
    _add(conn, cid, "https://a.com/", "a.com", {"Google Analytics 4": ["G-AAA"]})
    _add(conn, cid, "https://b.com/", "b.com", {"Google Analytics 4": ["G-AAA"]})
    # Group B: Meta Page across c.com, d.com — no overlap with A
    _add(conn, cid, "https://c.com/", "c.com", {"Meta Facebook Page": ["111"]})
    _add(conn, cid, "https://d.com/", "d.com", {"Meta Facebook Page": ["111"]})

    m = case_clusters(conn, cid)
    assert len(m["groups"]) == 2
    # Largest-first ordering; both have 2 domains here.
    sizes = sorted(g["domain_count"] for g in m["groups"])
    assert sizes == [2, 2]
    for g in m["groups"]:
        assert g["tier"] == TIER_CONFIRMED
        assert g["signal_count"] >= 1
        # every signal is named and carries a disposition channel
        for s in g["signals"]:
            assert s["value"]
            assert s["channel"]


def test_shared_id_bridges_domains_into_one_group():
    conn = _make_db()
    cid = _make_case(conn)
    # a-b share G-AAA; b-c share G-BBB  ->  a,b,c are one operator group
    _add(conn, cid, "https://a.com/", "a.com", {"Google Analytics 4": ["G-AAA"]})
    _add(conn, cid, "https://b.com/", "b.com",
         {"Google Analytics 4": ["G-AAA", "G-BBB"]})
    _add(conn, cid, "https://c.com/", "c.com", {"Google Analytics 4": ["G-BBB"]})

    m = case_clusters(conn, cid)
    assert len(m["groups"]) == 1
    assert m["groups"][0]["domain_count"] == 3
    assert sorted(m["groups"][0]["domains"]) == ["a.com", "b.com", "c.com"]


def test_grouping_works_without_tracking_ids_via_cert():
    # Non-tracking path: a shared TLS cert (same issuer+serial) must group
    # domains on its own — proves the model isn't tracking-ID-only.
    conn = _make_db()
    cid = _make_case(conn)
    cert = {"serialNumber": "AA:BB:CC:DD", "issuer": {"O": "Test CA"},
            "notBefore": "", "notAfter": "", "subjectAltName": []}
    _add(conn, cid, "https://a.com/", "a.com", tracking_ids=None, tls=cert)
    _add(conn, cid, "https://b.com/", "b.com", tracking_ids=None, tls=cert)
    m = case_clusters(conn, cid)
    assert len(m["groups"]) == 1
    g = m["groups"][0]
    assert g["domain_count"] == 2
    assert any(s["type"] == "cert" for s in g["signals"])


def test_grouping_works_via_ads_txt_template(tmp_path, monkeypatch):
    """Non-tracking path: byte-identical ads.txt groups the domains — but ONLY
    when the response bytes are retained and still hash to what the derived
    record claims. Byte-identity is the entire claim, so a cluster that cannot
    show the bytes cannot make it."""
    from kwara import acquisition as acq
    from kwara import config

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    conn = _make_db()
    cid = _make_case(conn)
    body = b"google.com, pub-1, DIRECT\n"
    sha = hashlib.sha256(body).hexdigest()
    ads = {"status": "ok", "raw_sha256": sha,
           "records": [{"adsystem": "google.com", "seller_id": "pub-1",
                        "relationship": "DIRECT"}]}
    for host in ("a.com", "b.com"):
        _add(conn, cid, f"https://{host}/", host, tracking_ids=None, ads=ads)
        sr = conn.execute("SELECT id FROM scan_runs ORDER BY id DESC "
                          "LIMIT 1").fetchone()["id"]
        aid = acq.record_fetch(conn, scan_run_id=sr,
                               requested_url=f"https://{host}/ads.txt",
                               status="ok", status_code=200, body=body)
        conn.execute("UPDATE scan_runs SET ads_txt_json=? WHERE id=?",
                     (json.dumps({**ads, "acquisition_id": aid}), sr))
    conn.commit()

    m = case_clusters(conn, cid)
    assert len(m["groups"]) == 1
    assert any(s["type"] == "ads_template" for s in m["groups"][0]["signals"])


def test_an_unretained_template_does_not_bind_a_group(tmp_path, monkeypatch):
    """Everything fetched before 2026-08-12 is in this state. The observation
    is still real and still reported; it just cannot merge operator groups,
    because nobody can now show the two files were byte-identical."""
    from kwara import config

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    conn = _make_db()
    cid = _make_case(conn)
    ads = {"status": "ok", "raw_sha256": "deadbeefcafe0001",
           "records": [{"adsystem": "google.com", "seller_id": "pub-1",
                        "relationship": "DIRECT"}]}
    _add(conn, cid, "https://a.com/", "a.com", tracking_ids=None, ads=ads)
    _add(conn, cid, "https://b.com/", "b.com", tracking_ids=None, ads=ads)

    m = case_clusters(conn, cid)
    assert not any(s["type"] == "ads_template"
                   for g in m["groups"] for s in g["signals"]), \
        "an unverifiable template merged an operator group"

    # ...but it is not hidden. The observation survives with its verdict.
    from kwara.clustering_infra import shared_ad_accounts
    t = shared_ad_accounts(conn, cid)["by_template"][0]
    assert t["domain_count"] == 2
    assert t["verification"] == "legacy_unverifiable"


def test_completeness_flags_missing_ads_txt():
    conn = _make_db()
    cid = _make_case(conn)
    _add(conn, cid, "https://a.com/", "a.com", {"Google Analytics 4": ["G-AAA"]})
    _add(conn, cid, "https://b.com/", "b.com", {"Google Analytics 4": ["G-AAA"]})
    comp = case_clusters(conn, cid)["completeness"]
    assert "ads_txt" in comp["gaps"]
    assert comp["level"] in ("低", "中", "高")
    assert comp["present"]["page_captured"] is True  # snapshots seeded


def test_cloaking_count_is_pending_not_asserted():
    conn = _make_db()
    cid = _make_case(conn)
    _add(conn, cid, "https://a.com/", "a.com", {"Google Analytics 4": ["G-AAA"]})
    b = case_clusters(conn, cid)["behaviour"]
    # framed as pending review, never an assertion
    assert "cloaking_pending" in b
