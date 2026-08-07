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

from kwara.db import get_conn, init_db, migrate_db
from kwara.index_db import (
    SIGNAL_HAR_ENDPOINT,
    SIGNAL_HEADER_VALUE,
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
    _seed_scanned_url(conn, cid, "https://hubsite.example/a",
                      final_domain="hubsite.example",
                      tracking_ids={"Google Analytics 4": ["G-T5N9K2Q7W3"]},
                      cert_serial="0A1B2C", cert_issuer="Google Trust Services",
                      registrar="NameSilo", asn="13335", as_org="Cloudflare")
    sigs = extract_case_signals(conn, cid, path, "case-A")
    types = {s["signal_type"] for s in sigs}
    assert types == {SIGNAL_TRACKING_ID, SIGNAL_CERT_SERIAL, SIGNAL_REGISTRAR,
                     SIGNAL_ASN, SIGNAL_FINAL_DOMAIN}
    ga = next(s for s in sigs if s["signal_type"] == SIGNAL_TRACKING_ID)
    assert ga["signal_value"] == "G-T5N9K2Q7W3"
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
    _seed_scanned_url(conn, cid, "https://hubsite.example/a",
                      tracking_ids={"Google Analytics 4": ["G-T5N9K2Q7W3"]})
    idx = _fresh_index()
    n = index_case(idx, conn, path, cid, "case-A")
    assert n >= 1
    hits = lookup(idx, "G-T5N9K2Q7W3")
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
    _seed_scanned_url(conn, a, "https://hubsite.example/x",
                      tracking_ids={"Google Analytics 4": ["G-SHARED"]})
    _seed_scanned_url(conn, b, "https://satellitesite.example/y",
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


def test_recurring_signals_separates_real_recurrence_from_overlapping_cases():
    """A signal on ONE domain that merely spans two overlapping cases has not
    resurfaced — it has been indexed twice. Measured on the 2026-08-05 index,
    99 of 119 recurring ads.txt accounts were exactly that, so domain_count is
    reported and ranks above case_count.
    """
    conn = get_index_conn(os.path.join(tempfile.mkdtemp(), "i.db"))

    def put(value, case_id, domain, srid):
        conn.execute(
            """INSERT OR REPLACE INTO signals (signal_type, signal_value,
               platform, source_db, case_id, case_title, scan_run_id,
               final_domain, observed_at, indexed_at)
               VALUES ('ads_txt_seller', ?, NULL, '/db', ?, 't', ?, ?, 'n', 'n')""",
            (value, case_id, srid, domain))

    # same domain, two overlapping cases — bookkeeping, not a recurrence
    put("pub-DUP", 1, "one.com", 1)
    put("pub-DUP", 2, "one.com", 2)
    # two distinct domains — a genuine cross-case recurrence
    put("pub-REAL", 1, "one.com", 3)
    put("pub-REAL", 2, "two.com", 4)
    conn.commit()

    rows = {r["signal_value"]: r for r in recurring_signals(conn)}
    assert rows["pub-DUP"]["case_count"] == 2
    assert rows["pub-DUP"]["domain_count"] == 1
    assert rows["pub-REAL"]["domain_count"] == 2
    # genuine recurrence ranks first
    assert recurring_signals(conn)[0]["signal_value"] == "pub-REAL"
    # and can be isolated outright
    strict = [r["signal_value"] for r in recurring_signals(conn, min_domains=2)]
    assert strict == ["pub-REAL"]


def _seed_snapshot_with_hosts(conn, case_id, landing, hosts):
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pid = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?,'','','','','','',?)""", (case_id, now)).lastrowid
    ua = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?,?,?,'',0,?)",
        (pid, case_id, f"https://{landing}/", now)).lastrowid
    sr = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?,?,?,0,'done')", (ua, now, f"https://{landing}/")).lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain, captured_at,
           capture_method, capture_status, request_domains_json)
           VALUES (?,?,?,?,'playwright','ok',?)""",
        (sr, f"https://{landing}/", landing, now, json.dumps(hosts)))
    conn.commit()


def test_har_endpoints_are_indexed_as_apexes_not_hostnames():
    """SSPs and CDNs hand out per-request subdomains — UUID-prefixed
    `t.ssp.*`, `rr2---sn-*.googlevideo.com`. Those are rare by construction and
    meaningless, and on the 2026-08-06 corpus they dominated everything that
    looked rare. Normalising to the registrable domain collapsed 402 hostnames
    to 180 and removed the whole noise class."""
    conn, _ = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_snapshot_with_hosts(conn, cid, "farm.com", [
        "aaaa-1111.t.ssp.example.com",
        "bbbb-2222.t.ssp.example.com",
        "cdn.operator-backend.net",
    ])
    vals = {s["signal_value"] for s in
            extract_case_signals(conn, cid, source_db="/tmp/x.db")
            if s["signal_type"] == SIGNAL_HAR_ENDPOINT}
    # both UUID hosts collapse to ONE value — that is the whole point
    assert vals == {"example.com", "operator-backend.net"}


def test_har_endpoint_skips_the_landing_domain_itself():
    """Self-reference by APEX: the hostname test elsewhere misses
    statics.hubsite.example when the landing is www.hubsite.example."""
    conn, _ = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_snapshot_with_hosts(conn, cid, "www.farm.com",
                              ["statics.farm.com", "farm.com", "third.party.net"])
    vals = {s["signal_value"] for s in
            extract_case_signals(conn, cid, source_db="/tmp/x.db")
            if s["signal_type"] == SIGNAL_HAR_ENDPOINT}
    assert vals == {"party.net"}


def test_har_endpoint_drops_whitelisted_noise():
    conn, _ = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_snapshot_with_hosts(conn, cid, "farm.com",
                              ["fonts.googleapis.com", "real.example.org"])
    vals = {s["signal_value"] for s in
            extract_case_signals(conn, cid, source_db="/tmp/x.db")
            if s["signal_type"] == SIGNAL_HAR_ENDPOINT}
    assert vals == {"example.org"}


def test_operator_cross_links_finds_an_endpoint_that_is_also_a_landing():
    """The one endpoint read that needs no threshold. Found on the real index:
    three QSH landings load from statics.privatecdn.example and s1.privatecdn2.example, the
    01-family cluster's private CDN — a link that had sat in the HAR for three
    months and contradicted a conclusion drawn from ads.txt alone."""
    from kwara.index_db import operator_cross_links
    conn = get_index_conn(os.path.join(tempfile.mkdtemp(), "i.db"))

    def put(stype, value, domain, case_id=1, srid=1):
        conn.execute(
            """INSERT OR REPLACE INTO signals (signal_type, signal_value, platform,
               source_db, case_id, case_title, scan_run_id, final_domain,
               observed_at, indexed_at)
               VALUES (?,?,NULL,'/db',?,'t',?,?,'n','n')""",
            (stype, value, case_id, srid, domain))

    put(SIGNAL_FINAL_DOMAIN, "assets.example", "assets.example", case_id=2)
    put(SIGNAL_HAR_ENDPOINT, "assets.example", "farm-a.com", srid=1)
    put(SIGNAL_HAR_ENDPOINT, "assets.example", "farm-b.com", srid=2)
    put(SIGNAL_HAR_ENDPOINT, "cdn.unrelated", "farm-a.com", srid=3)
    conn.commit()

    links = operator_cross_links(conn)
    assert [l["endpoint"] for l in links] == ["assets.example"]
    assert links[0]["called_by"] == ["farm-a.com", "farm-b.com"]
    assert links[0]["investigated_as_landing_in"][0]["case_id"] == 2


def test_cross_links_ignore_a_domain_loading_its_own_assets():
    from kwara.index_db import operator_cross_links
    conn = get_index_conn(os.path.join(tempfile.mkdtemp(), "i.db"))
    conn.execute(
        """INSERT INTO signals (signal_type, signal_value, platform, source_db,
           case_id, case_title, scan_run_id, final_domain, observed_at, indexed_at)
           VALUES (?,?,NULL,'/db',1,'t',1,?,'n','n')""",
        (SIGNAL_FINAL_DOMAIN, "farm.com", "farm.com"))
    conn.execute(
        """INSERT INTO signals (signal_type, signal_value, platform, source_db,
           case_id, case_title, scan_run_id, final_domain, observed_at, indexed_at)
           VALUES (?,?,NULL,'/db',1,'t',2,?,'n','n')""",
        (SIGNAL_HAR_ENDPOINT, "farm.com", "www.farm.com"))
    conn.commit()
    assert operator_cross_links(conn) == []


# ── response headers that identify a deployment ────────────────────────────

def _seed_header_scan(conn, case_id, landing, headers):
    """`headers` given as a dict for readability; redirect_hops stores the
    wire order as [[key, value], ...], which is what the analysis reads."""
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pid = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?,'','','','','','',?)""", (case_id, now)).lastrowid
    ua = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?,?,?,'',0,?)",
        (pid, case_id, f"https://{landing}/", now)).lastrowid
    sr = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?,?,?,1,'done')", (ua, now, f"https://{landing}/")).lastrowid
    # Two hops: per_domain_constants requires min_observations=2 before it
    # will call a header constant — one sighting is not evidence of stability.
    for hop in (0, 1):
        conn.execute(
            """INSERT INTO redirect_hops (scan_run_id, hop_order, url, status_code,
               resolved_url, fetched_at, response_headers_json)
               VALUES (?,?,?,200,?,?,?)""",
            (sr, hop, f"https://{landing}/", f"https://{landing}/", now,
             json.dumps([[k, v] for k, v in headers.items()])))
    conn.commit()


def test_origin_leaking_header_is_remembered_across_cases():
    """The design doc rates a shared server template alongside a shared GA4 ID,
    but until 2026-08-06 only the GA4 ID was indexed — so an origin leaking out
    from behind Cloudflare vanished when the case closed."""
    conn, _ = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_header_scan(conn, cid, "farm.com", {
        "x-server-hosted": "Malaysia Cloud Pte Ltd",
        "x-powered-by": "Apache/2.5.1 (Win64) OpenSSL/1.1.2e",
    })
    vals = {(s["platform"], s["signal_value"]) for s in
            extract_case_signals(conn, cid, source_db="/tmp/x.db")
            if s["signal_type"] == SIGNAL_HEADER_VALUE}
    assert ("x-server-hosted", "Malaysia Cloud Pte Ltd") in vals
    assert ("x-powered-by", "Apache/2.5.1 (Win64) OpenSSL/1.1.2e") in vals


def test_protocol_furniture_and_fixed_vocabulary_headers_are_skipped():
    """Values from a fixed vocabulary match any two unrelated hosts."""
    conn, _ = _fresh_case_db()
    cid = _seed_case(conn)
    _seed_header_scan(conn, cid, "farm.com", {
        "content-type": "text/html; charset=UTF-8",   # protocol furniture
        "x-frame-options": "SAMEORIGIN",              # fixed vocabulary
        "x-content-type-options": "nosniff",
        "server": "cloudflare",                       # universal infra token
        "x-drupal-cache": "MISS",                     # value carries nothing
        "x-age": "0",
    })
    assert not [s for s in extract_case_signals(conn, cid, source_db="/tmp/x.db")
                if s["signal_type"] == SIGNAL_HEADER_VALUE]
