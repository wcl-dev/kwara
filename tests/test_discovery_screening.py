"""discovery.screen_ads_txt() — the cheap first-stage discriminator.

Screening is exact-template only, on purpose. The measurement behind that
choice (2026-08-05, 31 apexes): byte-identical ads.txt clustered 14 of them
into 5 sibling groups, while "shared rare account" scoring collapsed — bigpublisher1
and bigpublisher2 shared 216 supposedly-rare accounts purely for carrying the two
fattest ads.txt files in a small pool. These tests lock in the exact-match
rule and, just as importantly, that a miss is never reported as clean.
"""
import os
import sqlite3
import tempfile

from kwara.discovery import (
    VERDICT_NO_ADS_TXT,
    VERDICT_NO_MATCH,
    VERDICT_OFF_SITE,
    VERDICT_TEMPLATE_MATCH,
    VERDICT_UNREACHABLE,
    cluster_by_template,
    known_templates,
    screen_ads_txt,
)
from kwara.index_db import SIGNAL_ADS_TXT_SELLER, SIGNAL_ADS_TXT_TEMPLATE, get_index_conn


def _ads(sha, *, status="ok", n=3):
    return {"status": status, "raw_sha256": sha,
            "records": [{"adsystem": "x.com", "seller_id": str(i),
                         "relationship": "DIRECT"} for i in range(n)]}


# ── screen_ads_txt ────────────────────────────────────────────────────────

def test_exact_template_match_promotes_and_names_the_siblings():
    known = {"SHA_FARM": ["visitor-landing.example", "crawler-landing.example"]}
    out = screen_ads_txt(_ads("SHA_FARM"), known)
    assert out["verdict"] == VERDICT_TEMPLATE_MATCH
    assert out["matched_sha"] == "SHA_FARM"
    assert out["matched_domains"] == ["visitor-landing.example", "crawler-landing.example"]


def test_unknown_template_is_no_match_not_clean():
    """The stage can promote, never exonerate — a miss must stay a miss."""
    out = screen_ads_txt(_ads("SHA_UNSEEN"), {"SHA_FARM": ["a.com"]})
    assert out["verdict"] == VERDICT_NO_MATCH
    assert out["matched_domains"] == []


def test_blocked_ads_txt_is_distinct_from_no_match():
    """A 403 is itself an OPSEC signal (a farm behind a challenge still
    matters), so it must not be folded into the ordinary miss bucket."""
    out = screen_ads_txt(_ads("SHA_403", status="non_200", n=0), {})
    assert out["verdict"] == VERDICT_NO_ADS_TXT
    assert out["status"] == "non_200"


def test_fetch_error_is_unreachable():
    assert screen_ads_txt(_ads("x", status="error", n=0), {})["verdict"] == \
        VERDICT_UNREACHABLE
    assert screen_ads_txt(None, {})["verdict"] == VERDICT_UNREACHABLE


def test_ok_status_with_no_records_does_not_match_on_hash_alone():
    """An empty 200 body must not template-match: a blank ads.txt is shared by
    countless unrelated parked domains."""
    known = {"SHA_EMPTY": ["parked.com"]}
    out = screen_ads_txt(_ads("SHA_EMPTY", n=0), known)
    assert out["verdict"] != VERDICT_TEMPLATE_MATCH


# ── known_templates ───────────────────────────────────────────────────────

def _index():
    td = tempfile.mkdtemp()
    return get_index_conn(os.path.join(td, "index.db"))


def _put(conn, stype, value, domain):
    conn.execute(
        """INSERT OR REPLACE INTO signals (signal_type, signal_value, platform,
           source_db, case_id, case_title, scan_run_id, final_domain,
           observed_at, indexed_at)
           VALUES (?, ?, NULL, '/db', 1, 't', ?, ?, 'now', 'now')""",
        (stype, value, abs(hash((value, domain))) % 10_000, domain),
    )
    conn.commit()


def test_known_templates_groups_domains_by_hash():
    conn = _index()
    _put(conn, SIGNAL_ADS_TXT_TEMPLATE, "SHA_A", "one.com")
    _put(conn, SIGNAL_ADS_TXT_TEMPLATE, "SHA_A", "two.com")
    _put(conn, SIGNAL_ADS_TXT_TEMPLATE, "SHA_B", "three.com")
    out = known_templates(conn)
    assert out["SHA_A"] == ["one.com", "two.com"]
    assert out["SHA_B"] == ["three.com"]


def test_known_templates_ignores_other_signal_types():
    """Only template hashes screen candidates — account signals must not leak
    into the hash space (that is the scoring path we measured as broken)."""
    conn = _index()
    _put(conn, SIGNAL_ADS_TXT_TEMPLATE, "SHA_A", "one.com")
    _put(conn, SIGNAL_ADS_TXT_SELLER, "pub-123", "two.com")
    assert list(known_templates(conn)) == ["SHA_A"]


def test_screening_uses_the_cross_case_index():
    """A template seen in a PAST investigation must screen today's candidate —
    the longitudinal advantage the index exists for."""
    conn = _index()
    _put(conn, SIGNAL_ADS_TXT_TEMPLATE, "SHA_OLD", "farm-from-2024.com")
    out = screen_ads_txt(_ads("SHA_OLD"), known_templates(conn))
    assert out["verdict"] == VERDICT_TEMPLATE_MATCH
    assert out["matched_domains"] == ["farm-from-2024.com"]


# ── fetch_for_screening: same-registrable-domain guard ────────────────────

def test_off_site_redirect_is_never_parsed():
    """Screening follows redirects (apex->www is routine for a bare candidate)
    but must not inherit another domain's ads.txt — the hazard contract 9
    guards against on the scan path."""
    out = screen_ads_txt({"status": "off_site_redirect", "records": [],
                          "landed_on": "https://someone-else.com/ads.txt"},
                         {"SHA": ["known.com"]})
    assert out["verdict"] == VERDICT_OFF_SITE
    assert out["matched_sha"] is None


def test_screen_domains_dedups_without_losing_caller_order(monkeypatch):
    """Callers front-load the candidates they care about (a .tw subset ahead of
    thousands of international domains). Dedup must not scatter them: a set
    comprehension here quietly randomised submission order through a
    half-hour sweep."""
    from kwara import discovery
    monkeypatch.setattr(discovery, "screen_domain",
                        lambda d, known, timeout=None: {
                            "domain": d, "verdict": VERDICT_NO_MATCH,
                            "matched_sha": None, "matched_domains": [],
                            "record_count": 1})
    submitted = []
    discovery.screen_domains(
        ["b.tw", "a.com", "b.tw", "c.com"], {}, workers=1,
        on_result=lambda r: submitted.append(r["domain"]))
    assert submitted == ["b.tw", "a.com", "c.com"]


# ── cluster_by_template: self-clustering ──────────────────────────────────

def _obs(domain, sha, n, status="ok"):
    return {"domain": domain, "raw_sha256": sha, "status": status,
            "record_count": n}


def test_self_clustering_groups_domains_sharing_a_file():
    """Needs no prior knowledge of any domain — the point of the stage that
    screening against a small known set cannot reach."""
    cl = cluster_by_template([_obs("a.com", "SHA1", 40), _obs("b.com", "SHA1", 40),
                              _obs("c.com", "SHA2", 40)])
    assert len(cl) == 1
    assert cl[0]["domains"] == ["a.com", "b.com"]
    assert cl[0]["kind"] == "portfolio"


def test_self_clustering_drops_shared_empty_templates():
    """Six clusters covering 121 domains shared a byte-identical ads.txt with
    NO DIRECT accounts on the 2026-08-05 sweep. An empty file is common to
    countless unrelated parked domains and is not a deployer signal."""
    cl = cluster_by_template([_obs("a.com", "EMPTY", 0), _obs("b.com", "EMPTY", 0)])
    assert cl == []


def test_self_clustering_flags_platform_generated_templates():
    """A byte-identical 900-account file across sites is a monetisation
    platform emitting one file for its clients, not one operator's estate."""
    cl = cluster_by_template([_obs("a.com", "BIG", 900), _obs("b.com", "BIG", 900),
                              _obs("c.com", "SML", 40), _obs("d.com", "SML", 40)])
    kinds = {c["sha256"]: c["kind"] for c in cl}
    assert kinds == {"BIG": "platform", "SML": "portfolio"}
    assert cl[0]["kind"] == "portfolio"   # operator portfolios rank first


def test_self_clustering_ignores_failed_fetches():
    cl = cluster_by_template([_obs("a.com", "SHA", 40, status="non_200"),
                              _obs("b.com", "SHA", 40, status="ok")])
    assert cl == []


def test_status_code_and_ownership_fields_survive_screening():
    """403 (active block) and 404 (no file) are different signals; OWNERDOMAIN
    and MANAGERDOMAIN are ads.txt's own first-party ownership claims."""
    out = screen_ads_txt({"status": "non_200", "status_code": 403,
                          "records": [], "raw_sha256": "x"}, {})
    assert out["status_code"] == 403
    ok = screen_ads_txt({"status": "ok", "raw_sha256": "s", "status_code": 200,
                         "records": [{"a": 1}], "owner_domain": "owner.example",
                         "manager_domain": "mgr.example"}, {})
    assert ok["owner_domain"] == "owner.example"
    assert ok["manager_domain"] == "mgr.example"
