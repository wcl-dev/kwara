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

from discovery import (
    VERDICT_NO_ADS_TXT,
    VERDICT_NO_MATCH,
    VERDICT_OFF_SITE,
    VERDICT_TEMPLATE_MATCH,
    VERDICT_UNREACHABLE,
    known_templates,
    screen_ads_txt,
)
from index_db import SIGNAL_ADS_TXT_SELLER, SIGNAL_ADS_TXT_TEMPLATE, get_index_conn


def _ads(sha, *, status="ok", n=3):
    return {"status": status, "raw_sha256": sha,
            "records": [{"adsystem": "x.com", "seller_id": str(i),
                         "relationship": "DIRECT"} for i in range(n)]}


# ── screen_ads_txt ────────────────────────────────────────────────────────

def test_exact_template_match_promotes_and_names_the_siblings():
    known = {"SHA_FARM": ["visitorlanding.example", "crawlerlanding.example"]}
    out = screen_ads_txt(_ads("SHA_FARM"), known)
    assert out["verdict"] == VERDICT_TEMPLATE_MATCH
    assert out["matched_sha"] == "SHA_FARM"
    assert out["matched_domains"] == ["visitorlanding.example", "crawlerlanding.example"]


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
