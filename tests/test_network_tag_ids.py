"""Google tag IDs read from the requests a page sent — leads, never links.

A HAR does not say which frame fired a request, so an ad creative's own tag
reads exactly like the operator's. These tests hold three things: what is
extracted (G-/GT-/GTM-/UA- on Google hosts only, never AW-/DC-), that the
index records it as its own lead type without repeating IDs the HTML already
carried, and that nothing which forms groups ever reads it.
"""
import json
import os
from argparse import Namespace

import pytest

from kwara.clusters import case_clusters
from kwara.db import get_conn, init_db, migrate_db
from kwara.fingerprints import (extract_network_tag_ids,
                                extract_network_tag_ids_from_har)
from kwara.index_db import (SIGNAL_NETWORK_TAG_ID, SIGNAL_TRACKING_ID,
                            extract_case_signals)

NOW = "2026-11-25 00:00:00 UTC"


# ── extraction ────────────────────────────────────────────────────────────

def test_reads_loader_and_collect_ids_on_google_hosts():
    got = extract_network_tag_ids([
        "https://www.googletagmanager.com/gtag/js?id=GT-ABCD1234",
        "https://region1.google-analytics.com/g/collect?v=2&tid=G-MEASURE987&cid=1",
        "https://analytics.google.com/g/collect?v=2&tid=G-OTHER12345",
        "https://www.googletagmanager.com/gtm.js?id=GTM-K7L5RZP",
        "https://www.google-analytics.com/j/collect?v=1&tid=UA-1234567-8",
    ])
    assert got == {
        "Google Tag": ["GT-ABCD1234"],
        "Google Analytics 4": ["G-MEASURE987", "G-OTHER12345"],
        "Google Tag Manager": ["GTM-K7L5RZP"],
        "Google Analytics (UA)": ["UA-1234567-8"],
    }


def test_ignores_other_hosts_even_when_the_parameter_looks_right():
    assert extract_network_tag_ids([
        "https://example.com/redirect?id=G-ABC123DEF",
        "https://notgoogletagmanager.com/gtag/js?id=GT-ABCD1234",
    ]) == {}


def test_ignores_ads_conversion_and_floodlight_ids():
    """Measured spanning operator groups known to be separate: advertisers'
    tags riding along in ad creatives, not the page's own account."""
    assert extract_network_tag_ids([
        "https://www.googletagmanager.com/gtag/js?id=AW-1234567890",
        "https://www.googletagmanager.com/gtag/js?id=DC-1234567",
    ]) == {}


def test_filters_placeholders():
    assert extract_network_tag_ids([
        "https://www.googletagmanager.com/gtm.js?id=GTM-XXXXXXX",
    ]) == {}


def test_har_reader_separates_unread_from_empty(tmp_path):
    assert extract_network_tag_ids_from_har(None) is None
    assert extract_network_tag_ids_from_har(str(tmp_path / "missing.har")) is None
    bad = tmp_path / "bad.har"
    bad.write_text("{not json")
    assert extract_network_tag_ids_from_har(str(bad)) is None

    empty = tmp_path / "empty.har"
    empty.write_text(json.dumps({"log": {"entries": [
        {"request": {"url": "https://cdn.example/a.js"}}]}}))
    assert extract_network_tag_ids_from_har(str(empty)) == {}


# ── fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "case.db")
    conn = get_conn(path)
    init_db(conn)
    migrate_db(conn)
    conn.execute("INSERT INTO cases (title, description, created_at, updated_at)"
                 " VALUES ('t','',?,?)", (NOW, NOW))
    conn.commit()
    return conn


@pytest.fixture
def db_path(db, tmp_path):
    return str(tmp_path / "case.db")


def _har(tmp_path, name, urls):
    p = tmp_path / f"{name}.har"
    p.write_text(json.dumps({"log": {"entries": [
        {"request": {"method": "GET", "url": u}} for u in urls]}}))
    return str(p)


def _site(conn, domain, *, tracking=None, network=None, har_path=None):
    cur = conn.execute(
        "INSERT INTO message_evidence (case_id, platform, permalink, actor_label,"
        " posted_at, message_text, screenshot_path, ingested_at)"
        " VALUES (1,'','','','','','',?)", (NOW,))
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain,"
        " url_order, created_at) VALUES (?,1,?,?,0,?)",
        (cur.lastrowid, f"https://{domain}/", domain, NOW))
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,"
        " status) VALUES (?,?,?,0,'done')",
        (cur.lastrowid, NOW, f"https://{domain}/"))
    conn.execute(
        "INSERT INTO snapshots (scan_run_id, final_url, final_domain, captured_at,"
        " capture_status, capture_method, tracking_ids_json,"
        " network_tag_ids_json, har_path)"
        " VALUES (?,?,?,?,'ok','playwright',?,?,?)",
        (cur.lastrowid, f"https://{domain}/", domain, NOW,
         json.dumps(tracking) if tracking is not None else None,
         json.dumps(network) if network is not None else None, har_path))
    conn.commit()


# ── index ────────────────────────────────────────────────────────────────

def test_network_only_ids_are_indexed_as_leads(db, db_path):
    _site(db, "a.test", tracking={"Meta Pixel": ["123456789012345"]},
          network={"Google Tag": ["GT-ABCD1234"]})
    sigs = extract_case_signals(db, 1, db_path)
    lead = [s for s in sigs if s["signal_type"] == SIGNAL_NETWORK_TAG_ID]
    assert [(s["signal_value"], s["platform"]) for s in lead] == \
        [("GT-ABCD1234", "Google Tag")]


def test_an_id_the_html_carried_is_not_repeated_as_a_lead(db, db_path):
    _site(db, "a.test", tracking={"Google Analytics 4": ["G-SAME123456"]},
          network={"Google Analytics 4": ["G-SAME123456"],
                   "Google Tag": ["GT-ABCD1234"]})
    sigs = extract_case_signals(db, 1, db_path)
    by_type = {}
    for s in sigs:
        by_type.setdefault(s["signal_type"], []).append(s["signal_value"])
    assert by_type[SIGNAL_TRACKING_ID] == ["G-SAME123456"]
    assert by_type[SIGNAL_NETWORK_TAG_ID] == ["GT-ABCD1234"]


def test_network_ids_index_even_when_the_html_had_none(db, db_path):
    _site(db, "a.test", tracking=None, network={"Google Tag": ["GT-ABCD1234"]})
    sigs = extract_case_signals(db, 1, db_path)
    assert any(s["signal_type"] == SIGNAL_NETWORK_TAG_ID for s in sigs)


# ── the rule: a lead never binds ─────────────────────────────────────────

def test_a_shared_network_id_never_forms_a_group(db):
    for d in ("a.test", "b.test"):
        _site(db, d, tracking={}, network={"Google Analytics 4": ["G-SHARED1234"],
                                           "Google Tag": ["GT-SHARED123"]})
    groups = [g for g in case_clusters(db, 1)["groups"] if len(g["domains"]) > 1]
    assert groups == []


# ── capture path and backfill ────────────────────────────────────────────

def test_backfill_fills_only_null_rows_and_only_with_apply(db, db_path, tmp_path):
    from kwara.cli import cmd_evidence_net_ids

    har = _har(tmp_path, "a", [
        "https://www.googletagmanager.com/gtag/js?id=GT-ABCD1234"])
    _site(db, "a.test", har_path=har)
    _site(db, "b.test", network={"Google Tag": ["GT-KEEP12345"]},
          har_path=_har(tmp_path, "b", []))

    args = Namespace(db=db_path, case=None, apply=False)
    dry = cmd_evidence_net_ids(args)
    assert dry["candidates"] == 1 and dry["with_ids"] == 1
    assert db.execute("SELECT network_tag_ids_json FROM snapshots"
                      " WHERE final_domain='a.test'").fetchone()[0] is None

    args.apply = True
    cmd_evidence_net_ids(args)
    rows = dict(db.execute(
        "SELECT final_domain, network_tag_ids_json FROM snapshots").fetchall())
    assert json.loads(rows["a.test"]) == {"Google Tag": ["GT-ABCD1234"]}
    assert json.loads(rows["b.test"]) == {"Google Tag": ["GT-KEEP12345"]}

    again = cmd_evidence_net_ids(args)
    assert again["candidates"] == 0


def test_capture_records_network_ids(db, tmp_path):
    """The live capture path writes the column, not only the backfill."""
    from kwara import snapshots

    cur = db.execute(
        "INSERT INTO message_evidence (case_id, platform, permalink, actor_label,"
        " posted_at, message_text, screenshot_path, ingested_at)"
        " VALUES (1,'','','','','','',?)", (NOW,))
    cur = db.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain,"
        " url_order, created_at) VALUES (?,1,'https://a.test/','a.test',0,?)",
        (cur.lastrowid, NOW))
    sr = db.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,"
        " status) VALUES (?,?,'https://a.test/',0,'done')",
        (cur.lastrowid, NOW)).lastrowid
    har = _har(tmp_path, "cap", [
        "https://region1.google-analytics.com/g/collect?v=2&tid=G-MEASURE987"])
    meta = {"case_id": 1, "final_url": "https://a.test/",
            "final_domain": "a.test", "hop_count": 0}
    snapshots._record_capture(db, sr, meta, {"har_path": har})
    got = db.execute("SELECT network_tag_ids_json FROM snapshots"
                     " WHERE scan_run_id=?", (sr,)).fetchone()[0]
    assert json.loads(got) == {"Google Analytics 4": ["G-MEASURE987"]}
