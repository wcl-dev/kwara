"""The collection layer, against a local origin instead of a mock.

Coverage before this file: scanner 20%, snapshots 20%, corroboration 25%,
pipeline 33%, narrative 44%. The pattern was not an accident — every one of
these makes outbound requests, and the established way to test them was to
patch requests.get, which exercises the call site and never the behaviour that
actually breaks: redirect chains, hop headers, truncation, timeouts.
"""
import json
import os
from unittest.mock import patch

import pytest

from kwara import config, narrative, pipeline, scanner
from kwara.db import get_conn, init_db, migrate_db


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A scratch case DB, plus its path — ingestion goes through the CLI, which
    is where URL extraction and artifact creation are actually composed."""
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    path = str(tmp_path / "c.db")
    conn = get_conn(path)
    init_db(conn)
    migrate_db(conn)
    return conn, path


def _case_with(db, urls):
    from kwara.cli import build_parser
    _conn, path = db

    def run(argv):
        ns = build_parser().parse_args(argv + ["--db", path, "--quiet"])
        return ns.fn(ns)

    cid = run(["case", "new", "--title", "collection"])["case_id"]
    run(["ingest", "url", "--case", str(cid)] + list(urls))
    return cid


# ── scanner ────────────────────────────────────────────────────────────────

def test_multi_hop_chain_records_every_hop_with_its_headers(site, db):
    """Header forensics reads response headers PER HOP — an origin leak often
    shows on the 302, not on the final page. Recording only the last response
    would lose it."""
    site.route("/", status=302, headers={"Location": "/mid",
                                         "x-server-hosted": "Malaysia Cloud Pte Ltd"})
    site.route("/mid", status=302, headers={"Location": "/end"})
    site.route("/end", body="<html>end</html>", headers={"x-powered-by": "PHP/7.4.33"})

    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)

    hops = conn.execute(
        "SELECT hop_order, status_code, response_headers_json FROM redirect_hops "
        "ORDER BY hop_order").fetchall()
    assert len(hops) >= 3, [dict(h) for h in hops]
    all_headers = " ".join(h["response_headers_json"] or "" for h in hops)
    assert "Malaysia Cloud Pte Ltd" in all_headers
    assert "PHP/7.4.33" in all_headers

    sr = conn.execute("SELECT final_url, status FROM scan_runs").fetchone()
    assert sr["status"] == "done"
    assert sr["final_url"].endswith("/end")


def test_redirect_loop_terminates(site, db):
    site.route("/a", status=302, headers={"Location": "/b"})
    site.route("/b", status=302, headers={"Location": "/a"})
    conn, _path = db
    cid = _case_with(db, [site.url_for("/a")])
    pipeline.run_fast_attribution(conn, cid)
    hops = conn.execute("SELECT COUNT(*) FROM redirect_hops").fetchone()[0]
    assert hops <= config.MAX_HOPS + 2, hops


def test_a_slow_origin_is_recorded_not_hung_on(site, db, monkeypatch):
    monkeypatch.setattr(config, "HTTP_TIMEOUT", 1)
    site.route("/slow", body="late", delay=3.0)
    conn, _path = db
    cid = _case_with(db, [site.url_for("/slow")])
    summary = pipeline.run_fast_attribution(conn, cid)
    row = conn.execute("SELECT status FROM scan_runs").fetchone()
    assert row is not None, summary
    assert row["status"] in ("done", "error"), dict(row)


# ── ads.txt over the wire ──────────────────────────────────────────────────

def test_ads_txt_is_fetched_parsed_and_stored(site, db):
    from fixtures.server import adstxt_bytes
    site.route("/", body="<html>x</html>")
    site.route("/ads.txt", body=adstxt_bytes("normal.txt"))
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)

    blob = conn.execute("SELECT ads_txt_json FROM scan_runs").fetchone()[0]
    ads = json.loads(blob)
    assert ads["status"] == "ok"
    assert ads["record_count"] > 0
    assert ads["raw_sha256"]


def test_a_blocked_ads_txt_is_recorded_as_a_block(site, db):
    """A 403 is itself a signal — a site gating its monetisation declaration is
    behaving differently from one that simply has none."""
    site.route("/", body="<html>x</html>")
    site.route("/ads.txt", status=403, body=b"denied")
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)
    ads = json.loads(conn.execute("SELECT ads_txt_json FROM scan_runs").fetchone()[0])
    assert ads["status"] == "non_200"
    assert ads["status_code"] == 403
    assert ads["records"] == []


def test_an_oversized_ads_txt_reports_no_hash(site, db):
    """A hash over a truncated body is not the file's hash, and template
    matching treats an equal hash as byte-identity — the strongest claim this
    tool makes about shared operation."""
    site.route("/", body="<html>x</html>")
    site.route("/ads.txt", body=b"google.com, pub-1, DIRECT\n" * 40_000)
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)
    ads = json.loads(conn.execute("SELECT ads_txt_json FROM scan_runs").fetchone()[0])
    assert ads.get("truncated") is True
    assert ads.get("raw_sha256") is None


def test_scan_path_does_not_follow_an_ads_txt_redirect(site, db):
    """Invariant 9. The scan already resolved the canonical host; following on
    would attribute another host's declaration to this one."""
    site.route("/", body="<html>x</html>")
    site.route("/ads.txt", status=302, headers={"Location": "/elsewhere.txt"})
    site.route("/elsewhere.txt", body=b"evil.com, pub-999, DIRECT\n")
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)
    ads = json.loads(conn.execute("SELECT ads_txt_json FROM scan_runs").fetchone()[0])
    assert ads["status"] == "non_200"
    assert "pub-999" not in json.dumps(ads)


# ── static extraction ──────────────────────────────────────────────────────

def test_static_tracking_ids_are_extracted_without_a_browser(site, db):
    from fixtures.server import page_bytes
    site.route("/", body=page_bytes("farm_static.html"))
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)
    blob = conn.execute(
        "SELECT tracking_ids_json FROM snapshots WHERE capture_method='http_only'"
    ).fetchone()[0]
    assert blob and json.loads(blob), "no static IDs extracted"


def test_placeholder_ids_are_not_stored_as_evidence(site, db):
    """Vendor-documentation placeholders in a page must not become attribution
    — an operator copying a tutorial would otherwise be linked to every other
    site that copied the same tutorial."""
    from fixtures.server import page_bytes
    site.route("/", body=page_bytes("placeholder_ids.html"))
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)
    blob = conn.execute(
        "SELECT tracking_ids_json FROM snapshots WHERE capture_method='http_only'"
    ).fetchone()[0]
    found = json.dumps(json.loads(blob or "{}"))
    for placeholder in ("XXXX", "EXAMPLE", "YOURID"):
        assert placeholder not in found.upper(), found


# ── best-effort semantics ──────────────────────────────────────────────────

def test_one_failing_url_does_not_abort_the_others(site, db):
    """run_fast_attribution is documented best-effort: per-item failures are
    collected, never raised. A batch that stops at the first dead domain would
    leave an analyst thinking the rest were checked."""
    site.route("/ok", body="<html>fine</html>")
    conn, _path = db
    cid = _case_with(db, [site.url_for("/ok"),
                          "http://127.0.0.1:9/definitely-closed"])
    summary = pipeline.run_fast_attribution(conn, cid)
    assert summary["scanned"] >= 1
    done = conn.execute("SELECT COUNT(*) FROM scan_runs WHERE status='done'").fetchone()[0]
    assert done >= 1


def test_rerunning_attribution_is_idempotent(site, db):
    site.route("/", body="<html>x</html>")
    site.route("/ads.txt", body=b"google.com, pub-1, DIRECT\n")
    conn, _path = db
    cid = _case_with(db, [site.url + "/"])
    pipeline.run_fast_attribution(conn, cid)
    first = conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]
    pipeline.run_fast_attribution(conn, cid)
    assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == first


# ── narrative prose ────────────────────────────────────────────────────────

def _sig(**kw):
    base = {"tracking": 0, "certs": 0, "hdr_tmpl": 0, "ads_template": 0,
            "cloaking": 0, "fake_ver": 0, "opsec": 0, "ads_operator": 0}
    base.update(kw)
    return base


@pytest.mark.parametrize("sig,expect_strong,expect_behaviour", [
    (_sig(), False, False),
    (_sig(tracking=1), True, False),
    (_sig(cloaking=1), False, True),
    (_sig(tracking=1, cloaking=1), True, True),
    (_sig(ads_template=2, fake_ver=1), True, True),
    (_sig(ads_operator=5), False, False),
])
def test_verdict_covers_every_combination(sig, expect_strong, expect_behaviour):
    """44% coverage meant most prose branches had never executed — and this is
    the text handed to a reader."""
    v = narrative.verdict(sig)
    assert (v["grouping"] == "strong") is expect_strong
    assert v["behaviour"] is expect_behaviour
    assert v["group_line"]
    assert (v["behaviour_line"] != "") is expect_behaviour


def test_money_signals_alone_never_assert_a_group():
    """ads.txt accounts are corroborating and explicitly non-binding; no
    quantity of them may produce a same-group determination."""
    v = narrative.verdict(_sig(ads_operator=99))
    assert v["grouping"] == "none"
