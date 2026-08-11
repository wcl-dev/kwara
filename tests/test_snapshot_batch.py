"""snapshots.py — the Playwright batch orchestration, 20% covered.

The worker itself is now tested; this is the half that decides WHAT to capture,
hands it to the subprocess, and writes the result back as evidence. It is where
invariant 6 lives (a failed re-capture must not shadow an earlier good one) and
where a case's browser locale is turned into an environment for the child.
"""
import json
import os

import pytest

from kwara import config, snapshots
from kwara.cli import build_parser
from kwara.db import get_conn, init_db, migrate_db


def _has_chromium() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return bool(p.chromium.executable_path) and \
                os.path.exists(p.chromium.executable_path)
    except Exception:
        return False


browser = pytest.mark.skipif(not _has_chromium(), reason="chromium not installed")


@pytest.fixture
def case(tmp_path, monkeypatch, site):
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    db = str(tmp_path / "c.db")

    def run(argv):
        ns = build_parser().parse_args(argv + ["--db", db, "--quiet"])
        return ns.fn(ns)

    site.route("/", body="<html><head><title>t</title></head>"
                         "<body><h1>landing</h1></body></html>")
    site.route("/ads.txt", body=b"clickforce.com.tw, pub-1, DIRECT\n")
    cid = run(["case", "new", "--title", "batch", "--locale-preset", "tw"])["case_id"]
    run(["ingest", "url", "--case", str(cid), site.url + "/"])
    run(["run", "attribute", "--case", str(cid)])
    return {"db": db, "case": cid, "run": run, "site": site}


# ── selection, no browser needed ───────────────────────────────────────────

def _targets_of(case, monkeypatch, extra=()):
    """Drive `run snapshot` with the capture stubbed out, and return the
    scan_run_ids it selected."""
    from kwara import pipeline
    seen = {}

    def fake(conn, targets, env_override=None):
        seen["targets"] = list(targets)
        seen["env"] = env_override
        return []

    monkeypatch.setattr(pipeline, "run_snapshot_batch", fake)
    case["run"](["run", "snapshot", "--case", str(case["case"]), *extra])
    return seen


def test_a_cheap_pass_does_not_mark_a_url_as_already_captured(case, monkeypatch):
    """Regression for 2026-08-08. Pending was `LEFT JOIN snapshots WHERE
    s.id IS NULL` — any snapshot at all counted as done. But `run attribute`
    writes an http_only snapshot for every URL, so `run snapshot` reported
    "nothing pending" and silently did nothing. That is the exact order both
    guides recommend, and it also starves the OPSEC verdict, which exists to
    compare the browser-free and browser paths against each other."""
    conn = get_conn(case["db"])
    assert conn.execute("SELECT COUNT(*) FROM snapshots WHERE "
                        "capture_method='http_only'").fetchone()[0] == 1, \
        "the cheap pass no longer writes a snapshot; this test needs rewriting"

    seen = _targets_of(case, monkeypatch)
    assert seen.get("targets"), \
        "a URL with only a browser-free capture was treated as already captured"


def test_a_finished_browser_capture_is_not_selected_again(case, monkeypatch):
    """The other half: pending must still exclude real captures, or every run
    would re-capture the whole case."""
    conn = get_conn(case["db"])
    sr = conn.execute("SELECT id FROM scan_runs ORDER BY id").fetchone()["id"]
    conn.execute(
        "INSERT INTO snapshots (scan_run_id, capture_method, capture_status) "
        "VALUES (?, 'playwright', 'ok')", (sr,))
    conn.commit()
    conn.close()

    assert not _targets_of(case, monkeypatch).get("targets")


def test_locale_preset_reaches_the_capture_environment(case, monkeypatch):
    """A case records the victim's region so a capture reproduces what they
    would have seen. If that never reaches the subprocess environment, the
    screenshot is of what WE saw, which is a different claim."""
    conn = get_conn(case["db"])
    row = conn.execute("SELECT browser_locale, browser_timezone FROM cases "
                       "WHERE id = ?", (case["case"],)).fetchone()
    assert row["browser_locale"], "locale preset did not persist"

    env = _targets_of(case, monkeypatch)["env"] or {}
    assert env.get("KWARA_BROWSER_LOCALE") == row["browser_locale"]
    assert env.get("KWARA_BROWSER_TIMEZONE") == row["browser_timezone"]


def test_subprocess_timeout_scales_with_batch_size():
    """One overall timeout covers the whole batch; if it did not scale, a large
    batch would be killed halfway and reported as a subprocess failure rather
    than as the partial capture it was."""
    small = snapshots._compute_subprocess_timeout(1, 30, "screenshot")
    large = snapshots._compute_subprocess_timeout(20, 30, "screenshot")
    assert large > small


def test_a_dead_subprocess_becomes_error_results_not_an_exception():
    """Capture is best-effort: the analyst gets an error row they can see and
    retry, not a traceback that loses the rest of the batch."""
    urls = [{"scan_run_id": 1, "final_url": "https://x.test/",
             "screenshot_path": "/tmp/a.png", "html_path": "/tmp/a.html"}]
    out = snapshots._error_results(urls, "subprocess timed out")
    assert len(out) == 1
    assert out[0].get("error")


# ── the other drain path ───────────────────────────────────────────────────

def test_run_pending_agrees_with_run_snapshot_about_what_is_pending(case):
    """`_run_pending` drains every case unattended and had the same 2026-08-08
    defect from the other direction: it looks at the LATEST snapshot per
    scan_run, and the cheap pass writes the newest row. Retry semantics are the
    part that must survive the fix — a browser capture that failed is pending
    again, and a later cheap pass must not mask it."""
    from kwara._run_pending import _pending_scan_run_ids

    conn = get_conn(case["db"])
    sr = conn.execute("SELECT id FROM scan_runs ORDER BY id").fetchone()["id"]

    def add(method, status):
        conn.execute("INSERT INTO snapshots (scan_run_id, capture_method, "
                     "capture_status) VALUES (?, ?, ?)", (sr, method, status))
        conn.commit()

    assert _pending_scan_run_ids(conn, case["case"]) == [sr], \
        "an http_only row made a never-captured URL look finished"

    add("playwright", "error")
    assert _pending_scan_run_ids(conn, case["case"]) == [sr], \
        "a failed browser capture is still work outstanding"

    add("http_only", "ok")
    assert _pending_scan_run_ids(conn, case["case"]) == [sr], \
        "a later cheap pass masked an earlier capture failure"

    add("cloaking_alt", "ok")
    assert _pending_scan_run_ids(conn, case["case"]) == [sr], \
        "the crawler-facing persona is not a capture of the visitor-facing page"

    # Only a successful visitor-facing render settles it — and once it exists,
    # a later failed retry cannot make it untrue (contract 6).
    add("playwright", "ok")
    assert _pending_scan_run_ids(conn, case["case"]) == []
    add("playwright", "timeout")
    assert _pending_scan_run_ids(conn, case["case"]) == [], \
        "a failed retry re-opened a scan_run whose page we already hold"


# ── real capture through the CLI ───────────────────────────────────────────

@pytest.mark.browser
@browser
def test_run_snapshot_records_evidence_and_survives_a_rerun(case):
    """Invariant 6 and 7 together: a second capture must write a NEW directory
    and must not shadow the first, and analysis must keep reading the latest
    USABLE one."""
    case["run"](["run", "snapshot", "--case", str(case["case"]), "--limit", "1"])
    conn = get_conn(case["db"])
    rows = conn.execute(
        "SELECT id, scan_run_id, capture_method, capture_status, screenshot_path, "
        "html_path FROM snapshots WHERE capture_method='playwright'").fetchall()
    assert rows, "no playwright snapshot recorded"
    first = rows[0]
    assert first["capture_status"] == "ok", dict(first)
    assert os.path.isfile(first["screenshot_path"])
    assert os.path.getsize(first["screenshot_path"]) > 0

    # Re-capture the SAME scan_run explicitly. Pending would rightly skip it
    # now, so name it — what is under test is that the second capture does not
    # land on top of the first.
    case["run"](["run", "snapshot", "--case", str(case["case"]),
                 "--scan-run", str(first["scan_run_id"])])
    conn2 = get_conn(case["db"])
    after = conn2.execute(
        "SELECT screenshot_path FROM snapshots WHERE capture_method='playwright' "
        "ORDER BY id").fetchall()
    if len(after) > 1:
        assert os.path.dirname(after[0]["screenshot_path"]) != \
            os.path.dirname(after[-1]["screenshot_path"]), \
            "a re-capture reused the first capture's directory"
        assert os.path.isfile(after[0]["screenshot_path"]), \
            "the original capture's file was overwritten or removed"


@pytest.mark.browser
@browser
def test_har_is_recorded_so_third_party_endpoints_can_be_clustered(case):
    """shared_endpoints reads request_domains_json, which only the Playwright
    path produces. No HAR means that whole signal silently returns nothing."""
    case["site"].route("/", body='<html><body>'
                                 '<img src="http://127.0.0.1:1/pixel.gif">'
                                 '</body></html>')
    case["run"](["run", "snapshot", "--case", str(case["case"]), "--limit", "1"])
    conn = get_conn(case["db"])
    row = conn.execute("SELECT request_domains_json FROM snapshots "
                       "WHERE capture_method='playwright' "
                       "AND request_domains_json IS NOT NULL").fetchone()
    assert row is not None, "no request domains recorded from the capture"
