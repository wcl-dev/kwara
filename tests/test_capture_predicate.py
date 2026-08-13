"""One definition of "this page was captured", and everything that asks it.

Regression for 2026-08-08 and 2026-08-11. The question "does this scan_run
have a capture of the rendered page?" was written out four times — in
`run snapshot`, in `case show`, in `clusters._completeness` and in
`_run_pending` — and all four disagreed. Every divergence was invisible to
the analyst and every one of them understated missing work:

  * `run snapshot` and `case show` counted the browser-free pass as a
    capture, so after `run attribute` the tool reported nothing pending.
  * `_completeness` reported page_captured=True — and therefore no gap — for
    cases in which no browser had ever rendered a page.
  * attribution picked whichever snapshot row was newest, which is always
    `cloaking_alt`: the persona a cloaker shows CRAWLERS. It read the
    crawler-facing page on 372 of 469 live scan_runs, and on 252 of those the
    two personas had landed on entirely different domains.

The definition now lives once, in `sql.browser_capture_exists`. These tests
exist so it stays once.
"""
import json
import os
from datetime import datetime, timezone

import pytest

from kwara._run_pending import _pending_scan_run_ids, _row_satisfies
from kwara.db import get_conn, init_db, migrate_db
from kwara.sql import browser_capture_exists, usable_snapshots


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.fixture
def db(tmp_path):
    conn = get_conn(str(tmp_path / "t.db"))
    init_db(conn)
    migrate_db(conn)
    now = _now()
    conn.execute("INSERT INTO cases (title, description, created_at, updated_at) "
                 "VALUES ('t', '', ?, ?)", (now, now))
    conn.commit()
    return conn


def _scan_run(conn, case_id=1, url="https://a.test/"):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""", (case_id, now))
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (cur.lastrowid, case_id, url, now))
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status) VALUES (?, ?, ?, 0, 'done')", (cur.lastrowid, now, url))
    conn.commit()
    return cur.lastrowid


def _snap(conn, scan_run_id, method, status, *, screenshot=None, tracking=None):
    cur = conn.execute(
        "INSERT INTO snapshots (scan_run_id, capture_method, capture_status, "
        "screenshot_path, tracking_ids_json) VALUES (?, ?, ?, ?, ?)",
        (scan_run_id, method, status, screenshot,
         json.dumps(tracking) if tracking is not None else None))
    conn.commit()
    return cur.lastrowid


def _sql_says_captured(conn, scan_run_id) -> bool:
    return bool(conn.execute(
        f"SELECT {browser_capture_exists('sr.id')} AS c FROM scan_runs sr "
        "WHERE sr.id = ?", (scan_run_id,)).fetchone()["c"])


# ── the definition itself ─────────────────────────────────────────────────

# (capture_method, capture_status, has_screenshot_file, captured?)
ROW_SHAPES = [
    ("playwright",   "ok",           False, True,  "a real browser render"),
    ("playwright",   "error",        False, False, "the render failed"),
    ("playwright",   "timeout",      False, False, "the render timed out"),
    ("playwright",   "cf_challenge", False, False, "we got the WAF, not the page"),
    ("http_only",    "ok",           False, False, "the browser-free pass is not a capture"),
    ("http_only",    "error",        False, False, "a failed cheap pass, still not a capture"),
    ("cloaking_alt", "ok",           False, False, "crawler-facing persona only"),
    ("manual",       "manual",       False, True,  "analyst supplied the page"),
    ("wayback",      "wayback",      False, True,  "a deliberate archive substitute"),
]


@pytest.mark.parametrize("method,status,has_file,expected,why", ROW_SHAPES)
def test_one_row_shape(db, method, status, has_file, expected, why):
    sr = _scan_run(db)
    _snap(db, sr, method, status)
    assert _sql_says_captured(db, sr) is expected, why


def test_a_scan_run_with_no_snapshot_at_all_is_not_captured(db):
    assert _sql_says_captured(db, _scan_run(db)) is False


def test_the_cheap_pass_does_not_shadow_a_missing_browser_capture(db):
    """The 2026-08-08 defect in one line. This is the state every URL is in
    immediately after `run attribute`."""
    sr = _scan_run(db)
    _snap(db, sr, "http_only", "ok")
    assert _sql_says_captured(db, sr) is False


def test_a_failed_recapture_does_not_undo_an_earlier_good_one(db):
    sr = _scan_run(db)
    _snap(db, sr, "playwright", "ok")
    _snap(db, sr, "playwright", "error")
    assert _sql_says_captured(db, sr) is True, \
        "having already captured the page cannot become untrue"


def test_cloaking_alt_beside_a_real_capture_is_fine(db):
    sr = _scan_run(db)
    _snap(db, sr, "playwright", "ok")
    _snap(db, sr, "cloaking_alt", "ok")
    assert _sql_says_captured(db, sr) is True


# ── the SQL definition and the Python one must not drift ──────────────────

@pytest.mark.parametrize("method,status,has_file,expected,why", ROW_SHAPES)
def test_python_refinement_agrees_with_the_sql_definition(
        db, tmp_path, method, status, has_file, expected, why):
    """`_run_pending` re-implements the predicate in Python because it alone
    may touch the filesystem. It must be a strict REFINEMENT — same answers
    everywhere except where a recorded file turns out to be missing."""
    sr = _scan_run(db)
    _snap(db, sr, method, status)
    assert _row_satisfies(method, status, None) is _sql_says_captured(db, sr), why


def test_legacy_row_is_trusted_only_when_the_file_survived(db, tmp_path):
    """The one place the two definitions are ALLOWED to differ. A row written
    before capture_status existed records a screenshot path; SQL can see the
    path was recorded, only Python can see whether the file is still there."""
    png = tmp_path / "shot.png"
    png.write_bytes(b"\x89PNG" + b"0" * 100)

    sr = _scan_run(db)
    _snap(db, sr, None, None, screenshot=str(png))
    assert _sql_says_captured(db, sr) is True
    assert _row_satisfies(None, None, str(png)) is True

    png.unlink()
    assert _sql_says_captured(db, sr) is True, "SQL cannot know the file is gone"
    assert _row_satisfies(None, None, str(png)) is False, \
        "the refinement exists precisely to catch this"

    missing = str(tmp_path / "never-written.png")
    assert _row_satisfies(None, None, missing) is False
    assert _row_satisfies(None, None, None) is False


def test_an_empty_screenshot_file_does_not_count(db, tmp_path):
    empty = tmp_path / "empty.png"
    empty.write_bytes(b"")
    assert _row_satisfies(None, None, str(empty)) is False


# ── every caller must ask the same question ───────────────────────────────

@pytest.fixture
def case_with_states(db, tmp_path):
    """One case holding every interesting state at once."""
    states = {
        "never_touched":  [],
        "cheap_only":     [("http_only", "ok")],
        "failed_browser": [("http_only", "ok"), ("playwright", "error")],
        "captured":       [("http_only", "ok"), ("playwright", "ok")],
        "crawler_only":   [("http_only", "ok"), ("cloaking_alt", "ok")],
    }
    ids = {}
    for name, snaps in states.items():
        sr = _scan_run(db, url=f"https://{name}.test/")
        ids[name] = sr
        for m, st in snaps:
            _snap(db, sr, m, st)
    return db, ids


def test_case_show_and_run_snapshot_report_the_same_pending_count(
        case_with_states, tmp_path, monkeypatch):
    """`case show` told the analyst 0 pending for cases with work outstanding,
    because it kept the query `run snapshot` had already moved past."""
    from kwara import pipeline
    from kwara.cli import build_parser

    conn, ids = case_with_states
    db_path = conn.execute("PRAGMA database_list").fetchone()[2]
    conn.close()

    seen = {}
    monkeypatch.setattr(pipeline, "run_snapshot_batch",
                        lambda c, t, env_override=None: seen.update(targets=list(t)) or [])

    def run(argv):
        ns = build_parser().parse_args(argv + ["--db", db_path, "--quiet"])
        return ns.fn(ns)

    shown = run(["case", "show", "--case", "1"])["pending_snapshots"]
    run(["run", "snapshot", "--case", "1"])
    selected = seen["targets"]

    assert shown == len(selected), \
        f"case show says {shown} pending, run snapshot selects {len(selected)}"
    assert set(selected) == {ids["never_touched"], ids["cheap_only"],
                             ids["failed_browser"], ids["crawler_only"]}
    assert ids["captured"] not in selected


def test_run_pending_selects_the_same_scan_runs(case_with_states):
    conn, ids = case_with_states
    assert set(_pending_scan_run_ids(conn, 1)) == {
        ids["never_touched"], ids["cheap_only"],
        ids["failed_browser"], ids["crawler_only"]}


def test_completeness_does_not_call_a_cheap_pass_a_page_capture(db):
    """Five live cases reported page_captured=True, gaps=[], completeness 高
    while holding nothing but browser-free fetches."""
    from kwara.clusters import _completeness

    sr = _scan_run(db)
    _snap(db, sr, "http_only", "ok")
    before = _completeness(db, 1, n_urls=1, scanned=1)
    assert before["present"]["page_captured"] is False
    assert any("capture" in g or "截圖" in g or "頁面" in g
               for g in before.get("gaps", [])), \
        f"a missing page capture must surface as a gap, got {before.get('gaps')}"

    _snap(db, sr, "playwright", "ok")
    after = _completeness(db, 1, n_urls=1, scanned=1)
    assert after["present"]["page_captured"] is True


# ── attribution must read the visitor-facing page ─────────────────────────

def _read(conn, scan_run_id):
    """(capture_methods, tracking ids, domains) attribution actually reads."""
    rows = conn.execute(
        f"SELECT s.capture_method AS m, s.tracking_ids_json AS t, "
        f"s.final_domain AS d FROM scan_runs sr JOIN snapshots s "
        f"ON s.id IN {usable_snapshots('tracking_ids_json')} "
        "WHERE sr.id = ?", (scan_run_id,)).fetchall()
    ids = {v for r in rows for v in json.loads(r["t"])}
    return {r["m"] for r in rows}, ids, {r["d"] for r in rows if r["d"]}


def test_attribution_reads_every_persona_the_site_served(db):
    """The headline. `ORDER BY id DESC` picked one capture, and since the
    cloaking_alt row is always written last it picked the CRAWLER-facing page
    on 372 of 469 live scan_runs. Preferring the visitor instead just moved
    the blind spot: measured on the live database, that recovered 756
    tracking-ID observations but dropped both crawler-facing landings out of the case.
    A cloaker serves different personas different pages on purpose, so both
    are evidence and attribution reads both."""
    sr = _scan_run(db)
    _snap(db, sr, "playwright", "ok", tracking=["G-VISITOR"])
    _snap(db, sr, "cloaking_alt", "ok", tracking=["G-CRAWLER"])

    methods, ids, _ = _read(db, sr)
    assert methods == {"playwright", "cloaking_alt"}
    assert ids == {"G-VISITOR", "G-CRAWLER"}


def test_both_landing_domains_of_a_cloaked_url_survive(db):
    """Why picking one persona loses a whole site. On 252 live scan_runs the
    two personas land on DIFFERENT domains — a browser reaches visitor-landing.example and
    a crawler reaches crawler-landing.example from the same URL. Both belong to the
    operation; keeping only one erases the other from every cluster."""
    sr = _scan_run(db)
    db.execute("INSERT INTO snapshots (scan_run_id, capture_method, "
               "capture_status, final_domain, tracking_ids_json) "
               "VALUES (?, 'playwright', 'ok', 'visitor-landing.example', ?)",
               (sr, json.dumps(["1000000000000001"])))
    db.execute("INSERT INTO snapshots (scan_run_id, capture_method, "
               "capture_status, final_domain, tracking_ids_json) "
               "VALUES (?, 'cloaking_alt', 'ok', 'crawler-landing.example', ?)",
               (sr, json.dumps(["1000000000000001"])))
    db.commit()

    _, ids, domains = _read(db, sr)
    assert domains == {"visitor-landing.example", "crawler-landing.example"}
    assert ids == {"1000000000000001"}, \
        "the ID binding the two domains must be readable from either"


def test_the_crawler_persona_alone_is_still_read(db):
    sr = _scan_run(db)
    _snap(db, sr, "cloaking_alt", "ok", tracking=["G-CRAWLER"])
    assert _read(db, sr)[1] == {"G-CRAWLER"}


def test_a_failed_capture_is_never_read_whatever_its_persona(db):
    """Contract 6. A Cloudflare interstitial is not something the site served,
    and a failure must not shadow a good capture of the same scan."""
    sr = _scan_run(db)
    _snap(db, sr, "playwright", "ok", tracking=["G-REAL"])
    _snap(db, sr, "playwright", "cf_challenge", tracking=["G-ON-THE-WAF-PAGE"])
    _snap(db, sr, "cloaking_alt", "error", tracking=["G-FROM-A-FAILURE"])
    assert _read(db, sr)[1] == {"G-REAL"}


def test_retries_within_one_scan_are_unioned_not_deduped_away(db):
    """Union scope is one scan_run — one moment — so repeated successful
    attempts all count. It never reaches back to a different day's scan."""
    sr = _scan_run(db)
    _snap(db, sr, "playwright", "ok", tracking=["G-FIRST"])
    _snap(db, sr, "playwright", "ok", tracking=["G-SECOND"])
    assert _read(db, sr)[1] == {"G-FIRST", "G-SECOND"}

    other = _scan_run(db, url="https://elsewhere.test/")
    _snap(db, other, "playwright", "ok", tracking=["G-OTHER-SCAN"])
    assert "G-OTHER-SCAN" not in _read(db, sr)[1]
