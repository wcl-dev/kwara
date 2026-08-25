"""A single hostile page must not be able to stop a batch.

On 2026-08-25 a 57-URL capture run stopped dead partway through: the Chromium
process stayed alive, no file was written for an hour, and the run had to be
killed by hand. The cause was one unbounded call — `page.screenshot(full_page=
True)` on an infinite-scroll page — sitting next to a `goto` and a
`wait_for_load_state` that both had timeouts.

Killing it cost more than the hour. Capture directories were allocated for all
57 URLs up front and no `snapshots` row was written until the whole batch came
back, so 25 finished captures became orphan directories: artifacts on disk that
the database has never heard of. There were 2,440 of those, 1.67 GB.

Three things are covered here, matching the three ways that went wrong:
  * the screenshot itself is bounded, and degrades rather than hanging;
  * a worker that stops reporting progress is killed and the batch resumes;
  * each chunk's rows are committed before the next chunk starts.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

import pytest

from kwara import config, snapshots
from kwara.db import get_conn, init_db, migrate_db

WORKER_DIR = os.path.dirname(os.path.abspath(snapshots.__file__))
sys.path.insert(0, WORKER_DIR)
import _snapshot_worker as worker  # noqa: E402


# ── the unbounded call ─────────────────────────────────────────────────────

class _FakePage:
    """Stands in for a Playwright page with a pathological full-page render."""

    def __init__(self, *, full_page_fails, viewport_fails=False):
        self.full_page_fails = full_page_fails
        self.viewport_fails = viewport_fails
        self.calls = []

    def screenshot(self, path=None, full_page=False, timeout=None):
        self.calls.append({"full_page": full_page, "timeout": timeout})
        if full_page and self.full_page_fails:
            raise TimeoutError("Timeout exceeded")
        if not full_page and self.viewport_fails:
            raise RuntimeError("boom")
        with open(path, "wb") as fh:
            fh.write(b"\x89PNG")


def test_every_screenshot_call_carries_a_timeout(tmp_path):
    """The whole defect in one assertion: an unbounded screenshot is what let a
    single page outlive the batch."""
    page = _FakePage(full_page_fails=False)
    assert worker._safe_screenshot(page, str(tmp_path / "s.png")) is None
    assert page.calls[0]["timeout"], "full-page screenshot was issued with no timeout"


def test_a_page_that_will_not_finish_rendering_degrades_to_the_viewport(tmp_path):
    """Weaker evidence, but evidence — and the batch keeps moving. A cropped
    screenshot of an infinite-scroll page is worth more than 30 domains that
    were never visited."""
    page = _FakePage(full_page_fails=True)
    shot = tmp_path / "s.png"
    note = worker._safe_screenshot(page, str(shot))

    assert note and "viewport" in note, note
    assert shot.is_file() and shot.stat().st_size > 0
    assert [c["full_page"] for c in page.calls] == [True, False]


def test_a_screenshot_that_fails_outright_still_returns(tmp_path):
    """No screenshot at all is the worst outcome and still must not raise:
    the HTML and HAR beside it are captured either way."""
    page = _FakePage(full_page_fails=True, viewport_fails=True)
    note = worker._safe_screenshot(page, str(tmp_path / "s.png"))
    assert note and "failed" in note, note


def test_the_screenshot_budget_is_configurable_and_never_unbounded(monkeypatch):
    monkeypatch.setenv("KWARA_SCREENSHOT_TIMEOUT", "12")
    assert worker._screenshot_timeout_sec() == 12.0
    for junk in ("", "abc", "0", "-5"):
        monkeypatch.setenv("KWARA_SCREENSHOT_TIMEOUT", junk)
        assert worker._screenshot_timeout_sec() > 0, junk


def test_a_degraded_screenshot_is_not_recorded_as_a_failed_capture(tmp_path):
    """Otherwise every enormous page becomes permanently 'pending' and the run
    re-captures it forever. The note belongs in capture_detail, where an analyst
    reading a cropped image can find out why — not in the status."""
    shot = tmp_path / "s.png"
    shot.write_bytes(b"\x89PNG" + b"\x00" * 4096)
    html = tmp_path / "page.html"
    html.write_text("<html><body>hi</body></html>" * 50, encoding="utf-8")

    r = {"request_domains": [], "error": None,
         "screenshot_path": str(shot), "html_path": str(html),
         "screenshot_note": "screenshot_degraded_to_viewport (full_page: TimeoutError)"}
    (_, _, ss, _, tags, status, detail) = snapshots._prepare_insert_row(
        "https://example.test/", 0, r)

    assert status == snapshots.CAPTURE_OK, (status, detail)
    assert "capture_error" not in tags
    assert ss == str(shot)
    assert "degraded_to_viewport" in (detail or ""), detail


def test_a_stalled_capture_is_reported_as_a_timeout_not_as_a_missing_file():
    """`capture_status` is what an analyst filters on to decide what to retry.
    A killed capture is a timeout; calling it file_missing hides why."""
    r = snapshots._error_results(
        [{"scan_run_id": 1}], "capture stalled; killed after 400s with no progress")[0]
    (_, _, _, _, _, status, _) = snapshots._prepare_insert_row(
        "https://example.test/", 0, r)
    assert status == snapshots.CAPTURE_TIMEOUT, status


def test_the_stall_budget_is_finite_and_tracks_the_screenshot_budget():
    small = snapshots._per_url_stall_cap(30, "headless_only",
                                         {"KWARA_SCREENSHOT_TIMEOUT": "10"})
    large = snapshots._per_url_stall_cap(30, "headless_only",
                                         {"KWARA_SCREENSHOT_TIMEOUT": "120"})
    assert 0 < small < large, (small, large)


# ── resuming past the URL that wedged the worker ───────────────────────────

def _jobs(n):
    return [{"scan_run_id": i, "final_url": f"https://s{i}.test/",
             "screenshot_path": f"/tmp/{i}.png", "html_path": f"/tmp/{i}.html"}
            for i in range(n)]


def test_a_wedged_worker_costs_one_url_not_the_whole_batch(monkeypatch):
    """The behaviour the incident was missing. Before, the only bound was the
    whole-batch timeout; when it fired, every capture already made was
    discarded and reported as a subprocess failure."""
    urls = _jobs(5)
    launches = []

    def fake_launch(chunk, timeout, mode, sub_env):
        launches.append([u["scan_run_id"] for u in chunk])
        if len(launches) == 1:
            # finished 0 and 1, then wedged on 2
            progress = {0: {"scan_run_id": chunk[0]["scan_run_id"], "error": None},
                        1: {"scan_run_id": chunk[1]["scan_run_id"], "error": None}}
            return None, progress, 2, ""
        progress = {i: {"scan_run_id": u["scan_run_id"], "error": None}
                    for i, u in enumerate(chunk)}
        return [progress[i] for i in range(len(chunk))], progress, None, ""

    monkeypatch.setattr(snapshots, "_launch_worker", fake_launch)
    out = snapshots._run_worker_phase(urls, 30, "headless_only")

    assert len(out) == len(urls)
    assert [r["scan_run_id"] for r in out] == [0, 1, 2, 3, 4], \
        "results came back out of order; they are zipped against the job list"
    assert not out[0]["error"] and not out[1]["error"], \
        "captures the worker had already finished were thrown away"
    assert "stalled" in (out[2]["error"] or ""), out[2]
    assert not out[3]["error"] and not out[4]["error"], \
        "the URLs after the stall were never retried"
    assert launches == [[0, 1, 2, 3, 4], [3, 4]]


def test_a_batch_where_everything_stalls_still_terminates(monkeypatch):
    """The resume loop drops at least the offending URL each time, so it cannot
    spin. Worth pinning: an unbounded retry loop would be a worse bug than the
    one being fixed."""
    urls = _jobs(4)
    calls = []

    def always_stalls(chunk, timeout, mode, sub_env):
        calls.append(len(chunk))
        return None, {}, 0, ""

    monkeypatch.setattr(snapshots, "_launch_worker", always_stalls)
    out = snapshots._run_worker_phase(urls, 30, "headless_only")

    assert len(out) == 4
    assert all("stalled" in (r["error"] or "") for r in out), out
    assert calls == [4, 3, 2, 1]


def test_a_worker_that_kills_itself_is_resumed_from_where_it_stopped(monkeypatch):
    """The worker's own watchdog takes the process down mid-batch, so there is
    no result file — only the progress it flushed. That is enough to carry on:
    a crash mid-batch is the other way captures used to be lost wholesale."""
    urls = _jobs(3)
    launches = []

    def dies_after_one(chunk, timeout, mode, sub_env):
        launches.append([u["scan_run_id"] for u in chunk])
        return None, {0: {"scan_run_id": chunk[0]["scan_run_id"], "error": None}}, \
            None, "no result file; stderr: worker killed itself"

    monkeypatch.setattr(snapshots, "_launch_worker", dies_after_one)
    out = snapshots._run_worker_phase(urls, 30, "headless_only")

    assert launches == [[0, 1, 2], [1, 2], [2]]
    assert [r["scan_run_id"] for r in out] == [0, 1, 2]
    assert not any(r["error"] for r in out), \
        "captures the worker flushed before dying were thrown away"


def test_a_worker_that_produces_nothing_at_all_is_not_relaunched(monkeypatch):
    """No results AND no progress is the environment, not one hostile URL —
    a missing browser, a full disk. Relaunching walks into the same wall once
    per URL and turns a clear failure into a long one."""
    urls = _jobs(4)
    launches = []

    def produces_nothing(chunk, timeout, mode, sub_env):
        launches.append(len(chunk))
        return None, {}, None, "no result file; stderr: playwright not installed"

    monkeypatch.setattr(snapshots, "_launch_worker", produces_nothing)
    out = snapshots._run_worker_phase(urls, 30, "headless_only")

    assert launches == [4], "the phase relaunched into a broken environment"
    assert all("playwright not installed" in (r["error"] or "") for r in out), out


@pytest.mark.parametrize("mode", ["headless_only", "headed_only"])
def test_the_worker_reports_progress_so_the_parent_can_tell_slow_from_wedged(mode):
    """The parent distinguishes the two by watching this file grow. If the
    worker stopped writing it, every slow capture would look like a stall."""
    src = open(worker.__file__, encoding="utf-8").read()
    assert "_report_progress" in src
    assert src.count("_report_progress(") >= 3, \
        "a capture path finishes a URL without telling the parent"
    assert "os.fsync" in src, \
        "progress buffered in the worker is gone when the parent kills it"


# ── incremental recording ──────────────────────────────────────────────────

def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snapshots"))
    conn = get_conn(str(tmp_path / "c.db"))
    init_db(conn)
    migrate_db(conn)
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) "
        "VALUES ('t','',?,?)", (_now(), _now()))
    case_id = cur.lastrowid
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?,'','','','','','',?)""", (case_id, _now()))
    mid = cur.lastrowid
    sr_ids = []
    for i in range(4):
        cur = conn.execute(
            "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
            "url_order, created_at) VALUES (?,?,?,?,?,?)",
            (mid, case_id, f"https://d{i}.test/", f"d{i}.test", i, _now()))
        cur = conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
            "status) VALUES (?,?,?,0,'done')",
            (cur.lastrowid, _now(), f"https://d{i}.test/"))
        sr_ids.append(cur.lastrowid)
    conn.commit()
    return conn, case_id, sr_ids, tmp_path


def test_each_chunk_is_recorded_before_the_next_one_starts(seeded, monkeypatch):
    """The orphan-directory fix. With one subprocess for the whole batch and
    one write at the end, killing a run at URL 25 of 57 left 25 sets of
    artifacts that no snapshots row pointed at."""
    conn, _, sr_ids, tmp_path = seeded
    monkeypatch.setenv("KWARA_SNAPSHOT_CHUNK", "2")

    observed = []

    def fake_capture(jobs, timeout=30, env_override=None):
        rows = conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
        allocated = sum(1 for _root, ds, _fs in os.walk(str(tmp_path / "snapshots"))
                        for d in ds if "T" in d and "_" in d)
        observed.append({"rows_before": rows, "size": len(jobs),
                         "dirs_allocated": allocated})
        return [{"scan_run_id": j["scan_run_id"], "screenshot_path": None,
                 "html_path": None, "request_domains": [], "error": None}
                for j in jobs]

    monkeypatch.setattr(snapshots, "_capture_in_subprocess", fake_capture)
    out = snapshots.snapshot_batch(conn, sr_ids)

    assert len(observed) == 2, "the batch was not chunked"
    assert [o["size"] for o in observed] == [2, 2]
    assert observed[0]["rows_before"] == 0
    assert observed[1]["rows_before"] == 2, \
        "the first chunk's rows were still unwritten when the second one started"
    assert observed[0]["dirs_allocated"] == 2, \
        "directories were allocated for URLs the run had not reached yet"
    assert len(out) == 4


def test_the_returned_ids_still_follow_the_order_they_were_asked_for(seeded, monkeypatch):
    """Chunking reorders the capture for rate-limit reasons; callers still get
    their own order back."""
    conn, _, sr_ids, _ = seeded
    monkeypatch.setenv("KWARA_SNAPSHOT_CHUNK", "2")
    monkeypatch.setattr(snapshots, "_capture_in_subprocess",
                        lambda jobs, timeout=30, env_override=None: [
                            {"scan_run_id": j["scan_run_id"], "screenshot_path": None,
                             "html_path": None, "request_domains": [], "error": None}
                            for j in jobs])

    ids = snapshots.snapshot_batch(conn, sr_ids)
    got = [conn.execute("SELECT scan_run_id FROM snapshots WHERE id = ?",
                        (i,)).fetchone()[0] for i in ids]
    assert got == sr_ids, got


def test_the_whole_launch_timeout_stops_the_phase_but_keeps_what_was_captured(monkeypatch):
    """The old behaviour on this path threw the entire batch away and reported
    a subprocess failure. Stopping is still right — a launch that blew its
    whole budget is an environment problem, not the next URL's fault — but the
    captures already made are evidence and must survive it."""
    urls = _jobs(4)
    launches = []

    def times_out(chunk, timeout, mode, sub_env):
        launches.append(len(chunk))
        return None, {0: {"scan_run_id": chunk[0]["scan_run_id"], "error": None}}, \
            None, "subprocess timed out"

    monkeypatch.setattr(snapshots, "_launch_worker", times_out)
    out = snapshots._run_worker_phase(urls, 30, "headless_only")

    assert launches == [4], "the phase relaunched after blowing its whole budget"
    assert not out[0]["error"], "a finished capture was discarded"
    assert all("timed out" in (r["error"] or "") for r in out[1:]), out
    assert snapshots._prepare_insert_row("https://x.test/", 0, out[1])[5] == \
        snapshots.CAPTURE_TIMEOUT
