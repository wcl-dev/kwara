"""Tests for the fast-attribution selection logic (pipeline).

The network steps reuse already-tested functions; what's new — and worth
locking — is WHICH artifacts/scan_runs each cheap step targets, especially
the shadow guard: a scan_run that already has a usable (e.g. Playwright)
snapshot must NOT be re-fetched lightweight, so richer evidence is never
overwritten.
"""
import os
import tempfile
from datetime import datetime, timezone

from kwara.db import get_conn, init_db, migrate_db
from kwara.pipeline import (_artifacts_covered_by_a_sibling,
                            _artifacts_needing_scan, _scan_runs_needing)


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _db():
    conn = get_conn(os.path.join(tempfile.mkdtemp(), "test.db"))
    init_db(conn); migrate_db(conn)
    return conn


def _case(conn):
    now = _now()
    return conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES ('t','',?,?)",
        (now, now),
    ).lastrowid


def _artifact(conn, case_id, url="https://x.com/"):
    now = _now()
    pid = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""", (case_id, url, now),
    ).lastrowid
    return conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, url, now),
    ).lastrowid


def _scan_run(conn, ua_id, status="done", ads=None, enriched=False):
    now = _now()
    sid = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, 'https://x.com/', 0, ?)", (ua_id, now, status),
    ).lastrowid
    if ads is not None:
        conn.execute("UPDATE scan_runs SET ads_txt_json=? WHERE id=?", (ads, sid))
    if enriched:
        conn.execute("UPDATE scan_runs SET domain_enriched_at=? WHERE id=?", (now, sid))
    conn.commit()
    return sid


def _snapshot(conn, sr_id, capture_status="ok", method="playwright"):
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain, captured_at,
           capture_status, capture_method, tracking_ids_json)
           VALUES (?, 'https://x.com/', 'x.com', ?, ?, ?, '{}')""",
        (sr_id, _now(), capture_status, method),
    )
    conn.commit()


def test_artifacts_needing_scan_excludes_those_with_done_scan():
    # Distinct URLs, because selection is now per URL rather than per artifact
    # row: three artifacts sharing one URL would collapse to one target and
    # say nothing about how scan status is read.
    conn = _db(); cid = _case(conn)
    a_done = _artifact(conn, cid, "https://done.test/")
    _scan_run(conn, a_done, status="done")
    a_none = _artifact(conn, cid, "https://none.test/")     # never scanned
    a_err = _artifact(conn, cid, "https://err.test/")
    _scan_run(conn, a_err, status="error")
    needing = set(_artifacts_needing_scan(conn, cid))
    assert a_none in needing
    assert a_err in needing                  # error scan doesn't count as done
    assert a_done not in needing


def test_one_url_carried_by_many_posts_is_scanned_once():
    """The saving step 2 exists for, and the shape live case data had.

    Twenty-two accounts pushing one link produced twenty-two artifacts and,
    before this, twenty-two outbound requests to the same URL.
    """
    conn = _db(); cid = _case(conn)
    ids = [_artifact(conn, cid, "https://pushed-by-many.test/x") for _ in range(22)]
    needing = _artifacts_needing_scan(conn, cid)
    assert needing == [min(ids)], "one fetch for the URL, not one per account"
    assert _artifacts_covered_by_a_sibling(conn, cid) == 21


def test_a_url_scanned_under_another_post_is_not_rescanned():
    """Scanned-ness belongs to the URL, not to the artifact row."""
    conn = _db(); cid = _case(conn)
    first = _artifact(conn, cid, "https://shared.test/x")
    _scan_run(conn, first, status="done")
    _artifact(conn, cid, "https://shared.test/x")           # a later post, same link
    assert _artifacts_needing_scan(conn, cid) == []
    assert _artifacts_covered_by_a_sibling(conn, cid) == 1


def test_dedup_does_not_reach_across_cases():
    conn = _db()
    scanned_case = _case(conn)
    a = _artifact(conn, scanned_case, "https://shared.test/x")
    _scan_run(conn, a, status="done")
    other_case = _case(conn)
    b = _artifact(conn, other_case, "https://shared.test/x")
    assert _artifacts_needing_scan(conn, other_case) == [b]


def test_lightweight_target_when_no_usable_snapshot():
    conn = _db(); cid = _case(conn)
    ua = _artifact(conn, cid); sid = _scan_run(conn, ua, status="done")
    # no snapshot at all -> needs lightweight (to get tracking IDs)
    assert sid in _scan_runs_needing(conn, cid)["lightweight"]


def test_shadow_guard_skips_scan_run_with_usable_snapshot():
    # The core correctness guard: an existing 'ok' (Playwright) snapshot must
    # NOT be overwritten by a cheap lightweight fetch.
    conn = _db(); cid = _case(conn)
    ua = _artifact(conn, cid); sid = _scan_run(conn, ua, status="done")
    _snapshot(conn, sid, capture_status="ok", method="playwright")
    assert sid not in _scan_runs_needing(conn, cid)["lightweight"]


def test_failed_snapshot_does_not_block_lightweight():
    # A file_missing/error snapshot is not usable, so lightweight should still fill it.
    conn = _db(); cid = _case(conn)
    ua = _artifact(conn, cid); sid = _scan_run(conn, ua, status="done")
    _snapshot(conn, sid, capture_status="file_missing", method="playwright")
    assert sid in _scan_runs_needing(conn, cid)["lightweight"]


def test_ads_and_intel_targets():
    conn = _db(); cid = _case(conn)
    # one needs both, one has both already
    ua1 = _artifact(conn, cid); s1 = _scan_run(conn, ua1, status="done")
    ua2 = _artifact(conn, cid); s2 = _scan_run(conn, ua2, status="done",
                                               ads='{"status":"ok"}', enriched=True)
    t = _scan_runs_needing(conn, cid)
    assert s1 in t["ads"] and s1 in t["intel"]
    assert s2 not in t["ads"] and s2 not in t["intel"]


def test_force_refreshes_http_only_but_never_playwright():
    # force may refresh a stale lightweight ('http_only') snapshot, but must
    # NEVER target a scan_run with a full Playwright snapshot (shadow guard).
    conn = _db(); cid = _case(conn)
    ua_lw = _artifact(conn, cid); s_lw = _scan_run(conn, ua_lw, status="done")
    _snapshot(conn, s_lw, capture_status="ok", method="http_only")
    ua_pw = _artifact(conn, cid); s_pw = _scan_run(conn, ua_pw, status="done")
    _snapshot(conn, s_pw, capture_status="ok", method="playwright")

    default = _scan_runs_needing(conn, cid)["lightweight"]
    assert s_lw not in default and s_pw not in default      # both have ok snapshots

    forced = _scan_runs_needing(conn, cid, force=True)["lightweight"]
    assert s_lw in forced                                    # http_only refreshed
    assert s_pw not in forced                                # playwright protected


def test_only_latest_done_scan_run_considered():
    # If an artifact was re-scanned, only its latest done scan_run is a target.
    conn = _db(); cid = _case(conn)
    ua = _artifact(conn, cid)
    old = _scan_run(conn, ua, status="done")
    new = _scan_run(conn, ua, status="done")
    lw = _scan_runs_needing(conn, cid)["lightweight"]
    assert new in lw and old not in lw
