"""Tests for account-pattern exploration functions.

Both functions are deliberately descriptive: no thresholds, no flags. Tests
verify the reported numbers are accurate for handcrafted fixtures.
"""
import os
import tempfile
from datetime import datetime, timezone

from clustering_url import (
    _extract_content_id,
    account_content_matrix,
    content_time_distribution,
)
from db import get_conn, init_db, migrate_db


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


def _add(conn, case_id, actor, posted_at, original_url, final_url=None):
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', ?, ?, ?, '', ?)""",
        (case_id, actor, posted_at, original_url, _now()),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, original_url, _now()),
    )
    ua_id = cur.lastrowid
    if final_url:
        conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
            "status) VALUES (?, ?, ?, 0, 'done')",
            (ua_id, _now(), final_url),
        )
    conn.commit()


# ── _extract_content_id ────────────────────────────────────────────────────


def test_extract_content_id_prefers_utm_term():
    assert _extract_content_id("https://x.com/?utm_term=145&uid=999") == "145"


def test_extract_content_id_falls_back_to_uid():
    assert _extract_content_id("https://x.com/?uid=638") == "638"


def test_extract_content_id_returns_none_when_absent():
    assert _extract_content_id("https://x.com/?other=1") is None
    assert _extract_content_id(None) is None


# ── account_content_matrix ─────────────────────────────────────────────────


def test_matrix_basic_counts():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "Alice", "2026-01-01 10:00", "https://x.com/?utm_term=145")
    _add(conn, case_id, "Alice", "2026-01-01 11:00", "https://x.com/?utm_term=145")
    _add(conn, case_id, "Bob",   "2026-01-01 12:00", "https://x.com/?utm_term=145")
    _add(conn, case_id, "Bob",   "2026-01-01 13:00", "https://x.com/?utm_term=200")

    m = account_content_matrix(conn, case_id)
    assert m["matrix"][("Alice", "145")] == 2
    assert m["matrix"][("Bob",   "145")] == 1
    assert m["matrix"][("Bob",   "200")] == 1
    assert m["actor_totals"] == {"Alice": 2, "Bob": 2}
    assert m["content_totals"] == {"145": 3, "200": 1}


def test_matrix_sorts_actors_by_total_desc():
    conn = _make_db()
    case_id = _make_case(conn)
    for _ in range(5):
        _add(conn, case_id, "Heavy", "2026-01-01 10:00", "https://x.com/?utm_term=1")
    _add(conn, case_id, "Light", "2026-01-01 10:00", "https://x.com/?utm_term=1")
    m = account_content_matrix(conn, case_id)
    assert m["actors"][0] == "Heavy"
    assert m["actors"][1] == "Light"


def test_matrix_uses_uid_when_utm_term_absent():
    """crawlerlanding.example wrapper case: original URL has uid=, no utm_term."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "Alice", "2026-01-01 10:00", "https://crawlerlanding.example/redacted139/1?uid=638")
    _add(conn, case_id, "Bob",   "2026-01-01 11:00", "https://crawlerlanding.example/redacted139/1?uid=638")
    m = account_content_matrix(conn, case_id)
    assert m["matrix"][("Alice", "638")] == 1
    assert m["matrix"][("Bob",   "638")] == 1


def test_matrix_empty_case():
    conn = _make_db()
    case_id = _make_case(conn)
    m = account_content_matrix(conn, case_id)
    assert m == {
        "actors": [], "contents": [], "matrix": {},
        "actor_totals": {}, "content_totals": {},
    }


def test_matrix_skips_posts_without_content_id():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "Alice", "2026-01-01 10:00", "https://x.com/")  # no params
    _add(conn, case_id, "Bob",   "2026-01-01 11:00", "https://x.com/?utm_term=1")
    m = account_content_matrix(conn, case_id)
    assert "Alice" not in m["actor_totals"]
    assert m["actor_totals"] == {"Bob": 1}


# ── content_time_distribution ──────────────────────────────────────────────


def test_time_distribution_basic():
    conn = _make_db()
    case_id = _make_case(conn)
    # 3 posts of utm_term=1 at 10:00, 10:30, 11:00 (intervals: 30, 30 min)
    _add(conn, case_id, "A", "2026-01-01 10:00", "https://x.com/?utm_term=1")
    _add(conn, case_id, "B", "2026-01-01 10:30", "https://x.com/?utm_term=1")
    _add(conn, case_id, "C", "2026-01-01 11:00", "https://x.com/?utm_term=1")

    res = content_time_distribution(conn, case_id)
    assert len(res) == 1
    r = res[0]
    assert r["content_id"] == "1"
    assert r["post_count"] == 3
    assert r["actor_count"] == 3
    assert r["span_minutes"] == 60
    assert r["min_interval_minutes"] == 30.0
    assert r["median_interval_minutes"] == 30.0


def test_time_distribution_excludes_singletons():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "A", "2026-01-01 10:00", "https://x.com/?utm_term=1")
    res = content_time_distribution(conn, case_id)
    assert res == []


def test_time_distribution_min_interval_captures_burst():
    """Two close posts and one distant — min_interval must reflect the burst."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "A", "2026-01-01 10:00", "https://x.com/?utm_term=1")
    _add(conn, case_id, "B", "2026-01-01 10:03", "https://x.com/?utm_term=1")  # 3 min later
    _add(conn, case_id, "C", "2026-01-01 14:00", "https://x.com/?utm_term=1")  # +4h
    res = content_time_distribution(conn, case_id)
    assert res[0]["min_interval_minutes"] == 3.0
    assert res[0]["span_minutes"] == 240


def test_time_distribution_handles_unparseable_timestamps():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "A", "garbage", "https://x.com/?utm_term=1")
    _add(conn, case_id, "B", "2026-01-01 10:30", "https://x.com/?utm_term=1")
    res = content_time_distribution(conn, case_id)
    assert res == []  # only one parseable post, below threshold


def test_time_distribution_sorted_by_post_count_desc():
    conn = _make_db()
    case_id = _make_case(conn)
    # term=hot has 3 posts, term=cold has 2
    for ts in ("2026-01-01 10:00", "2026-01-01 11:00", "2026-01-01 12:00"):
        _add(conn, case_id, "A", ts, "https://x.com/?utm_term=hot")
    for ts in ("2026-01-01 10:00", "2026-01-01 12:00"):
        _add(conn, case_id, "A", ts, "https://x.com/?utm_term=cold")
    res = content_time_distribution(conn, case_id)
    assert res[0]["content_id"] == "hot"
    assert res[1]["content_id"] == "cold"
