"""Tests for clustering_url.wrapper_relationships()."""
import os
import tempfile
from datetime import datetime, timezone

from clustering_url import wrapper_relationships
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


def _add_scanned(conn, case_id, original_url, final_url, hop_count=2):
    """Add a post + url_artifact + done scan_run with given final_url."""
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, original_url, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, original_url, now),
    )
    ua_id = cur.lastrowid
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, ?, 'done')",
        (ua_id, now, final_url, hop_count),
    )
    conn.commit()


def _add_unscanned(conn, case_id, original_url):
    """Add a post + url_artifact but no scan_run (or running scan)."""
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, original_url, now),
    )
    pid = cur.lastrowid
    conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, original_url, now),
    )
    conn.commit()


def test_empty_case_returns_empty_list():
    conn = _make_db()
    case_id = _make_case(conn)
    assert wrapper_relationships(conn, case_id) == []


def test_unscanned_url_excluded():
    conn = _make_db()
    case_id = _make_case(conn)
    _add_unscanned(conn, case_id, "https://crawlerlanding.example/redacted139/1")
    assert wrapper_relationships(conn, case_id) == []


def test_same_domain_redirect_excluded():
    """A redirect that stays on the same hostname is not a wrapper."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add_scanned(conn, case_id,
                 "https://example.com/short/abc",
                 "https://example.com/redacted139s/full-path")
    assert wrapper_relationships(conn, case_id) == []


def test_single_wrapper_to_target_relationship():
    """One URL: crawlerlanding.example → visitorlanding.example should appear as one row."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add_scanned(conn, case_id,
                 "https://crawlerlanding.example/redacted139/277290?uid=638",
                 "https://visitorlanding.example/redacted139/277290?utm_term=638")
    out = wrapper_relationships(conn, case_id)
    assert len(out) == 1
    r = out[0]
    assert r["original_domain"] == "crawlerlanding.example"
    assert r["final_domain"] == "visitorlanding.example"
    assert r["url_count"] == 1
    assert r["post_count"] == 1


def test_multiple_urls_same_wrapper_aggregate():
    """Multiple URLs from the same wrapper-target pair → 1 row, count = N."""
    conn = _make_db()
    case_id = _make_case(conn)
    for i in range(5):
        _add_scanned(
            conn, case_id,
            f"https://crawlerlanding.example/redacted139/{i}?uid={i}",
            f"https://visitorlanding.example/redacted139/{i}?utm_term={i}",
        )
    out = wrapper_relationships(conn, case_id)
    assert len(out) == 1
    assert out[0]["url_count"] == 5
    assert out[0]["post_count"] == 5


def test_one_wrapper_to_multiple_targets_makes_multiple_rows():
    """If crawlerlanding.example redirects some URLs to A and others to B, we get 2 rows."""
    conn = _make_db()
    case_id = _make_case(conn)
    for i in range(3):
        _add_scanned(conn, case_id, f"https://crawlerlanding.example/a/{i}", "https://visitorlanding.example/")
    for i in range(2):
        _add_scanned(conn, case_id, f"https://crawlerlanding.example/b/{i}", "https://other.example/")

    out = wrapper_relationships(conn, case_id)
    assert len(out) == 2
    targets = {(r["original_domain"], r["final_domain"]) for r in out}
    assert targets == {
        ("crawlerlanding.example", "visitorlanding.example"),
        ("crawlerlanding.example", "other.example"),
    }


def test_sorted_by_url_count_desc():
    conn = _make_db()
    case_id = _make_case(conn)
    # bigger group: 5 URLs
    for i in range(5):
        _add_scanned(conn, case_id,
                     f"https://big-wrapper.example/{i}",
                     "https://big-target.example/")
    # smaller group: 2 URLs
    for i in range(2):
        _add_scanned(conn, case_id,
                     f"https://small-wrapper.example/{i}",
                     "https://small-target.example/")
    out = wrapper_relationships(conn, case_id)
    assert out[0]["original_domain"] == "big-wrapper.example"
    assert out[0]["url_count"] == 5
    assert out[1]["original_domain"] == "small-wrapper.example"


def test_hop_count_min_max_recorded():
    conn = _make_db()
    case_id = _make_case(conn)
    _add_scanned(conn, case_id, "https://a.com/1", "https://b.com/", hop_count=1)
    _add_scanned(conn, case_id, "https://a.com/2", "https://b.com/", hop_count=3)
    _add_scanned(conn, case_id, "https://a.com/3", "https://b.com/", hop_count=2)
    out = wrapper_relationships(conn, case_id)
    assert len(out) == 1
    assert out[0]["min_hops"] == 1
    assert out[0]["max_hops"] == 3


def test_sample_urls_capped_at_5():
    conn = _make_db()
    case_id = _make_case(conn)
    for i in range(10):
        _add_scanned(conn, case_id, f"https://w.com/{i}", "https://t.com/")
    out = wrapper_relationships(conn, case_id)
    assert len(out[0]["sample_urls"]) == 5


def test_malformed_final_url_skipped():
    """If final_url has no hostname, the row is skipped, no crash."""
    conn = _make_db()
    case_id = _make_case(conn)
    # Insert with intentionally malformed final_url
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, 'https://a.com/', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, 'this-is-not-a-url', 0, 'done')",
        (ua_id, now),
    )
    conn.commit()
    # urlparse('this-is-not-a-url').hostname returns None
    assert wrapper_relationships(conn, case_id) == []
