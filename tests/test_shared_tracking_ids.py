"""Tests for clustering.shared_tracking_ids()."""
import json
import os
import tempfile
from datetime import datetime, timezone

from clustering_infra import shared_tracking_ids
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


def _add(conn, case_id, original_url, final_url, final_domain, tracking_ids: dict | None):
    """Add a post + url + scan_run + snapshot in one shot."""
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
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, now, final_url),
    )
    sr_id = cur.lastrowid
    ids_json = json.dumps(tracking_ids) if tracking_ids is not None else None
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, tracking_ids_json)
           VALUES (?, ?, ?, ?, 'ok', ?)""",
        (sr_id, final_url, final_domain, now, ids_json),
    )
    conn.commit()


def test_empty_case_returns_empty_list():
    conn = _make_db()
    case_id = _make_case(conn)
    assert shared_tracking_ids(conn, case_id) == []


def test_same_pixel_id_across_two_domains_clusters():
    conn = _make_db()
    case_id = _make_case(conn)
    pixel = {"Meta Pixel": ["1234567890123456"]}
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com", pixel)
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com", pixel)
    res = shared_tracking_ids(conn, case_id)
    assert len(res) == 1
    r = res[0]
    assert r["platform"] == "Meta Pixel"
    assert r["tracking_id"] == "1234567890123456"
    assert r["domain_count"] == 2
    assert sorted(r["domains"]) == ["a.com", "b.com"]


def test_singleton_excluded():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         {"Meta Pixel": ["9999999999999999"]})
    assert shared_tracking_ids(conn, case_id) == []


def test_multiple_distinct_clusters():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/1", "https://a.com/", "a.com",
         {"Meta Pixel": ["1111111111111111"]})
    _add(conn, case_id, "http://x/2", "https://b.com/", "b.com",
         {"Meta Pixel": ["1111111111111111"]})
    _add(conn, case_id, "http://x/3", "https://c.com/", "c.com",
         {"Google Analytics 4": ["G-AB12CD34"]})
    _add(conn, case_id, "http://x/4", "https://d.com/", "d.com",
         {"Google Analytics 4": ["G-AB12CD34"]})
    res = shared_tracking_ids(conn, case_id)
    assert len(res) == 2
    platforms = {r["platform"] for r in res}
    assert platforms == {"Meta Pixel", "Google Analytics 4"}


def test_sorted_by_domain_count_desc():
    conn = _make_db()
    case_id = _make_case(conn)
    # bigger cluster: Pixel on 3 domains
    for d in ("a.com", "b.com", "c.com"):
        _add(conn, case_id, f"http://x/{d}", f"https://{d}/", d,
             {"Meta Pixel": ["7777777777777777"]})
    # smaller cluster: GA on 2 domains
    for d in ("d.com", "e.com"):
        _add(conn, case_id, f"http://x/{d}", f"https://{d}/", d,
             {"Google Analytics 4": ["G-XYZ123"]})
    res = shared_tracking_ids(conn, case_id)
    assert res[0]["domain_count"] == 3
    assert res[0]["platform"] == "Meta Pixel"
    assert res[1]["domain_count"] == 2


def test_same_id_on_same_domain_multiple_times_doesnt_inflate():
    """If 5 URLs from a.com all share Pixel X, that's still 1 domain."""
    conn = _make_db()
    case_id = _make_case(conn)
    pixel = {"Meta Pixel": ["1234567890123456"]}
    for i in range(5):
        _add(conn, case_id, f"http://x/{i}", "https://a.com/p", "a.com", pixel)
    # Singleton — only one domain → excluded
    assert shared_tracking_ids(conn, case_id) == []


def test_malformed_tracking_ids_json_skipped():
    conn = _make_db()
    case_id = _make_case(conn)
    # Insert manually with bad JSON
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
        "url_order, created_at) VALUES (?, ?, 'http://x/a', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, 'https://a.com/', 0, 'done')",
        (ua_id, now),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, tracking_ids_json)
           VALUES (?, 'https://a.com/', 'a.com', ?, 'ok', '{not json')""",
        (sr_id, now),
    )
    conn.commit()
    assert shared_tracking_ids(conn, case_id) == []


def test_multiple_ids_per_platform_each_clusters_independently():
    """One snapshot can have several Pixel IDs; each must be evaluated separately."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         {"Meta Pixel": ["1111111111111111", "2222222222222222"]})
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         {"Meta Pixel": ["1111111111111111"]})  # only the first ID
    res = shared_tracking_ids(conn, case_id)
    assert len(res) == 1
    assert res[0]["tracking_id"] == "1111111111111111"


def test_later_bad_snapshot_does_not_erase_earlier_good_one():
    """Codex review fix #2: a re-capture that fails (Cloudflare challenge,
    empty HTML) on top of a successful earlier snapshot must not erase the
    earlier attribution evidence. We pick the latest *usable* snapshot, not
    the latest snapshot.
    """
    conn = _make_db()
    case_id = _make_case(conn)
    pixel = {"Meta Pixel": ["1234567890123456"]}
    # Two URLs, both with the same Pixel — initial captures all good
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com", pixel)
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com", pixel)

    # Sanity baseline: both contribute, cluster fires
    baseline = shared_tracking_ids(conn, case_id)
    assert len(baseline) == 1
    assert baseline[0]["domain_count"] == 2

    # Now add a LATER bad snapshot to a.com's existing scan_run:
    # capture_status='cf_challenge', tracking_ids_json='{}' (empty dict).
    sr_a = conn.execute(
        "SELECT sr.id FROM scan_runs sr JOIN url_artifacts ua ON ua.id = sr.url_artifact_id "
        "WHERE ua.original_url = 'http://x/a' ORDER BY sr.id DESC LIMIT 1"
    ).fetchone()["id"]
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, tracking_ids_json)
           VALUES (?, 'https://a.com/', 'a.com', ?, 'cf_challenge', '{}')""",
        (sr_a, _now()),
    )
    conn.commit()

    after = shared_tracking_ids(conn, case_id)
    assert len(after) == 1, (
        "later bad snapshot must not erase earlier good attribution"
    )
    assert sorted(after[0]["domains"]) == ["a.com", "b.com"]


def test_only_bad_snapshot_yields_no_signal():
    """Sanity: if the ONLY snapshot is empty/failed, no cluster surfaces."""
    conn = _make_db()
    case_id = _make_case(conn)
    # add() inserts a 'ok' snapshot — bypass it manually
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
        "url_order, created_at) VALUES (?, ?, 'http://x/bad', '', 0, ?)",
        (pid, case_id, now),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, 'https://bad.com/', 0, 'done')",
        (ua_id, now),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, tracking_ids_json)
           VALUES (?, 'https://bad.com/', 'bad.com', ?, 'cf_challenge', '{}')""",
        (sr_id, now),
    )
    conn.commit()
    assert shared_tracking_ids(conn, case_id) == []
