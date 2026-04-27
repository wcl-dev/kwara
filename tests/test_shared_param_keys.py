"""Tests for ticket 1.2 — operator-level key clustering.

shared_param_keys() catches the case where the SAME parameter key appears
across many posts but with VARYING values — a signature of one operator
giving each post/victim a unique ID. Defaults:
  PARAM_KEY_MIN_POSTS   = 3
  PARAM_KEY_MIN_VALUES  = 2
  PARAM_KEY_MAX_DOMAINS = 5
"""
import os
import tempfile
from datetime import datetime, timezone

from clustering_url import shared_param_keys
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


def _add(conn, case_id, url):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, url, now),
    )
    pid = cur.lastrowid
    conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, url, now),
    )
    conn.commit()


def test_aff_id_with_varying_values_clusters():
    """Classic operator-level pattern: same key, every post a different ID."""
    conn = _make_db()
    case_id = _make_case(conn)
    for i in (1, 2, 3, 4, 5):
        _add(conn, case_id, f"https://shop.example/?aff_id=A{i:04d}")
    results = shared_param_keys(conn, case_id)
    matches = [r for r in results if r["param_key"] == "aff_id"]
    assert len(matches) == 1
    m = matches[0]
    assert m["distinct_posts"] == 5
    assert m["distinct_values"] == 5
    assert m["distinct_domains"] == 1
    assert len(m["top_values"]) == 5


def test_below_min_posts_threshold_is_excluded():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://shop.example/?aff_id=A1")
    _add(conn, case_id, "https://shop.example/?aff_id=A2")
    # Only 2 posts; default PARAM_KEY_MIN_POSTS is 3
    results = shared_param_keys(conn, case_id)
    assert [r for r in results if r["param_key"] == "aff_id"] == []


def test_single_value_across_posts_is_excluded():
    """That's the shared_params case (campaign-level), not operator-level."""
    conn = _make_db()
    case_id = _make_case(conn)
    for _ in range(5):
        _add(conn, case_id, "https://shop.example/?aff_id=A1")
    results = shared_param_keys(conn, case_id)
    assert [r for r in results if r["param_key"] == "aff_id"] == []


def test_too_many_domains_is_excluded():
    """Keys appearing across many domains (e.g. q=) are likely generic noise."""
    conn = _make_db()
    case_id = _make_case(conn)
    # Same key, different value each post, across 6 domains > MAX (5)
    for i, host in enumerate(
        ["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"], start=1
    ):
        _add(conn, case_id, f"https://{host}/?id=val{i}")
    results = shared_param_keys(conn, case_id)
    assert [r for r in results if r["param_key"] == "id"] == []


def test_top_values_truncated_to_5():
    conn = _make_db()
    case_id = _make_case(conn)
    for i in range(10):
        _add(conn, case_id, f"https://shop.example/?aff_id=A{i}")
    results = shared_param_keys(conn, case_id)
    m = next(r for r in results if r["param_key"] == "aff_id")
    assert m["distinct_values"] == 10
    assert len(m["top_values"]) == 5


def test_owner_kind_for_known_generic_key():
    """uid is in _PARAM_EXACT as 'generic' → owner_kind = generic, owner empty."""
    from param_attribution import OWNER_KIND_GENERIC
    conn = _make_db()
    case_id = _make_case(conn)
    for v in ("u1", "u2", "u3"):
        _add(conn, case_id, f"https://x.com/?uid={v}")
    results = shared_param_keys(conn, case_id)
    m = next(r for r in results if r["param_key"] == "uid")
    assert m["owner_kind"] == OWNER_KIND_GENERIC
    assert m["owner"] == ""
    assert m["purpose_key"] == "param.user_tracking_id"


def test_long_value_collisions_use_hash():
    """Long values are hashed: identical long tokens count as ONE distinct value."""
    conn = _make_db()
    case_id = _make_case(conn)
    long_a = "a" * 200
    long_b = "b" * 200
    long_c = "c" * 200
    _add(conn, case_id, f"https://x.com/?token={long_a}")
    _add(conn, case_id, f"https://x.com/?token={long_a}")  # duplicate
    _add(conn, case_id, f"https://x.com/?token={long_b}")
    _add(conn, case_id, f"https://x.com/?token={long_c}")
    results = shared_param_keys(conn, case_id)
    m = next(r for r in results if r["param_key"] == "token")
    assert m["distinct_posts"] == 4
    assert m["distinct_values"] == 3  # a, b, c (a counted once)


def test_empty_case_returns_empty_list():
    conn = _make_db()
    case_id = _make_case(conn)
    assert shared_param_keys(conn, case_id) == []
