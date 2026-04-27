"""Tests for ticket 1.3 — relaxed filters in clustering.shared_params().

Verifies single-char keys are no longer dropped and long values are
compared via SHA-256 prefix instead of being silently filtered.
"""
import os
import tempfile
from datetime import datetime, timezone

from clustering import _normalize_param_value, shared_params
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


def _add_post(conn, case_id, original_url, final_url=None):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence
           (case_id, platform, permalink, actor_label, posted_at, message_text,
            screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, original_url, now),
    )
    post_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (post_id, case_id, original_url, now),
    )
    ua_id = cur.lastrowid
    if final_url:
        conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
            "status) VALUES (?, ?, ?, 0, 'done')",
            (ua_id, now, final_url),
        )
    conn.commit()


def test_normalize_short_value_returns_literal():
    cmp_, disp = _normalize_param_value("abc")
    assert cmp_ == "abc"
    assert disp == "abc"


def test_normalize_long_value_returns_hash():
    long = "x" * 200
    cmp_, disp = _normalize_param_value(long)
    assert cmp_.startswith("__hash__:")
    assert disp.startswith("[hash:") and disp.endswith("…]")
    # Same input → same hash
    cmp2, _ = _normalize_param_value(long)
    assert cmp_ == cmp2


def test_normalize_long_value_distinct_inputs_distinct_hashes():
    cmp_a, _ = _normalize_param_value("a" * 200)
    cmp_b, _ = _normalize_param_value("b" * 200)
    assert cmp_a != cmp_b


def test_single_char_key_now_clusters():
    """Previously `?u=` style params were silently dropped. They should now cluster."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://line.me/?u=https://target.example/article/1")
    _add_post(conn, case_id, "https://line.me/?u=https://target.example/article/1")
    results = shared_params(conn, case_id)
    keys = {r["param_key"] for r in results}
    assert "u" in keys, f"single-char key 'u' should cluster, got {keys}"


def test_long_value_clusters_via_hash():
    """Two posts carrying the same opaque 200-char token should cluster."""
    conn = _make_db()
    case_id = _make_case(conn)
    long_token = "x" * 200
    _add_post(conn, case_id, f"https://shopee.tw/?af_token={long_token}")
    _add_post(conn, case_id, f"https://shopee.tw/?af_token={long_token}")
    results = shared_params(conn, case_id)
    matches = [r for r in results if r["param_key"] == "af_token"]
    assert len(matches) == 1, f"expected af_token cluster, got {results}"
    assert matches[0]["post_count"] == 2
    assert matches[0]["param_value"].startswith("[hash:")


def test_long_values_with_different_content_do_not_falsely_cluster():
    """Distinct long tokens must not collide into a fake cluster."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, f"https://shopee.tw/?af_token={'a' * 200}")
    _add_post(conn, case_id, f"https://shopee.tw/?af_token={'b' * 200}")
    results = shared_params(conn, case_id)
    matches = [r for r in results if r["param_key"] == "af_token"]
    assert matches == [], f"distinct tokens must not cluster, got {matches}"


def test_empty_key_still_skipped():
    """Truly empty keys (which can happen with malformed URLs) stay filtered."""
    conn = _make_db()
    case_id = _make_case(conn)
    # parse_qs ignores keyless `?=value` so this is mostly defensive.
    _add_post(conn, case_id, "https://example.com/?valid=1")
    _add_post(conn, case_id, "https://example.com/?valid=1")
    results = shared_params(conn, case_id)
    assert all(r["param_key"] for r in results), "no empty keys in output"
