"""Tests for the owner-kind enum exposed by shared_params().

After the i18n decoupling, clustering returns three stable kinds:
  - OWNER_KIND_PLATFORM   recognised vendor; `owner` = raw label like "Google Analytics"
  - OWNER_KIND_GENERIC    generic tracking convention (uid, aff_id, ref, …)
  - OWNER_KIND_UNKNOWN    key not recognised by identify_param()

The view layer translates kind+raw-owner into a localised string at
render time. Clustering itself no longer touches i18n.
"""
import os
import tempfile
from datetime import datetime, timezone

from clustering_url import shared_params
from param_attribution import (
    OWNER_KIND_GENERIC,
    OWNER_KIND_PLATFORM,
    OWNER_KIND_UNKNOWN,
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


def _add_post(conn, case_id, url):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence
           (case_id, platform, permalink, actor_label, posted_at, message_text,
            screenshot_path, ingested_at)
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


def _row_for(results, key):
    return next((r for r in results if r["param_key"] == key), None)


def test_generic_table_hit_marked_generic_kind():
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://picread.net/article/1?uid=638")
    _add_post(conn, case_id, "https://picread.net/article/2?uid=638")
    r = _row_for(shared_params(conn, case_id), "uid")
    assert r is not None
    assert r["owner_kind"] == OWNER_KIND_GENERIC
    assert r["platform_id"] == "generic"
    assert r["purpose_key"] == "param.user_tracking_id"


def test_unknown_key_marked_unknown_kind():
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://example.com/?xyz_weird_token=12345")
    _add_post(conn, case_id, "https://example.com/?xyz_weird_token=12345")
    r = _row_for(shared_params(conn, case_id), "xyz_weird_token")
    assert r is not None
    assert r["owner_kind"] == OWNER_KIND_UNKNOWN
    assert r["platform_id"] == ""
    assert r["purpose_key"] == ""


def test_known_platform_marked_platform_kind_with_canonical_id():
    """utm_source → OWNER_KIND_PLATFORM, canonical platform_id."""
    from param_attribution import PLATFORM_GOOGLE_ANALYTICS
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://example.com/?utm_source=newsletter")
    _add_post(conn, case_id, "https://example.com/?utm_source=newsletter")
    r = _row_for(shared_params(conn, case_id), "utm_source")
    assert r is not None
    assert r["owner_kind"] == OWNER_KIND_PLATFORM
    assert r["platform_id"] == PLATFORM_GOOGLE_ANALYTICS
    assert r["purpose_key"] == "param.traffic_source"


def test_three_kinds_coexist_in_same_case():
    from param_attribution import PLATFORM_GOOGLE_ANALYTICS
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id,
              "https://example.com/?utm_source=fb&aff_id=A1&xyz_weird=1")
    _add_post(conn, case_id,
              "https://example.com/?utm_source=fb&aff_id=A1&xyz_weird=1")
    by_key = {r["param_key"]: r for r in shared_params(conn, case_id)}
    assert by_key["utm_source"]["owner_kind"]  == OWNER_KIND_PLATFORM
    assert by_key["utm_source"]["platform_id"] == PLATFORM_GOOGLE_ANALYTICS
    assert by_key["aff_id"]["owner_kind"]      == OWNER_KIND_GENERIC
    assert by_key["xyz_weird"]["owner_kind"]   == OWNER_KIND_UNKNOWN


def test_clustering_output_does_not_depend_on_active_language():
    """Regression: previously the result strings depended on i18n.set_lang().
    Now they should be deterministic regardless of UI language."""
    from i18n import set_lang
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://x.com/?uid=638")
    _add_post(conn, case_id, "https://x.com/?uid=638")

    set_lang("en")
    r_en = _row_for(shared_params(conn, case_id), "uid")
    set_lang("zh-TW")
    r_zh = _row_for(shared_params(conn, case_id), "uid")
    assert r_en == r_zh, "clustering output must not depend on UI language"
