"""Tests for ticket 1.1 — owner-label split for generic vs unrecognized params.

Previously every `generic` entry in clustering._PARAM_EXACT (`uid`, `aff_id`,
`ref`, `click_id`, `tracking_id`, `campaign_id`, `source`, …) was overwritten
to display as "unrecognized platform" — indistinguishable from a key the
table had never heard of. The two cases now render differently:
  - generic-table hit → "Unattributed Tracker" (we know it's a tracker
                          but cannot attribute the operator)
  - no table hit       → "unrecognized platform"
"""
import os
import tempfile
from datetime import datetime, timezone

from clustering import shared_params
from db import get_conn, init_db, migrate_db
from i18n import set_lang, t


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


def _owners_for(results, key):
    return [r["owner"] for r in results if r["param_key"] == key]


def test_generic_table_hit_renders_as_unattributed_tracker_en():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://picread.net/article/1?uid=638")
    _add_post(conn, case_id, "https://picread.net/article/2?uid=638")
    results = shared_params(conn, case_id)
    owners = _owners_for(results, "uid")
    assert owners == ["Unattributed Tracker"], (
        f"uid (in generic table) should render as Unattributed Tracker, got {owners}"
    )


def test_generic_table_hit_renders_as_zh_label():
    set_lang("zh-TW")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://shop.example/?aff_id=A1")
    _add_post(conn, case_id, "https://shop.example/?aff_id=A1")
    results = shared_params(conn, case_id)
    owners = _owners_for(results, "aff_id")
    assert owners == ["未歸屬追蹤碼"], owners


def test_unknown_key_still_renders_as_unrecognized_platform():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://example.com/?xyz_weird_token=12345")
    _add_post(conn, case_id, "https://example.com/?xyz_weird_token=12345")
    results = shared_params(conn, case_id)
    owners = _owners_for(results, "xyz_weird_token")
    assert owners == [t("param.unrecognized_platform")], owners


def test_known_platform_unaffected():
    """utm_source is a Google Analytics key — should NOT change."""
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id, "https://example.com/?utm_source=newsletter")
    _add_post(conn, case_id, "https://example.com/?utm_source=newsletter")
    results = shared_params(conn, case_id)
    owners = _owners_for(results, "utm_source")
    assert owners == ["Google Analytics"], owners


def test_generic_and_platform_and_unknown_coexist_in_same_case():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_post(conn, case_id,
              "https://example.com/?utm_source=fb&aff_id=A1&xyz_weird=1")
    _add_post(conn, case_id,
              "https://example.com/?utm_source=fb&aff_id=A1&xyz_weird=1")
    results = shared_params(conn, case_id)
    by_key = {r["param_key"]: r["owner"] for r in results}
    assert by_key.get("utm_source") == "Google Analytics"
    assert by_key.get("aff_id") == "Unattributed Tracker"
    assert by_key.get("xyz_weird") == t("param.unrecognized_platform")
