"""Tests for clustering.ad_tracking_platforms()."""
import os
import tempfile
from datetime import datetime, timezone

from clustering import ad_tracking_platforms
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


def _add(conn, case_id, url, final_url=None):
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', ?, '', ?)""",
        (case_id, url, now),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, url, now),
    )
    ua_id = cur.lastrowid
    if final_url:
        conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
            "status) VALUES (?, ?, ?, 0, 'done')",
            (ua_id, now, final_url),
        )
    conn.commit()


def test_empty_case_returns_empty_list():
    conn = _make_db()
    case_id = _make_case(conn)
    assert ad_tracking_platforms(conn, case_id) == []


def test_known_platform_aggregated():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://x.com/?utm_source=fb&utm_term=145")
    _add(conn, case_id, "https://x.com/?utm_term=200")
    res = ad_tracking_platforms(conn, case_id)
    ga = next(r for r in res if r["owner"] == "Google Analytics")
    assert ga["url_count"] == 2
    assert "utm_source" in ga["param_keys"]
    assert "utm_term" in ga["param_keys"]


def test_generic_keys_use_unattributed_label():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://x.com/?aff_id=A1")
    _add(conn, case_id, "https://x.com/?uid=638")
    res = ad_tracking_platforms(conn, case_id)
    labels = {r["owner"] for r in res}
    assert t("param.unattributed_tracker") in labels
    # The single unattributed bucket should hold both keys
    bucket = next(r for r in res if r["owner"] == t("param.unattributed_tracker"))
    assert "aff_id" in bucket["param_keys"]
    assert "uid" in bucket["param_keys"]


def test_unknown_keys_skipped():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://x.com/?xyz_weird_token=foo")
    _add(conn, case_id, "https://x.com/?utm_term=1")
    res = ad_tracking_platforms(conn, case_id)
    owners = {r["owner"] for r in res}
    assert "Google Analytics" in owners
    # xyz_weird_token has no owner in identify_param → must NOT appear
    for r in res:
        assert "xyz_weird_token" not in r["param_keys"]


def test_multi_platform_in_same_url():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://x.com/?fbclid=ABC&gclid=DEF&utm_source=fb")
    res = ad_tracking_platforms(conn, case_id)
    owners = {r["owner"] for r in res}
    assert {"Meta / Facebook", "Google Ads", "Google Analytics"} <= owners


def test_url_count_uses_distinct_url_artifacts():
    """Same URL appearing in original_url AND final_url shouldn't double-count."""
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id,
         "https://shortlink/?utm_term=1",
         final_url="https://x.com/?utm_term=1")
    res = ad_tracking_platforms(conn, case_id)
    ga = next(r for r in res if r["owner"] == "Google Analytics")
    assert ga["url_count"] == 1
    assert ga["post_count"] == 1


def test_sorted_by_url_count_desc():
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    for i in range(5):
        _add(conn, case_id, f"https://x.com/?utm_term={i}")  # 5 GA hits
    _add(conn, case_id, "https://x.com/?fbclid=A")           # 1 Meta hit
    res = ad_tracking_platforms(conn, case_id)
    assert res[0]["owner"] == "Google Analytics"
    assert res[0]["url_count"] == 5
