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
    assert ga["signal_source"] == "url_param"
    assert ga["tracking_ids"] == []  # no HTML signal


def _add_with_snapshot(conn, case_id, url, final_url, final_domain, tracking_ids: dict):
    """Add post + url + scan + snapshot with HTML tracking IDs populated."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
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
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, now, final_url),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, tracking_ids_json)
           VALUES (?, ?, ?, ?, 'ok', ?)""",
        (sr_id, final_url, final_domain, now, json.dumps(tracking_ids)),
    )
    conn.commit()


def test_html_only_signal():
    """Snapshot with Meta Pixel but URL has no tracking params → html_embedded only."""
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_with_snapshot(conn, case_id, "https://a.com/", "https://a.com/", "a.com",
                       {"Meta Pixel": ["1234567890123456"]})
    res = ad_tracking_platforms(conn, case_id)
    meta = next(r for r in res if r["owner"] == "Meta / Facebook")
    assert meta["signal_source"] == "html_embedded"
    assert meta["tracking_ids"] == ["1234567890123456"]
    assert meta["param_keys"] == []


def test_both_signals_merge_into_same_owner():
    """fbclid in URL + Meta Pixel in HTML → one row, signal_source='both'."""
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_with_snapshot(conn, case_id,
                       "https://a.com/?fbclid=ABC",
                       "https://a.com/?fbclid=ABC", "a.com",
                       {"Meta Pixel": ["1234567890123456"]})
    res = ad_tracking_platforms(conn, case_id)
    meta_rows = [r for r in res if r["owner"] == "Meta / Facebook"]
    assert len(meta_rows) == 1, "URL+HTML signals must collapse into ONE row"
    meta = meta_rows[0]
    assert meta["signal_source"] == "both"
    assert "fbclid" in meta["param_keys"]
    assert "1234567890123456" in meta["tracking_ids"]


def test_html_platform_label_mapping():
    """Google Analytics 4 (HTML) and utm_source (URL) collapse to 'Google Analytics'."""
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_with_snapshot(conn, case_id,
                       "https://a.com/?utm_source=fb",
                       "https://a.com/?utm_source=fb", "a.com",
                       {"Google Analytics 4": ["G-ABCD1234"]})
    res = ad_tracking_platforms(conn, case_id)
    ga = next(r for r in res if r["owner"] == "Google Analytics")
    assert ga["signal_source"] == "both"
    assert "G-ABCD1234" in ga["tracking_ids"]


def test_gtm_html_only_keeps_distinct_label():
    """GTM has no URL-param equivalent — its label stands alone."""
    set_lang("en")
    conn = _make_db()
    case_id = _make_case(conn)
    _add_with_snapshot(conn, case_id, "https://a.com/", "https://a.com/", "a.com",
                       {"Google Tag Manager": ["GTM-ABCDEF"]})
    res = ad_tracking_platforms(conn, case_id)
    gtm = next(r for r in res if r["owner"] == "Google Tag Manager")
    assert gtm["signal_source"] == "html_embedded"
    assert gtm["tracking_ids"] == ["GTM-ABCDEF"]


def test_generic_keys_marked_generic_kind():
    """aff_id, uid → both fold into one OWNER_KIND_GENERIC bucket."""
    from clustering import OWNER_KIND_GENERIC
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "https://x.com/?aff_id=A1")
    _add(conn, case_id, "https://x.com/?uid=638")
    res = ad_tracking_platforms(conn, case_id)
    generic_rows = [r for r in res if r["owner_kind"] == OWNER_KIND_GENERIC]
    assert len(generic_rows) == 1, "aff_id + uid must collapse into one generic bucket"
    bucket = generic_rows[0]
    assert bucket["owner"] == ""  # not a vendor — UI translates via owner_kind
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
