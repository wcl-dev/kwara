"""Tests for clustering_infra.shared_endpoints() (Phase 3 ticket A)."""
import json
import os
import tempfile
from datetime import datetime, timezone

from clustering_infra import _is_direct_ip, _is_noise_endpoint, shared_endpoints
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


def _add(conn, case_id, original_url, final_url, final_domain, request_domains):
    """Add post + url + scan + snapshot with request_domains_json populated."""
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
    rd_json = json.dumps(request_domains) if request_domains is not None else None
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, request_domains_json, capture_method)
           VALUES (?, ?, ?, ?, 'ok', ?, 'playwright')""",
        (sr_id, final_url, final_domain, now, rd_json),
    )
    conn.commit()
    return sr_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_is_direct_ip_recognises_ipv4():
    assert _is_direct_ip("203.0.113.5")
    assert _is_direct_ip("10.0.0.1")
    assert not _is_direct_ip("api.example.com")
    assert not _is_direct_ip("203.0.113")  # not a full IPv4
    assert not _is_direct_ip("")


def test_is_direct_ip_recognises_ipv6():
    assert _is_direct_ip("2001:db8::1")
    assert _is_direct_ip("::1")


def test_is_noise_endpoint_matches_known_cdns():
    assert _is_noise_endpoint("fonts.googleapis.com")
    assert _is_noise_endpoint("cdn.jsdelivr.net")
    assert _is_noise_endpoint("connect.facebook.net")


def test_is_noise_endpoint_matches_subdomains_of_listed_hosts():
    """Suffix match: listing 'doubleclick.net' also filters 'cm.g.doubleclick.net'."""
    assert _is_noise_endpoint("cm.g.doubleclick.net")
    assert _is_noise_endpoint("googleads.g.doubleclick.net")
    assert _is_noise_endpoint("ep1.adtrafficquality.google")
    assert _is_noise_endpoint("static.cloudflareinsights.com")


def test_is_noise_endpoint_case_insensitive():
    assert _is_noise_endpoint("FONTS.GOOGLEAPIS.COM")


def test_is_noise_endpoint_does_not_match_real_endpoints():
    assert not _is_noise_endpoint("api.scammer-cdn.xyz")
    assert not _is_noise_endpoint("203.0.113.5")


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def test_empty_case_returns_empty_list():
    conn = _make_db()
    case_id = _make_case(conn)
    assert shared_endpoints(conn, case_id) == []


def test_two_landings_share_one_third_party_endpoint():
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         ["api.scammer.xyz", "fonts.googleapis.com"])
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["api.scammer.xyz", "cdnjs.cloudflare.com"])
    res = shared_endpoints(conn, case_id)
    assert len(res) == 1
    r = res[0]
    assert r["endpoint"] == "api.scammer.xyz"
    assert r["domain_count"] == 2
    assert sorted(r["domains"]) == ["a.com", "b.com"]
    assert r["is_direct_ip"] is False


def test_noise_endpoints_excluded_even_when_shared():
    """fonts.googleapis.com on every landing must NOT cluster — too generic."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         ["fonts.googleapis.com"])
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["fonts.googleapis.com"])
    res = shared_endpoints(conn, case_id)
    assert res == []


def test_landing_own_domain_excluded():
    """A request to the landing's own domain isn't third-party."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         ["a.com", "api.scammer.xyz"])
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["b.com", "api.scammer.xyz", "a.com"])  # b also calls a.com (interesting!)
    res = shared_endpoints(conn, case_id)
    pairs = {r["endpoint"]: r["domain_count"] for r in res}
    # a.com → only b sees it as third-party (a sees it as own) → 1 landing → excluded
    assert "a.com" not in pairs
    # api.scammer.xyz on both → clusters
    assert pairs["api.scammer.xyz"] == 2


def test_subdomain_of_landing_also_excluded():
    """www.example.com landing receiving requests to api.example.com — same site."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://example.com/", "example.com",
         ["cdn.example.com", "api.scammer.xyz"])
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["cdn.example.com", "api.scammer.xyz"])
    res = shared_endpoints(conn, case_id)
    pairs = {r["endpoint"] for r in res}
    # cdn.example.com shows up: not a subdomain of b.com, but IS of example.com.
    # For the b.com landing it's third-party; for example.com it's filtered.
    # So cdn.example.com cluster has only b.com → singleton → excluded.
    assert "cdn.example.com" not in pairs
    assert "api.scammer.xyz" in pairs


def test_singleton_endpoint_excluded():
    """Endpoint called by only 1 landing isn't a cross-domain signal."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         ["api.scammer.xyz"])
    res = shared_endpoints(conn, case_id)
    assert res == []


def test_direct_ip_endpoint_flagged():
    """A literal IP endpoint shared across landings is flagged is_direct_ip=True."""
    conn = _make_db()
    case_id = _make_case(conn)
    _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
         ["203.0.113.5"])
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["203.0.113.5"])
    res = shared_endpoints(conn, case_id)
    assert len(res) == 1
    assert res[0]["endpoint"] == "203.0.113.5"
    assert res[0]["is_direct_ip"] is True


def test_direct_ip_floated_within_same_tier():
    """If two endpoints have the same domain_count, direct IP comes first."""
    conn = _make_db()
    case_id = _make_case(conn)
    for landing in ("a.com", "b.com"):
        _add(conn, case_id, f"http://x/{landing}", f"https://{landing}/", landing,
             ["203.0.113.5", "api.scammer.xyz"])
    res = shared_endpoints(conn, case_id)
    assert len(res) == 2
    assert res[0]["endpoint"] == "203.0.113.5"
    assert res[1]["endpoint"] == "api.scammer.xyz"


def test_lightweight_snapshot_with_null_request_domains_excluded():
    """A lightweight HTTP-only snapshot has request_domains_json=NULL and
    must not break the aggregation. Codex2 #2 latest-usable pattern: an
    earlier Playwright snapshot's request_domains is preferred over a
    later lightweight one."""
    conn = _make_db()
    case_id = _make_case(conn)
    sr_a = _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
                ["api.scammer.xyz"])
    # Add a LATER lightweight snapshot on top of sr_a (no request_domains)
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, request_domains_json, capture_method)
           VALUES (?, 'https://a.com/', 'a.com', ?, 'ok', NULL, 'http_only')""",
        (sr_a, _now()),
    )
    conn.commit()
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["api.scammer.xyz"])
    res = shared_endpoints(conn, case_id)
    # Earlier Playwright snapshot's request_domains still feeds the cluster
    assert len(res) == 1
    assert res[0]["endpoint"] == "api.scammer.xyz"
    assert sorted(res[0]["domains"]) == ["a.com", "b.com"]


def test_failed_recapture_does_not_shadow_earlier_good_one():
    """Codex review fix #2 pattern: later cf_challenge snapshot must not
    erase earlier good request_domains."""
    conn = _make_db()
    case_id = _make_case(conn)
    sr_a = _add(conn, case_id, "http://x/a", "https://a.com/", "a.com",
                ["api.scammer.xyz"])
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
           captured_at, capture_status, request_domains_json, capture_method)
           VALUES (?, 'https://a.com/', 'a.com', ?, 'cf_challenge', '[]', 'playwright')""",
        (sr_a, _now()),
    )
    conn.commit()
    _add(conn, case_id, "http://x/b", "https://b.com/", "b.com",
         ["api.scammer.xyz"])
    res = shared_endpoints(conn, case_id)
    assert len(res) == 1
    assert sorted(res[0]["domains"]) == ["a.com", "b.com"]
