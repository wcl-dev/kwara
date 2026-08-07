"""Phase 4.2B — header analysis over redirect_hops.response_headers_json.

QSH 2026-04-28 patterns are the positive controls:
  - crawlerlanding.example leaks `x-server-hosted: Malaysia Cloud Pte Ltd`
    consistently across hops (per-domain constant)
  - all three operator domains share fake `x-powered-by: Apache/2.5.1
    ... OpenSSL/1.1.2e PHP/8` (cross-domain template + fake versions)
  - cookies pin Domain= to the backend instead of the CDN apex
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

import pytest

from kwara.db import get_conn, init_db, migrate_db
from kwara.header_analysis import (
    cookie_origin_signals,
    cross_domain_shared_template,
    detect_fake_versions,
    per_domain_constants,
)


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _seed_case(conn) -> int:
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES ('t', '', ?, ?)",
        (_now(), _now()),
    )
    return cur.lastrowid


def _seed_hop(conn, case_id: int, url: str, headers: list[list[str]]) -> int:
    """Insert message → url_artifact → scan_run → redirect_hop with headers."""
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, _now()),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, url, _now()),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, status) "
        "VALUES (?, ?, ?, 0, 'done')",
        (ua_id, _now(), url),
    )
    sr_id = cur.lastrowid
    conn.execute(
        """INSERT INTO redirect_hops (scan_run_id, hop_order, url, status_code,
                                       location, resolved_url, fetched_at,
                                       response_headers_json)
           VALUES (?, 0, ?, 200, NULL, NULL, ?, ?)""",
        (sr_id, url, _now(), json.dumps(headers)),
    )
    conn.commit()
    return sr_id


# ---------------------------------------------------------------------------
# per_domain_constants
# ---------------------------------------------------------------------------

def test_per_domain_constants_returns_stable_value_across_hops():
    """crawlerlanding.example seen 3x with the same x-server-hosted = constant."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    for _ in range(3):
        _seed_hop(conn, case_id, "http://crawlerlanding.example/redacted139/x", [
            ["Server", "nginx"],
            ["x-server-hosted", "Malaysia Cloud Pte Ltd"],
            ["Date", "Tue, 30 Mar 2026 12:00:00 GMT"],  # volatile, must skip
        ])
    out = per_domain_constants(conn, case_id)
    assert "crawlerlanding.example" in out
    assert out["crawlerlanding.example"]["server"] == "nginx"
    assert out["crawlerlanding.example"]["x-server-hosted"] == "Malaysia Cloud Pte Ltd"
    # Volatile headers (Date) excluded
    assert "date" not in out["crawlerlanding.example"]


def test_per_domain_constants_drops_headers_with_changing_values():
    """If a domain returned different Server values, that header is NOT
    a constant — drop it."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://x.com/a", [["Server", "nginx/1.20"]])
    _seed_hop(conn, case_id, "http://x.com/b", [["Server", "nginx/1.21"]])
    out = per_domain_constants(conn, case_id)
    assert "server" not in out.get("x.com", {})


def test_per_domain_constants_requires_min_observations():
    """A header seen only once is not pinned as a constant."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://x.com/a", [["x-fingerprint", "abc"]])
    out = per_domain_constants(conn, case_id, min_observations=2)
    assert "x.com" not in out


# ---------------------------------------------------------------------------
# cross_domain_shared_template
# ---------------------------------------------------------------------------

def test_cross_domain_shared_template_picks_up_shared_x_powered_by():
    """All three operator domains share the same fake x-powered-by =
    operator template, ≥ GA4 sharing in evidence weight."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    fake = "Apache/2.5.1 (Win64) OpenSSL/1.1.2e PHP/8"
    for d in ("hubsite.example", "satellitesite.example", "visitorlanding.example"):
        _seed_hop(conn, case_id, f"http://{d}/redacted139", [
            ["Server", "Apache"],
            ["x-powered-by", fake],
        ])
    out = cross_domain_shared_template(conn, case_id, min_domains=2)
    matches = [r for r in out if r["header"] == "x-powered-by" and r["value"] == fake]
    assert len(matches) == 1
    assert set(matches[0]["domains"]) == {"hubsite.example", "satellitesite.example", "visitorlanding.example"}


def test_cross_domain_shared_template_below_min_domains_not_returned():
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://a.com/", [["x-powered-by", "single"]])
    out = cross_domain_shared_template(conn, case_id, min_domains=2)
    assert out == []


# ---------------------------------------------------------------------------
# detect_fake_versions
# ---------------------------------------------------------------------------

def test_detect_fake_apache_25_and_openssl_112():
    """The QSH crawlerlanding fingerprint — Apache 2.5.1 + OpenSSL 1.1.2e are
    confirmed-impossible versions."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://crawlerlanding.example/", [
        ["Server", "Apache/2.5.1 (Win64)"],
        ["x-powered-by", "OpenSSL/1.1.2e PHP/8"],
    ])
    out = detect_fake_versions(conn, case_id)
    reasons = {r["reason"] for r in out}
    assert any("Apache" in r for r in reasons)
    assert any("OpenSSL 1.1.2" in r for r in reasons)


def test_detect_fake_apache_in_x_powered_by():
    """Regression: 2026-04-29 new-case E2E surfaced that operators put the
    fake `Apache/2.5.1 (Win64) OpenSSL/1.1.2e PHP/8` string in X-Powered-By
    while Server itself is just `cloudflare`. The Apache pattern was
    previously tied to Server-only and missed it entirely."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://crawlerlanding.example/", [
        ["Server", "cloudflare"],
        ["x-powered-by", "Apache/2.5.1 (Win64) OpenSSL/1.1.2e PHP/8"],
    ])
    out = detect_fake_versions(conn, case_id)
    apache_hits = [r for r in out if "Apache" in r["reason"]]
    openssl_hits = [r for r in out if "OpenSSL" in r["reason"]]
    assert len(apache_hits) == 1
    assert apache_hits[0]["header"] == "x-powered-by"
    assert len(openssl_hits) == 1


def test_detect_fake_versions_real_versions_not_flagged():
    """Real versions (Apache 2.4.x, OpenSSL 1.1.1, nginx 1.22) must pass."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://realsite.com/", [
        ["Server", "Apache/2.4.62 (Ubuntu)"],
        ["x-powered-by", "OpenSSL/1.1.1u PHP/8.2"],
    ])
    _seed_hop(conn, case_id, "http://nginxsite.com/", [
        ["Server", "nginx/1.22.1"],
    ])
    out = detect_fake_versions(conn, case_id)
    assert out == []


# ---------------------------------------------------------------------------
# cookie_origin_signals
# ---------------------------------------------------------------------------

def test_cookie_origin_leak_when_domain_attr_differs():
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://crawlerlanding.example/redacted139/x", [
        ["Set-Cookie",
         "sid=abc; Domain=.realorigin.example; Path=/; HttpOnly; SameSite=Lax"],
    ])
    out = cookie_origin_signals(conn, case_id)
    assert any(
        r["response_domain"] == "crawlerlanding.example" and r["cookie_domain"] == "realorigin.example"
        for r in out["origin_leaks"]
    )


def test_cookie_no_origin_leak_when_domain_matches_apex():
    """Cookie with Domain=.example.com served by api.example.com is
    legit (same apex), must NOT trigger the leak signal."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    _seed_hop(conn, case_id, "http://api.example.com/", [
        ["Set-Cookie", "sid=abc; Domain=.example.com; Path=/; HttpOnly"],
    ])
    out = cookie_origin_signals(conn, case_id)
    assert out["origin_leaks"] == []


def test_cookie_shared_template_across_domains():
    """Same cookie attribute combination on >=2 domains = same-operator signal."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    for d in ("hubsite.example", "satellitesite.example"):
        _seed_hop(conn, case_id, f"http://{d}/", [
            ["Set-Cookie", "sid=x; Path=/; HttpOnly; SameSite=Lax"],
        ])
    out = cookie_origin_signals(conn, case_id)
    sharing = [t for t in out["shared_templates"]
               if t["path"] == "/" and t["httponly"] is True
               and t["samesite"] == "lax"]
    assert len(sharing) == 1
    assert set(sharing[0]["domains"]) == {"hubsite.example", "satellitesite.example"}


def test_cookie_signals_handle_missing_response_headers_json():
    """No headers in any redirect_hop must not raise."""
    conn = _fresh_db()
    case_id = _seed_case(conn)
    out = cookie_origin_signals(conn, case_id)
    assert out == {"origin_leaks": [], "shared_templates": []}
