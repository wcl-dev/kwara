"""`url_count` means distinct URLs, not distinct url_artifacts rows.

The two are not the same. A URL gets one artifact row per post that carried
it, and N accounts pushing one link is the normal case in a coordination
investigation — it is the finding, not an anomaly. Keying the count sets on
ua.id therefore counted the same URL once per account, and inflated hardest on
exactly the clusters that mattered most: on real case data one tracking ID
read 43 URLs where 8 distinct URLs carried it.

post_count is the honest measure of "how many accounts pushed this" and is
keyed on message id; these tests pin both, so a future change cannot quietly
collapse the two back together in either direction.
"""
import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from kwara.clustering_infra import (
    asn_clusters,
    ad_tracking_platforms,
    certificate_authorities,
    shared_ad_accounts,
    shared_certificates,
    shared_tracking_ids,
)
from kwara.clustering_url import shared_destinations, wrapper_relationships
from kwara.db import get_conn, init_db, migrate_db

URL = "https://landing.example/post-1.html?utm_term=551&fbclid=abc"
FINAL = "https://landing.example/post-1.html"
DOMAIN = "landing.example"

# Two posts carrying the identical URL — the shape this whole file is about.
DUPLICATED = 2

TLS = json.dumps({
    "issuer": {"organizationName": "Test CA", "commonName": "Test CA X1"},
    "serialNumber": "AABBCC",
    "notBefore": "Jan  1 00:00:00 2025 GMT",
})
TRACKING = {"Google Analytics 4": ["G-DUPTEST123"]}
ADS_TXT = json.dumps({
    "status": "ok",
    "records": [{"adsystem": "google.com", "seller_id": "pub-999",
                 "relationship": "DIRECT"}],
    "raw_sha256": "deadbeef",
})


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.fixture
def conn():
    td = tempfile.mkdtemp()
    c = get_conn(os.path.join(td, "test.db"))
    init_db(c)
    migrate_db(c)
    yield c
    c.close()


@pytest.fixture
def case_id(conn):
    now = _now()
    cid = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) "
        "VALUES ('dupes', '', ?, ?)", (now, now)).lastrowid
    conn.commit()
    return cid


def _add_post_carrying(conn, case_id, permalink, original_url=URL,
                       final_url=FINAL, final_domain=DOMAIN):
    """One post -> one artifact -> one done scan -> one usable snapshot.

    Mirrors what ingest does for a post that quotes `original_url`: a fresh
    message_evidence row every time, and therefore a fresh url_artifacts row
    even when the URL is one the case already holds.
    """
    now = _now()
    pid = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, 'facebook', ?, ?, '', ?, '', ?)""",
        (case_id, permalink, permalink, original_url, now)).lastrowid
    ua_id = conn.execute(
        """INSERT INTO url_artifacts (message_id, case_id, original_url, domain,
           url_order, created_at) VALUES (?, ?, ?, ?, 0, ?)""",
        (pid, case_id, original_url, final_domain, now)).lastrowid
    sr_id = conn.execute(
        """INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,
           status, ip_address, asn, as_org, as_country, tls_info_json, ads_txt_json)
           VALUES (?, ?, ?, 1, 'done', '203.0.113.7', '13335', 'TestNet', 'US', ?, ?)""",
        (ua_id, now, final_url, TLS, ADS_TXT)).lastrowid
    conn.execute(
        """INSERT INTO snapshots (scan_run_id, final_url, final_domain, captured_at,
           capture_status, capture_method, tracking_ids_json, request_domains_json)
           VALUES (?, ?, ?, ?, 'ok', 'playwright', ?, '[]')""",
        (sr_id, final_url, final_domain, now, json.dumps(TRACKING)))
    conn.commit()
    return pid, ua_id


@pytest.fixture
def duplicated_case(conn, case_id):
    """One URL, two accounts — two artifacts, two scans, two snapshots."""
    for i in range(DUPLICATED):
        _add_post_carrying(conn, case_id, f"https://facebook.test/page{i}/posts/1")
    return case_id


def _one(rows):
    assert len(rows) == 1, f"expected a single group, got {len(rows)}"
    return rows[0]


# ---------------------------------------------------------------------------
# Every count that used to key on ua.id.
# ---------------------------------------------------------------------------

def test_asn_cluster_counts_the_url_once_per_url(conn, duplicated_case):
    c = _one(asn_clusters(conn, duplicated_case))
    assert [u["original_url"] for u in c["urls"]] == [URL]


def test_certificate_authority_url_count(conn, duplicated_case):
    assert _one(certificate_authorities(conn, duplicated_case))["url_count"] == 1


def _add_second_domain(conn, case_id):
    """Same cert / same ad account, different landing domain — the minimum for
    a 2+-domain cluster to form. One post, so it contributes exactly one URL."""
    _add_post_carrying(conn, case_id, "https://facebook.test/second/posts/1",
                       original_url="https://second.example/a.html",
                       final_url="https://second.example/a.html",
                       final_domain="second.example")


def _url_counts(result) -> list[int]:
    return [e["url_count"] for group in result.values()
            if isinstance(group, list) for e in group if "url_count" in e]


def test_shared_certificates_url_count(conn, duplicated_case):
    _add_second_domain(conn, duplicated_case)
    counts = _url_counts(shared_certificates(conn, duplicated_case))
    assert counts, "expected a cert cluster to form"
    # 2 distinct URLs across 2 domains — not 3, which is what counting
    # artifacts gave when one of them was posted twice.
    assert all(n == 2 for n in counts), counts


def test_shared_tracking_ids_url_count(conn, duplicated_case):
    """Tracking clusters need 2+ domains too."""
    _add_second_domain(conn, duplicated_case)
    rows = [r for r in shared_tracking_ids(conn, duplicated_case)
            if r.get("tracking_id") == "G-DUPTEST123"]
    assert rows, "expected the shared pixel to cluster"
    assert rows[0]["url_count"] == 2  # not 3
    assert rows[0]["post_count"] == 3  # all three accounts still counted


def test_ad_tracking_platforms_splits_urls_from_posts(conn, duplicated_case):
    """The clearest statement of the contract: one URL, two accounts."""
    ga = [r for r in ad_tracking_platforms(conn, duplicated_case)
          if r["platform_id"] == "google_analytics"]
    assert ga, "expected the GA4 pixel to surface"
    assert ga[0]["url_count"] == 1
    assert ga[0]["post_count"] == DUPLICATED


def test_shared_ad_accounts_url_count(conn, duplicated_case):
    _add_second_domain(conn, duplicated_case)
    counts = _url_counts(shared_ad_accounts(conn, duplicated_case))
    assert counts, "expected an ad-account cluster to form"
    assert all(n == 2 for n in counts), counts


def test_shared_destinations_lists_the_url_once(conn, duplicated_case):
    result = shared_destinations(conn, duplicated_case)
    groups = result[0] if isinstance(result, tuple) else result
    for g in groups:
        assert [u["original_url"] for u in g["urls"]] == [URL]


def test_wrapper_relationships_url_count(conn, case_id):
    """Redirect pairs: two accounts posting one wrapper URL is one URL."""
    for i in range(DUPLICATED):
        _add_post_carrying(conn, case_id, f"https://facebook.test/w{i}/posts/1",
                           original_url="https://wrap.example/go?u=1")
    conn.execute("UPDATE scan_runs SET final_url = 'https://landing.example/x'")
    conn.commit()
    rows = wrapper_relationships(conn, case_id)
    assert rows and rows[0]["url_count"] == 1
    assert rows[0]["post_count"] == DUPLICATED


# ---------------------------------------------------------------------------
# The other direction: distinct URLs must still count separately.
# ---------------------------------------------------------------------------

def test_distinct_urls_are_not_collapsed(conn, case_id):
    _add_post_carrying(conn, case_id, "https://facebook.test/a/posts/1",
                       original_url="https://landing.example/one.html")
    _add_post_carrying(conn, case_id, "https://facebook.test/b/posts/1",
                       original_url="https://landing.example/two.html")
    ga = [r for r in ad_tracking_platforms(conn, case_id)
          if r["platform_id"] == "google_analytics"]
    assert ga[0]["url_count"] == 2
    assert ga[0]["post_count"] == 2
