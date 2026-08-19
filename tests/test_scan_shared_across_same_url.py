"""A scan belongs to the URL; the artifact row records which post carried it.

Today every artifact has a scan of its own, so this distinction is invisible
and these tests are a no-op restatement of current behaviour. That is the
point: they are step 1 of letting the scan step stop re-fetching a URL the
case already holds. Once it does, an artifact will routinely have no scan of
its own, and the analysis joins must resolve one through a sibling carrying
the same URL — otherwise the artifact drops out of every INNER JOIN and takes
its post with it, collapsing "22 accounts pushed this link" to "1".

The line these tests draw, and that step 2 depends on:

  attribution / clustering   borrows a sibling's scan — the question is what
                             the URL does and who pushed it
  collection coverage        never borrows — the question is what was
                             actually fetched

Getting that backwards in either direction is a silent falsehood: borrowing in
coverage reports work that never happened, and not borrowing in attribution
deletes the coordination finding.
"""
import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from kwara.clustering_infra import asn_clusters, ad_tracking_platforms
from kwara.clustering_url import shared_destinations
from kwara.clusters import case_counts
from kwara.db import get_conn, init_db, migrate_db

URL = "https://landing.example/post-1.html?utm_term=551"
FINAL = "https://landing.example/post-1.html"
DOMAIN = "landing.example"
TRACKING = {"Google Analytics 4": ["G-SIBLING01"]}


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


def _new_case(conn, title="c"):
    now = _now()
    cid = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) "
        "VALUES (?, '', ?, ?)", (title, now, now)).lastrowid
    conn.commit()
    return cid


def _add_post(conn, case_id, permalink, *, scanned: bool, original_url=URL):
    """A post carrying `original_url`, with or without a scan of its own.

    `scanned=False` is the shape step 2 produces: the case already holds this
    URL, so the scan step skips it and no scan_run row is ever written for
    this artifact.
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
        (pid, case_id, original_url, DOMAIN, now)).lastrowid
    if scanned:
        sr_id = conn.execute(
            """INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,
               status, ip_address, asn, as_org, as_country)
               VALUES (?, ?, ?, 1, 'done', '203.0.113.7', '13335', 'TestNet', 'US')""",
            (ua_id, now, FINAL)).lastrowid
        conn.execute(
            """INSERT INTO snapshots (scan_run_id, final_url, final_domain, captured_at,
               capture_status, capture_method, tracking_ids_json, request_domains_json)
               VALUES (?, ?, ?, ?, 'ok', 'playwright', ?, '[]')""",
            (sr_id, FINAL, DOMAIN, now, json.dumps(TRACKING)))
    conn.commit()
    return pid, ua_id


@pytest.fixture
def one_scan_two_posts(conn):
    """Two accounts pushed one link; only the first artifact was scanned."""
    cid = _new_case(conn)
    _add_post(conn, cid, "https://facebook.test/page0/posts/1", scanned=True)
    _add_post(conn, cid, "https://facebook.test/page1/posts/1", scanned=False)
    return cid


# ---------------------------------------------------------------------------
# Attribution borrows.
# ---------------------------------------------------------------------------

def test_unscanned_artifact_still_counts_its_post(conn, one_scan_two_posts):
    """The finding this whole design exists to protect."""
    ga = [r for r in ad_tracking_platforms(conn, one_scan_two_posts)
          if r["platform_id"] == "google_analytics"]
    assert ga, "expected the GA4 pixel to surface"
    assert ga[0]["post_count"] == 2, "the unscanned post must not vanish"
    assert ga[0]["url_count"] == 1, "one URL, however many posts carried it"


def test_html_only_signal_reaches_the_unscanned_post(conn):
    """The sharpest case: a URL with no query string.

    The url_param lens reads ua.original_url and fires without any scan, so a
    URL carrying tracking parameters keeps its post counted either way. Strip
    the parameters and the only evidence is the pixel in the captured HTML —
    which the unscanned artifact can reach only by borrowing its sibling's
    scan. post_count here is 1 without that borrow.
    """
    bare_url = "https://landing.example/post-1.html"
    cid = _new_case(conn)
    _add_post(conn, cid, "https://facebook.test/p0/posts/1", scanned=True,
              original_url=bare_url)
    _add_post(conn, cid, "https://facebook.test/p1/posts/1", scanned=False,
              original_url=bare_url)

    ga = [r for r in ad_tracking_platforms(conn, cid)
          if r["platform_id"] == "google_analytics"]
    assert ga, "expected the GA4 pixel to surface"
    assert ga[0]["signal_source"] == "html_embedded"
    assert ga[0]["post_count"] == 2
    assert ga[0]["url_count"] == 1


def test_asn_cluster_keeps_the_unscanned_post(conn, one_scan_two_posts):
    clusters = asn_clusters(conn, one_scan_two_posts)
    assert len(clusters) == 1
    assert clusters[0]["post_count"] == 2
    assert clusters[0]["url_count"] == 1


def test_shared_destinations_keeps_the_unscanned_post(conn, one_scan_two_posts):
    result = shared_destinations(conn, one_scan_two_posts)
    groups = result[0] if isinstance(result, tuple) else result
    assert groups
    assert groups[0]["post_count"] == 2


def test_a_different_url_borrows_nothing(conn):
    """Borrowing is keyed on the URL, not on 'some scan exists in this case'."""
    cid = _new_case(conn)
    _add_post(conn, cid, "https://facebook.test/a/posts/1", scanned=True)
    _add_post(conn, cid, "https://facebook.test/b/posts/1", scanned=False,
              original_url="https://unrelated.example/other.html")
    ga = [r for r in ad_tracking_platforms(conn, cid)
          if r["platform_id"] == "google_analytics"]
    assert ga[0]["post_count"] == 1
    assert ga[0]["url_count"] == 1


def test_borrowing_does_not_cross_case_boundaries(conn):
    """A scan in another case is another case's evidence, whatever the URL.

    The bare case still reports the tracking parameters spelled out in the URL
    it holds — that lens reads ua.original_url and has never needed a scan.
    What it must NOT gain is anything only the other case's fetch could know:
    the ASN, the landing domain, the pixel embedded in the HTML.
    """
    scanned_case = _new_case(conn, "scanned")
    _add_post(conn, scanned_case, "https://facebook.test/x/posts/1", scanned=True)

    bare_case = _new_case(conn, "bare")
    _add_post(conn, bare_case, "https://facebook.test/y/posts/1", scanned=False)

    assert asn_clusters(conn, bare_case) == [], "ASN comes only from a real scan"
    for row in ad_tracking_platforms(conn, bare_case):
        assert row["signal_source"] == "url_param", row
        assert row["tracking_ids"] == [], "no HTML pixel without a capture"


# ---------------------------------------------------------------------------
# Coverage does not.
# ---------------------------------------------------------------------------

def test_case_counts_reports_what_was_actually_scanned(conn, one_scan_two_posts):
    """clusters.case_counts answers 'how much have we collected'.

    Borrowing here would claim a fetch that never happened — the same
    falsehood as writing a scan_run row per artifact from a single fetch.
    """
    url_count, scanned = case_counts(conn, one_scan_two_posts)
    assert url_count == 2, "two artifact rows, because two posts carried the URL"
    assert scanned == 1, "one of them was actually fetched"
