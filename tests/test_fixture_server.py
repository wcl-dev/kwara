"""The local test origin — verified before anything is built on it.

Six suites depend on this fixture. A server that quietly fails to record a
request, or serves the same body regardless of query string, would let those
suites pass while testing nothing. So it is checked directly.
"""
import time

import pytest
import requests

from fixtures.server import TestSite, adstxt_bytes, page_bytes


def test_serves_a_body_and_headers(site):
    site.route("/x", body="<html>hi</html>",
               headers={"x-server-hosted": "Malaysia Cloud Pte Ltd"})
    r = requests.get(site.url_for("/x"), timeout=5)
    assert r.status_code == 200
    assert "hi" in r.text
    # Header forensics reads response headers per hop; if the origin cannot
    # set them, none of that layer can be tested.
    assert r.headers["x-server-hosted"] == "Malaysia Cloud Pte Ltd"


def test_serves_a_multi_hop_redirect_chain(site):
    site.route("/", status=302, headers={"Location": "/a"})
    site.route("/a", status=302, headers={"Location": "/b"})
    site.route("/b", body="landed")
    r = requests.get(site.url, timeout=5)
    assert [h.status_code for h in r.history] == [302, 302]
    assert r.text == "landed"


def test_records_every_request_including_user_agent(site):
    site.route("/p", body="ok")
    requests.get(site.url_for("/p"), timeout=5, headers={"User-Agent": "kwara-test"})
    assert [str(q.path) for q in site.requests] == ["/p"]
    assert site.requests[0].user_agent == "kwara-test"


def test_response_can_differ_by_query_string(site):
    """Cloaking detection compares a URL with tracking params against the same
    URL stripped. Without an origin that answers differently, the whole
    signal is untestable."""
    site.route_dynamic(
        "/c", lambda req: (200, {}, b"WITH" if req.params.get("utm_term") else b"WITHOUT"))
    assert requests.get(site.url_for("/c?utm_term=1"), timeout=5).text == "WITH"
    assert requests.get(site.url_for("/c"), timeout=5).text == "WITHOUT"


def test_response_can_differ_by_user_agent(site):
    """The OPSEC signal is a WAF that blocks scrapers and admits browsers."""
    site.route_dynamic("/g", lambda req: (
        (403, {}, b"blocked") if "kwara" in req.user_agent else (200, {}, b"allowed")))
    assert requests.get(site.url_for("/g"), timeout=5,
                        headers={"User-Agent": "kwara-scanner"}).status_code == 403
    assert requests.get(site.url_for("/g"), timeout=5,
                        headers={"User-Agent": "Mozilla/5.0"}).status_code == 200


def test_delay_is_long_enough_to_trip_a_timeout(site):
    site.route("/s", body="late", delay=0.4)
    with pytest.raises(requests.exceptions.Timeout):
        requests.get(site.url_for("/s"), timeout=0.15)


def test_unrouted_path_is_404(site):
    assert requests.get(site.url_for("/nope"), timeout=5).status_code == 404


def test_two_origins_can_run_at_once():
    """A redirect that leaves the domain, and two landing domains sharing one
    tracking ID, both need a second origin."""
    with TestSite() as other:
        other.route("/", body="second")
        first = TestSite()
        try:
            first.route("/", status=302, headers={"Location": other.url_for("/")})
            r = requests.get(first.url, timeout=5)
            assert r.text == "second"
            assert first.url != other.url
        finally:
            first.close()


def test_fixture_files_load(site):
    assert b"gtag(" in page_bytes("farm_static.html")
    assert b"DIRECT" in adstxt_bytes("normal.txt")
    assert adstxt_bytes("empty.txt").strip() == b""
