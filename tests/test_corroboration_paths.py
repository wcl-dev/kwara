"""Third-party corroboration, and the Wayback fallback.

Corroboration is what lets a recipient check the work without trusting the
investigator: an independent archive, an independent scan, and a timestamp
nobody involved controls. It was at 25% coverage, and wayback_fallback at 0% —
so the failure handling, which is the part that matters when a service is down
mid-investigation, had never run.

The three services are contacted at fixed URLs, so they are mocked at the
requests boundary rather than served locally; what is being tested is the
branching, not the transport.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from kwara import corroboration, wayback_fallback


# Captured before the autouse fixture below can replace it — the limiter has
# its own test, and that test must reach the real implementation.
_REAL_RATE_WAIT = corroboration._rate_wait


@pytest.fixture(autouse=True)
def _no_rate_limit_sleep(monkeypatch):
    """The module rate-limits itself out of politeness to the archives — 5s
    between Wayback calls, 3s between urlscan ones. Correct in production and
    pure waste here: it added 8 seconds of sleeping to this file and told us
    nothing. The limiter's own behaviour is asserted separately below."""
    monkeypatch.setattr(corroboration, "_rate_wait", lambda service: None)


def test_the_rate_limiter_actually_waits(monkeypatch):
    """Asserted directly, since every other test in this file disables it.
    Hammering a free community archive is how access gets withdrawn."""
    import time
    monkeypatch.setattr(corroboration, "_RATE_LIMITS", {"probe": 0.15})
    monkeypatch.setattr(corroboration, "_last_call", {})
    start = time.monotonic()
    _REAL_RATE_WAIT("probe")
    _REAL_RATE_WAIT("probe")
    assert time.monotonic() - start >= 0.15


def _resp(status=200, body=b"", headers=None, text=None):
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.text = text if text is not None else body.decode("utf-8", "replace")
    r.headers = headers or {}
    r.raise_for_status = MagicMock()
    return r


# ── urlscan ────────────────────────────────────────────────────────────────

def test_urlscan_without_a_key_is_reported_not_attempted(monkeypatch):
    """The free tier needs a key. Silently returning nothing would make a
    missing key indistinguishable from a submission that failed."""
    monkeypatch.setattr(corroboration, "URLSCAN_API_KEY", "")
    out = corroboration.submit_urlscan("https://example.test/")
    assert out["skipped"] is True
    assert "KWARA_URLSCAN_API_KEY" in out["error"]


def test_urlscan_success_returns_a_permalink(monkeypatch):
    monkeypatch.setattr(corroboration, "URLSCAN_API_KEY", "k")
    payload = {"result": "https://urlscan.io/result/abc/", "uuid": "abc"}
    resp = _resp(200, json.dumps(payload).encode())
    resp.json = MagicMock(return_value=payload)
    with patch.object(corroboration.requests, "post", return_value=resp):
        out = corroboration.submit_urlscan("https://example.test/")
    assert out["service"] == "urlscan.io"
    assert out.get("permalink") == payload["result"]
    assert "error" not in out


def test_urlscan_transport_failure_is_captured_not_raised(monkeypatch):
    monkeypatch.setattr(corroboration, "URLSCAN_API_KEY", "k")
    with patch.object(corroboration.requests, "post",
                      side_effect=requests.exceptions.ConnectionError("down")):
        out = corroboration.submit_urlscan("https://example.test/")
    assert out["error"], out


# ── wayback ────────────────────────────────────────────────────────────────

def test_wayback_success_returns_a_permalink():
    resp = _resp(200, b"ok", {"Content-Location": "/web/1/x"})
    resp.url = "https://web.archive.org/web/1/x"
    with patch.object(corroboration.requests, "get", return_value=resp):
        out = corroboration.save_to_wayback("https://example.test/")
    assert out["service"] == "archive.org"
    assert out.get("permalink"), out


def test_wayback_failure_is_captured():
    with patch.object(corroboration.requests, "get",
                      side_effect=requests.exceptions.Timeout("slow")):
        out = corroboration.save_to_wayback("https://example.test/")
    assert out["error"], out


# ── RFC 3161 ───────────────────────────────────────────────────────────────

def test_timestamp_request_is_well_formed():
    """The DER request is built by hand; a malformed one is rejected by the TSA
    with an opaque error, so it is worth asserting the shape directly."""
    req = corroboration._build_timestamp_request(b"\x00" * 32)
    assert isinstance(req, (bytes, bytearray)) and len(req) > 32
    assert req[0] == 0x30      # SEQUENCE


def test_timestamp_failure_is_captured():
    with patch.object(corroboration.requests, "post",
                      side_effect=requests.exceptions.ConnectionError("no tsa")):
        out = corroboration.get_rfc3161_timestamp(b"payload")
    assert out["service"] == "rfc3161"
    assert out["error"], out


# ── the combined call ──────────────────────────────────────────────────────

def test_one_service_failing_does_not_lose_the_others():
    """An investigation does not stop because one archive is down, and a
    partial record must say which part is missing rather than looking whole."""
    with patch.object(corroboration, "save_to_wayback",
                      return_value={"service": "archive.org", "permalink": "w"}), \
         patch.object(corroboration, "submit_urlscan",
                      return_value={"service": "urlscan.io", "error": "boom"}), \
         patch.object(corroboration, "get_rfc3161_timestamp",
                      return_value={"service": "rfc3161", "token_b64": "t"}):
        out = corroboration.corroborate_url("https://example.test/")
    blob = json.dumps(out)
    assert "archive.org" in blob and "boom" in blob and "rfc3161" in blob


def test_every_service_failing_still_returns_a_record():
    """A NULL corroboration is indistinguishable from 'never attempted'. A
    failure stub is the difference between 'we looked' and 'we did not'."""
    with patch.object(corroboration, "save_to_wayback",
                      return_value={"service": "archive.org", "error": "x"}), \
         patch.object(corroboration, "submit_urlscan",
                      return_value={"service": "urlscan.io", "error": "y"}), \
         patch.object(corroboration, "get_rfc3161_timestamp",
                      return_value={"service": "rfc3161", "error": "z"}):
        out = corroboration.corroborate_url("https://example.test/")
    assert out is not None and isinstance(out, dict)


# ── wayback fallback ───────────────────────────────────────────────────────

def test_wayback_fallback_reports_absence_without_raising():
    """Used when a live capture failed. No snapshot in the archive is a normal
    outcome, not an error.

    Patched at `_SESSION`, not `requests` — the module holds its own session,
    so patching requests.get intercepts nothing and the test quietly reaches
    the real archive.org instead. That is a broken test, not a passing one.
    """
    resp = _resp(200, b'{"archived_snapshots": {}}')
    resp.json = MagicMock(return_value={"archived_snapshots": {}})
    with patch.object(wayback_fallback._SESSION, "get", return_value=resp):
        url, err = wayback_fallback._wayback_api_available("https://example.test/")
    assert url is None
    assert err == "no_archived_snapshot"


def test_wayback_fallback_finds_a_snapshot():
    data = {"archived_snapshots": {"closest": {
        "available": True, "url": "http://web.archive.org/web/1/x"}}}
    resp = _resp(200, json.dumps(data).encode())
    resp.json = MagicMock(return_value=data)
    with patch.object(wayback_fallback._SESSION, "get", return_value=resp):
        url, err = wayback_fallback._wayback_api_available("https://example.test/")
    assert url == "http://web.archive.org/web/1/x"
    assert err is None


def test_wayback_fallback_survives_a_dead_archive():
    with patch.object(wayback_fallback._SESSION, "get",
                      side_effect=requests.exceptions.ConnectionError("down")):
        url, err = wayback_fallback._wayback_api_available("https://example.test/")
    assert url is None
    assert err.startswith("wayback_available:")
