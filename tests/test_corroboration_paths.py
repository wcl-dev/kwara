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


def _tsa_reply(status=0, *, status_string=None, fail_info_bit=None, token=True):
    """A DER TimeStampResp, as a TSA actually answers one.

    Verified byte-for-byte against `openssl ts -reply -text`: the rejection
    built here prints the same "Status: Rejected. / Status description: Error
    during serial number generation." that FreeTSA returned in the field.
    """
    def der(tag, value):
        return bytes([tag, len(value)]) + value

    info = der(0x02, bytes([status]))
    if status_string is not None:
        info += der(0x30, der(0x0c, status_string.encode()))
    if fail_info_bit is not None:                      # single named bit
        n_bytes = fail_info_bit // 8 + 1
        bits = bytearray(n_bytes)
        bits[fail_info_bit // 8] = 1 << (7 - fail_info_bit % 8)
        unused = n_bytes * 8 - (fail_info_bit + 1)
        info += der(0x03, bytes([unused]) + bytes(bits))
    body = der(0x30, info)
    if token:
        body += der(0x30, b"\x05\x00")                 # opaque, never parsed
    return der(0x30, body)


def _tsa_resp(*args, **kwargs):
    return _resp(200, _tsa_reply(*args, **kwargs),
                 {"Content-Type": "application/timestamp-reply"})


def test_granted_timestamp_is_stored():
    with patch.object(corroboration.requests, "post", return_value=_tsa_resp(0)):
        out = corroboration.get_rfc3161_timestamp(b"payload")
    assert out.get("token_b64"), out
    assert out["status"] == "granted"
    assert not out.get("error")


def test_granted_with_mods_is_still_a_usable_token():
    """grantedWithMods (1) means the TSA changed something it was allowed to
    change — the token is valid and refusing it would throw evidence away."""
    with patch.object(corroboration.requests, "post", return_value=_tsa_resp(1)):
        out = corroboration.get_rfc3161_timestamp(b"payload")
    assert out.get("token_b64"), out
    assert out["status"] == "grantedWithMods"


def test_a_rejection_is_never_stored_as_a_timestamp():
    """The failure this exists for: a refusal arrives as HTTP 200 with
    Content-Type application/timestamp-reply and a ~50-byte body carrying no
    token. Stored blind, it reads as a timestamp in the record and proves
    nothing — the whole point of corroboration is that a recipient can check
    it without trusting us."""
    reply = _tsa_resp(2, status_string="Error during serial number generation.",
                      token=False)
    with patch.object(corroboration.requests, "post", return_value=reply):
        out = corroboration.get_rfc3161_timestamp(b"payload", attempts=1)
    assert "token_b64" not in out, out
    assert out["error"], out
    assert "serial number generation" in out["error"]


def test_a_transient_rejection_is_retried():
    """FreeTSA's serial-number error clears on the next request — observed in
    the field, and one bad draw must not cost the file its timestamp."""
    replies = [_tsa_resp(2, status_string="Error during serial number generation.",
                         token=False),
               _tsa_resp(0)]
    with patch.object(corroboration.requests, "post",
                      side_effect=replies) as post:
        out = corroboration.get_rfc3161_timestamp(b"payload", attempts=3)
    assert out.get("token_b64"), out
    assert post.call_count == 2


def test_a_malformed_request_is_not_retried():
    """badRequest names our own request as the problem. Re-sending the
    identical bytes three times just triples the load on a free service."""
    reply = _tsa_resp(2, fail_info_bit=2, token=False)   # badRequest
    with patch.object(corroboration.requests, "post",
                      return_value=reply) as post:
        out = corroboration.get_rfc3161_timestamp(b"payload", attempts=3)
    assert "token_b64" not in out, out
    assert "badRequest" in out["error"], out
    assert post.call_count == 1


def test_granted_but_empty_reply_is_not_a_token():
    """status=granted with no timeStampToken is nothing to store."""
    with patch.object(corroboration.requests, "post",
                      return_value=_tsa_resp(0, token=False)):
        out = corroboration.get_rfc3161_timestamp(b"payload", attempts=1)
    assert "token_b64" not in out, out
    assert out["error"], out


def test_an_unparseable_reply_is_an_error_not_a_token():
    """A body that is not a TimeStampResp at all — a captive portal, a proxy
    error page served with the right content-type — must not be base64'd into
    the record as evidence."""
    junk = _resp(200, b"<html>proxy error</html>",
                 {"Content-Type": "application/timestamp-reply"})
    with patch.object(corroboration.requests, "post", return_value=junk):
        out = corroboration.get_rfc3161_timestamp(b"payload", attempts=1)
    assert "token_b64" not in out, out
    assert "unparseable" in out["error"], out


def test_failure_info_bits_are_named():
    """The bit names are what tell a caller whether a retry is worth it."""
    info = corroboration._parse_timestamp_response(
        _tsa_reply(2, fail_info_bit=25, token=False))     # systemFailure
    assert info["fail_info"] == "systemFailure", info
    assert corroboration._tsa_failure_is_transient(info)


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
