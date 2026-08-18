"""The PublicWWW candidate source must never let the API key reach disk.

kwara retains what it fetches — `acquisition` records the requested URL, the
screen bank records each observation's URL, and `export case` bundles both.
PublicWWW's export API carries the key in the query *string*, so the one rule
this source lives by is that its HTTP transaction stays transient: the key
travels in request params (never a URL that gets logged or stored), nothing is
recorded as an acquisition or banked, and only the domains survive the call.

These tests assert that rule the way the repo asserts its other safety
invariants — against the parsed source and against behaviour, not against a
comment promising good intentions.
"""
import inspect

import pytest

from kwara import discovery


def test_key_unset_refuses_rather_than_runs(monkeypatch):
    """No key means the source is unavailable and says so — it must not fall
    through to an unauthenticated request or a silent empty result."""
    monkeypatch.setattr(discovery, "PUBLICWWW_API_KEY", None)
    with pytest.raises(RuntimeError):
        discovery.candidates_from_publicwww(["G-ABC1234"])


class _FakeResp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_key_travels_in_params_never_in_the_logged_url(monkeypatch):
    """The whole point: the key goes in params, so nothing that could be
    logged or persisted (the request URL) ever contains it."""
    monkeypatch.setattr(discovery, "PUBLICWWW_API_KEY", "SECRETKEY")
    seen = {}

    class Sess:
        def get(self, url, params=None, timeout=None, headers=None):
            seen["url"], seen["params"] = url, params
            return _FakeResp("a.farm.com\nb.farm.com\n")

    got = discovery.candidates_from_publicwww(["G-ABC1234"], session=Sess())

    assert "SECRETKEY" not in seen["url"]        # never in the path
    assert seen["params"]["key"] == "SECRETKEY"  # only in params
    assert got == ["farm.com"]                   # apex-collapsed and deduped


def test_source_never_touches_the_retention_path():
    """A reviewer changing this source cannot wire it into the machinery that
    would persist the keyed request without this test going red."""
    src = inspect.getsource(discovery.candidates_from_publicwww)
    for banned in ("record_acquisition", "bank_body", "reserve_run"):
        assert banned not in src, f"{banned} would persist the keyed request"


def test_parser_collapses_to_apex_and_drops_header_rows():
    text = "url\nwww.a.com;12\nb.a.com,3\nshop.c.net\n"
    assert discovery.parse_domain_list(text) == ["a.com", "c.net"]


def test_parser_can_keep_full_hostnames():
    text = "www.a.com\nb.a.com\n"
    assert discovery.parse_domain_list(text, apex=False) == [
        "b.a.com", "www.a.com"]


def test_parses_hosts_and_adblock_formats():
    """The same parser folds a blocklist into the funnel: hosts sinkholes and
    adblock domain-anchor rules in, apexes out; exception and element-hiding
    rules dropped."""
    text = (
        "# a hosts file\n"
        "0.0.0.0 ads.bad.com\n"
        "127.0.0.1 tracker.bad.com # trailing note\n"
        "! an adblock list\n"
        "||evil.net^$third-party\n"
        "@@||good.net^\n"            # exception — must be dropped
        "example.com##.banner\n"     # element hiding — must be dropped
        "plain.org\n"
    )
    assert discovery.parse_domain_list(text) == ["bad.com", "evil.net", "plain.org"]


def test_normalize_over_mcp_folds_a_blocklist(tmp_path):
    """The local normalize transform is exposed so a blocklist can enter the
    same funnel as sellers.json — no network, no key."""
    from kwara import mcp_server
    src = tmp_path / "block.txt"
    src.write_text("0.0.0.0 a.bad.com\n||c.evil.net^\n")
    res = mcp_server.normalize_domains(file=str(src))
    assert set(res["domains"]) == {"bad.com", "evil.net"}


def test_cli_command_is_withheld_from_mcp():
    """Querying PublicWWW discloses which fingerprint is being hunted, so like
    `run corroborate` it is CLI-only and must be listed in _WITHHELD."""
    from kwara.mcp_server import _WITHHELD
    assert "cmd_discover_publicwww" in _WITHHELD
