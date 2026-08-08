"""The three parsers that eat input the investigated site controls.

A crash or a silent mis-parse here is an attack surface, not merely a bug: the
bytes come from the operator being investigated, who has every reason to feed
something awkward.
"""
import pytest

from kwara.adstxt import parse_ads_txt
from kwara.fingerprints import extract_tracking_ids
from kwara.utils import domain as dom
from kwara.utils.domain import extract_domain_from_url as apex


# ── ads.txt ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    "", "   \n\t\n", "# only a comment",
    "google.com, pub-1, DIRECT",                       # no trailing newline
    "google.com, pub-1, DIRECT\r\nrubicon.com, 2, RESELLER\r\n",   # CRLF
    "﻿google.com, pub-1, DIRECT\n",               # UTF-8 BOM
    "google.com\n",                                    # too few fields
    "a, b, c, d, e, f, g\n",                           # too many
    "google.com, pub-1, DIRECT, f08c47fec0942fa0\n",   # with cert authority id
    "OWNERDOMAIN=a.example\nMANAGERDOMAIN=b.example\ngoogle.com, pub-1, DIRECT\n",
    "google.com, pub-1, DIRECT\nOWNERDOMAIN=late.example\n",  # variable after records
    "OWNERDOMAIN=one.example\nOWNERDOMAIN=two.example\n",     # duplicated
    "x" * 50_000 + "\n",                               # one absurd line
    "google.com, pub-1, DIRECT\n" * 20_000,            # many lines
])
def test_parse_ads_txt_never_raises(raw):
    records, variables = parse_ads_txt(raw)
    assert isinstance(records, list)
    assert isinstance(variables, dict)


def test_parse_ads_txt_reads_records_and_variables():
    records, variables = parse_ads_txt(
        "OWNERDOMAIN=owner.example\n"
        "MANAGERDOMAIN=mgr.example\n"
        "google.com, pub-1, DIRECT\n"
        "rubiconproject.com, 22588, RESELLER\n")
    assert len(records) == 2
    direct = [r for r in records if (r.get("relationship") or "").upper() == "DIRECT"]
    assert len(direct) == 1 and direct[0]["seller_id"] == "pub-1"
    assert variables.get("owner_domain") == "owner.example"
    assert variables.get("manager_domain") == "mgr.example"


def test_parse_ads_txt_survives_invalid_utf8():
    """Decoding is lossy by design — a mangled byte must cost one record, not
    the whole file."""
    raw = b"google.com, pub-1, DIRECT\n\xff\xfe bad\nrubicon.com, 2, RESELLER\n"
    records, _ = parse_ads_txt(raw.decode("utf-8", errors="replace"))
    assert len(records) >= 2


# ── fingerprints ───────────────────────────────────────────────────────────

def _ids(html):
    return {str(v) for v in extract_tracking_ids(html).values()}


@pytest.mark.parametrize("html", [
    "<script>gtag('config', 'G-B2C3D4E5F6');</script>",
    '<script src="https://www.googletagmanager.com/gtag/js?id=G-B2C3D4E5F6"></script>',
])
def test_real_invocations_are_matched(html):
    assert any("G-B2C3D4E5F6" in v for v in _ids(html))


@pytest.mark.parametrize("html", [
    "<!-- example: G-B2C3D4E5F6 -->",
    "<p>Your measurement ID looks like G-B2C3D4E5F6.</p>",
    '{"docs": "G-B2C3D4E5F6"}',
    "<script>gtag('config', 'G-XXXXXXXX');</script>",
    "<script>gtag('config', 'GTM-EXAMPLE');</script>",
])
def test_documentation_and_placeholders_are_not_extracted(html):
    assert not any("G-B2C3D4E5F6" in v or "XXXX" in v or "EXAMPLE" in v
                   for v in _ids(html)), _ids(html)


def test_repeated_digits_are_kept_repeated_letters_are_not():
    """AW-1111111111 exists in the wild. A rare false positive beats silently
    discarding a legitimate attribution; repeated LETTERS are documentation."""
    from kwara.fingerprints import _looks_like_placeholder
    assert not _looks_like_placeholder("AW-1111111111")
    assert _looks_like_placeholder("AW-XXXXXXXXXX")


# ── registrable domain ─────────────────────────────────────────────────────

def test_hosting_tenants_stay_distinct():
    """tldextract excludes the PSL private section by default, so unrelated
    tenants collapsed to one asset — which let an off-site redirect pass the
    same-domain check and turned a tenancy coincidence into an operator link."""
    assert apex("alice.github.io") != apex("bob.github.io")
    assert apex("a.blogspot.com") != apex("b.blogspot.com")
    assert apex("x.pages.dev") != apex("y.pages.dev")


@pytest.mark.parametrize("host,expected", [
    ("www.foo.com", "foo.com"),
    ("statics.hubsite.example", "hubsite.example"),
    ("FOO.COM", "foo.com"),
    ("foo.com.", "foo.com"),
    ("a.b.c.foo.com", "foo.com"),
    ("https://www.foo.com/path?q=1", "foo.com"),
])
def test_ordinary_hosts_reduce_to_the_registrable_domain(host, expected):
    assert apex(host) == expected


def test_unicode_and_punycode_are_one_host():
    assert apex("bücher.de") == apex("xn--bcher-kva.de")


@pytest.mark.parametrize("host", ["", "   ", None])
def test_empty_input_is_empty_not_an_exception(host):
    assert apex(host) == ""


def test_fallback_keeps_multi_label_suffixes_apart(monkeypatch):
    """Without tldextract, "uk" sits in COMMON_TLDS and claimed victim.co.uk
    first, collapsing every .co.uk site to co.uk — every British domain became
    the same asset."""
    monkeypatch.setattr(dom, "HAS_TLDEXTRACT", False)
    assert dom.extract_domain_from_url("victim.co.uk") == "victim.co.uk"
    assert dom.extract_domain_from_url("attacker.co.uk") == "attacker.co.uk"
    assert dom.extract_domain_from_url("shop.com.tw") == "shop.com.tw"
    assert dom.extract_domain_from_url("a.b.example.com") == "example.com"
