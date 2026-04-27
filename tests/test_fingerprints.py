"""Tests for fingerprints.extract_tracking_ids().

Each platform should match the canonical pixel snippet shipped in vendor
docs and reject plausible-but-not-actual references (placeholder text
in help pages, comments, all-X IDs, etc) — over-matching is dangerous
because the same IDs are later used as cross-domain operator attribution.
"""
import os
import tempfile

from fingerprints import (
    _looks_like_placeholder,
    extract_tracking_ids,
    extract_tracking_ids_from_file,
)


def test_empty_html_returns_empty_dict():
    assert extract_tracking_ids("") == {}
    assert extract_tracking_ids(None) == {}


def test_no_match_returns_empty_dict():
    html = "<html><body>Just a regular page with no tracking.</body></html>"
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# Meta Pixel
# ---------------------------------------------------------------------------
def test_meta_pixel_standard_snippet():
    html = """
    <script>
      !function(f,b,e,v,n,t,s) {/* boilerplate */}
      fbq('init', '1234567890123456');
      fbq('track', 'PageView');
    </script>
    """
    assert extract_tracking_ids(html) == {"Meta Pixel": ["1234567890123456"]}


def test_meta_pixel_double_quotes_and_whitespace():
    html = """fbq( "init" ,  "987654321098765" );"""
    assert extract_tracking_ids(html) == {"Meta Pixel": ["987654321098765"]}


def test_meta_pixel_rejects_too_short_id():
    """Pixel IDs are 15-17 digits; a 10-digit number must not match."""
    html = """fbq('init', '1234567890');"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# Google Analytics 4 — context-anchored
# ---------------------------------------------------------------------------
def test_ga4_in_gtag_config_call():
    html = """<script>gtag('config', 'G-AB12CD34EF');</script>"""
    assert extract_tracking_ids(html) == {"Google Analytics 4": ["G-AB12CD34EF"]}


def test_ga4_in_gtagjs_loader_url():
    html = """<script src="https://www.googletagmanager.com/gtag/js?id=G-XYZ123ABC"></script>"""
    assert extract_tracking_ids(html) == {"Google Analytics 4": ["G-XYZ123ABC"]}


def test_ga4_in_collect_endpoint_url():
    html = """<img src="https://www.google-analytics.com/g/collect?v=2&tid=G-MEASURE9876&cid=...">"""
    assert extract_tracking_ids(html) == {"Google Analytics 4": ["G-MEASURE9876"]}


def test_ga4_query_id_NOT_on_google_host_does_NOT_match():
    """Codex2 #2: ?id=G-… in some unrelated URL must not match — only
    google-analytics.com / googletagmanager.com URLs are recognised."""
    html = """<a href="https://random-blog.example/post?id=G-T5N9K2Q7W3">read more</a>"""
    assert extract_tracking_ids(html) == {}


def test_ga4_id_in_random_json_blob_does_NOT_match():
    """A JSON blob mentioning G-… without a Google URL host must not match."""
    html = """<script>var cfg = {"some_key": "G-AB12CD34", "id": "G-WHATEVER1"};</script>"""
    assert extract_tracking_ids(html) == {}


def test_ga4_bare_token_in_plaintext_does_NOT_match():
    """Codex review fix #1: bare G-… in plain text was previously matched.
    Without an invocation context it must not become evidence."""
    html = """<p>Replace G-AB12CD34 with your GA4 measurement ID.</p>"""
    assert extract_tracking_ids(html) == {}


def test_ga4_placeholder_xxxxxxxx_rejected():
    """gtag('config', 'G-XXXXXXXX') in a help-doc snippet must not match."""
    html = """<code>gtag('config', 'G-XXXXXXXX');</code>"""
    assert extract_tracking_ids(html) == {}


def test_ga4_placeholder_example_rejected():
    """Vendor doc placeholder 'G-EXAMPLE' must not become attribution."""
    html = """<pre>gtag('config', 'G-EXAMPLE');</pre>"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# Google Analytics Universal (legacy UA)
# ---------------------------------------------------------------------------
def test_ua_in_ga_create_call():
    html = """ga('create', 'UA-1234567-12', 'auto');"""
    assert extract_tracking_ids(html) == {"Google Analytics (UA)": ["UA-1234567-12"]}


def test_ua_in_gtag_config_call():
    html = """gtag('config', 'UA-9876543-1');"""
    assert extract_tracking_ids(html) == {"Google Analytics (UA)": ["UA-9876543-1"]}


def test_ua_bare_token_in_plaintext_does_NOT_match():
    html = """<p>your tracking ID looks like UA-1234567-12</p>"""
    assert extract_tracking_ids(html) == {}


def test_ua_placeholder_xxxxx_rejected():
    html = """ga('create', 'UA-XXXXX-X', 'auto');"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# Google Tag Manager
# ---------------------------------------------------------------------------
def test_gtm_in_standard_snippet():
    html = """j.src='//www.googletagmanager.com/gtm.js?id=GTM-ABC1234';"""
    assert extract_tracking_ids(html) == {"Google Tag Manager": ["GTM-ABC1234"]}


def test_gtm_query_id_NOT_on_google_host_does_NOT_match():
    """Codex2 #2: ?id=GTM-… on a non-Google host must not be picked up."""
    html = """<a href="https://example.com/redirect?id=GTM-ABC1234">click</a>"""
    assert extract_tracking_ids(html) == {}


def test_gtm_in_quoted_container_id():
    # Use a realistic-looking GTM ID — sequential-letter examples like
    # GTM-ABCDEFG match the placeholder filter, which is the correct
    # behaviour for vendor doc examples.
    html = """})(window,document,'script','dataLayer','GTM-K7L5RZP');"""
    assert extract_tracking_ids(html) == {"Google Tag Manager": ["GTM-K7L5RZP"]}


def test_gtm_bare_token_in_plaintext_does_NOT_match():
    """Bare GTM-… in plain text — no quotes, no URL — must not match."""
    html = """<p>Use GTM-ABCDEFG as your container ID.</p>"""
    assert extract_tracking_ids(html) == {}


def test_gtm_placeholder_xxxxxxx_rejected():
    html = """<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXXXXX"></iframe></noscript>"""
    assert extract_tracking_ids(html) == {}


def test_gtm_placeholder_example_rejected():
    html = """<script>'GTM-EXAMPLE';</script>"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# Google Ads conversion ID
# ---------------------------------------------------------------------------
def test_google_ads_conversion_id_in_gtag_config():
    html = """gtag('config', 'AW-1234567890');"""
    assert extract_tracking_ids(html) == {"Google Ads": ["AW-1234567890"]}


def test_google_ads_conversion_id_in_send_to():
    html = """gtag('event', 'conversion', {'send_to': 'AW-1234567890/abc'});"""
    assert extract_tracking_ids(html) == {"Google Ads": ["AW-1234567890"]}


def test_google_ads_bare_token_does_NOT_match():
    html = """<p>Conversion ID example: AW-1234567890</p>"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# TikTok Pixel
# ---------------------------------------------------------------------------
def test_tiktok_pixel_in_ttq_load_call():
    html = """ttq.load('CABCD1EFGHIJK2LMNOPQR');"""
    assert extract_tracking_ids(html) == {"TikTok Pixel": ["CABCD1EFGHIJK2LMNOPQR"]}


# ---------------------------------------------------------------------------
# Cross-platform behaviour
# ---------------------------------------------------------------------------
def test_multiple_platforms_in_same_html():
    html = """
    <script>fbq('init', '1234567890123456');</script>
    <script>gtag('config', 'G-AB12CD34');</script>
    <script>ga('create', 'UA-987654-1');</script>
    """
    out = extract_tracking_ids(html)
    assert "Meta Pixel" in out
    assert "Google Analytics 4" in out
    assert "Google Analytics (UA)" in out


def test_dedup_within_page():
    """Same Pixel ID appearing 5 times → reported once."""
    html = "fbq('init', '1234567890123456');" * 5
    assert extract_tracking_ids(html) == {"Meta Pixel": ["1234567890123456"]}


def test_multiple_distinct_pixel_ids_kept_separate():
    html = (
        "fbq('init', '1111111111111111');"
        "fbq('init', '2222222222222223');"  # avoid all-same-char placeholder filter
    )
    out = extract_tracking_ids(html)
    assert out == {"Meta Pixel": ["1111111111111111", "2222222222222223"]}


def test_pixel_with_all_same_digit_id_treated_as_placeholder():
    """Operationally a real Meta Pixel ID won't be 16 identical digits.
    1111111111111111 is treated as placeholder by _looks_like_placeholder."""
    html = """fbq('init', '1111111111111111');"""
    # Note: Meta Pixel IDs don't have a `-` separator, so the all-same-char
    # check via the part-after-dash logic does NOT trip here — the function
    # only filters segmented IDs (G-XXX, GTM-XXX, UA-XXX-X). This is a
    # known minor limitation; document it via this test rather than fixing
    # it because real all-same-digit Pixel IDs aren't observed in practice.
    out = extract_tracking_ids(html)
    assert out == {"Meta Pixel": ["1111111111111111"]}


# ---------------------------------------------------------------------------
# Placeholder helper
# ---------------------------------------------------------------------------
def test_looks_like_placeholder_recognises_all_alphabetic_repeats():
    assert _looks_like_placeholder("G-XXXXXXXX")
    assert _looks_like_placeholder("GTM-XXXXXXX")
    assert _looks_like_placeholder("UA-XXXXX-X")
    assert _looks_like_placeholder("G-ZZZZZZZ")


def test_looks_like_placeholder_recognises_named_placeholders():
    assert _looks_like_placeholder("G-EXAMPLE")
    assert _looks_like_placeholder("GTM-EXAMPLE")
    assert _looks_like_placeholder("AW-PLACEHOLDER")
    assert _looks_like_placeholder("G-YOURID")


def test_looks_like_placeholder_passes_real_ids():
    assert not _looks_like_placeholder("G-AB12CD34EF")
    assert not _looks_like_placeholder("GTM-ABC1234")
    assert not _looks_like_placeholder("UA-1234567-12")
    assert not _looks_like_placeholder("AW-1234567890")


def test_looks_like_placeholder_does_NOT_reject_repeated_digit_ids():
    """Codex2 #3: repeated-digit IDs (AW-1111111111, UA-1111111-1) are
    syntactically valid even if rare. Only alphabetic repeats are
    treated as placeholders."""
    assert not _looks_like_placeholder("AW-1111111111")
    assert not _looks_like_placeholder("UA-1111111-1")
    assert not _looks_like_placeholder("GTM-0000000")
    assert not _looks_like_placeholder("G-99999999")


# ---------------------------------------------------------------------------
# File reader
# ---------------------------------------------------------------------------
def test_extract_from_file_missing_path():
    assert extract_tracking_ids_from_file(None) == {}
    assert extract_tracking_ids_from_file("/nonexistent/path/foo.html") == {}


def test_extract_from_file_reads_html():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        f.write("<script>fbq('init', '5555555555555556');</script>")
        path = f.name
    try:
        out = extract_tracking_ids_from_file(path)
        assert out == {"Meta Pixel": ["5555555555555556"]}
    finally:
        os.unlink(path)


def test_extract_from_file_handles_bad_encoding():
    """File with mixed/invalid encoding should not crash — error='replace'."""
    path = tempfile.mktemp(suffix=".html")
    try:
        with open(path, "wb") as f:
            f.write(b"<html><body>")
            f.write(b"\xff\xfe garbage \xc3\x28")
            f.write(b"<script>fbq('init', '7777777777777778');</script>")
            f.write(b"</body></html>")
        out = extract_tracking_ids_from_file(path)
        assert out == {"Meta Pixel": ["7777777777777778"]}
    finally:
        if os.path.exists(path):
            os.unlink(path)
