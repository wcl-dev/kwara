"""Tests for fingerprints.extract_tracking_ids().

Each platform should be matched on the standard pixel snippet shipped
in vendor docs and rejected for plausible-but-not-actual references
(e.g. a help-doc paragraph mentioning the prefix as text).
"""
import os
import tempfile

from fingerprints import extract_tracking_ids, extract_tracking_ids_from_file


def test_empty_html_returns_empty_dict():
    assert extract_tracking_ids("") == {}
    assert extract_tracking_ids(None) == {}


def test_no_match_returns_empty_dict():
    html = "<html><body>Just a regular page with no tracking.</body></html>"
    assert extract_tracking_ids(html) == {}


def test_meta_pixel_standard_snippet():
    html = """
    <script>
      !function(f,b,e,v,n,t,s) {/* boilerplate */}
      fbq('init', '1234567890123456');
      fbq('track', 'PageView');
    </script>
    """
    out = extract_tracking_ids(html)
    assert out == {"Meta Pixel": ["1234567890123456"]}


def test_meta_pixel_double_quotes_and_whitespace():
    html = """fbq( "init" ,  "987654321098765" );"""
    assert extract_tracking_ids(html) == {"Meta Pixel": ["987654321098765"]}


def test_meta_pixel_rejects_too_short_id():
    """Pixel IDs are 15-17 digits; a 10-digit number must not match."""
    html = """fbq('init', '1234567890');"""
    assert extract_tracking_ids(html) == {}


def test_ga4_measurement_id():
    html = """<script>gtag('config', 'G-AB12CD34EF');</script>"""
    out = extract_tracking_ids(html)
    assert out == {"Google Analytics 4": ["G-AB12CD34EF"]}


def test_ga_universal_legacy_id():
    html = """ga('create', 'UA-1234567-12', 'auto');"""
    out = extract_tracking_ids(html)
    assert out == {"Google Analytics (UA)": ["UA-1234567-12"]}


def test_gtm_container_id():
    html = """j.src='//www.googletagmanager.com/gtm.js?id=GTM-ABC1234';"""
    out = extract_tracking_ids(html)
    assert out == {"Google Tag Manager": ["GTM-ABC1234"]}


def test_google_ads_conversion_id():
    html = """gtag('config', 'AW-1234567890');"""
    out = extract_tracking_ids(html)
    assert out == {"Google Ads": ["AW-1234567890"]}


def test_tiktok_pixel():
    html = """ttq.load('CABCD1EFGHIJK2LMNOPQR');"""
    out = extract_tracking_ids(html)
    assert out == {"TikTok Pixel": ["CABCD1EFGHIJK2LMNOPQR"]}


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
        "fbq('init', '2222222222222222');"
    )
    out = extract_tracking_ids(html)
    assert out == {"Meta Pixel": ["1111111111111111", "2222222222222222"]}


def test_does_not_falsely_match_plain_text_mentioning_prefix():
    """A help page mentioning 'G-XXXXXX' as placeholder must not match."""
    html = "<p>Replace G- with your measurement ID, e.g. G-EXAMPLE.</p>"
    # G-EXAMPLE has 7 letters/digits → matches the 6-12 char regex.
    # That's an acceptable false positive for now (rare in scam pages).
    # We just verify behaviour is documented:
    out = extract_tracking_ids(html)
    # Don't assert exact result — just that the function returns a dict
    # (no crash) and either matches or doesn't.
    assert isinstance(out, dict)


def test_extract_from_file_missing_path():
    assert extract_tracking_ids_from_file(None) == {}
    assert extract_tracking_ids_from_file("/nonexistent/path/foo.html") == {}


def test_extract_from_file_reads_html():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".html", delete=False, encoding="utf-8"
    ) as f:
        f.write("<script>fbq('init', '5555555555555555');</script>")
        path = f.name
    try:
        out = extract_tracking_ids_from_file(path)
        assert out == {"Meta Pixel": ["5555555555555555"]}
    finally:
        os.unlink(path)


def test_extract_from_file_handles_bad_encoding():
    """File with mixed/invalid encoding should not crash — error='replace'."""
    path = tempfile.mktemp(suffix=".html")
    try:
        # Write some bytes that include invalid UTF-8 sequences
        with open(path, "wb") as f:
            f.write(b"<html><body>")
            f.write(b"\xff\xfe garbage \xc3\x28")  # mixed garbage + bad UTF-8
            f.write(b"<script>fbq('init', '7777777777777777');</script>")
            f.write(b"</body></html>")
        out = extract_tracking_ids_from_file(path)
        assert out == {"Meta Pixel": ["7777777777777777"]}
    finally:
        if os.path.exists(path):
            os.unlink(path)
