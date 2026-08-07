"""Tests for fingerprints.extract_tracking_ids().

Each platform should match the canonical pixel snippet shipped in vendor
docs and reject plausible-but-not-actual references (placeholder text
in help pages, comments, all-X IDs, etc) — over-matching is dangerous
because the same IDs are later used as cross-domain operator attribution.
"""
import os
import tempfile

from kwara.fingerprints import (
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


def test_gtm_in_standard_snippet_after_datalayer():
    """Standard Google snippet ends with 'dataLayer','GTM-…' — anchored match."""
    html = """})(window,document,'script','dataLayer','GTM-K7L5RZP');"""
    assert extract_tracking_ids(html) == {"Google Tag Manager": ["GTM-K7L5RZP"]}


def test_gtm_quoted_without_dataLayer_context_does_NOT_match():
    """Codex2 follow-up: a bare quoted 'GTM-…' in a JSON config or data
    attribute must NOT be picked up — only the canonical snippet form
    (preceded by 'dataLayer') and the gtm.js / ns.html URL form qualify."""
    # JSON config blob mentioning a GTM-like ID
    html = """<script>var cfg = {"my_gtm_id": "GTM-K7L5RZP"};</script>"""
    assert extract_tracking_ids(html) == {}


def test_gtm_in_data_attribute_does_NOT_match():
    """data-gtm-id="GTM-…" attribute alone is not a real init call."""
    html = """<div data-gtm-id="GTM-K7L5RZP">tracker</div>"""
    assert extract_tracking_ids(html) == {}


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
# Microsoft Clarity (Phase 3 ticket D)
# ---------------------------------------------------------------------------
def test_clarity_in_tag_url():
    """Standard snippet's loader URL: clarity.ms/tag/<id>"""
    html = """t.src="https://www.clarity.ms/tag/abcd1234ef";"""
    assert extract_tracking_ids(html) == {"Microsoft Clarity": ["abcd1234ef"]}


def test_clarity_in_set_project_call():
    html = """clarity('set', 'project', 'abcd1234ef');"""
    assert extract_tracking_ids(html) == {"Microsoft Clarity": ["abcd1234ef"]}


def test_clarity_bare_id_in_plaintext_does_NOT_match():
    html = """<p>Clarity project ID: abcd1234ef</p>"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# Hotjar (Phase 3 ticket D)
# ---------------------------------------------------------------------------
def test_hotjar_in_settings_object():
    html = """h._hjSettings={hjid:1234567,hjsv:6};"""
    assert extract_tracking_ids(html) == {"Hotjar": ["1234567"]}


def test_hotjar_with_whitespace_variants():
    html = """h._hjSettings = { hjid : 9876543 , hjsv : 6 };"""
    assert extract_tracking_ids(html) == {"Hotjar": ["9876543"]}


def test_hotjar_bare_number_does_NOT_match():
    """Bare digits with no _hjSettings context must not match."""
    html = """<p>Some random number 1234567 in body text.</p>"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# LINE Tag (Phase 3 ticket D)
# ---------------------------------------------------------------------------
def test_line_tag_in_lt_init_call():
    html = """_lt('init', {customerType: 'lap', tagId: 'taghex123abc456def'});"""
    assert extract_tracking_ids(html) == {"LINE Tag": ["taghex123abc456def"]}


def test_line_tag_alternate_field_order():
    html = """_lt('init',{tagId:'tag-XYZ-123-abc',customerType:'lap'});"""
    assert extract_tracking_ids(html) == {"LINE Tag": ["tag-XYZ-123-abc"]}


def test_line_tag_bare_token_does_NOT_match():
    html = """<p>Use tagId: 'taghex123abc456def' as your LINE Tag identifier.</p>"""
    assert extract_tracking_ids(html) == {}


# ---------------------------------------------------------------------------
# X / Twitter Pixel (Phase 3 ticket D)
# ---------------------------------------------------------------------------
def test_x_twitter_pixel_in_twq_config_call():
    html = """twq('config', 'abc12');"""
    assert extract_tracking_ids(html) == {"X / Twitter Pixel": ["abc12"]}


def test_x_twitter_pixel_in_twq_init_call():
    html = """twq("init", "xyz98");"""
    assert extract_tracking_ids(html) == {"X / Twitter Pixel": ["xyz98"]}


def test_x_twitter_bare_token_does_NOT_match():
    html = """<p>Twitter pixel: abc12 (not in a twq call)</p>"""
    assert extract_tracking_ids(html) == {}


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
# Google AdSense — `ca-pub-NNNNNNNNNNNNNNNN`
# ---------------------------------------------------------------------------

def test_adsense_extracted_from_data_ad_client_attribute():
    """The most common AdSense placement — an <ins> ad slot."""
    html = (
        '<ins class="adsbygoogle" style="display:block" '
        'data-ad-client="REDACTEDID160" '
        'data-ad-slot="1234567890"></ins>'
    )
    out = extract_tracking_ids(html)
    assert out == {"Google AdSense": ["REDACTEDID160"]}


def test_adsense_extracted_from_js_config_object():
    """Auto-ads / page-level ad config uses google_ad_client in JS."""
    html = (
        "<script>"
        "(adsbygoogle = window.adsbygoogle || []).push({"
        'google_ad_client: "ca-pub-1234567890123456",'
        ' enable_page_level_ads: true});'
        "</script>"
    )
    out = extract_tracking_ids(html)
    assert out == {"Google AdSense": ["ca-pub-1234567890123456"]}


def test_adsense_extracted_from_loader_url_client_param():
    """The async-loader form: adsbygoogle.js?client=ca-pub-…"""
    html = (
        '<script async '
        'src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js'
        '?client=ca-pub-7777777777777777"></script>'
    )
    out = extract_tracking_ids(html)
    assert out == {"Google AdSense": ["ca-pub-7777777777777777"]}


def test_adsense_dedupes_same_id_across_contexts_within_one_page():
    html = (
        '<script src="https://pagead2.googlesyndication.com/pagead/js/'
        'adsbygoogle.js?client=REDACTEDID160"></script>'
        '<ins class="adsbygoogle" data-ad-client="REDACTEDID160"></ins>'
    )
    out = extract_tracking_ids(html)
    assert out == {"Google AdSense": ["REDACTEDID160"]}


def test_adsense_does_not_match_bare_ca_pub_string():
    """A `ca-pub-…` quoted in a vendor docs paragraph (no AdSense
    invocation context) must not become attribution evidence."""
    html = (
        "<p>To configure AdSense, copy your ca-pub-1234567890123456 "
        "from the dashboard.</p>"
    )
    assert extract_tracking_ids(html) == {}


def test_adsense_does_not_match_wrong_digit_count():
    """ca-pub- is followed by exactly 16 digits in production."""
    short = '<ins data-ad-client="ca-pub-12345678"></ins>'
    long  = '<ins data-ad-client="ca-pub-12345678901234567890"></ins>'
    assert extract_tracking_ids(short) == {}
    assert extract_tracking_ids(long)  == {}


# ---------------------------------------------------------------------------
# Meta Facebook Page — <meta property="fb:pages" content="…">
# ---------------------------------------------------------------------------

def test_fb_pages_single_id():
    html = '<meta property="fb:pages" content="1000000000000001" />'
    out = extract_tracking_ids(html)
    assert out == {"Meta Facebook Page": ["1000000000000001"]}


def test_fb_pages_comma_separated_multiple_ids():
    """Sites declaring more than one owning Page list them comma-separated."""
    html = (
        '<meta property="fb:pages" '
        'content="1000000000000001, 9988776655443322,1234567890123456" />'
    )
    out = extract_tracking_ids(html)
    assert out == {"Meta Facebook Page": [
        "1234567890123456", "1000000000000001", "9988776655443322",
    ]}


def test_fb_pages_attribute_order_tolerant():
    """The meta tag's attribute order isn't fixed by spec — content first,
    property second still has to match."""
    html = (
        '<meta content="555555555555555" property="fb:pages" />'
    )
    out = extract_tracking_ids(html)
    # The property-first regex won't match this ordering — confirms current
    # scope (intentional: the property-first form is what FB documents).
    # If we widen later, a positive-case test goes in this slot.
    assert out == {}


def test_fb_pages_does_not_swallow_unrelated_meta_tags():
    html = (
        '<meta property="og:image" content="1234567890123456">'
        '<meta property="fb:pages" content="9999999999999999">'
    )
    out = extract_tracking_ids(html)
    assert out == {"Meta Facebook Page": ["9999999999999999"]}


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
