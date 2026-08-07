"""Tests for the platform-attribution table in param_attribution.

After the platform_id refactor, identify_param() returns a canonical
PLATFORM_* identifier (lowercase snake_case) instead of a free-text
English label. Display names live in PLATFORM_DISPLAY_NAMES and are
applied at the view layer. These tests pin the canonical IDs so a
table edit can't silently drift out of sync with the cross-source
aggregation in clustering_infra.
"""
from kwara.param_attribution import (
    PARAM_EXACT as _PARAM_EXACT,
    PARAM_PREFIX as _PARAM_PREFIX,
    PLATFORM_APPSFLYER,
    PLATFORM_DISPLAY_NAMES,
    PLATFORM_GENERIC,
    PLATFORM_GOOGLE_ANALYTICS,
    PLATFORM_KLAVIYO,
    PLATFORM_LINE_LIFF,
    PLATFORM_MAILCHIMP,
    PLATFORM_META_FACEBOOK,
    identify_param,
)


def test_liff_id_recognised_as_line():
    pid, purpose_key = identify_param("liffId")  # case-insensitive
    assert pid == PLATFORM_LINE_LIFF
    assert purpose_key == "param.liff_app_id"


def test_klaviyo_kx_recognised():
    pid, purpose_key = identify_param("_kx")
    assert pid == PLATFORM_KLAVIYO
    assert purpose_key == "param.klaviyo_subscriber"


def test_klaviyo_kxidcid_recognised():
    pid, _ = identify_param("kxidcid")
    assert pid == PLATFORM_KLAVIYO


def test_klaviyo_prefix_matches():
    pid, purpose_key = identify_param("klaviyo_email_id")
    assert pid == PLATFORM_KLAVIYO
    assert purpose_key == "param.klaviyo_tracking"


def test_appsflyer_prefix_matches_af_siteid():
    """Common Shopee / app affiliate parameter."""
    pid, purpose_key = identify_param("af_siteid")
    assert pid == PLATFORM_APPSFLYER
    assert purpose_key == "param.appsflyer_attribution"


def test_appsflyer_prefix_matches_af_sub_siteid():
    pid, _ = identify_param("af_sub_siteid")
    assert pid == PLATFORM_APPSFLYER


def test_appsflyer_prefix_matches_af_click_lookback():
    pid, _ = identify_param("af_click_lookback")
    assert pid == PLATFORM_APPSFLYER


def test_existing_platforms_unaffected():
    """Regression: prior keys must keep their attribution."""
    assert identify_param("fbclid") == (PLATFORM_META_FACEBOOK, "param.click_id")
    assert identify_param("utm_campaign") == (PLATFORM_GOOGLE_ANALYTICS, "param.campaign_name")
    assert identify_param("mc_cid") == (PLATFORM_MAILCHIMP, "param.campaign_id")


def test_generic_keys_use_generic_sentinel():
    """uid, aff_id, ref → PLATFORM_GENERIC, not a vendor."""
    assert identify_param("uid")[0] == PLATFORM_GENERIC
    assert identify_param("aff_id")[0] == PLATFORM_GENERIC
    assert identify_param("ref")[0] == PLATFORM_GENERIC


def test_unknown_keys_still_unknown():
    assert identify_param("xyz_weird_token") == ("", "")


def test_case_insensitive_lookup_for_new_entries():
    assert identify_param("LIFFID")[0] == PLATFORM_LINE_LIFF
    assert identify_param("LiffId")[0] == PLATFORM_LINE_LIFF
    assert identify_param("AF_SITEID")[0] == PLATFORM_APPSFLYER


def test_every_table_platform_id_has_a_display_name_or_is_special():
    """Every platform_id used in the tables must either map to a display
    name or be one of the special sentinels (PLATFORM_GENERIC). This guards
    against typos in PARAM_EXACT/PARAM_PREFIX after a future edit."""
    seen_ids: set[str] = set()
    for _k, (pid, _purpose) in _PARAM_EXACT.items():
        seen_ids.add(pid)
    for _prefix, pid, _purpose in _PARAM_PREFIX:
        seen_ids.add(pid)
    for pid in seen_ids:
        if pid == PLATFORM_GENERIC:
            continue  # rendered via owner_kind, no display entry by design
        assert pid in PLATFORM_DISPLAY_NAMES, (
            f"platform_id {pid!r} used in attribution tables but missing "
            f"from PLATFORM_DISPLAY_NAMES"
        )


def test_table_invariants():
    """Sanity: every exact entry has a non-empty platform_id and purpose key."""
    for k, (pid, purpose_key) in _PARAM_EXACT.items():
        assert pid, f"key {k!r} has empty platform_id"
        assert purpose_key.startswith("param."), f"key {k!r} has bad purpose key"
    for prefix, pid, purpose_key in _PARAM_PREFIX:
        assert prefix and pid, f"prefix {prefix!r} malformed"
        assert purpose_key.startswith("param.")
