"""Tests for ticket 1.4 — extended platform attribution table.

Adds high-confidence entries for LINE LIFF, AppsFlyer (used by Shopee,
Foodpanda, etc.), and Klaviyo. Each new entry must:
  1. Be recognised by identify_param()
  2. Resolve to a documented purpose i18n key
  3. NOT collide with existing well-known platforms
"""
from param_attribution import (
    PARAM_EXACT as _PARAM_EXACT,
    PARAM_PREFIX as _PARAM_PREFIX,
    identify_param,
)


def test_liff_id_recognised_as_line():
    owner, purpose_key = identify_param("liffId")  # case-insensitive
    assert owner == "LINE LIFF"
    assert purpose_key == "param.liff_app_id"


def test_klaviyo_kx_recognised():
    owner, purpose_key = identify_param("_kx")
    assert owner == "Klaviyo"
    assert purpose_key == "param.klaviyo_subscriber"


def test_klaviyo_kxidcid_recognised():
    owner, _ = identify_param("kxidcid")
    assert owner == "Klaviyo"


def test_klaviyo_prefix_matches():
    owner, purpose_key = identify_param("klaviyo_email_id")
    assert owner == "Klaviyo"
    assert purpose_key == "param.klaviyo_tracking"


def test_appsflyer_prefix_matches_af_siteid():
    """Common Shopee / app affiliate parameter."""
    owner, purpose_key = identify_param("af_siteid")
    assert owner == "AppsFlyer"
    assert purpose_key == "param.appsflyer_attribution"


def test_appsflyer_prefix_matches_af_sub_siteid():
    owner, _ = identify_param("af_sub_siteid")
    assert owner == "AppsFlyer"


def test_appsflyer_prefix_matches_af_click_lookback():
    owner, _ = identify_param("af_click_lookback")
    assert owner == "AppsFlyer"


def test_existing_platforms_unaffected():
    """Regression: prior keys must keep their attribution."""
    assert identify_param("fbclid") == ("Meta / Facebook", "param.click_id")
    assert identify_param("utm_campaign") == ("Google Analytics", "param.campaign_name")
    assert identify_param("mc_cid") == ("Mailchimp", "param.campaign_id")


def test_unknown_keys_still_unknown():
    assert identify_param("xyz_weird_token") == ("", "")


def test_case_insensitive_lookup_for_new_entries():
    assert identify_param("LIFFID")[0] == "LINE LIFF"
    assert identify_param("LiffId")[0] == "LINE LIFF"
    assert identify_param("AF_SITEID")[0] == "AppsFlyer"


def test_table_invariants():
    """Sanity: every exact entry has a non-empty owner and purpose key."""
    for k, (owner, purpose_key) in _PARAM_EXACT.items():
        assert owner, f"key {k!r} has empty owner"
        assert purpose_key.startswith("param."), f"key {k!r} has bad purpose key"
    for prefix, owner, purpose_key in _PARAM_PREFIX:
        assert prefix and owner, f"prefix {prefix!r} malformed"
        assert purpose_key.startswith("param.")
