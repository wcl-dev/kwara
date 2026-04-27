"""URL parameter attribution + clustering primitives shared across modules.

Holds the canonical parameter-attribution tables and the small set of
helpers that both URL-clustering (clustering_url) and infra-clustering
(clustering_infra) need. Pure-data and pure-logic — no SQL, no i18n.

Public surface:
  OWNER_KIND_PLATFORM / OWNER_KIND_GENERIC / OWNER_KIND_UNKNOWN
        Stable enum returned by clustering functions; view layers
        translate based on the kind, never on a translated owner string.
  identify_param(key)              Map a query key to (owner_raw, purpose_i18n_key).
  classify_owner(owner_raw)        Map identify_param's owner string to one
                                   of the OWNER_KIND_* constants.
  merge_risk_tags(json_a, json_b)  Union two JSON-serialised tag lists,
                                   tolerating malformed input.
"""
from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Stable owner-kind enum
# ---------------------------------------------------------------------------
# Clustering output uses these strings instead of localised labels, so the
# data layer stays language-agnostic and views translate at render time.
OWNER_KIND_PLATFORM = "platform"   # Recognised vendor (e.g. Google Analytics)
OWNER_KIND_GENERIC  = "generic"    # Generic tracking convention (uid, aff_id…)
OWNER_KIND_UNKNOWN  = "unknown"    # Key not recognised by identify_param()


def classify_owner(owner_raw: str) -> str:
    """Map identify_param() owner string to the stable owner_kind enum."""
    if owner_raw == "generic":
        return OWNER_KIND_GENERIC
    if owner_raw:
        return OWNER_KIND_PLATFORM
    return OWNER_KIND_UNKNOWN


# ---------------------------------------------------------------------------
# Known URL parameter attribution
# ---------------------------------------------------------------------------
# Exact-match table: param_key -> (owner, i18n_key for purpose).
# Purpose values are i18n keys looked up at display time by the view layer.
PARAM_EXACT: dict[str, tuple[str, str]] = {
    # Google Analytics / UTM (Urchin Tracking Module)
    "utm_source":   ("Google Analytics", "param.traffic_source"),
    "utm_medium":   ("Google Analytics", "param.traffic_medium"),
    "utm_campaign": ("Google Analytics", "param.campaign_name"),
    "utm_term":     ("Google Analytics", "param.paid_keyword"),
    "utm_content":  ("Google Analytics", "param.ad_creative"),
    "utm_id":       ("Google Analytics", "param.campaign_id"),
    # Google Ads
    "gclid":        ("Google Ads", "param.click_id"),
    "gclsrc":       ("Google Ads", "param.click_source_type"),
    "gbraid":       ("Google Ads", "param.app_attribution_ios"),
    "wbraid":       ("Google Ads", "param.web_to_app"),
    "dclid":        ("Google Ads (DCM)", "param.doubleclick_click_id"),
    # Facebook / Meta
    "fbclid":       ("Meta / Facebook", "param.click_id"),
    "fb_action_ids":("Meta / Facebook", "param.action_id"),
    # Twitter / X
    "twclid":       ("X / Twitter", "param.click_id"),
    # Microsoft / Bing Ads
    "msclkid":      ("Microsoft Ads", "param.click_id"),
    # TikTok
    "ttclid":       ("TikTok Ads", "param.click_id"),
    # Yahoo
    "yclid":        ("Yahoo Ads", "param.click_id"),
    # HubSpot
    "hsa_cam":      ("HubSpot", "param.campaign_id"),
    "hsa_grp":      ("HubSpot", "param.ad_group_id"),
    "hsa_src":      ("HubSpot", "param.traffic_source"),
    "hsa_net":      ("HubSpot", "param.ad_network"),
    # Mailchimp
    "mc_cid":       ("Mailchimp", "param.campaign_id"),
    "mc_eid":       ("Mailchimp", "param.recipient_id"),
    # LINE LIFF (Front-end Framework) — official LINE platform parameter
    # https://developers.line.biz/en/docs/liff/
    "liffid":       ("LINE LIFF", "param.liff_app_id"),
    # Klaviyo — email marketing platform
    "_kx":          ("Klaviyo", "param.klaviyo_subscriber"),
    "kxidcid":      ("Klaviyo", "param.klaviyo_id"),
    # Common affiliate / tracking
    "ref":          ("generic", "param.referral_affiliate"),
    "aff":          ("generic", "param.affiliate_code"),
    "aff_id":       ("generic", "param.affiliate_id"),
    "affiliate_id": ("generic", "param.affiliate_id"),
    "uid":          ("generic", "param.user_tracking_id"),
    "sid":          ("generic", "param.session_id"),
    "click_id":     ("generic", "param.click_tracking_id"),
    "tracking_id":  ("generic", "param.tracking_id"),
    "campaign_id":  ("generic", "param.campaign_id"),
    "source":       ("generic", "param.traffic_source"),
}

# Prefix-match table: if the key starts with this prefix -> (owner, i18n_key).
# Order matters — first match wins; place specific prefixes before generic ones.
PARAM_PREFIX: list[tuple[str, str, str]] = [
    ("utm_",     "Google Analytics", "param.utm_tracking"),
    ("hsa_",     "HubSpot",          "param.hubspot_ad"),
    ("mc_",      "Mailchimp",        "param.mailchimp_tracking"),
    ("fb_",      "Meta / Facebook",  "param.facebook_tracking"),
    ("_ga",      "Google Analytics", "param.ga_tracking"),
    # AppsFlyer — industry-standard mobile measurement partner. Used by
    # Shopee, Foodpanda and most app campaigns. Keys: af_siteid, af_sub_siteid,
    # af_click_lookback, af_xp, af_channel, etc.
    ("af_",      "AppsFlyer",        "param.appsflyer_attribution"),
    # Klaviyo — secondary key prefix beyond _kx
    ("klaviyo_", "Klaviyo",          "param.klaviyo_tracking"),
]


def identify_param(key: str) -> tuple[str, str]:
    """Return (owner, purpose_i18n_key) for a known URL parameter, or ('', '') if unknown."""
    lower = key.lower()
    exact = PARAM_EXACT.get(lower)
    if exact:
        return exact
    for prefix, owner, purpose_key in PARAM_PREFIX:
        if lower.startswith(prefix):
            return owner, purpose_key
    return "", ""


# ---------------------------------------------------------------------------
# Risk-tag merging (used by both URL and infra clustering)
# ---------------------------------------------------------------------------
def merge_risk_tags(snap_json, intel_json) -> list:
    """Union snapshot page tags and scan-level intel tags (e.g. new_domain from WHOIS).

    Tolerates None and malformed JSON on either side.
    """
    a = []
    b = []
    if snap_json:
        try:
            a = json.loads(snap_json)
        except (ValueError, TypeError):
            a = []
    if intel_json:
        try:
            b = json.loads(intel_json)
        except (ValueError, TypeError):
            b = []
    seen = set()
    out = []
    for tag in a + b:
        if tag not in seen:
            seen.add(tag)
            out.append(tag)
    return out
