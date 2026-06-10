"""URL parameter attribution + clustering primitives shared across modules.

Holds the canonical parameter-attribution tables and the small set of
helpers that both URL-clustering (clustering_url) and infra-clustering
(clustering_infra) need. Pure-data and pure-logic — no SQL, no i18n.

Public surface:
  OWNER_KIND_PLATFORM / OWNER_KIND_GENERIC / OWNER_KIND_UNKNOWN
        Stable enum returned by clustering functions; view layers
        translate based on the kind, never on a translated owner string.
  PLATFORM_*                       Stable canonical IDs for known vendors.
  PLATFORM_DISPLAY_NAMES           {platform_id: English display name}.
  identify_param(key)              Map a query key to (platform_id, purpose_i18n_key).
                                   platform_id is "" for unknown, PLATFORM_GENERIC
                                   for the generic-tracker bucket, or one of the
                                   PLATFORM_* constants for recognised vendors.
  classify_owner(platform_id)      Map identify_param's first value to OWNER_KIND_*.
  merge_risk_tags(json_a, json_b)  Union two JSON-serialised tag lists.

Why platform_id and display names are separate: aggregation across modules
(clustering_url, clustering_infra) must dedupe by an exact-match key. If the
key were a free-text English label, a typo in either identify_param or the
HTML-to-platform map would silently break merging — losing 'both' detections.
A canonical lowercase ID makes drift loud (refers to an undefined constant)
rather than silent.
"""
from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Stable owner-kind enum (rendered via i18n in the view layer)
# ---------------------------------------------------------------------------
OWNER_KIND_PLATFORM = "platform"   # Recognised vendor (e.g. PLATFORM_GOOGLE_ANALYTICS)
OWNER_KIND_GENERIC  = "generic"    # Generic tracking convention (uid, aff_id…)
OWNER_KIND_UNKNOWN  = "unknown"    # Key not recognised by identify_param()


# ---------------------------------------------------------------------------
# Canonical platform IDs (lowercase, snake_case)
# ---------------------------------------------------------------------------
# Use these constants instead of free-text labels anywhere aggregation /
# dedup is involved. Adding a new platform: pick a stable ID, register it
# here AND in PLATFORM_DISPLAY_NAMES below; both PARAM_EXACT/PARAM_PREFIX
# (URL-param) and HTML_PLATFORM_TO_PLATFORM_ID (in clustering_infra) refer
# to it by symbol.
PLATFORM_GOOGLE_ANALYTICS  = "google_analytics"
PLATFORM_GOOGLE_ADS        = "google_ads"
PLATFORM_GOOGLE_ADS_DCM    = "google_ads_dcm"
PLATFORM_GOOGLE_TAG_MANAGER = "google_tag_manager"
PLATFORM_META_FACEBOOK     = "meta_facebook"
PLATFORM_X_TWITTER         = "x_twitter"
PLATFORM_MICROSOFT_ADS     = "microsoft_ads"
PLATFORM_TIKTOK_ADS        = "tiktok_ads"
PLATFORM_YAHOO_ADS         = "yahoo_ads"
PLATFORM_HUBSPOT           = "hubspot"
PLATFORM_MAILCHIMP         = "mailchimp"
PLATFORM_LINE_LIFF         = "line_liff"
PLATFORM_KLAVIYO           = "klaviyo"
PLATFORM_APPSFLYER         = "appsflyer"
# Phase 3 ticket D — second batch of HTML-embedded tracking platforms
PLATFORM_MICROSOFT_CLARITY = "microsoft_clarity"
PLATFORM_HOTJAR            = "hotjar"
PLATFORM_LINE_TAG          = "line_tag"
# Phase 4 follow-up — surfaced by 2026-04-29 new-case E2E. Picread.net's
# SEO persona (now captured via cloaking_alt) embedded these two and
# shared the same IDs with visitorlanding.example, the cross-domain attribution
# evidence kwara was missing.
PLATFORM_GOOGLE_ADSENSE         = "google_adsense"
PLATFORM_META_FACEBOOK_PAGE     = "meta_facebook_page"
# Phase 8 — a DIRECT seller account declared in a domain's ads.txt
# (adstxt.py). Not a URL-param or HTML signal; carried as the platform_id
# of shared-monetisation-account clusters so reports can cite it like any
# other canonical platform.
PLATFORM_ADS_TXT_SELLER         = "ads_txt_seller"
# "generic" is the sentinel for keys that are tracking conventions but
# can't be attributed to a specific vendor (uid, aff_id, ref…). Mapped to
# OWNER_KIND_GENERIC at classify time.
PLATFORM_GENERIC           = "generic"

# Display name lookup for the view layer. Note: not every platform_id has
# an entry — OWNER_KIND_GENERIC and OWNER_KIND_UNKNOWN are translated via
# i18n, not looked up here.
PLATFORM_DISPLAY_NAMES: dict[str, str] = {
    PLATFORM_GOOGLE_ANALYTICS:   "Google Analytics",
    PLATFORM_GOOGLE_ADS:         "Google Ads",
    PLATFORM_GOOGLE_ADS_DCM:     "Google Ads (DCM)",
    PLATFORM_GOOGLE_TAG_MANAGER: "Google Tag Manager",
    PLATFORM_META_FACEBOOK:      "Meta / Facebook",
    PLATFORM_X_TWITTER:          "X / Twitter",
    PLATFORM_MICROSOFT_ADS:      "Microsoft Ads",
    PLATFORM_TIKTOK_ADS:         "TikTok Ads",
    PLATFORM_YAHOO_ADS:          "Yahoo Ads",
    PLATFORM_HUBSPOT:            "HubSpot",
    PLATFORM_MAILCHIMP:          "Mailchimp",
    PLATFORM_LINE_LIFF:          "LINE LIFF",
    PLATFORM_KLAVIYO:            "Klaviyo",
    PLATFORM_APPSFLYER:          "AppsFlyer",
    PLATFORM_MICROSOFT_CLARITY:  "Microsoft Clarity",
    PLATFORM_HOTJAR:             "Hotjar",
    PLATFORM_LINE_TAG:           "LINE Tag",
    PLATFORM_GOOGLE_ADSENSE:     "Google AdSense",
    PLATFORM_META_FACEBOOK_PAGE: "Meta / Facebook Page",
    PLATFORM_ADS_TXT_SELLER:     "ads.txt Seller (DIRECT)",
}


def classify_owner(platform_id: str) -> str:
    """Map identify_param() first-return-value to the stable owner_kind enum."""
    if platform_id == PLATFORM_GENERIC:
        return OWNER_KIND_GENERIC
    if platform_id:
        return OWNER_KIND_PLATFORM
    return OWNER_KIND_UNKNOWN


# ---------------------------------------------------------------------------
# Known URL parameter attribution
# ---------------------------------------------------------------------------
# Exact-match table: param_key -> (platform_id, i18n_key for purpose).
PARAM_EXACT: dict[str, tuple[str, str]] = {
    # Google Analytics / UTM (Urchin Tracking Module)
    "utm_source":   (PLATFORM_GOOGLE_ANALYTICS, "param.traffic_source"),
    "utm_medium":   (PLATFORM_GOOGLE_ANALYTICS, "param.traffic_medium"),
    "utm_campaign": (PLATFORM_GOOGLE_ANALYTICS, "param.campaign_name"),
    "utm_term":     (PLATFORM_GOOGLE_ANALYTICS, "param.paid_keyword"),
    "utm_content":  (PLATFORM_GOOGLE_ANALYTICS, "param.ad_creative"),
    "utm_id":       (PLATFORM_GOOGLE_ANALYTICS, "param.campaign_id"),
    # Google Ads
    "gclid":        (PLATFORM_GOOGLE_ADS, "param.click_id"),
    "gclsrc":       (PLATFORM_GOOGLE_ADS, "param.click_source_type"),
    "gbraid":       (PLATFORM_GOOGLE_ADS, "param.app_attribution_ios"),
    "wbraid":       (PLATFORM_GOOGLE_ADS, "param.web_to_app"),
    "dclid":        (PLATFORM_GOOGLE_ADS_DCM, "param.doubleclick_click_id"),
    # Facebook / Meta
    "fbclid":       (PLATFORM_META_FACEBOOK, "param.click_id"),
    "fb_action_ids":(PLATFORM_META_FACEBOOK, "param.action_id"),
    # Twitter / X
    "twclid":       (PLATFORM_X_TWITTER, "param.click_id"),
    # Microsoft / Bing Ads
    "msclkid":      (PLATFORM_MICROSOFT_ADS, "param.click_id"),
    # TikTok
    "ttclid":       (PLATFORM_TIKTOK_ADS, "param.click_id"),
    # Yahoo
    "yclid":        (PLATFORM_YAHOO_ADS, "param.click_id"),
    # HubSpot
    "hsa_cam":      (PLATFORM_HUBSPOT, "param.campaign_id"),
    "hsa_grp":      (PLATFORM_HUBSPOT, "param.ad_group_id"),
    "hsa_src":      (PLATFORM_HUBSPOT, "param.traffic_source"),
    "hsa_net":      (PLATFORM_HUBSPOT, "param.ad_network"),
    # Mailchimp
    "mc_cid":       (PLATFORM_MAILCHIMP, "param.campaign_id"),
    "mc_eid":       (PLATFORM_MAILCHIMP, "param.recipient_id"),
    # LINE LIFF (Front-end Framework) — official LINE platform parameter
    # https://developers.line.biz/en/docs/liff/
    "liffid":       (PLATFORM_LINE_LIFF, "param.liff_app_id"),
    # Klaviyo — email marketing platform
    "_kx":          (PLATFORM_KLAVIYO, "param.klaviyo_subscriber"),
    "kxidcid":      (PLATFORM_KLAVIYO, "param.klaviyo_id"),
    # Common affiliate / tracking — generic bucket (operator unknown)
    "ref":          (PLATFORM_GENERIC, "param.referral_affiliate"),
    "aff":          (PLATFORM_GENERIC, "param.affiliate_code"),
    "aff_id":       (PLATFORM_GENERIC, "param.affiliate_id"),
    "affiliate_id": (PLATFORM_GENERIC, "param.affiliate_id"),
    "uid":          (PLATFORM_GENERIC, "param.user_tracking_id"),
    "sid":          (PLATFORM_GENERIC, "param.session_id"),
    "click_id":     (PLATFORM_GENERIC, "param.click_tracking_id"),
    "tracking_id":  (PLATFORM_GENERIC, "param.tracking_id"),
    "campaign_id":  (PLATFORM_GENERIC, "param.campaign_id"),
    "source":       (PLATFORM_GENERIC, "param.traffic_source"),
}

# Prefix-match table: if the key starts with this prefix -> (platform_id, i18n_key).
# Order matters — first match wins; place specific prefixes before generic ones.
PARAM_PREFIX: list[tuple[str, str, str]] = [
    ("utm_",     PLATFORM_GOOGLE_ANALYTICS, "param.utm_tracking"),
    ("hsa_",     PLATFORM_HUBSPOT,          "param.hubspot_ad"),
    ("mc_",      PLATFORM_MAILCHIMP,        "param.mailchimp_tracking"),
    ("fb_",      PLATFORM_META_FACEBOOK,    "param.facebook_tracking"),
    ("_ga",      PLATFORM_GOOGLE_ANALYTICS, "param.ga_tracking"),
    # AppsFlyer — industry-standard mobile measurement partner. Used by
    # Shopee, Foodpanda and most app campaigns. Keys: af_siteid, af_sub_siteid,
    # af_click_lookback, af_xp, af_channel, etc.
    ("af_",      PLATFORM_APPSFLYER,        "param.appsflyer_attribution"),
    # Klaviyo — secondary key prefix beyond _kx
    ("klaviyo_", PLATFORM_KLAVIYO,          "param.klaviyo_tracking"),
]


def identify_param(key: str) -> tuple[str, str]:
    """Return (platform_id, purpose_i18n_key) for a known URL parameter, or ('', '') if unknown.

    platform_id is one of:
      - a PLATFORM_* canonical ID (e.g. PLATFORM_GOOGLE_ANALYTICS) for recognised vendors
      - PLATFORM_GENERIC for keys in the generic tracking-convention bucket
      - "" when the key is not recognised at all
    """
    lower = key.lower()
    exact = PARAM_EXACT.get(lower)
    if exact:
        return exact
    for prefix, platform_id, purpose_key in PARAM_PREFIX:
        if lower.startswith(prefix):
            return platform_id, purpose_key
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
