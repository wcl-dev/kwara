"""
clustering.py — Shared Destinations, Parameter Analysis & URL Parameter Attribution

Factual grouping functions (no intent inference):
  shared_destinations() : domains grouped by final destination, with risk tags
  shared_params()       : query param key+value pairs seen across 2+ distinct posts,
                          with platform attribution (owner/purpose) for known trackers
  asn_clusters()        : landing domains grouped by ASN
  shared_certificates() : domains grouped by shared TLS cert / same-day issuance
  identify_param()      : map a URL parameter key to its known owner/purpose
"""
import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

from config import (
    KNOWN_SHORTLINK_DOMAINS,
    PARAM_KEY_MAX_DOMAINS,
    PARAM_KEY_MIN_POSTS,
    PARAM_KEY_MIN_VALUES,
    PARAM_VALUE_HASH_THRESHOLD,
)
from i18n import t

# ---------------------------------------------------------------------------
# Known URL parameter attribution
# ---------------------------------------------------------------------------
# Exact-match table: param_key -> (owner, i18n_key for purpose)
# Purpose values are i18n keys looked up at display time via t().
_PARAM_EXACT: dict[str, tuple[str, str]] = {
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

# Prefix-match table: if the key starts with this prefix -> (owner, i18n_key)
# Order matters — first match wins; place specific prefixes before generic ones.
_PARAM_PREFIX: list[tuple[str, str, str]] = [
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
    exact = _PARAM_EXACT.get(lower)
    if exact:
        return exact
    for prefix, owner, purpose_key in _PARAM_PREFIX:
        if lower.startswith(prefix):
            return owner, purpose_key
    return "", ""

# Domains that are themselves shortlink services.
# When a scan's final_domain lands here it means the scan did not penetrate
# the redirect — the real destination is unknown. Exclude from shared_destinations.
def _merge_risk_tags(snap_json, intel_json) -> list:
    """Union snapshot page tags and scan-level intel tags (e.g. new_domain from WHOIS)."""
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
    for t in a + b:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def shared_destinations(conn: sqlite3.Connection, case_id: int) -> tuple:
    """
    Group scanned URLs by final destination domain.
    Base: latest done scan_run per url_artifact (avoids double-counting re-scanned URLs).
    Risk tags attached where a snapshot exists.

    Returns (resolved, unresolved) tuple of lists sorted by: has_risk_tags desc, post_count desc.
    """
    rows = conn.execute(
        """SELECT sr.final_url,
                  ua.id AS ua_id, ua.original_url,
                  me.id AS post_id, me.platform, me.actor_label,
                  s.risk_tags,
                  sr.intel_risk_tags
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs
               WHERE url_artifact_id = ua.id AND status = 'done'
               ORDER BY id DESC LIMIT 1
           )
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = (
                   SELECT id FROM snapshots WHERE scan_run_id = sr.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND sr.final_url IS NOT NULL""",
        (case_id,),
    ).fetchall()

    seen_urls  = defaultdict(set)
    seen_posts = defaultdict(set)
    data       = defaultdict(lambda: {
        "urls": [], "posts": [], "tag_counts": defaultdict(int), "flagged_url_count": 0,
    })

    for r in rows:
        domain = urlparse(r["final_url"]).hostname or ""
        if not domain:
            continue

        if r["ua_id"] not in seen_urls[domain]:
            seen_urls[domain].add(r["ua_id"])
            url_tags = _merge_risk_tags(r["risk_tags"], r["intel_risk_tags"])
            data[domain]["urls"].append({"original_url": r["original_url"], "risk_tags": url_tags})
            if url_tags:
                data[domain]["flagged_url_count"] += 1
                for tag in url_tags:
                    data[domain]["tag_counts"][tag] += 1

        if r["post_id"] not in seen_posts[domain]:
            seen_posts[domain].add(r["post_id"])
            data[domain]["posts"].append({
                "post_id":  r["post_id"],
                "platform": r["platform"] or "—",
                "actor":    r["actor_label"] or "—",
            })

    resolved = []
    unresolved = []

    for domain, d in data.items():
        entry = {
            "final_domain":      domain,
            "url_count":         len(d["urls"]),
            "post_count":        len(seen_posts[domain]),
            "flagged_url_count": d["flagged_url_count"],
            "tag_counts":        dict(d["tag_counts"]),
            "urls":              d["urls"],
            "posts":             d["posts"],
        }
        if domain in KNOWN_SHORTLINK_DOMAINS:
            unresolved.append(entry)
        else:
            resolved.append(entry)

    resolved.sort(key=lambda x: (-len(x["tag_counts"]), -x["flagged_url_count"], -x["post_count"]))
    return resolved, unresolved


def asn_clusters(conn: sqlite3.Connection, case_id: int) -> list:
    """
    Group landing domains by ASN (hosting provider).
    Uses ASN from snapshot row or from scan_runs after domain intel (no snapshot required).

    Returns list of dicts sorted by url_count desc.
    """
    rows = conn.execute(
        """SELECT sr.final_url,
                  COALESCE(s.final_domain, '') AS snap_domain,
                  COALESCE(s.ip_address, sr.ip_address) AS ip_address,
                  COALESCE(s.asn, sr.asn) AS asn,
                  COALESCE(s.as_org, sr.as_org) AS as_org,
                  COALESCE(s.as_country, sr.as_country) AS as_country,
                  s.risk_tags,
                  sr.intel_risk_tags,
                  ua.id AS ua_id, ua.original_url,
                  me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs
               WHERE url_artifact_id = ua.id AND status = 'done'
               ORDER BY id DESC LIMIT 1
           )
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = (
                   SELECT id FROM snapshots WHERE scan_run_id = sr.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND COALESCE(s.asn, sr.asn) IS NOT NULL""",
        (case_id,),
    ).fetchall()

    seen_urls    = defaultdict(set)
    seen_domains = defaultdict(set)
    seen_posts   = defaultdict(set)
    data         = defaultdict(lambda: {
        "as_org": None, "as_country": None,
        "domains": [], "urls": [], "posts": [],
        "tag_counts": defaultdict(int), "flagged_url_count": 0,
    })

    for r in rows:
        asn = r["asn"]
        if not asn:
            continue

        data[asn]["as_org"]     = r["as_org"]
        data[asn]["as_country"] = r["as_country"]

        fd = r["snap_domain"] or (urlparse(r["final_url"]).hostname or "")
        if not fd:
            continue

        if fd not in seen_domains[asn]:
            seen_domains[asn].add(fd)
            data[asn]["domains"].append({
                "domain":     fd,
                "ip_address": r["ip_address"],
            })

        if r["ua_id"] not in seen_urls[asn]:
            seen_urls[asn].add(r["ua_id"])
            url_tags = _merge_risk_tags(r["risk_tags"], r["intel_risk_tags"])
            data[asn]["urls"].append({"original_url": r["original_url"], "risk_tags": url_tags})
            if url_tags:
                data[asn]["flagged_url_count"] += 1
                for tag in url_tags:
                    data[asn]["tag_counts"][tag] += 1

        if r["post_id"] not in seen_posts[asn]:
            seen_posts[asn].add(r["post_id"])
            data[asn]["posts"].append(r["post_id"])

    result = []
    for asn, d in data.items():
        result.append({
            "asn":               asn,
            "as_org":            d["as_org"] or "—",
            "as_country":        d["as_country"] or "—",
            "domain_count":      len(d["domains"]),
            "url_count":         len(d["urls"]),
            "post_count":        len(d["posts"]),
            "flagged_url_count": d["flagged_url_count"],
            "tag_counts":        dict(d["tag_counts"]),
            "domains":           d["domains"],
            "urls":              d["urls"],
        })

    result.sort(key=lambda x: (-len(x["tag_counts"]), -x["url_count"]))
    return result


def _normalize_param_value(val: str) -> tuple[str, str]:
    """Return (comparison_key, display_value) for a query parameter value.

    Long values (e.g. base64 tokens, JWTs, encrypted affiliate IDs) are
    compared by their SHA-256 prefix so two posts carrying the same opaque
    token still cluster together — but the rendered table shows the hash
    rather than the raw token to avoid blowing out column width.
    """
    if val is None:
        return "", ""
    if len(val) <= PARAM_VALUE_HASH_THRESHOLD:
        return val, val
    digest = hashlib.sha256(val.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"__hash__:{digest}", f"[hash:{digest}…]"


def shared_params(conn: sqlite3.Connection, case_id: int) -> list:
    """
    Find query parameter key+value pairs that appear across 2+ distinct posts.
    Checks both original_url (shortlink) and final_url (destination).

    Empty keys are skipped. Long values are compared by SHA-256 prefix so
    opaque tokens (Shopee affiliate, SendGrid click tracking, JWTs) still
    cluster — see _normalize_param_value().

    Returns list sorted by post_count desc.
    """
    rows = conn.execute(
        """SELECT ua.original_url, sr.final_url, me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    param_posts:   defaultdict[tuple[str, str], set] = defaultdict(set)
    param_urls:    defaultdict[tuple[str, str], set] = defaultdict(set)
    param_domains: defaultdict[tuple[str, str], set] = defaultdict(set)
    param_display: dict[tuple[str, str], str] = {}

    for r in rows:
        for url in (r["original_url"], r["final_url"]):
            if not url:
                continue
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for key, values in parse_qs(parsed.query).items():
                if not key:
                    continue
                for val in values:
                    cmp_val, display_val = _normalize_param_value(val)
                    bucket = (key, cmp_val)
                    param_posts[bucket].add(r["post_id"])
                    param_urls[bucket].add(url)
                    param_domains[bucket].add(domain)
                    param_display.setdefault(bucket, display_val)

    results = []
    for bucket, posts in param_posts.items():
        if len(posts) < 2:
            continue
        k, _cmp = bucket
        owner, purpose_key = identify_param(k)
        domains = sorted(param_domains[bucket])
        if owner == "generic":
            owner = t("param.unattributed_tracker")
            purpose = t(purpose_key) if purpose_key else t("param.unattributed_purpose")
        elif not owner:
            owner = t("param.unrecognized_platform")
            purpose = t("param.unidentified")
        else:
            purpose = t(purpose_key) if purpose_key else ""
        results.append({
            "param_key":   k,
            "param_value": param_display.get(bucket, ""),
            "owner":       owner,
            "purpose":     purpose,
            "domains":     ", ".join(domains),
            "post_count":  len(posts),
            "url_count":   len(param_urls[bucket]),
        })
    results.sort(key=lambda x: (-x["post_count"], -x["url_count"]))
    return results


def shared_param_keys(conn: sqlite3.Connection, case_id: int) -> list:
    """Operator-level coordination signal — sibling to shared_params().

    shared_params() compares (key, value) pairs and catches "same campaign,
    same URL". It misses sophisticated operators who give each victim/post
    a unique tracking ID (e.g. ?aff_id=A1, ?aff_id=A2, ?aff_id=A3 …) — no
    single value clusters even though they're clearly the same system.

    shared_param_keys() compares the KEY itself: a key appearing in many
    posts with several different values, confined to few domains, suggests
    the same operator's backend is on the other end. Thresholds in
    config.py:
      PARAM_KEY_MIN_POSTS   posts must contain the key
      PARAM_KEY_MIN_VALUES  distinct values must be observed
      PARAM_KEY_MAX_DOMAINS domains must not exceed (filters out keys like
                            ?q= that appear everywhere)

    Returns list sorted by distinct_posts desc, distinct_values desc.
    """
    rows = conn.execute(
        """SELECT ua.original_url, sr.final_url, me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    key_posts:    defaultdict[str, set] = defaultdict(set)
    key_values:   defaultdict[str, set] = defaultdict(set)
    key_domains:  defaultdict[str, set] = defaultdict(set)
    # Insertion-ordered list of display values (deduped against key_values).
    key_value_displays: defaultdict[str, list] = defaultdict(list)

    for r in rows:
        for url in (r["original_url"], r["final_url"]):
            if not url:
                continue
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for key, values in parse_qs(parsed.query).items():
                if not key:
                    continue
                for val in values:
                    cmp_val, display_val = _normalize_param_value(val)
                    if cmp_val not in key_values[key]:
                        key_values[key].add(cmp_val)
                        key_value_displays[key].append(display_val)
                    key_posts[key].add(r["post_id"])
                    key_domains[key].add(domain)

    results: list = []
    for key, posts in key_posts.items():
        if len(posts) < PARAM_KEY_MIN_POSTS:
            continue
        if len(key_values[key]) < PARAM_KEY_MIN_VALUES:
            continue
        if len(key_domains[key]) > PARAM_KEY_MAX_DOMAINS:
            continue

        owner, purpose_key = identify_param(key)
        if owner == "generic":
            owner = t("param.unattributed_tracker")
            purpose = t(purpose_key) if purpose_key else t("param.unattributed_purpose")
        elif not owner:
            owner = t("param.unrecognized_platform")
            purpose = t("param.unidentified")
        else:
            purpose = t(purpose_key) if purpose_key else ""

        results.append({
            "param_key":        key,
            "owner":            owner,
            "purpose":          purpose,
            "distinct_posts":   len(posts),
            "distinct_values":  len(key_values[key]),
            "distinct_domains": len(key_domains[key]),
            "top_values":       key_value_displays[key][:5],
            "domains":          sorted(key_domains[key]),
        })

    results.sort(key=lambda x: (-x["distinct_posts"], -x["distinct_values"]))
    return results


# ---------------------------------------------------------------------------
# Account-pattern exploration (descriptive, no thresholds)
# ---------------------------------------------------------------------------
# These functions surface raw distributions for the analyst to read; they
# deliberately do NOT flag posts as "coordinated" or "suspicious", because
# any threshold tuned on a single dataset would overfit to that operator.
# Calibration must be done by the analyst with cross-case context.

# Parameter keys that commonly carry a "content ID" — checked in priority
# order. Empirical: crawlerlanding wrapper rewrites uid → utm_term, so both refer
# to the same underlying content slot.
_CONTENT_ID_KEYS = ("utm_term", "uid", "utm_id", "campaign_id")


def _extract_content_id(url: str | None) -> str | None:
    if not url:
        return None
    qs = parse_qs(urlparse(url).query)
    for key in _CONTENT_ID_KEYS:
        vals = qs.get(key)
        if vals:
            return vals[0]
    return None


def account_content_matrix(conn: sqlite3.Connection, case_id: int) -> dict:
    """Cross-tab of (poster account × content ID) → post count.

    Content ID is extracted from URL parameters in this priority:
      utm_term > uid > utm_id > campaign_id
    Both the original_url and final_url (if scanned) are inspected; the
    first match wins per post.

    Returns:
      {
        "actors":   [actor_label, ...] sorted by total posts desc,
        "contents": [content_id, ...] sorted by total posts desc,
        "matrix":   {(actor, content_id): post_count, ...},
        "actor_totals":   {actor: total_posts, ...},
        "content_totals": {content_id: total_posts, ...},
      }
    """
    rows = conn.execute(
        """SELECT me.id AS post_id,
                  COALESCE(NULLIF(TRIM(me.actor_label), ''), '—') AS actor,
                  ua.original_url, sr.final_url
           FROM message_evidence me
           JOIN url_artifacts ua ON ua.message_id = me.id
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    # Per post, take the first content_id found (avoid double-counting if a
    # message has multiple URLs all carrying the same campaign tag).
    post_content: dict[int, tuple[str, str]] = {}
    for r in rows:
        if r["post_id"] in post_content:
            continue
        cid = _extract_content_id(r["original_url"]) or _extract_content_id(r["final_url"])
        if cid is None:
            continue
        post_content[r["post_id"]] = (r["actor"], cid)

    matrix: dict[tuple[str, str], int] = defaultdict(int)
    actor_totals: dict[str, int] = defaultdict(int)
    content_totals: dict[str, int] = defaultdict(int)
    for actor, cid in post_content.values():
        matrix[(actor, cid)] += 1
        actor_totals[actor] += 1
        content_totals[cid] += 1

    actors = sorted(actor_totals, key=lambda a: (-actor_totals[a], a))
    contents = sorted(content_totals, key=lambda c: (-content_totals[c], c))

    return {
        "actors":         actors,
        "contents":       contents,
        "matrix":         dict(matrix),
        "actor_totals":   dict(actor_totals),
        "content_totals": dict(content_totals),
    }


def content_time_distribution(conn: sqlite3.Connection, case_id: int) -> list:
    """Per-content-ID timing distribution.

    For each content ID with >=2 posts, returns descriptive timing stats:
      content_id, post_count, actor_count,
      first_posted, last_posted, span_minutes,
      min_interval_minutes  (shortest gap between any two consecutive posts),
      median_interval_minutes

    Sorted by post_count desc. NO threshold-based "burst" flag — analyst
    interprets the distribution.
    """
    rows = conn.execute(
        """SELECT me.posted_at,
                  COALESCE(NULLIF(TRIM(me.actor_label), ''), '—') AS actor,
                  ua.original_url, sr.final_url
           FROM message_evidence me
           JOIN url_artifacts ua ON ua.message_id = me.id
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    # content_id -> list of (datetime, actor)
    per_content: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for r in rows:
        cid = _extract_content_id(r["original_url"]) or _extract_content_id(r["final_url"])
        if cid is None or not r["posted_at"]:
            continue
        ts = _parse_post_timestamp(r["posted_at"])
        if ts is None:
            continue
        per_content[cid].append((ts, r["actor"]))

    out: list[dict] = []
    for cid, events in per_content.items():
        if len(events) < 2:
            continue
        events.sort(key=lambda e: e[0])
        times = [e[0] for e in events]
        actors = {e[1] for e in events}
        intervals = [
            (times[i + 1] - times[i]).total_seconds() / 60
            for i in range(len(times) - 1)
        ]
        intervals.sort()
        median = intervals[len(intervals) // 2] if intervals else 0
        span = (times[-1] - times[0]).total_seconds() / 60
        out.append({
            "content_id":             cid,
            "post_count":             len(events),
            "actor_count":            len(actors),
            "first_posted":           times[0].strftime("%Y-%m-%d %H:%M"),
            "last_posted":            times[-1].strftime("%Y-%m-%d %H:%M"),
            "span_minutes":           int(span),
            "min_interval_minutes":   round(min(intervals), 1),
            "median_interval_minutes": round(median, 1),
        })

    out.sort(key=lambda x: (-x["post_count"], -x["actor_count"]))
    return out


# Common posted_at formats observed in CSV imports: "2026-03-24 08:48"
# (no seconds), ISO with 'T', and full ISO with seconds.
_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
)


def _parse_post_timestamp(s: str) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    for fmt in _TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Shared TLS certificates
# ---------------------------------------------------------------------------
# OpenSSL textual date: "Apr 27 00:00:00 2026 GMT". Single-digit days come back
# with a doubled space ("Apr  7 ...") so we normalise whitespace before parsing.
_OPENSSL_DATE_FORMATS = (
    "%b %d %H:%M:%S %Y %Z",
    "%b %d %H:%M:%S %Y",
)


def _parse_openssl_date(s: str | None) -> datetime | None:
    if not s:
        return None
    normalised = " ".join(s.split())
    for fmt in _OPENSSL_DATE_FORMATS:
        try:
            return datetime.strptime(normalised, fmt)
        except (ValueError, TypeError):
            continue
    return None


def _issuer_label(issuer_dict: dict | None) -> str:
    """Friendly issuer label from a cert issuer DN dict."""
    if not isinstance(issuer_dict, dict):
        return ""
    org = issuer_dict.get("organizationName") or ""
    cn = issuer_dict.get("commonName") or ""
    if isinstance(org, list):
        org = org[0] if org else ""
    if isinstance(cn, list):
        cn = cn[0] if cn else ""
    if org and cn and org != cn:
        return f"{org} ({cn})"
    return org or cn or ""


def shared_certificates(conn: sqlite3.Connection, case_id: int) -> dict:
    """
    Group landing URLs by TLS certificate evidence.

    Returns a dict with two cluster lists:
      by_cert    : a single cert (same issuer + serialNumber) covers 2+ distinct
                   landing domains in this case. Strongest signal — same server /
                   same operator.
      by_issuance: 2+ distinct certs were issued within a 24-hour window covering
                   2+ distinct landing domains in this case. Suggests batch
                   provisioning, even if certs are not literally the same.

    Cluster order: by_cert sorted by domain_count desc; by_issuance sorted by
    domain_count desc then cert_count desc.
    """
    rows = conn.execute(
        """SELECT sr.tls_info_json, sr.final_url,
                  ua.id AS ua_id,
                  me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs
               WHERE url_artifact_id = ua.id AND status = 'done'
               ORDER BY id DESC LIMIT 1
           )
           WHERE ua.case_id = ?
             AND sr.tls_info_json IS NOT NULL
             AND TRIM(sr.tls_info_json) != ''""",
        (case_id,),
    ).fetchall()

    cert_data: dict[tuple[str, str], dict] = {}

    for r in rows:
        try:
            tls = json.loads(r["tls_info_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(tls, dict):
            continue
        serial = (tls.get("serialNumber") or "").strip()
        if not serial:
            continue
        domain = (urlparse(r["final_url"] or "").hostname or "").lower()
        if not domain:
            continue
        issuer = _issuer_label(tls.get("issuer"))
        key = (issuer, serial)

        entry = cert_data.get(key)
        if entry is None:
            entry = {
                "issuer":     issuer,
                "serial":     serial,
                "not_before": tls.get("notBefore") or "",
                "not_after":  tls.get("notAfter") or "",
                "san_list":   tls.get("subjectAltName") or [],
                "domains":    set(),
                "urls":       set(),
                "posts":      set(),
            }
            cert_data[key] = entry
        entry["domains"].add(domain)
        entry["urls"].add(r["ua_id"])
        entry["posts"].add(r["post_id"])

    # ── Cluster A: same cert covering 2+ distinct domains ──────────────
    by_cert: list[dict] = []
    for entry in cert_data.values():
        if len(entry["domains"]) < 2:
            continue
        by_cert.append({
            "issuer":       entry["issuer"] or "—",
            "serial":       entry["serial"],
            "not_before":   entry["not_before"],
            "not_after":    entry["not_after"],
            "san_count":    len(entry["san_list"]),
            "domains":      sorted(entry["domains"]),
            "domain_count": len(entry["domains"]),
            "url_count":    len(entry["urls"]),
            "post_count":   len(entry["posts"]),
        })
    by_cert.sort(key=lambda x: (-x["domain_count"], -x["url_count"]))

    # ── Cluster B: distinct certs issued within a 24h window ───────────
    cert_records = []
    for entry in cert_data.values():
        nb = _parse_openssl_date(entry["not_before"])
        if nb is None:
            continue
        cert_records.append({
            "issuer":         entry["issuer"] or "—",
            "serial":         entry["serial"],
            "not_before_dt":  nb,
            "not_before_str": entry["not_before"],
            "domains":        sorted(entry["domains"]),
        })
    cert_records.sort(key=lambda x: x["not_before_dt"])

    window_clusters: list[list[dict]] = []
    current: list[dict] = []
    for rec in cert_records:
        if not current:
            current = [rec]
            continue
        if rec["not_before_dt"] - current[0]["not_before_dt"] <= timedelta(hours=24):
            current.append(rec)
        else:
            if len(current) >= 2:
                window_clusters.append(current)
            current = [rec]
    if len(current) >= 2:
        window_clusters.append(current)

    by_issuance: list[dict] = []
    for cluster in window_clusters:
        all_domains: set[str] = set()
        for rec in cluster:
            all_domains.update(rec["domains"])
        if len(all_domains) < 2:
            continue
        issuers = sorted({rec["issuer"] for rec in cluster})
        by_issuance.append({
            "window_start": cluster[0]["not_before_str"],
            "window_end":   cluster[-1]["not_before_str"],
            "cert_count":   len(cluster),
            "domain_count": len(all_domains),
            "domains":      sorted(all_domains),
            "issuers":      ", ".join(issuers),
        })
    by_issuance.sort(key=lambda x: (-x["domain_count"], -x["cert_count"]))

    return {
        "by_cert":     by_cert,
        "by_issuance": by_issuance,
    }


def certificate_authorities(conn: sqlite3.Connection, case_id: int) -> list:
    """List CAs that signed TLS certs for the case's landing domains.

    Provider-lens companion to shared_certificates(): rather than flagging
    cross-domain reuse, this just enumerates which CAs are involved and
    how widely. Useful for accountability mapping (which CA's policies
    apply to this campaign).

    Returns list of dicts sorted by domain_count desc:
      issuer, domain_count, url_count, cert_count, domains, earliest_notBefore
    """
    rows = conn.execute(
        """SELECT sr.tls_info_json, sr.final_url, ua.id AS ua_id
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs
               WHERE url_artifact_id = ua.id AND status = 'done'
               ORDER BY id DESC LIMIT 1
           )
           WHERE ua.case_id = ?
             AND sr.tls_info_json IS NOT NULL
             AND TRIM(sr.tls_info_json) != ''""",
        (case_id,),
    ).fetchall()

    # issuer_label -> {serials: set, domains: set, urls: set, earliest: datetime|None}
    by_issuer: dict[str, dict] = {}
    for r in rows:
        try:
            tls = json.loads(r["tls_info_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(tls, dict):
            continue
        issuer = _issuer_label(tls.get("issuer")) or "—"
        serial = (tls.get("serialNumber") or "").strip()
        domain = (urlparse(r["final_url"] or "").hostname or "").lower()
        if not domain:
            continue
        nb = _parse_openssl_date(tls.get("notBefore"))

        entry = by_issuer.setdefault(issuer, {
            "serials": set(),
            "domains": set(),
            "urls":    set(),
            "earliest": None,
        })
        if serial:
            entry["serials"].add(serial)
        entry["domains"].add(domain)
        entry["urls"].add(r["ua_id"])
        if nb is not None and (entry["earliest"] is None or nb < entry["earliest"]):
            entry["earliest"] = nb

    out: list[dict] = []
    for issuer, e in by_issuer.items():
        out.append({
            "issuer":              issuer,
            "domain_count":        len(e["domains"]),
            "url_count":           len(e["urls"]),
            "cert_count":          len(e["serials"]),
            "domains":             sorted(e["domains"]),
            "earliest_notBefore":  (e["earliest"].strftime("%Y-%m-%d") if e["earliest"] else ""),
        })
    out.sort(key=lambda x: (-x["domain_count"], -x["url_count"]))
    return out


def shared_tracking_ids(conn: sqlite3.Connection, case_id: int) -> list:
    """Cross-domain tracking-ID clusters — strongest operator-attribution signal.

    Reads tracking_ids_json from each snapshot (populated by
    fingerprints.extract_tracking_ids_from_file at capture time) and finds
    every (platform, ID) pair that appears on 2 or more distinct landing
    domains within this case.

    A pixel/GA/GTM ID belongs to exactly one underlying account. When the
    same ID is embedded in HTML across multiple landing domains, those
    domains are tracked from the same operator's account — a very hard
    signal to spoof and immune to Cloudflare/CDN fronting because it lives
    in the page itself.

    Returns list sorted by domain_count desc, then by platform name:
      [{platform, tracking_id, domain_count, url_count, post_count, domains}]
    Singletons (ID seen on only one domain) are excluded.
    """
    rows = conn.execute(
        """SELECT s.tracking_ids_json,
                  COALESCE(s.final_domain, '') AS final_domain,
                  ua.id AS ua_id,
                  me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs
               WHERE url_artifact_id = ua.id AND status = 'done'
               ORDER BY id DESC LIMIT 1
           )
           JOIN snapshots s ON s.id = (
               SELECT id FROM snapshots WHERE scan_run_id = sr.id
               ORDER BY id DESC LIMIT 1
           )
           WHERE ua.case_id = ?
             AND s.tracking_ids_json IS NOT NULL
             AND TRIM(s.tracking_ids_json) != ''""",
        (case_id,),
    ).fetchall()

    # (platform, tracking_id) -> {domains, urls, posts}
    by_id: dict[tuple[str, str], dict] = {}
    for r in rows:
        try:
            ids_by_platform = json.loads(r["tracking_ids_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(ids_by_platform, dict):
            continue
        domain = (r["final_domain"] or "").lower()
        if not domain:
            continue
        for platform, ids in ids_by_platform.items():
            if not isinstance(ids, list):
                continue
            for ident in ids:
                if not ident:
                    continue
                key = (platform, ident)
                entry = by_id.setdefault(key, {
                    "domains": set(),
                    "urls":    set(),
                    "posts":   set(),
                })
                entry["domains"].add(domain)
                entry["urls"].add(r["ua_id"])
                entry["posts"].add(r["post_id"])

    out: list[dict] = []
    for (platform, ident), e in by_id.items():
        if len(e["domains"]) < 2:
            continue
        out.append({
            "platform":     platform,
            "tracking_id":  ident,
            "domain_count": len(e["domains"]),
            "url_count":    len(e["urls"]),
            "post_count":   len(e["posts"]),
            "domains":      sorted(e["domains"]),
        })
    out.sort(key=lambda x: (-x["domain_count"], x["platform"]))
    return out


def ad_tracking_platforms(conn: sqlite3.Connection, case_id: int) -> list:
    """List ad / analytics platforms with footprint on this case's URLs.

    Provider-lens companion to shared_params(): rather than flagging
    cross-post reuse, this enumerates which platforms have signal on
    the case's URLs based on identified URL parameters.

    LIMITATION: only sees signals that travel in the URL itself
    (utm_*, fbclid, gclid, af_*, _kx, …). Page-embedded tracking
    (Meta Pixel ID in HTML, GA Property ID, GTM container) requires
    HTML scraping which is a separate roadmap stage.

    "generic" entries (uid, aff_id, ref, etc.) are surfaced under the
    "Unattributed Tracker" label — known tracking semantics, unknown
    operator.

    Returns list sorted by url_count desc:
      owner, param_keys (sorted), url_count, domain_count, post_count, domains
    """
    rows = conn.execute(
        """SELECT ua.id AS ua_id, me.id AS post_id,
                  ua.original_url, sr.final_url
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    # owner_label -> {param_keys: set, urls: set(ua_id), posts: set, domains: set}
    by_owner: dict[str, dict] = {}

    for r in rows:
        observed_owners: set[tuple[str, str]] = set()  # (owner_label, param_key)
        for url in (r["original_url"], r["final_url"]):
            if not url:
                continue
            parsed = urlparse(url)
            domain = (parsed.hostname or "").lower()
            if not domain:
                continue
            for key, _vals in parse_qs(parsed.query).items():
                if not key:
                    continue
                owner, _purpose_key = identify_param(key)
                if not owner:
                    continue  # truly unknown — skip
                label = (
                    t("param.unattributed_tracker")
                    if owner == "generic" else owner
                )
                observed_owners.add((label, key))
                entry = by_owner.setdefault(label, {
                    "param_keys": set(),
                    "urls":       set(),
                    "posts":      set(),
                    "domains":    set(),
                })
                entry["param_keys"].add(key)
                entry["urls"].add(r["ua_id"])
                entry["posts"].add(r["post_id"])
                entry["domains"].add(domain)

    out: list[dict] = []
    for label, e in by_owner.items():
        out.append({
            "owner":        label,
            "param_keys":   sorted(e["param_keys"]),
            "url_count":    len(e["urls"]),
            "post_count":   len(e["posts"]),
            "domain_count": len(e["domains"]),
            "domains":      sorted(e["domains"]),
        })
    out.sort(key=lambda x: (-x["url_count"], -x["domain_count"]))
    return out
