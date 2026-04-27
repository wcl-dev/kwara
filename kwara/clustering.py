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
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

from config import KNOWN_SHORTLINK_DOMAINS
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
_PARAM_PREFIX: list[tuple[str, str, str]] = [
    ("utm_",  "Google Analytics", "param.utm_tracking"),
    ("hsa_",  "HubSpot",          "param.hubspot_ad"),
    ("mc_",   "Mailchimp",        "param.mailchimp_tracking"),
    ("fb_",   "Meta / Facebook",  "param.facebook_tracking"),
    ("_ga",   "Google Analytics",  "param.ga_tracking"),
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


def shared_params(conn: sqlite3.Connection, case_id: int) -> list:
    """
    Find query parameter key+value pairs that appear across 2+ distinct posts.
    Checks both original_url (shortlink) and final_url (destination).

    Filters out noise: single-char keys, values > 100 chars.
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

    param_posts   = defaultdict(set)
    param_urls    = defaultdict(set)
    param_domains = defaultdict(set)

    for r in rows:
        for url in (r["original_url"], r["final_url"]):
            if not url:
                continue
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            for key, values in parse_qs(parsed.query).items():
                if len(key) <= 1:
                    continue
                for val in values:
                    if len(val) > 100:
                        continue
                    param_posts[(key, val)].add(r["post_id"])
                    param_urls[(key, val)].add(url)
                    param_domains[(key, val)].add(domain)

    results = []
    for (k, v), posts in param_posts.items():
        if len(posts) < 2:
            continue
        owner, purpose_key = identify_param(k)
        domains = sorted(param_domains[(k, v)])
        if not owner or owner == "generic":
            owner = t("param.unrecognized_platform")
            purpose = t("param.unidentified")
        else:
            purpose = t(purpose_key) if purpose_key else ""
        results.append({
            "param_key":   k,
            "param_value": v,
            "owner":       owner,
            "purpose":     purpose,
            "domains":     ", ".join(domains),
            "post_count":  len(posts),
            "url_count":   len(param_urls[(k, v)]),
        })
    results.sort(key=lambda x: (-x["post_count"], -x["url_count"]))
    return results


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
