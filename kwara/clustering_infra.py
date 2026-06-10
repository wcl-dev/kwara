"""Infrastructure-layer clustering across a case.

Functions in this module operate on the host/cert/HTML-tracking layer:
which ASNs host the landing domains, which TLS certs they share, which
HTML-embedded pixel IDs cross multiple domains. Pure read-only on the
DB — no third-party network calls, no i18n.

Public surface:
  asn_clusters             ASN clusters across landing domains
  shared_certificates      same-cert and same-window-issuance clusters
  certificate_authorities  CAs ranked by domain footprint
  shared_tracking_ids      same Pixel/GA/GTM ID across multiple domains
  ad_tracking_platforms    URL params + HTML pixels merged per platform
  shared_ad_accounts       ads.txt DIRECT accounts + identical-template
                           clusters (frequency-weighted: manager vs operator)

Companion module: clustering_url (URL/post-level clustering).
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse

import ipaddress

from config import ADS_TXT_MANAGER_BREADTH, HAR_NOISE_HOSTS
from param_attribution import (
    PLATFORM_ADS_TXT_SELLER,
    PLATFORM_GOOGLE_ADS,
    PLATFORM_GOOGLE_ADSENSE,
    PLATFORM_GOOGLE_ANALYTICS,
    PLATFORM_GOOGLE_TAG_MANAGER,
    PLATFORM_HOTJAR,
    PLATFORM_LINE_TAG,
    PLATFORM_META_FACEBOOK,
    PLATFORM_META_FACEBOOK_PAGE,
    PLATFORM_MICROSOFT_CLARITY,
    PLATFORM_TIKTOK_ADS,
    PLATFORM_X_TWITTER,
    classify_owner,
    identify_param,
    merge_risk_tags,
)
from sql import LATEST_DONE_SCAN_RUN, latest_usable_snapshot


def _is_direct_ip(host: str) -> bool:
    """True if host looks like a literal IPv4/IPv6 address rather than DNS."""
    try:
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


def _is_noise_endpoint(host: str) -> bool:
    """Common CDNs / fonts / analytics — legitimate baseline web infra
    that virtually every page loads. Filtered out of cross-domain
    third-party aggregation.

    Matches both exact hostname AND any subdomain of an entry in
    config.HAR_NOISE_HOSTS — so listing 'doubleclick.net' also filters
    'cm.g.doubleclick.net', 'googleads.g.doubleclick.net' etc.
    """
    h = host.lower()
    for noise in HAR_NOISE_HOSTS:
        if h == noise or h.endswith("." + noise):
            return True
    return False


def asn_clusters(conn: sqlite3.Connection, case_id: int) -> list:
    """
    Group landing domains by ASN (hosting provider).
    Uses ASN from snapshot row or from scan_runs after domain intel (no snapshot required).

    Returns list of dicts sorted by url_count desc.
    """
    rows = conn.execute(
        f"""SELECT sr.final_url,
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
           JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
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
            url_tags = merge_risk_tags(r["risk_tags"], r["intel_risk_tags"])
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


# ---------------------------------------------------------------------------
# TLS certificate clustering
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
        f"""SELECT sr.tls_info_json, sr.final_url,
                  ua.id AS ua_id,
                  me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
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
        f"""SELECT sr.tls_info_json, sr.final_url, ua.id AS ua_id
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
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
        f"""SELECT s.tracking_ids_json,
                  COALESCE(s.final_domain, '') AS final_domain,
                  ua.id AS ua_id,
                  me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
           -- Pick the latest *usable* snapshot, not just latest-by-id
           -- (codex review fix #2). A bad re-snapshot (Cloudflare challenge,
           -- timeout, empty HTML) on top of an earlier good one previously
           -- erased the earlier attribution silently.
           JOIN snapshots s ON s.id = {latest_usable_snapshot("tracking_ids_json")}
           WHERE ua.case_id = ?""",
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


# Map fingerprints.py platform labels to the canonical platform_id used by
# identify_param(), so URL-param and HTML-embedded signals fold into the
# same row of the providers table. Symbol references (PLATFORM_*) make
# typos loud (NameError) instead of silent ("merged into wrong bucket").
_HTML_PLATFORM_TO_PLATFORM_ID: dict[str, str] = {
    "Meta Pixel":            PLATFORM_META_FACEBOOK,
    "Google Analytics 4":    PLATFORM_GOOGLE_ANALYTICS,
    "Google Analytics (UA)": PLATFORM_GOOGLE_ANALYTICS,
    "Google Tag Manager":    PLATFORM_GOOGLE_TAG_MANAGER,  # no URL-param equivalent
    "Google Ads":            PLATFORM_GOOGLE_ADS,
    "TikTok Pixel":          PLATFORM_TIKTOK_ADS,
    # Phase 3 ticket D — second batch
    "Microsoft Clarity":     PLATFORM_MICROSOFT_CLARITY,
    "Hotjar":                PLATFORM_HOTJAR,
    "LINE Tag":              PLATFORM_LINE_TAG,
    "X / Twitter Pixel":     PLATFORM_X_TWITTER,
    # Phase 4 follow-up: HTML-only signals (no URL-param equivalent)
    "Google AdSense":        PLATFORM_GOOGLE_ADSENSE,
    "Meta Facebook Page":    PLATFORM_META_FACEBOOK_PAGE,
}


def ad_tracking_platforms(conn: sqlite3.Connection, case_id: int) -> list:
    """List ad / analytics platforms with footprint on this case's URLs.

    Combines two signal sources:
      url_param      — query parameters identified by identify_param()
                       (utm_*, fbclid, gclid, af_*, _kx, …)
      html_embedded  — tracking IDs extracted from snapshot HTML by
                       fingerprints.extract_tracking_ids()
                       (Pixel ID, GA property, GTM container, …)

    Each row reports its `signal_source`: 'url_param' | 'html_embedded' |
    'both'. 'both' is the strongest — independent confirmation that the
    platform's account interacts with the URL.

    "generic" URL-param entries (uid, aff_id, ref, etc.) are surfaced
    under the OWNER_KIND_GENERIC label — known tracking semantics,
    unknown operator. View layer translates owner_kind at render time.

    Returns list sorted by url_count desc, with 'both' rows breaking
    ties before html-only rows before url-only rows.
    """
    rows = conn.execute(
        f"""SELECT ua.id AS ua_id, me.id AS post_id,
                  ua.original_url, sr.final_url,
                  s.tracking_ids_json,
                  COALESCE(s.final_domain, '') AS snap_domain
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           -- Pick the latest *usable* snapshot (codex fix #2). HTML pixel
           -- signals only count when the capture actually succeeded; a later
           -- failed re-snapshot shouldn't shadow an earlier good one.
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = {latest_usable_snapshot("tracking_ids_json")}
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    by_platform: dict[str, dict] = {}

    def _entry(platform_id: str) -> dict:
        return by_platform.setdefault(platform_id, {
            "param_keys":    set(),
            "tracking_ids":  set(),
            "urls":          set(),
            "posts":         set(),
            "domains":       set(),
            "has_url":       False,
            "has_html":      False,
            # Per-source provenance for the same-evidence intersection check
            # used to compute signal_source — see fix #3.
            "url_uas":       set(),
            "url_domains":   set(),
            "html_uas":      set(),
            "html_domains":  set(),
        })

    for r in rows:
        # ── URL parameter signals ──────────────────────────────
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
                platform_id, _purpose_key = identify_param(key)
                if not platform_id:
                    continue  # truly unknown — skip from provider lens
                e = _entry(platform_id)
                e["param_keys"].add(key)
                e["urls"].add(r["ua_id"])
                e["posts"].add(r["post_id"])
                e["domains"].add(domain)
                e["has_url"] = True
                e["url_uas"].add(r["ua_id"])
                e["url_domains"].add(domain)

        # ── HTML-embedded tracking ID signals ──────────────────
        if r["tracking_ids_json"]:
            try:
                ids_by_platform = json.loads(r["tracking_ids_json"])
            except (ValueError, TypeError):
                ids_by_platform = None
            if isinstance(ids_by_platform, dict):
                snap_domain = (r["snap_domain"] or "").lower()
                for fp_label, ids in ids_by_platform.items():
                    if not isinstance(ids, list):
                        continue
                    # Unknown fingerprints labels fall back to themselves so
                    # rare/new platforms still appear in the table.
                    platform_id = _HTML_PLATFORM_TO_PLATFORM_ID.get(fp_label, fp_label)
                    e = _entry(platform_id)
                    for ident in ids:
                        if ident:
                            e["tracking_ids"].add(ident)
                    e["urls"].add(r["ua_id"])
                    e["posts"].add(r["post_id"])
                    if snap_domain:
                        e["domains"].add(snap_domain)
                    e["has_html"] = True
                    e["html_uas"].add(r["ua_id"])
                    if snap_domain:
                        e["html_domains"].add(snap_domain)

    _SOURCE_RANK = {
        "both":              0,
        "mixed_nonoverlap":  1,
        "html_embedded":     2,
        "url_param":         3,
    }
    out: list[dict] = []
    for platform_id, e in by_platform.items():
        # signal_source semantics (codex review fix #3 + follow-up):
        #   both              URL and HTML evidence intersect on at least one
        #                     ua_id or domain — independent confirmation.
        #   mixed_nonoverlap  URL and HTML evidence both present in this case
        #                     but never on the same ua_id or domain. Weaker
        #                     than 'both' but still notable; kept as a
        #                     distinct label so the UI doesn't have to lie
        #                     in either direction.
        #   html_embedded     HTML pixel only.
        #   url_param         URL parameter only.
        url_overlaps_html = bool(
            (e["url_uas"] & e["html_uas"])
            or (e["url_domains"] & e["html_domains"])
        )
        if e["has_url"] and e["has_html"]:
            source = "both" if url_overlaps_html else "mixed_nonoverlap"
        elif e["has_html"]:
            source = "html_embedded"
        else:
            source = "url_param"
        out.append({
            "platform_id":   platform_id,
            "owner_kind":    classify_owner(platform_id),
            "signal_source": source,
            "param_keys":    sorted(e["param_keys"]),
            "tracking_ids":  sorted(e["tracking_ids"]),
            "url_count":     len(e["urls"]),
            "post_count":    len(e["posts"]),
            "domain_count":  len(e["domains"]),
            "domains":       sorted(e["domains"]),
        })
    out.sort(key=lambda x: (-x["url_count"], -x["domain_count"], _SOURCE_RANK[x["signal_source"]]))
    return out


def shared_endpoints(conn: sqlite3.Connection, case_id: int) -> list:
    """Cross-domain third-party endpoint aggregation (Phase 3 ticket A).

    For each landing domain in the case, read the snapshot's request
    hostnames (snapshots.request_domains_json — populated by Playwright
    captures only; lightweight HTTP fetches contribute nothing here).
    Find endpoints called by 2 or more distinct landing domains, and
    drop noise endpoints listed in config.HAR_NOISE_HOSTS.

    Direct-IP endpoints (no DNS hostname) are flagged ``is_direct_ip``
    — particularly suspicious because they typically bypass CDN/proxy
    routing and reveal real backend infrastructure.

    Snapshot selection follows the same latest-usable pattern as
    shared_tracking_ids (codex review fix #2): newest snapshot per
    scan_run with capture_status='ok' and a non-empty
    request_domains_json. A later failed re-capture doesn't erase
    earlier good data.

    Returns list sorted by domain_count desc, with direct-IP entries
    floated to the top of each tier.
    """
    rows = conn.execute(
        f"""SELECT s.request_domains_json,
                  COALESCE(s.final_domain, '') AS final_domain
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
           JOIN snapshots s ON s.id = {latest_usable_snapshot("request_domains_json")}
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    endpoint_to_landings: dict[str, set] = defaultdict(set)

    for r in rows:
        landing = (r["final_domain"] or "").lower()
        if not landing:
            continue
        try:
            domains = json.loads(r["request_domains_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(domains, list):
            continue
        for raw in domains:
            host = (raw or "").strip().lower()
            if not host:
                continue
            # Skip the landing's own domain (and immediate subdomains) —
            # not third-party.
            if host == landing or host.endswith("." + landing):
                continue
            if _is_noise_endpoint(host):
                continue
            endpoint_to_landings[host].add(landing)

    out: list[dict] = []
    for endpoint, landings in endpoint_to_landings.items():
        if len(landings) < 2:
            continue
        out.append({
            "endpoint":     endpoint,
            "domain_count": len(landings),
            "domains":      sorted(landings),
            "is_direct_ip": _is_direct_ip(endpoint),
        })
    # Sort: domain_count desc, direct-IP first within tier (flag = True
    # surfaces these as priority signals — direct IPs reveal real
    # backend infrastructure that bypasses CDN routing).
    out.sort(key=lambda x: (-x["domain_count"], not x["is_direct_ip"], x["endpoint"]))
    return out


def shared_ad_accounts(conn: sqlite3.Connection, case_id: int) -> dict:
    """Cluster landing domains by their ads.txt monetisation evidence.

    Reads scan_runs.ads_txt_json (Phase 8, fetched by adstxt.py). Returns
    two cluster lists:

      by_account  : a DIRECT (adsystem, seller_id) account appears on 2+
                    distinct domains in this case. Frequency-weighted via
                    `tier`:
                      operator — appears on a *rare subset* of the case's
                                 ads.txt domains (breadth_ratio <
                                 ADS_TXT_MANAGER_BREADTH). Strong: a shared
                                 money account on few domains.
                      manager  — appears on most/all domains. Weak: this is
                                 a shared monetisation manager / reseller
                                 network templated across client sites, NOT
                                 a same-operator signal.
      by_template : 2+ domains served a byte-identical ads.txt (same raw
                    sha256). Strongest operator signal — a shared
                    monetisation template.

    Only DIRECT lines feed by_account (RESELLER is downstream supply-chain
    noise, not the publisher's own money account). `case_domains` (distinct
    domains carrying a parseable ads.txt) is the breadth denominator.

    by_account sorted operator-tier-first then domain_count desc; by_template
    sorted domain_count desc. platform_id on every by_account row is the
    canonical PLATFORM_ADS_TXT_SELLER (contract 1).
    """
    rows = conn.execute(
        f"""SELECT sr.ads_txt_json, sr.final_url,
                  ua.id AS ua_id, me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
           WHERE ua.case_id = ?
             AND sr.ads_txt_json IS NOT NULL
             AND TRIM(sr.ads_txt_json) != ''""",
        (case_id,),
    ).fetchall()

    # (adsystem, seller_id) → {domains, urls, posts}
    account_data: dict[tuple[str, str], dict] = {}
    # raw_sha256 → {domains}
    template_data: dict[str, set] = defaultdict(set)
    # distinct domains with a parseable ads.txt (breadth denominator)
    case_domains: set[str] = set()

    for r in rows:
        try:
            ads = json.loads(r["ads_txt_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(ads, dict):
            continue
        domain = (urlparse(r["final_url"] or "").hostname or "").lower()
        if not domain:
            continue

        # Template clustering keys off the raw sha256 regardless of parse
        # status (a 403 still has a body hash, but only count domains that
        # actually served ads.txt content — status ok with records).
        records = ads.get("records") or []
        if ads.get("status") == "ok" and records:
            case_domains.add(domain)
            sha = ads.get("raw_sha256")
            if sha:
                template_data[sha].add(domain)

        for rec in records:
            if (rec.get("relationship") or "").upper() != "DIRECT":
                continue
            adsystem = (rec.get("adsystem") or "").lower()
            seller_id = (rec.get("seller_id") or "").strip()
            if not adsystem or not seller_id:
                continue
            key = (adsystem, seller_id)
            entry = account_data.get(key)
            if entry is None:
                entry = {"domains": set(), "urls": set(), "posts": set()}
                account_data[key] = entry
            entry["domains"].add(domain)
            entry["urls"].add(r["ua_id"])
            entry["posts"].add(r["post_id"])

    denom = len(case_domains) or 1

    # ── Cluster A: shared DIRECT accounts (frequency-weighted) ─────────
    by_account: list[dict] = []
    for (adsystem, seller_id), entry in account_data.items():
        if len(entry["domains"]) < 2:
            continue
        domain_count = len(entry["domains"])
        breadth_ratio = domain_count / denom
        tier = "manager" if breadth_ratio >= ADS_TXT_MANAGER_BREADTH else "operator"
        by_account.append({
            "platform_id":   PLATFORM_ADS_TXT_SELLER,
            "adsystem":      adsystem,
            "seller_id":     seller_id,
            "tier":          tier,
            "breadth_ratio": round(breadth_ratio, 3),
            "domains":       sorted(entry["domains"]),
            "domain_count":  domain_count,
            "url_count":     len(entry["urls"]),
            "post_count":    len(entry["posts"]),
        })
    # operator-tier first (the real attribution signal), then domain_count.
    by_account.sort(key=lambda x: (x["tier"] != "operator", -x["domain_count"],
                                   x["adsystem"], x["seller_id"]))

    # ── Cluster B: byte-identical ads.txt templates ───────────────────
    by_template: list[dict] = []
    for sha, domains in template_data.items():
        if len(domains) < 2:
            continue
        by_template.append({
            "sha256":       sha,
            "sha256_short": sha[:12],
            "domains":      sorted(domains),
            "domain_count": len(domains),
        })
    by_template.sort(key=lambda x: (-x["domain_count"], x["sha256"]))

    return {
        "by_account":  by_account,
        "by_template": by_template,
    }
