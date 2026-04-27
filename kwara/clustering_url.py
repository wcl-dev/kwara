"""URL- and account-level clustering across a case.

Functions in this module operate on the URL/post layer of evidence:
which destination domains URLs resolve to, which query parameters
repeat, which actors share which content. Pure read-only on the DB —
no third-party network calls, no i18n.

Public surface:
  shared_destinations         landing-domain clusters (with risk tags)
  shared_params               recurring (key, value) param pairs across posts
  shared_param_keys           operator-level: same key, varying values
  account_content_matrix      poster × content_id pivot
  content_time_distribution   per-content_id timing distribution

Companion module: clustering_infra (TLS, ASN, HTML pixel signals).
"""
from __future__ import annotations

import hashlib
import sqlite3
from collections import defaultdict
from datetime import datetime
from urllib.parse import parse_qs, urlparse

from config import (
    KNOWN_SHORTLINK_DOMAINS,
    PARAM_KEY_MAX_DOMAINS,
    PARAM_KEY_MIN_POSTS,
    PARAM_KEY_MIN_VALUES,
    PARAM_VALUE_HASH_THRESHOLD,
)
from param_attribution import (
    classify_owner,
    identify_param,
    merge_risk_tags,
)


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
            url_tags = merge_risk_tags(r["risk_tags"], r["intel_risk_tags"])
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


def wrapper_relationships(conn: sqlite3.Connection, case_id: int) -> list:
    """Aggregate (original_domain → final_domain) pairs where the redirect
    chain crosses domains.

    A "wrapper" here means: the URL the analyst received in a post landed
    on a *different* domain after the scan resolved its redirect chain.
    Picread → visitorlanding is the canonical example: posters share
    ``crawlerlanding.example/redacted139/X?uid=…`` but every URL ends up on ``visitorlanding.example``
    after a 2-hop redirect, with the ``uid`` parameter renamed to
    ``utm_term``. Without surfacing this, an analyst has to manually
    correlate ``url_artifacts.original_url`` against
    ``scan_runs.final_url`` URL-by-URL.

    Base: latest done scan_run per url_artifact (matches shared_destinations).

    Returns list sorted by url_count desc, then post_count desc:
      [{
        "original_domain": "crawlerlanding.example",
        "final_domain":    "visitorlanding.example",
        "url_count":       21,        # distinct url_artifacts
        "post_count":      21,        # distinct messages
        "min_hops":        2,
        "max_hops":        2,
        "sample_urls":     [first 5 distinct original_urls],
      }]
    """
    rows = conn.execute(
        """SELECT ua.id AS ua_id, ua.original_url,
                  sr.final_url, sr.hop_count,
                  me.id AS post_id
           FROM url_artifacts ua
           JOIN message_evidence me ON me.id = ua.message_id
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs
               WHERE url_artifact_id = ua.id AND status = 'done'
               ORDER BY id DESC LIMIT 1
           )
           WHERE ua.case_id = ? AND sr.final_url IS NOT NULL""",
        (case_id,),
    ).fetchall()

    by_pair: dict[tuple[str, str], dict] = {}

    for r in rows:
        original = (urlparse(r["original_url"] or "").hostname or "").lower()
        final = (urlparse(r["final_url"] or "").hostname or "").lower()
        if not original or not final or original == final:
            continue

        key = (original, final)
        entry = by_pair.setdefault(key, {
            "ua_ids":      set(),
            "post_ids":    set(),
            "hops":        [],
            "sample_urls": [],
        })
        entry["ua_ids"].add(r["ua_id"])
        entry["post_ids"].add(r["post_id"])
        if r["hop_count"] is not None:
            entry["hops"].append(r["hop_count"])
        # Keep up to 5 distinct sample URLs (insertion order, no duplicates)
        if r["original_url"] and r["original_url"] not in entry["sample_urls"]:
            if len(entry["sample_urls"]) < 5:
                entry["sample_urls"].append(r["original_url"])

    out: list[dict] = []
    for (original, final), e in by_pair.items():
        hops = e["hops"] or [0]
        out.append({
            "original_domain": original,
            "final_domain":    final,
            "url_count":       len(e["ua_ids"]),
            "post_count":      len(e["post_ids"]),
            "min_hops":        min(hops),
            "max_hops":        max(hops),
            "sample_urls":     e["sample_urls"],
        })
    out.sort(key=lambda x: (-x["url_count"], -x["post_count"]))
    return out


_HASH_PREFIX_LEN = 12  # hex chars; 12 = 48 bits, safe to ~10M distinct values


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
    digest = hashlib.sha256(val.encode("utf-8", errors="replace")).hexdigest()[:_HASH_PREFIX_LEN]
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
        platform_id, purpose_key = identify_param(k)
        results.append({
            "param_key":   k,
            "param_value": param_display.get(bucket, ""),
            "owner_kind":  classify_owner(platform_id),
            # platform_id is "" when owner_kind == OWNER_KIND_UNKNOWN.
            # The view layer maps platform_id → display name via
            # PLATFORM_DISPLAY_NAMES; OWNER_KIND_GENERIC / UNKNOWN are
            # rendered via i18n at display time.
            "platform_id": platform_id,
            "purpose_key": purpose_key,  # raw i18n key, view layer calls t()
            "domains":     ", ".join(sorted(param_domains[bucket])),
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

        platform_id, purpose_key = identify_param(key)
        results.append({
            "param_key":        key,
            "owner_kind":       classify_owner(platform_id),
            "platform_id":      platform_id,
            "purpose_key":      purpose_key,
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
