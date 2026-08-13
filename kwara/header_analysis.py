"""Phase 4.2B — analysis functions over `redirect_hops.response_headers_json`.

Four orthogonal lenses on the per-hop header set, all read-only over
the data captured by scanner.py. They feed the Headers sub-tab in the
Analyze view; QSH 2026-04-28 is the positive control:

  per_domain_constants    crawler-landing.example consistently exposes
                          x-server-hosted: Malaysia Cloud Pte Ltd —
                          the origin behind Cloudflare.
  cross_domain_template   hubsite / satellitesite / visitorlanding sharing the
                          same fake x-powered-by ⇒ same operator
                          template (evidence weight ≥ GA4 sharing).
  fake_versions           Apache 2.5.1 / OpenSSL 1.1.2e don't exist;
                          fabricating these is intentional decoy.
  cookie_origin           Set-Cookie domain= leaks origin host even
                          when the response itself is CDN-fronted.

All functions return plain lists/dicts so views can render them with
no business logic in the i18n layer.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Header parsing helpers
# ---------------------------------------------------------------------------

def _iter_hops_with_headers(conn: sqlite3.Connection, case_id: int):
    """Yield (hop_url_domain, [[k, v], ...]) for every redirect_hop in
    `case_id` that has response_headers_json populated.

    Restricted to scans that COMPLETED. A failed or aborted scan's hops are
    not evidence of what a site constantly serves, and counting them let a
    header seen only in an old failed attempt qualify as a per-domain constant
    while the index attributed it to the latest successful scan — provenance
    pointing at a run that never observed it."""
    rows = conn.execute(
        """SELECT rh.url, rh.response_headers_json
           FROM redirect_hops rh
           JOIN scan_runs sr ON sr.id = rh.scan_run_id
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE ua.case_id = ?
             AND sr.status = 'done'
             AND rh.response_headers_json IS NOT NULL
             AND TRIM(rh.response_headers_json) != ''""",
        (case_id,),
    ).fetchall()
    for row in rows:
        try:
            pairs = json.loads(row["response_headers_json"])
        except (TypeError, ValueError):
            continue
        if not isinstance(pairs, list):
            continue
        domain = (urlparse(row["url"]).hostname or "").lower()
        # Each pair is [key, value]; gracefully drop malformed.
        clean: list[list[str]] = []
        for p in pairs:
            if isinstance(p, list) and len(p) == 2:
                clean.append([str(p[0]), str(p[1])])
        if clean:
            yield domain, clean


# ---------------------------------------------------------------------------
# 1. per-domain constant headers
# ---------------------------------------------------------------------------

# Headers that legitimately vary per request (timestamps, request-IDs,
# CDN-routing breadcrumbs) — excluded from the constant set so they
# don't drown out the operator-template signal.
_VOLATILE_HEADER_KEYS = {
    "date", "age", "expires", "last-modified", "set-cookie",
    "etag", "content-length", "content-encoding",
    "x-request-id", "x-trace-id", "cf-ray", "cf-cache-status",
    "x-amz-cf-id", "x-amz-cf-pop", "x-served-by", "x-cache",
    "x-cache-hits", "x-timer", "via", "alt-svc", "vary",
}


def per_domain_constants(conn: sqlite3.Connection, case_id: int,
                         *, min_observations: int = 2) -> dict[str, dict[str, str]]:
    """Headers that stay constant across multiple hops/scans for a domain.

    A header counts as 'constant' if it appears at least `min_observations`
    times for the domain AND has only one observed value across them. Volatile
    headers (timestamps, request IDs, CDN routing) are skipped.

    Returns: {domain: {header_name (lowercased): value}}.
    """
    # domain -> header_lower -> Counter[value]
    obs: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for domain, pairs in _iter_hops_with_headers(conn, case_id):
        if not domain:
            continue
        for k, v in pairs:
            kl = k.lower().strip()
            if not kl or kl in _VOLATILE_HEADER_KEYS:
                continue
            obs[domain][kl][v] += 1

    out: dict[str, dict[str, str]] = {}
    for domain, headers in obs.items():
        constants: dict[str, str] = {}
        for kl, counter in headers.items():
            total = sum(counter.values())
            if total < min_observations:
                continue
            if len(counter) == 1:
                ((value, _count),) = counter.items()
                constants[kl] = value
        if constants:
            out[domain] = constants
    return out


# ---------------------------------------------------------------------------
# 2. cross-domain shared template (multiple domains, same header value)
# ---------------------------------------------------------------------------

# Headers we look for when hunting same-template signatures. Skip Server
# alone (legitimately shared by every nginx/Apache install on earth);
# combinations of Server + x-powered-by + a custom header are what
# narrow it down.
_TEMPLATE_HEADER_KEYS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-server-hosted",
    "x-host",
    "x-backend-server",
}


def cross_domain_shared_template(
    conn: sqlite3.Connection, case_id: int,
    *, min_domains: int = 2,
) -> list[dict[str, Any]]:
    """Find (header_name, header_value) pairs observed on >=`min_domains` distinct
    domains. Strong signal when the value is a custom server fingerprint or a
    fake version — both indicate operator template reuse.

    Returns: list of {"header": str, "value": str, "domains": [str]}.
    """
    pair_to_domains: dict[tuple[str, str], set[str]] = defaultdict(set)
    for domain, pairs in _iter_hops_with_headers(conn, case_id):
        if not domain:
            continue
        for k, v in pairs:
            kl = k.lower().strip()
            if kl not in _TEMPLATE_HEADER_KEYS:
                continue
            pair_to_domains[(kl, v)].add(domain)
    out = []
    for (header, value), domains in pair_to_domains.items():
        if len(domains) >= min_domains:
            out.append({
                "header": header,
                "value": value,
                "domains": sorted(domains),
            })
    # Sort by domain count desc, then header name (deterministic for tests
    # and analyst screenshots — round-6 codex tie-breaker hygiene)
    out.sort(key=lambda x: (-len(x["domains"]), x["header"], x["value"]))
    return out


# ---------------------------------------------------------------------------
# 3. fake / impossible version strings
# ---------------------------------------------------------------------------

# (regex on header value, reason). Each pattern targets a software
# version confirmed not to have shipped. The header *key* isn't fixed —
# operators routinely put fake fingerprints under both Server and
# X-Powered-By (and occasionally custom headers), so we scan any header
# whose key is in _FINGERPRINT_HEADER_KEYS.
_FINGERPRINT_HEADER_KEYS = frozenset({
    "server", "x-powered-by", "x-aspnet-version", "x-runtime",
})

_FAKE_VERSION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Apache 2.5+ has never shipped (stopped at 2.4 as of 2026)
    (re.compile(r"Apache/(2\.[5-9]|[3-9])\.", re.I),
     "Apache version >= 2.5 has never shipped"),
    # OpenSSL 1.1.2 was skipped (1.1.1 → 3.x)
    (re.compile(r"OpenSSL/1\.1\.2", re.I),
     "OpenSSL 1.1.2 was never released (1.1.1 → 3.x)"),
    # PHP 9.x doesn't exist (yet)
    (re.compile(r"PHP/(9|1[0-9])", re.I),
     "PHP version >= 9 has never shipped"),
    # nginx 2.x doesn't exist
    (re.compile(r"nginx/[2-9]\.", re.I),
     "nginx never had a 2.x line; current is 1.x"),
]


def detect_fake_versions(
    conn: sqlite3.Connection, case_id: int,
) -> list[dict[str, Any]]:
    """Identify response-header values that claim a software version that
    has never shipped — a strong active anti-forensic signal.

    Scans any header whose key is in _FINGERPRINT_HEADER_KEYS so a fake
    version baked into X-Powered-By is caught even if Server itself is
    "cloudflare". One row per (domain, header, value, reason) tuple so
    a single value triggering multiple regexes (Apache + OpenSSL inside
    one X-Powered-By) is reported as separate evidence items.

    Returns: list of {"domain", "header", "value", "reason"}.
    """
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for domain, pairs in _iter_hops_with_headers(conn, case_id):
        for k, v in pairs:
            kl = k.lower().strip()
            if kl not in _FINGERPRINT_HEADER_KEYS:
                continue
            for pat, reason in _FAKE_VERSION_PATTERNS:
                if pat.search(v):
                    key = (domain, kl, v, reason)
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append({
                        "domain": domain,
                        "header": kl,
                        "value": v,
                        "reason": reason,
                    })
    out.sort(key=lambda x: (x["domain"], x["header"], x["reason"]))
    return out


# ---------------------------------------------------------------------------
# 4. Set-Cookie domain leak / shared cookie templates
# ---------------------------------------------------------------------------

_DOMAIN_RE     = re.compile(r"(?i)\bdomain\s*=\s*\.?([^;]+)")
_PATH_RE       = re.compile(r"(?i)\bpath\s*=\s*([^;]+)")
_HTTPONLY_RE   = re.compile(r"(?i)\bhttponly\b")
_SECURE_RE     = re.compile(r"(?i)\bsecure\b")
_SAMESITE_RE   = re.compile(r"(?i)\bsamesite\s*=\s*([^;]+)")


def _parse_set_cookie(value: str) -> dict[str, Any]:
    """Pull out the structured attributes from a Set-Cookie value."""
    cookie_domain = ""
    m = _DOMAIN_RE.search(value)
    if m:
        cookie_domain = m.group(1).strip().lower()
    cookie_path = ""
    m = _PATH_RE.search(value)
    if m:
        cookie_path = m.group(1).strip()
    samesite = ""
    m = _SAMESITE_RE.search(value)
    if m:
        samesite = m.group(1).strip().lower()
    return {
        "domain":   cookie_domain,
        "path":     cookie_path,
        "httponly": bool(_HTTPONLY_RE.search(value)),
        "secure":   bool(_SECURE_RE.search(value)),
        "samesite": samesite,
    }


def cookie_origin_signals(
    conn: sqlite3.Connection, case_id: int,
) -> dict[str, list]:
    """Two outputs from Set-Cookie analysis:

      origin_leaks   list of {response_domain, cookie_domain} where cookie's
                     Domain= attribute resolves to a host that's NOT a
                     suffix of the response's apex — i.e. the operator
                     leaked the true backend host while routing through
                     a CDN proxy.
      shared_templates  list of cookie attribute templates (path + flags +
                     samesite) observed across >=2 distinct response
                     domains. Same value-shape on multiple domains is a
                     same-operator signal at the cookie layer.
    """
    leaks: list[dict[str, str]] = []
    template_to_domains: dict[tuple[str, bool, bool, str], set[str]] = defaultdict(set)
    seen_leak: set[tuple[str, str]] = set()

    for domain, pairs in _iter_hops_with_headers(conn, case_id):
        if not domain:
            continue
        for k, v in pairs:
            if k.lower() != "set-cookie":
                continue
            attrs = _parse_set_cookie(v)
            cd = attrs["domain"]
            if cd:
                # Origin-leak heuristic: cookie domain ⊄ response apex.
                # Keep it simple — exact suffix match on the trailing two
                # labels. False positives possible (multi-suffix TLDs);
                # that's acceptable because the analyst still sees the
                # raw pair and judges.
                resp_apex = ".".join(domain.split(".")[-2:])
                cookie_apex = ".".join(cd.split(".")[-2:])
                if cookie_apex and cookie_apex != resp_apex:
                    key = (domain, cd)
                    if key not in seen_leak:
                        seen_leak.add(key)
                        leaks.append({
                            "response_domain": domain,
                            "cookie_domain":   cd,
                        })
            # Template = (path, httponly, secure, samesite). Operators that
            # copy the same backend stack tend to emit identical attribute
            # combinations across all their domains.
            template = (
                attrs["path"], attrs["httponly"], attrs["secure"], attrs["samesite"],
            )
            template_to_domains[template].add(domain)

    shared_templates: list[dict[str, Any]] = []
    for template, domains in template_to_domains.items():
        if len(domains) >= 2:
            path, httponly, secure, samesite = template
            shared_templates.append({
                "path":     path,
                "httponly": httponly,
                "secure":   secure,
                "samesite": samesite,
                "domains":  sorted(domains),
            })
    shared_templates.sort(key=lambda x: (-len(x["domains"]), x["path"]))
    leaks.sort(key=lambda x: (x["response_domain"], x["cookie_domain"]))
    return {
        "origin_leaks":     leaks,
        "shared_templates": shared_templates,
    }
