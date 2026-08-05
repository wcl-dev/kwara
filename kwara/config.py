"""
config.py — Central configuration for kwara.

Single source of truth for paths, timeouts, thresholds, and rule-engine
constants. Values that reasonably vary per deployment are also read from
environment variables so operators can tune them without editing code.

This module is intentionally dependency-free (only stdlib) so it can be
imported from anywhere without pulling in heavy transitive deps. In
particular, _snapshot_worker.py is a subprocess entry point and does NOT
import this module — it reads its own KWARA_BROWSER_* env vars directly.
See the docstring at the top of _snapshot_worker.py for its locale knobs.

Environment variables honored here:
  KWARA_DB_PATH         — SQLite database path
                          (default: <this dir>/data/kwara.db)
  KWARA_INDEX_DB_PATH   — central cross-case signal index DB (Phase 5.1);
                          spans cases across multiple KWARA_DB_PATH files
                          (default: ~/.kwara/index.db)
  KWARA_HTTP_TIMEOUT    — per-request timeout for scanner.py (seconds, int)
                          (default: 10)
  KWARA_MAX_HOPS        — redirect chain cutoff (default: 20)
  KWARA_NEW_DOMAIN_DAYS — "new_domain" risk flag threshold in days
                          (default: 180)
  KWARA_LANG            — operator-facing language for rule-based insights
                          and human-readable summaries. Accepts any BCP 47
                          tag; anything starting with "en" normalizes to
                          English, otherwise Traditional Chinese.
                          (default: zh)

Note: KWARA_LANG is the OPERATOR's language (what the investigator reads).
It is independent of KWARA_BROWSER_LOCALE (what the victim's browser would
have seen when hitting the scam page) — do not conflate them.
"""
from __future__ import annotations

import os


# ── Paths ────────────────────────────────────────────────────────────────
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH: str = os.environ.get(
    "KWARA_DB_PATH",
    os.path.join(_THIS_DIR, "data", "kwara.db"),
)

# Cross-case signal index (Phase 5.1). A single central DB that accumulates
# strong attribution signals across every case the analyst indexes — even
# cases living in *different* kwara DB files. Default lives under the user's
# home (not the per-investigation data dir) so it survives switching DB_PATH.
INDEX_DB_PATH: str = os.path.expanduser(
    os.environ.get("KWARA_INDEX_DB_PATH", "~/.kwara/index.db")
)


# ── HTTP scanner knobs ───────────────────────────────────────────────────
HTTP_TIMEOUT: int = int(os.environ.get("KWARA_HTTP_TIMEOUT", "10"))
MAX_HOPS: int = int(os.environ.get("KWARA_MAX_HOPS", "20"))

# User-Agent for scanner.py. Defaults to a browser-like string to avoid
# tipping off active scam sites that evidence collection is in progress.
# Override via KWARA_SCANNER_UA if you prefer an honest identifier.
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
SCANNER_USER_AGENT: str = os.environ.get("KWARA_SCANNER_UA", _DEFAULT_UA)


# ── Operator language for rule-based insights ───────────────────────────
def _normalize_lang(raw: str) -> str:
    tag = (raw or "").strip().lower()
    return "en" if tag.startswith("en") else "zh"


LANG: str = _normalize_lang(os.environ.get("KWARA_LANG", "en"))


# ── Domain intelligence thresholds ───────────────────────────────────────
# "new_domain" risk flag fires when the WHOIS creation date is within this
# many days of the source post's publication date. 180 days is a heuristic
# — new scam campaigns typically burn domains faster than 6 months.
NEW_DOMAIN_DAYS: int = int(os.environ.get("KWARA_NEW_DOMAIN_DAYS", "180"))


# ── Risk rule constants (snapshots.py) ───────────────────────────────────
# File extensions considered high-risk when they appear as the final URL.
# Triggers the `suspicious_download` risk tag.
SUSPICIOUS_EXTS: frozenset[str] = frozenset({
    ".exe", ".zip", ".apk", ".dmg", ".msi",
    ".bat", ".sh", ".ps1", ".jar", ".rar", ".7z",
})

# Known third-party tracker/analytics hosts. A landing page contacting
# HIGH_TRACKER_THRESHOLD or more of these earns the `high_tracker_count`
# risk tag.
TRACKER_DOMAINS: frozenset[str] = frozenset({
    "google-analytics.com", "googletagmanager.com", "facebook.net",
    "doubleclick.net", "googlesyndication.com", "hotjar.com",
    "mixpanel.com", "segment.com", "amplitude.com", "clarity.ms",
    "adnxs.com", "taboola.com", "outbrain.com",
})

HIGH_TRACKER_THRESHOLD: int = 3


# Hosts to exclude from cross-domain third-party endpoint aggregation
# (clustering_infra.shared_endpoints). These are legitimate CDNs / fonts /
# analytics that virtually every web page loads — including them produces
# noise rather than attribution signal.
#
# Matching is suffix-aware: an entry of "doubleclick.net" filters BOTH
# the exact host and any subdomain (e.g. "cm.g.doubleclick.net"). List
# the broadest level you're comfortable filtering. Edit to extend.
HAR_NOISE_HOSTS: frozenset[str] = frozenset({
    # ── CDN — fonts and JS libraries ──────────────────────────────
    "googleapis.com",         # fonts.*, ajax.*, www.*
    "gstatic.com",            # fonts.*, www.*
    "jsdelivr.net",           # cdn.*
    "cloudflareinsights.com", # Cloudflare Web Analytics (every CF site)
    "cdnjs.cloudflare.com",
    "unpkg.com", "code.jquery.com",
    "aspnetcdn.com",          # ajax.*
    "bootstrapcdn.com",       # maxcdn.*, stackpath.*

    # ── Google analytics / ads (clustered separately via
    #     tracking_ids / ad_tracking_platforms — re-listing here
    #     would double-count) ─────────────────────────────────────
    "google-analytics.com",
    "googletagmanager.com",
    "googletagservices.com",
    "googleadservices.com",
    "doubleclick.net",
    "googlesyndication.com",
    "adtrafficquality.google",
    "google.com",             # www.google.com (reCAPTCHA, Maps, etc.)

    # ── Meta / Facebook tracking ─────────────────────────────────
    "facebook.net",
    "fbcdn.net",

    # ── Embedded video ───────────────────────────────────────────
    "youtube.com",
    "ytimg.com",
})


# ── URL parameter clustering knobs (clustering.py) ───────────────────────
# Query parameter values longer than this character count are compared by
# their SHA-256 hash (truncated for display) instead of by literal string.
# Catches modern tracking systems that embed long base64 / JWT-style tokens
# (Shopee affiliate, SendGrid click tracking, Klaviyo) where the literal
# value would otherwise be filtered out as noise.
PARAM_VALUE_HASH_THRESHOLD: int = int(
    os.environ.get("KWARA_PARAM_VALUE_HASH_THRESHOLD", "100")
)

# Operator-level coordination via shared_param_keys() — flags KEYS that
# appear in many posts with VARYING values (a sophisticated operator gives
# each victim a unique tracking ID). Tighter thresholds = less noise but
# more missed signals; loosen if running on small samples.
PARAM_KEY_MIN_POSTS:   int = int(os.environ.get("KWARA_PARAM_KEY_MIN_POSTS", "3"))
PARAM_KEY_MIN_VALUES:  int = int(os.environ.get("KWARA_PARAM_KEY_MIN_VALUES", "2"))
PARAM_KEY_MAX_DOMAINS: int = int(os.environ.get("KWARA_PARAM_KEY_MAX_DOMAINS", "5"))


# ── Phase 4 OPSEC-forensics knobs (cloaking.py, opsec.py) ────────────────
# Centralised here so reports can cite the exact thresholds in effect, per
# the "no magic numbers in analysis modules" contract. Phase 4 modules read
# these instead of hard-coding their own constants.

# cloaking.py — with-params vs without-params bodies are treated as the
# same content while their size differs by less than this fraction.
# Accommodates ad-script variability without firing on minor template diffs.
CLOAKING_BODY_SIZE_DIFF: float = float(
    os.environ.get("KWARA_CLOAKING_BODY_SIZE_DIFF", "0.30")
)

# opsec.py — lightweight-fetch success-rate cutoffs that map a domain to an
# OPSEC level (Playwright must itself succeed >= OPSEC_PW_MIN first):
#   lightweight >= OPSEC_LW_HIGH        → low    (no UA gate)
#   OPSEC_LW_LOW <= lightweight < HIGH  → medium (partial gate)
#   lightweight < OPSEC_LW_LOW          → strong (near-total UA gate)
OPSEC_LW_HIGH: float = float(os.environ.get("KWARA_OPSEC_LW_HIGH", "0.70"))
OPSEC_LW_LOW:  float = float(os.environ.get("KWARA_OPSEC_LW_LOW", "0.20"))
OPSEC_PW_MIN:  float = float(os.environ.get("KWARA_OPSEC_PW_MIN", "0.70"))


# ── Phase 8 ads.txt monetization-forensics knobs (adstxt.py) ────────────
# kwara fetches each landing domain's /ads.txt — the publisher's own public
# declaration of which ad systems it authorises and under which account
# (DIRECT = "this account collects the money"). Shared DIRECT accounts and
# byte-identical ads.txt templates are operator-attribution signals.
ADS_TXT_TIMEOUT:   int = int(os.environ.get("KWARA_ADS_TXT_TIMEOUT", "10"))
# 256KB cap — empirically ads.txt files run to 700+ lines on MFA sites.
ADS_TXT_MAX_BYTES: int = int(os.environ.get("KWARA_ADS_TXT_MAX_BYTES", "262144"))
# Frequency weighting (the crux): a DIRECT account appearing on >= this
# fraction of the case's ads.txt-bearing domains is treated as a shared
# monetisation MANAGER / reseller-network account (weak attribution), not a
# same-operator signal. Below the threshold → operator-cluster candidate
# (strong). Mirrors the common-vs-rare-ID handling in clustering.
ADS_TXT_MANAGER_BREADTH: float = float(
    os.environ.get("KWARA_ADS_TXT_MANAGER_BREADTH", "0.8")
)
# Template (shared-monetisation) demotion. Two landing domains whose DIRECT
# account sets overlap heavily are running the same monetisation TEMPLATE (an
# MFA / reseller stack), so their shared accounts are NOT per-operator
# attribution — they get demoted to manager-tier regardless of breadth. This
# catches what within-case breadth alone misses: globally-ubiquitous exchanges
# (criteo/openx/…) that sit on only a few of a small case's domains (caught by
# the 2026-06-11 consolidated-case load, which falsely merged α+β+farm10).
# OVERLAP = fraction of the smaller ads.txt shared; MIN_SHARED guards against
# demoting a genuinely-rare account that two domains happen to share alone.
ADS_TXT_TEMPLATE_OVERLAP: float = float(
    os.environ.get("KWARA_ADS_TXT_TEMPLATE_OVERLAP", "0.4")
)
ADS_TXT_TEMPLATE_MIN_SHARED: int = int(
    os.environ.get("KWARA_ADS_TXT_TEMPLATE_MIN_SHARED", "8")
)
# The template demotion above used to require EVERY carrier pair to be linked.
# One thin ads.txt among many carriers defeated the whole test: measured pair
# ratios for the 23-domain accounts in the 2026-08-05 consolidated case ran
# 0.65–0.81 and never reached 1.0, so nothing was demoted. Fraction of linked
# pairs instead of unanimity.
ADS_TXT_TEMPLATE_PAIR_RATIO: float = float(
    os.environ.get("KWARA_ADS_TXT_TEMPLATE_PAIR_RATIO", "0.6")
)
# Corpus-independent footprint. ADS_TXT_MANAGER_BREADTH above is measured
# against the CURRENT case, so a narrow case hides how far an account really
# spreads — aralego|par-8A22… read as operator on 8 domains in case 3 while
# carrying 19 apexes DB-wide, including unrelated mainstream farms. Tier is
# therefore decided on the account's footprint across EVERY case in the DB,
# counted in registrable domains so that subdomains of one apex
# (redacted139.operatorhub.example + operatorhub.example) cannot inflate it.
#
# NOTE these are absolute counts, not ratios, and deliberately so: a ratio
# needs a reference population of *normal* sites, and an investigation corpus
# is all suspects. The authoritative answer is the SSP's own sellers.json
# `seller_type` (PUBLISHER vs INTERMEDIARY); until that is wired up these
# thresholds are a conservative stand-in.
ADS_TXT_OPERATOR_MAX_APEXES: int = int(
    os.environ.get("KWARA_ADS_TXT_OPERATOR_MAX_APEXES", "4")
)
# Index gate for the carrier domain. The tier machinery only ever sees accounts
# carried by 2+ domains in a case, so an account seen on exactly one domain
# bypasses every demotion and lands in the cross-case index unfiltered. That is
# deliberate for a genuinely rare account — cross-case recurrence of a rare
# money account is the whole point of the index — but it breaks on a large
# legitimate publisher: the 2026-08-05 rebuild indexed 1056 distinct seller
# values, 91% carried by a single domain, and bigpublisher2.example (526) plus bigpublisher1.example
# (351) supplied 83% of them. Those are ordinary programmatic supply shared
# with thousands of unrelated sites, and they made ads_txt_seller the largest
# recurring-signal class by 6x.
#
# So: a domain declaring this many DIRECT accounts is running a full
# programmatic stack, and no single account in it distinguishes an operator.
# Measured spread in the case DB — farms declared 1–284 DIRECT accounts, the
# two large media publishers 860 and 1409 — so the default sits in that gap
# and errs toward indexing. Gates the account signals only; the ads.txt
# TEMPLATE hash is still indexed for every domain.
ADS_TXT_INDEX_MAX_CARRIER_ACCOUNTS: int = int(
    os.environ.get("KWARA_ADS_TXT_INDEX_MAX_CARRIER_ACCOUNTS", "500")
)
ADS_TXT_MANAGER_MIN_APEXES: int = int(
    os.environ.get("KWARA_ADS_TXT_MANAGER_MIN_APEXES", "10")
)


# ── Evidence-coverage weighting (narrative.verdict) ──────────────────────
# `coverage` answers "how much evidence is on the table", so no single class
# may own the figure. Until 2026-08-05 it was a raw weighted count capped at
# 100, and a case carrying 193 operator-tier ads.txt accounts scored 1544 on
# that term alone — the WEAKEST evidence class saturated the number by itself
# and it stopped discriminating between cases.
#
# Now each class contributes at most COVERAGE_CLASS_CAP instances and holds a
# fixed share of the total: grouping evidence (what actually binds domains to
# one operator — tracking IDs, certs, header templates, identical ads.txt)
# 60%, observed evasion behaviour 30%, monetisation accounts 10%. Monetisation
# is last on purpose: clusters.py explicitly refuses to let ads.txt accounts
# bind operator groups, so they must not drive the headline figure either.
COVERAGE_CLASS_CAP: int = int(os.environ.get("KWARA_COVERAGE_CLASS_CAP", "3"))
COVERAGE_WEIGHTS: dict[str, int] = {"grouping": 6, "behaviour": 3, "money": 1}


# ── Candidate screening (discovery.py) ───────────────────────────────────
# Concurrency for the ads.txt screening sweep. Bounded on purpose: a screening
# run contacts thousands of unrelated third-party sites, and the tool has no
# business hammering them. Raise only with a reason.
DISCOVERY_WORKERS: int = int(os.environ.get("KWARA_DISCOVERY_WORKERS", "8"))
# Screening follows redirects (a bare candidate domain routinely 301s apex->www
# or http->https, and refusing to follow would report ordinary sites as having
# no ads.txt). The hop limit is low because a legitimate /ads.txt is at most a
# couple of hops away; anything longer is a redirect chain, not a canonical
# host. The landing host is checked against the candidate's registrable domain
# regardless of hop count — see discovery.fetch_for_screening.
DISCOVERY_MAX_REDIRECTS: int = int(
    os.environ.get("KWARA_DISCOVERY_MAX_REDIRECTS", "3")
)


# ── Shortlink SaaS catalog (clustering.py + snapshots.py + app.py) ───────
# Domains that are themselves shortlink services. When a scan's final_domain
# lands here it means the scan did not penetrate the redirect — the real
# destination is unknown. Excluded from shared_destinations analysis and
# tagged `url_shortener_chain` in risk flags.
KNOWN_SHORTLINK_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "bitly.com", "t.co", "tinyurl.com", "ow.ly", "goo.gl",
    "short.io", "rebrand.ly", "bl.ink", "buff.ly", "dlvr.it", "ift.tt",
    "lnkd.in", "fb.me", "youtu.be", "amzn.to", "tiny.cc",
    "is.gd", "v.gd", "cutt.ly", "shrtco.de", "clck.ru",
    "s.id", "rb.gy", "short.link", "tiny.one",
    # Regional / common redirect landing hosts
    "reurl.cc", "ppt.cc", "picsee.co", "trib.al",
    "vm.tiktok.com", "ig.me",
    # Not listed: generic content/image landing sites (e.g. hubsite) — those
    # are surfaced via hop_count>=2 redirector detection in app.py, not as
    # "shortlink SaaS".
})


# ── Evidence integrity & third-party corroboration ───────────────────────

# HMAC key for signing manifest.json in evidence packs. If unset, the
# export still works but manifest.sig is omitted.
HMAC_KEY: str | None = os.environ.get("KWARA_HMAC_KEY") or None

# urlscan.io API key (free community tier: 100 scans/day).
# If unset, urlscan integration is silently skipped.
URLSCAN_API_KEY: str | None = os.environ.get("KWARA_URLSCAN_API_KEY") or None

# RFC 3161 Time Stamp Authority URL. FreeTSA is the default (free, no key).
TSA_URL: str = os.environ.get(
    "KWARA_TSA_URL",
    "https://freetsa.org/tsr",
)
