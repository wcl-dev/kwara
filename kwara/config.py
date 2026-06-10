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
    # Not listed: generic content/image landing sites (e.g. picelse) — those
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
