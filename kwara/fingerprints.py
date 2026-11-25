"""HTML tracking-ID extraction (kwara Phase 2).

Regex extraction of platform-specific tracking IDs embedded in landing-page
HTML. No JS engine or DOM parser dependency — the canonical pixel snippets
all hard-code the ID as a string literal in a recognisable invocation
context (``fbq('init', '…')``, ``gtag('config', '…')``, etc), so a
context-anchored regex is sufficient and far cheaper.

When *the same* tracking ID appears across multiple landing domains in
a case, it identifies the operator's underlying ad / analytics account
— a far harder signal to spoof than URL parameters or ASN, and the
strongest evidence we can collect short of seizure.

LIMITATIONS:
  - Only what's visible in the captured HTML at snapshot time. Misses
    IDs that JS builds at runtime from concatenated fragments (rare —
    almost all pixel snippets ship the ID as a literal).
  - IDs inside iframes whose document we did not capture.
  - IDs loaded after the capture timeout fired.
  - IDs that only ever appear in network requests (GT- Google tags, tags
    fired by a GTM container). extract_network_tag_ids_from_har() reads
    those from the HAR, as leads only — see the note above it.

DESIGN NOTE — context anchoring (codex review fix #1):
Earlier versions matched bare tokens like ``G-AB12CD34``. That's fine
for UI hinting, but unsafe when the same string is later used as
"same ID across multiple domains = same operator account" evidence
because vendor docs, help pages, and code comments routinely contain
plausible placeholders. Every pattern below now requires the ID to
appear inside a real invocation (gtag/ga/fbq/ttq/gtm.js URL/quoted
GTM container literal). Obvious placeholders (G-XXXXXXXX, GTM-EXAMPLE,
all-same-char IDs) are filtered post-match.
"""
from __future__ import annotations

import re

# Each entry: (platform_label, compiled regex, capturing-group index).
# A platform may appear multiple times — each row is one invocation
# context that the same platform is matched against.
_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # ── Meta Pixel ─────────────────────────────────────────────────────
    # fbq('init', '1234567890123456')  — Pixel IDs are 15-17 digit numerics.
    (
        "Meta Pixel",
        re.compile(r"""fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d{15,17})['"]"""),
        1,
    ),
    # ── Google Analytics 4 — measurement ID G-XXXXXXXX ─────────────────
    # gtag('config', 'G-…')  / ga('create', 'G-…')
    (
        "Google Analytics 4",
        re.compile(
            r"""(?:gtag|ga)\s*\(\s*['"](?:config|create)['"]\s*,\s*['"](G-[A-Z0-9]{6,12})['"]"""
        ),
        1,
    ),
    # gtag.js loader URL or g/collect URL — must be on a Google host.
    # Anchoring to googletagmanager.com / google-analytics.com prevents
    # `?id=G-…` in unrelated docs/blog comments / JSON blobs from being
    # treated as evidence (codex2 #2).
    (
        "Google Analytics 4",
        re.compile(
            r"""(?:googletagmanager\.com|google-analytics\.com)[^"'<>\s]*?[?&](?:id|tid)=(G-[A-Z0-9]{6,12})\b"""
        ),
        1,
    ),
    # ── Google Analytics Universal (legacy UA-12345-1) ─────────────────
    (
        "Google Analytics (UA)",
        re.compile(
            r"""(?:gtag|ga)\s*\(\s*['"](?:config|create)['"]\s*,\s*['"](UA-\d{4,12}-\d{1,4})['"]"""
        ),
        1,
    ),
    (
        "Google Analytics (UA)",
        re.compile(
            r"""(?:googletagmanager\.com|google-analytics\.com)[^"'<>\s]*?[?&]tid=(UA-\d{4,12}-\d{1,4})\b"""
        ),
        1,
    ),
    # ── Google Tag Manager — GTM-XXXXXX container ──────────────────────
    # Standard snippet ends with the 'dataLayer' literal followed by the
    # container ID: `(...)(window,document,'script','dataLayer','GTM-…')`
    # Anchoring to the 'dataLayer' literal (codex2 follow-up) prevents
    # arbitrary quoted GTM-… strings in unrelated JSON / data-attributes
    # from being treated as evidence.
    (
        "Google Tag Manager",
        re.compile(
            r"""['"]dataLayer['"]\s*,\s*['"](GTM-[A-Z0-9]{4,8})['"]"""
        ),
        1,
    ),
    # Loader / noscript URLs: gtm.js?id=GTM-… , ns.html?id=GTM-…
    # Same host-anchoring as GA4 — codex2 #2.
    (
        "Google Tag Manager",
        re.compile(
            r"""googletagmanager\.com[^"'<>\s]*?[?&]id=(GTM-[A-Z0-9]{4,8})\b"""
        ),
        1,
    ),
    # ── Google Ads conversion ID AW-XXXXXXXXX ──────────────────────────
    (
        "Google Ads",
        re.compile(r"""gtag\s*\(\s*['"]config['"]\s*,\s*['"](AW-\d{9,12})['"]"""),
        1,
    ),
    # send_to: 'AW-…/conversion_label'
    (
        "Google Ads",
        re.compile(r"""['"]send_to['"]\s*:\s*['"](AW-\d{9,12})(?:/[^'"]*)?['"]"""),
        1,
    ),
    # ── TikTok Pixel ttq.load('…') ─────────────────────────────────────
    (
        "TikTok Pixel",
        re.compile(r"""ttq\.load\s*\(\s*['"]([A-Z0-9]{15,25})['"]"""),
        1,
    ),
    # ── Microsoft Clarity (Phase 3 ticket D) ───────────────────────────
    # Standard snippet: t.src="https://www.clarity.ms/tag/<id>"
    # Or: clarity('set', 'project', '<id>')
    # IDs are short lowercase alphanumeric (their docs: 10 chars).
    (
        "Microsoft Clarity",
        re.compile(r"""clarity\.ms/tag/([a-z0-9]{6,20})\b"""),
        1,
    ),
    (
        "Microsoft Clarity",
        re.compile(r"""clarity\s*\(\s*['"]set['"]\s*,\s*['"]project['"]\s*,\s*['"]([a-z0-9]{6,20})['"]"""),
        1,
    ),
    # ── Hotjar (Phase 3 ticket D) ──────────────────────────────────────
    # Standard snippet has _hjSettings={hjid:NNNNNN, hjsv:N};
    (
        "Hotjar",
        re.compile(r"""_hjSettings\s*=\s*\{\s*hjid\s*:\s*(\d{4,10})\s*,"""),
        1,
    ),
    # ── LINE Tag — _lt('init', {customerType:..., tagId: '<id>' ...}) ──
    (
        "LINE Tag",
        re.compile(
            r"""_lt\s*\(\s*['"]init['"]\s*,\s*\{[^}]*tagId\s*:\s*['"]([A-Za-z0-9_-]{8,40})['"]"""
        ),
        1,
    ),
    # ── X / Twitter Pixel — twq('config'|'init', '<id>') ───────────────
    (
        "X / Twitter Pixel",
        re.compile(
            r"""twq\s*\(\s*['"](?:config|init)['"]\s*,\s*['"]([A-Za-z0-9]{4,20})['"]"""
        ),
        1,
    ),
    # ── Google AdSense — publisher account ID `ca-pub-NNNNNNNNNNNNNNNN` ─
    # The ID belongs to a single Google account, so the same `ca-pub-`
    # appearing on multiple domains is hard evidence of one operator
    # (same evidence weight as GA4-account sharing). Three invocation
    # contexts; each anchors the ID to a real AdSense surface so a stray
    # `ca-pub-…` quoted in tutorials / docs cannot become evidence.
    (
        "Google AdSense",
        re.compile(r"""data-ad-client\s*=\s*['"](ca-pub-\d{16})['"]"""),
        1,
    ),
    (
        "Google AdSense",
        re.compile(
            r"""['"]?google_ad_client['"]?\s*[:=]\s*['"](ca-pub-\d{16})['"]"""
        ),
        1,
    ),
    (
        "Google AdSense",
        re.compile(
            r"""googlesyndication\.com[^"'<>\s]*?[?&]client=(ca-pub-\d{16})\b"""
        ),
        1,
    ),
    # ── Meta / Facebook Page — `<meta property="fb:pages" content="…">` ─
    # The site's self-declared owning FB Page(s). Cross-domain match
    # links domains to the same FB Page operator. content="" can be
    # comma-separated for sites claiming multiple pages — handled
    # post-match in extract_tracking_ids().
    (
        "Meta Facebook Page",
        re.compile(
            r"""<meta\s+[^>]*property\s*=\s*['"]fb:pages['"][^>]*content\s*=\s*['"]([0-9,\s]+)['"]"""
        ),
        1,
    ),
]


# Common placeholder tail tokens that vendor docs and help pages use as
# "fill in your own ID here" examples. Anything matching is filtered out
# post-match so it cannot become cross-domain attribution evidence.
_PLACEHOLDER_TAILS = frozenset({
    "EXAMPLE", "PLACEHOLDER", "YOURID", "YOUR_ID",
    "TODO", "ABCDEFG", "ABCDEFGH", "ABCDEFGHI",
    "00000000", "11111111", "12345678", "123456789",
})


def _looks_like_placeholder(ident: str) -> bool:
    """Heuristic: reject ``G-XXXXXXXX``, ``GTM-EXAMPLE``, ``UA-XXXXX-X`` etc.

    A real operator's tracking ID should not collapse to a single repeated
    *alphabetic* character within any of its segments, nor match the
    canonical placeholder labels seen in vendor documentation. The
    repeated-character check is restricted to alphabetic runs because
    repeated-digit IDs (e.g. ``AW-1111111111``, ``UA-1111111-1``) are
    syntactically valid and have been observed in the wild — rare, but we
    don't want to silently lose attribution evidence over a heuristic
    (codex2 #3).
    """
    parts = ident.upper().split("-")
    if len(parts) < 2:
        return False
    for part in parts[1:]:
        if not part:
            continue
        # Repeated-character check — only when ALL chars are letters.
        # XXXX / ZZZZ / VVVV trip; 1111 / 0000 / 9999 do not.
        if len(part) >= 3 and len(set(part)) == 1 and part.isalpha():
            return True
        if part in _PLACEHOLDER_TAILS:
            return True
    return False


# Labels whose captured group can carry multiple IDs separated by commas
# or whitespace. Currently fb:pages is the only such case; vendor docs
# allow multi-page declarations.
_MULTI_VALUE_LABELS = frozenset({"Meta Facebook Page"})
_MULTI_VALUE_SPLIT = re.compile(r"[,\s]+")


def extract_tracking_ids(html: str) -> dict[str, list[str]]:
    """Return ``{platform_label: sorted_unique_ids}`` for every pattern hit.

    Empty dict if html is falsy or no pattern matched. Each platform's
    ID list is sorted and deduplicated within a single page (the same
    Pixel ID appearing 5 times is one signal, not five). Obvious
    placeholders are filtered. Multi-value capture groups (fb:pages
    content="ID1,ID2") are split here.
    """
    if not html:
        return {}
    out: dict[str, set[str]] = {}
    for label, pattern, group in _PATTERNS:
        for m in pattern.finditer(html):
            try:
                ident_raw = m.group(group)
            except IndexError:
                continue
            if not ident_raw:
                continue
            candidates = (
                _MULTI_VALUE_SPLIT.split(ident_raw)
                if label in _MULTI_VALUE_LABELS
                else [ident_raw]
            )
            for ident in candidates:
                ident = ident.strip()
                if not ident or _looks_like_placeholder(ident):
                    continue
                out.setdefault(label, set()).add(ident)
    return {k: sorted(v) for k, v in out.items()}


def extract_tracking_ids_from_file(html_path: str | None) -> dict[str, list[str]]:
    """Read an HTML file from disk and run extract_tracking_ids().

    Returns empty dict on missing file, unreadable file, or empty content.
    Tolerates bad encoding (``errors='replace'``).
    """
    if not html_path:
        return {}
    try:
        with open(html_path, encoding="utf-8", errors="replace") as f:
            html = f.read()
    except OSError:
        return {}
    return extract_tracking_ids(html)


# ── Network layer: Google tag IDs in the requests a page actually sent ────
#
# A Google tag can sit behind a GTM container, be merged under a GT- Google
# tag, or be assembled by script at runtime, and in each case the HTML may
# never carry the measurement ID as a literal. The request that reports back
# to Google always does, as `id=` on the loader or `tid=` on the collect hit.
#
# Measured 2026-11-25 over 2,369 stored HARs: 773 captures carried a Google ID
# in their requests that HTML extraction missed, but 359 of those were one
# platform-wide ID already rejected as a fingerprint, and of the remaining 35
# distinct IDs, 20 appeared in a single capture. No GT- ID was found on more
# than one domain at that point. So this is a gap closed ahead of need, not a
# source of current attribution.
#
# Everything found here is a LEAD and never binds a group, for two reasons:
#   - A HAR does not say which frame sent a request. An ad creative or an
#     embedded widget fires its own tags from inside the page, and those land
#     in the HAR exactly like the operator's own. The platform-wide ID above,
#     on 359 captures across unrelated operators, is one such ID.
#   - A GT- Google tag can route to several destinations; what a shared one
#     implies about account ownership has not been measured here.
# For the same reason the extractor deliberately ignores AW- (Google Ads
# conversion) and DC- (Floodlight): in the measurement above both spanned
# operator groups known to be separate, consistent with advertisers' own
# conversion tags riding along in ad creatives.
_NETWORK_GOOGLE_HOSTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "g.doubleclick.net",
)
_NETWORK_ID_PARAMS = ("id", "tid")
_NETWORK_ID_FORMS: list[tuple[str, re.Pattern]] = [
    ("Google Analytics 4", re.compile(r"^G-[A-Z0-9]{6,12}$")),
    ("Google Tag", re.compile(r"^GT-[A-Z0-9]{6,12}$")),
    ("Google Tag Manager", re.compile(r"^GTM-[A-Z0-9]{4,8}$")),
    ("Google Analytics (UA)", re.compile(r"^UA-\d{4,12}-\d{1,4}$")),
]


def _is_google_tag_host(host: str) -> bool:
    host = (host or "").lower()
    return any(host == h or host.endswith("." + h)
               for h in _NETWORK_GOOGLE_HOSTS)


def extract_network_tag_ids(urls) -> dict[str, list[str]]:
    """``{platform_label: sorted_unique_ids}`` from request URLs.

    Only URLs on a Google tag host are read, and only their ``id`` / ``tid``
    query parameters, so an ``?id=G-…`` on any other host is ignored.
    Placeholders are filtered as for HTML.
    """
    from urllib.parse import parse_qs, urlsplit

    out: dict[str, set[str]] = {}
    for url in urls:
        try:
            parts = urlsplit(url or "")
        except ValueError:
            continue
        if not _is_google_tag_host(parts.hostname or ""):
            continue
        query = parse_qs(parts.query)
        for param in _NETWORK_ID_PARAMS:
            for value in query.get(param, []):
                value = value.strip()
                if _looks_like_placeholder(value):
                    continue
                for label, form in _NETWORK_ID_FORMS:
                    if form.match(value):
                        out.setdefault(label, set()).add(value)
                        break
    return {k: sorted(v) for k, v in out.items()}


def extract_network_tag_ids_from_har(har_path: str | None) -> dict[str, list[str]] | None:
    """Run extract_network_tag_ids() over a HAR's request URLs.

    Returns None when there is no HAR or it cannot be read (nothing was
    observed), and ``{}`` when the HAR was read and held no Google tag ID.
    Callers store the two differently, so a backfill can tell "not yet
    derived" from "derived, empty".
    """
    if not har_path:
        return None
    import json
    try:
        with open(har_path, encoding="utf-8", errors="replace") as f:
            entries = json.load(f).get("log", {}).get("entries", [])
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(entries, list):
        return None
    urls = []
    for e in entries:
        if isinstance(e, dict):
            req = e.get("request")
            if isinstance(req, dict) and isinstance(req.get("url"), str):
                urls.append(req["url"])
    return extract_network_tag_ids(urls)
