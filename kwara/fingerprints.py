"""HTML tracking-ID extraction (kwara Phase 2).

Pure-regex extraction of platform-specific tracking IDs embedded in
landing-page HTML. No dependency on a JS engine or DOM parser — we
match against the literal text of the saved HTML, which is sufficient
because the standard pixel snippets all hard-code the ID as a string
literal (``fbq('init', 'NNN…')``, ``gtag('config', 'G-…')``, etc).

When *the same* tracking ID appears across multiple landing domains in
a case, it identifies the operator's underlying ad / analytics account
— a far harder signal to spoof than URL parameters or ASN, and the
strongest evidence we can collect short of seizure.

LIMITATION: extracts only what's visible in the captured HTML at
snapshot time. Misses:
  - IDs that JS builds at runtime from concatenated fragments
    (rare — almost all pixel snippets ship the ID as a literal)
  - IDs inside iframes whose document we did not capture
  - IDs loaded after the capture timeout fired
"""
from __future__ import annotations

import re

# Each entry: (platform_label, compiled regex, capturing-group index).
# Order matters only for documentation; matches are independent.
_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # Meta Pixel: fbq('init', '1234567890123456')
    # Pixel IDs are numeric, length typically 15–17 digits.
    (
        "Meta Pixel",
        re.compile(r"""fbq\s*\(\s*['"]init['"]\s*,\s*['"](\d{15,17})['"]"""),
        1,
    ),
    # Google Analytics 4 measurement ID: G-XXXXXXXXXX
    (
        "Google Analytics 4",
        re.compile(r"""\bG-[A-Z0-9]{6,12}\b"""),
        0,
    ),
    # Universal Analytics tracking ID (legacy): UA-12345-1
    (
        "Google Analytics (UA)",
        re.compile(r"""\bUA-\d{4,12}-\d{1,4}\b"""),
        0,
    ),
    # Google Tag Manager container: GTM-XXXXXX
    (
        "Google Tag Manager",
        re.compile(r"""\bGTM-[A-Z0-9]{4,8}\b"""),
        0,
    ),
    # Google Ads conversion ID: AW-1234567890
    (
        "Google Ads",
        re.compile(r"""\bAW-\d{9,12}\b"""),
        0,
    ),
    # TikTok Pixel: ttq.load('XXXXXXXXXXXXXXXXXXXX') — 15–25 chars,
    # uppercase alphanumeric. Quoted form is what TikTok docs ship.
    (
        "TikTok Pixel",
        re.compile(r"""ttq\.load\s*\(\s*['"]([A-Z0-9]{15,25})['"]"""),
        1,
    ),
]


def extract_tracking_ids(html: str) -> dict[str, list[str]]:
    """Return ``{platform_label: sorted_unique_ids}`` for every pattern hit.

    Empty dict if html is falsy or no pattern matched. Each platform's
    ID list is sorted and deduplicated within a single page (the same
    Pixel ID appearing 5 times is one signal, not five).
    """
    if not html:
        return {}
    out: dict[str, set[str]] = {}
    for label, pattern, group in _PATTERNS:
        for m in pattern.finditer(html):
            try:
                ident = m.group(group)
            except IndexError:
                continue
            if ident:
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
