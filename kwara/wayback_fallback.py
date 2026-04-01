"""Optional Internet Archive fallback when live capture fails (e.g. Cloudflare).

Fetches the latest archived HTML and optionally a screenshot of the Wayback viewer page.
"""
from __future__ import annotations

import os
import time

import requests

_SESSION = requests.Session()
_SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; kwara/1.0; +https://github.com/wcl-dev/kwara)",
})


def _wayback_api_available(url: str) -> tuple[str | None, str | None]:
    """Return (wayback_page_url, error_detail) for viewing in browser / screenshot."""
    try:
        r = _SESSION.get(
            "https://archive.org/wayback/available",
            params={"url": url},
            timeout=25,
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return None, f"wayback_available: {exc}"

    arch = (data.get("archived_snapshots") or {}).get("closest") or {}
    wurl = arch.get("url")
    if not wurl:
        return None, "no_archived_snapshot"
    return wurl, None


def fetch_wayback_html(wayback_url: str) -> tuple[str | None, str | None]:
    try:
        r = _SESSION.get(wayback_url, timeout=45)
        r.raise_for_status()
        return r.text, None
    except Exception as exc:
        return None, str(exc)[:300]


def try_wayback_evidence(
    original_url: str,
    html_path: str,
    *,
    min_delay_sec: float = 1.0,
) -> tuple[bool, str | None]:
    """Save archived HTML to html_path. Returns (ok, detail).

    Respects archive.org crawling etiquette with a short delay.
    """
    time.sleep(min_delay_sec)
    wurl, err = _wayback_api_available(original_url)
    if err or not wurl:
        return False, err or "no_wayback"

    html, herr = fetch_wayback_html(wurl)
    if not html:
        return False, herr or "fetch_failed"

    os.makedirs(os.path.dirname(html_path) or ".", exist_ok=True)
    with open(html_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(html)

    return True, f"wayback:{wurl}"
