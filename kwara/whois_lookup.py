import re
from datetime import datetime, timezone

import requests

try:
    import whois as _whois
except ImportError:
    _whois = None

UNKNOWN = "Unknown/Private"

_DATE_PATTERNS = [
    (re.compile(r"(\d{4})-(\d{2})-(\d{2})"),
     lambda m: f"{m.group(1)}-{m.group(2)}-{m.group(3)}"),
    (re.compile(r"(\d{2})[-/.](\d{2})[-/.](\d{4})"),
     lambda m: f"{m.group(3)}-{m.group(2)}-{m.group(1)}"),
    (re.compile(r"(\d{2})-([A-Za-z]{3})-(\d{4})"),
     lambda m: f"{m.group(3)}-{_MON.get(m.group(2).lower()[:3], '01')}-{m.group(1)}"),
]
_MON = {
    "jan": "01", "feb": "02", "mar": "03", "apr": "04",
    "may": "05", "jun": "06", "jul": "07", "aug": "08",
    "sep": "09", "oct": "10", "nov": "11", "dec": "12",
}

_RDAP_BOOTSTRAP = {
    "com": "https://rdap.verisign.com/com/v1",
    "net": "https://rdap.verisign.com/net/v1",
    "org": "https://rdap.org",
    "info": "https://rdap.afilias.net/rdap/info/v1",
    "biz": "https://rdap.afilias-srs.net/rdap/biz/v1",
    "io": "https://rdap.nic.io",
    "me": "https://rdap.nic.me",
    "cc": "https://rdap.verisign.com/cc/v1",
    "tv": "https://rdap.verisign.com/tv/v1",
}


def normalize_date(value) -> str:
    if value is None:
        return UNKNOWN
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    if isinstance(value, (list, tuple)):
        for v in value:
            result = normalize_date(v)
            if result != UNKNOWN:
                return result
        return UNKNOWN
    s = str(value).strip()
    if not s or s.lower() in ("n/a", "unknown", "private"):
        return UNKNOWN
    for pat, fmt in _DATE_PATTERNS:
        m = pat.search(s)
        if m:
            try:
                return fmt(m)
            except (IndexError, KeyError):
                continue
    return UNKNOWN


def _query_rdap(domain: str) -> tuple[str | None, str | None, str]:
    """RDAP HTTP lookup. Returns (registrar, creation_date, error)."""
    tld = domain.rsplit(".", 1)[-1].lower()
    base = _RDAP_BOOTSTRAP.get(tld)
    if not base:
        return None, None, f"no RDAP server for .{tld}"
    url = f"{base}/domain/{domain}"
    try:
        r = requests.get(url, timeout=15, headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None, None, f"HTTP {r.status_code}"
        d = r.json()
    except Exception as exc:
        return None, None, f"rdap: {exc}"

    registrar = None
    for ent in d.get("entities", []):
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
            if not registrar:
                registrar = ent.get("handle")
            break

    created = None
    for ev in d.get("events", []):
        if ev.get("eventAction") == "registration":
            raw = ev.get("eventDate", "")
            created = raw[:10] if raw else None
            break

    return registrar, created, ""


def _query_whois_legacy(domain: str) -> tuple[str, str, str]:
    """Traditional WHOIS port-43 lookup via python-whois with timeout."""
    if not _whois:
        return UNKNOWN, UNKNOWN, "python-whois not installed"

    import socket
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        w = _whois.whois(domain)
    except Exception as exc:
        return UNKNOWN, UNKNOWN, f"error: {exc}"
    finally:
        socket.setdefaulttimeout(old_timeout)

    reg = getattr(w, "registrar", None) or getattr(w, "registrar_name", None)
    if isinstance(reg, (list, tuple)):
        reg = reg[0] if reg else None
    registrar = (str(reg).strip() if reg else UNKNOWN) or UNKNOWN

    creation_date = normalize_date(getattr(w, "creation_date", None))
    return registrar, creation_date, ""


_whois_cache: dict[str, tuple[str, str, str]] = {}


def query_whois(domain: str) -> tuple[str, str, str]:
    """Return (registrar, creation_date, error). All strings.

    Tries RDAP (HTTP-based, no port-43 needed) first, then falls back to
    the traditional python-whois library. Results are cached per domain
    to avoid repeated slow lookups during batch runs.
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return UNKNOWN, UNKNOWN, "empty domain"

    if domain in _whois_cache:
        return _whois_cache[domain]

    reg, created, err = _query_rdap(domain)
    if not err and (reg or created):
        result = (reg or UNKNOWN, created or UNKNOWN, "")
        _whois_cache[domain] = result
        return result

    legacy_reg, legacy_created, legacy_err = _query_whois_legacy(domain)
    if legacy_reg != UNKNOWN or legacy_created != UNKNOWN:
        result = (legacy_reg, legacy_created, legacy_err)
        _whois_cache[domain] = result
        return result

    result = (reg or UNKNOWN, created or UNKNOWN, err or legacy_err)
    _whois_cache[domain] = result
    return result
