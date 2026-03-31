import re
from datetime import datetime, timezone

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


def query_whois(domain: str) -> tuple[str, str, str]:
    """Return (registrar, creation_date, error). All strings."""
    if not _whois:
        return UNKNOWN, UNKNOWN, "python-whois not installed"
    domain = (domain or "").strip().lower()
    if not domain:
        return UNKNOWN, UNKNOWN, "empty domain"
    try:
        w = _whois.whois(domain)
    except Exception as exc:
        msg = str(exc).lower()
        if "connection refused" in msg:
            return UNKNOWN, UNKNOWN, "connection_refused"
        if "rate limit" in msg or "limit exceeded" in msg:
            return UNKNOWN, UNKNOWN, "rate_limited"
        return UNKNOWN, UNKNOWN, f"error: {exc}"

    reg = getattr(w, "registrar", None) or getattr(w, "registrar_name", None)
    if isinstance(reg, (list, tuple)):
        reg = reg[0] if reg else None
    registrar = (str(reg).strip() if reg else UNKNOWN) or UNKNOWN

    creation_date = normalize_date(getattr(w, "creation_date", None))
    return registrar, creation_date, ""
