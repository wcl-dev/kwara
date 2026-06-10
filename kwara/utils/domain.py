from urllib.parse import urlparse

try:
    import tldextract  # type: ignore[import-untyped]
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

COMMON_TLDS = frozenset(
    "com org net edu gov mil int info biz name co uk au de fr jp tw cn".split()
)


def extract_domain_from_url(url_or_domain: str) -> str:
    """
    從 URL 或已是網域的字串中提取「主網域」(eTLD+1)。
    例：https://www.google.com/search?q=google.com -> google.com
    """
    s = (url_or_domain or "").strip().lower()
    if not s:
        return ""

    if "://" not in s:
        return _get_registrable_domain(s)

    parsed = urlparse(s)
    host = (parsed.netloc or parsed.path or s).split("/")[0].split("?")[0]
    if not host:
        return ""
    return _get_registrable_domain(host)


def _get_registrable_domain(host: str) -> str:
    """從 host（如 www.google.com）取得註冊網域（如 google.com）。"""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(host)  # type: ignore[possibly-unbound]
        return ext.top_domain_under_public_suffix or host
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    if parts[-1] in COMMON_TLDS:
        return ".".join(parts[-2:])
    if len(parts) >= 3 and parts[-1] in ("uk", "jp", "au") and parts[-2] in ("co", "com", "org", "ac", "gov"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
