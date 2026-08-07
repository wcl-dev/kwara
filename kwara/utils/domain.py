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


# Multi-label suffixes the bare-TLD rule below would otherwise cut in half.
# Only reachable in the no-tldextract fallback; ordering matters, because
# "uk" is itself in COMMON_TLDS and would claim victim.co.uk first.
_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.tw", "org.tw", "net.tw", "gov.tw", "edu.tw", "idv.tw",
    "com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "org.hk",
    "com.sg", "com.my", "com.br", "com.mx", "co.kr", "or.kr",
})


def _ascii_host(host: str) -> str:
    """IDNA/punycode-normalised host, so a Unicode name and the ASCII form a
    library produced for the same site compare equal. bücher.de and
    xn--bcher-kva.de are one host; treating them as two made an on-site
    redirect look off-site."""
    h = (host or "").strip().strip(".").lower()
    if not h:
        return ""
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return h


def _get_registrable_domain(host: str) -> str:
    """從 host（如 www.google.com）取得註冊網域（如 google.com）。

    include_psl_private_domains=True is load-bearing, not a preference. With
    the PSL private section excluded (tldextract's default), alice.github.io
    and bob.github.io both reduce to github.io — so two unrelated tenants
    become one asset. That made an off-site redirect pass the same-domain
    check, merged unrelated tenants into one apex when counting an account's
    footprint, and let operator_cross_links report a tenancy coincidence as a
    threshold-free operator link. Blogspot, pages.dev and every other hosting
    suffix have the same shape.
    """
    host = _ascii_host(host)
    if not host:
        return ""
    if HAS_TLDEXTRACT:
        ext = tldextract.extract(  # type: ignore[possibly-unbound]
            host, include_psl_private_domains=True)
        return ext.top_domain_under_public_suffix or host
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    if parts[-1] in COMMON_TLDS:
        return ".".join(parts[-2:])
    return ".".join(parts[-2:])
