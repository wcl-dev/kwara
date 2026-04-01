"""
ip_lookup.py — DNS resolution + ASN enrichment

lookup_ip(domain) -> dict
  Resolves domain to IP, then queries RDAP/WHOIS for ASN info.
  Returns: {ip, asn, as_org, as_country, error}
  All fields are strings or None. Never raises.
"""
import socket

_ip_cache: dict[str, dict] = {}


def lookup_ip(domain: str) -> dict:
    result = {"ip": None, "asn": None, "as_org": None, "as_country": None, "error": None}

    domain = (domain or "").strip().lower()
    if not domain:
        result["error"] = "empty domain"
        return result

    if domain in _ip_cache:
        return dict(_ip_cache[domain])

    try:
        result["ip"] = socket.gethostbyname(domain)
    except Exception as exc:
        result["error"] = str(exc)[:200]
        return result

    try:
        from ipwhois import IPWhois
        obj = IPWhois(result["ip"])
        data = obj.lookup_rdap(asn_methods=["dns", "whois", "http"], inc_nir=False, depth=0)
        result["asn"] = data.get("asn")
        result["as_org"] = (
            data.get("asn_description")
            or (data.get("network") or {}).get("name")
        )
        result["as_country"] = data.get("asn_country_code")
    except Exception as exc:
        result["error"] = str(exc)[:200]

    _ip_cache[domain] = dict(result)
    return result
