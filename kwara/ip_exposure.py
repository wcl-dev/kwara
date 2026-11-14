"""Find and remove the investigator's own IP address from captured evidence.

A page's third-party ad requests routinely echo the visitor's address back:
Temu's ``cip`` header, Appier's ``x-client-ip``, MediaGo's ``x-forwarded-for``,
GliaStudio's ``custom-connecting-ip``, ``x-proxy-origin``, ``auip=`` query
parameters, or an error page printing "Your IP". An embedded video player does
it too, in its page config (``"remoteHost":``) and in the ``/ip/<address>/``
segment of the video URLs it requests — and behind a VPN that address belongs
to no local ISP, so a range check never sees it; only the position does. The HAR records every one of
them, so an evidence pack exported from a store like that carries the analyst's
address on every page that showed an ad. On one live store that was 582 files
across 19 cases, 22 distinct addresses, none of them evidence of anything.

Two passes, because a heuristic alone under-finds. The *echo* pass reads the
positions where a remote is known to echo the client address and collects the
values it finds there — that is how the address is discovered without asking
the network. The *known* pass then re-scans every byte of the file for each
discovered value (plus anything in ``KWARA_INVESTIGATOR_IPS``), so an address
that also landed in a JSON body or a query string outside the echo positions
is caught too. Redaction replaces the value with a fixed marker; a HAR is
re-parsed afterwards so a broken file is never written over a good one.

The investigator's address is never evidence. Redacting it at capture time,
before anything is timestamped or exported, is therefore lossless for the
case — which is why the capture path does it by default.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re

REDACTION_MARKER = "[REDACTED-INVESTIGATOR-IP]"

# Response headers whose value is, by convention, the address the remote saw
# the request come from. Lower-case; compared case-insensitively.
ECHO_HEADERS = frozenset({
    "cip", "x-client-ip", "client-ip", "x-real-ip", "x-forwarded-for",
    "true-client-ip", "x-your-ip", "x-remote-addr", "remote-addr",
    "x-originating-ip", "x-cluster-client-ip", "fastly-client-ip",
    "cf-connecting-ip", "x-envoy-external-address", "custom-connecting-ip",
    "x-request-ip", "x-connecting-ip", "x-client-address", "x-user-ip",
    "x-original-forwarded-for", "x-proxy-origin", "yourip",
})
# Query-string keys ad-tech uses to pass the visitor address along.
ECHO_QUERY_KEYS = frozenset({"auip", "ip", "cip", "clientip", "client_ip",
                             "userip", "user_ip", "ipaddr", "ip_addr"})
# Text right before an address on a page or in a body that prints it.
_ECHO_TEXT = re.compile(
    r"(您的\s*IP|你的\s*IP|Your\s+IP(?:\s+address)?(?:\s+is)?|client[_ -]?ip"
    r"|remote[_ -]?addr|remote[_ -]?host|visitor[_ -]?ip|ip_addr|ip_?orig"
    r"|\"ip\"\s*:\s*\"?)",
    re.I,
)
# A path segment some media CDNs use to bind a URL to the viewer: the video
# URLs an embedded player requests carry ``/ip/<address>/``.
_PATH_IP = re.compile(r"/ip/([^/?#]+)")
# Documentation ranges (RFC 5737, RFC 3849). The stdlib calls them private,
# which would make them invisible here; they never occur in real traffic, so
# counting them as public costs nothing and lets tests use them instead of
# anyone's real address.
_DOC_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
_IPV4 = re.compile(
    r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})"
    r"(?![\d.])"
)
_IPV6 = re.compile(
    r"(?<![0-9a-fA-F:])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})(?![0-9a-fA-F:])"
)
# x-forwarded-for lists client first, then proxies; only the first hop is the
# visitor. Splitting on comma/semicolon covers both separators seen in the wild.
_LIST_SPLIT = re.compile(r"[,;]\s*")


def configured_ips() -> list[str]:
    """Addresses the operator declared as their own (comma-separated env)."""
    raw = os.environ.get("KWARA_INVESTIGATOR_IPS", "")
    return [x.strip() for x in raw.split(",") if x.strip()]


def redaction_enabled() -> bool:
    """Capture-time redaction is on unless KWARA_REDACT_INVESTIGATOR_IP=0."""
    return os.environ.get("KWARA_REDACT_INVESTIGATOR_IP", "1") != "0"


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if any(addr.version == n.version and addr in n for n in _DOC_NETS):
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_unspecified
                or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def _addresses_in(text: str) -> list[str]:
    return [ip for ip in _IPV4.findall(text) + _IPV6.findall(text) if _is_public(ip)]


def _first_hop(value: str) -> list[str]:
    parts = _LIST_SPLIT.split(value.strip())
    return _addresses_in(parts[0]) if parts else []


def echo_candidates_in_har(har: dict) -> list[dict]:
    """Addresses a remote echoed back as *the client's*, with where it said so.

    Server addresses and request hostnames are excluded: a value that is also
    the address of a server in the same HAR is that server, not the visitor.
    """
    entries = har.get("log", {}).get("entries", [])
    servers, hosts = set(), set()
    for e in entries:
        if e.get("serverIPAddress"):
            servers.add(e["serverIPAddress"].strip("[]"))
        try:
            hosts.add(e["request"]["url"].split("/")[2].split(":")[0].strip("[]"))
        except (KeyError, IndexError):
            pass
    found: list[dict] = []
    for e in entries:
        url = e.get("request", {}).get("url", "")
        for h in e.get("response", {}).get("headers", []):
            name = (h.get("name") or "").lower()
            if name in ECHO_HEADERS:
                for ip in _first_hop(h.get("value") or ""):
                    found.append({"where": "response-header", "header": name,
                                  "ip": ip, "url": url})
        qs = url.partition("?")[2]
        for kv in qs.split("&"):
            key, _, val = kv.partition("=")
            if key.lower() in ECHO_QUERY_KEYS:
                for ip in _addresses_in(val.replace("%3A", ":")):
                    found.append({"where": "request-query", "key": key,
                                  "ip": ip, "url": url})
        for m in _PATH_IP.finditer(url.partition("?")[0]):
            for ip in _addresses_in(m.group(1).replace("%3A", ":")):
                found.append({"where": "request-path", "ip": ip, "url": url})
        body = e.get("response", {}).get("content", {}).get("text") or ""
        if body and len(body) < 4096:
            stripped = body.strip()
            if _addresses_in(stripped) == [stripped]:
                found.append({"where": "response-body", "ip": stripped, "url": url})
        # A labelled echo inside any response body: an embedded video player
        # writes the viewer's address into its page config as ``remoteHost``.
        # Unlike a header, nothing about the address itself gives it away — it
        # can be a VPN exit in any country — so the label is the only signal.
        if body:
            for h in echo_candidates_in_text(body):
                found.append({"where": "response-text", "marker": h["marker"],
                              "ip": h["ip"], "url": url})
    return [f for f in found if f["ip"] not in servers and f["ip"] not in hosts]


def echo_candidates_in_text(text: str) -> list[dict]:
    """Addresses printed next to a "Your IP"-style label in HTML or a body."""
    found = []
    for m in _ECHO_TEXT.finditer(text):
        window = text[m.end(): m.end() + 80]
        for ip in _addresses_in(window)[:1]:
            found.append({"where": "text", "marker": m.group(1), "ip": ip})
    return found


def discover(har_path: str | None, html_path: str | None,
             extra_ips: list[str] | None = None) -> dict:
    """Run the echo pass over a capture; return the addresses to treat as ours.

    Result: ``{"ips": [...], "evidence": [...hits...], "parse_error": str|None}``.
    ``ips`` is the union of echoed addresses and ``extra_ips`` /
    ``KWARA_INVESTIGATOR_IPS``; ``evidence`` says where each was seen.
    """
    hits: list[dict] = []
    parse_error = None
    if har_path and os.path.isfile(har_path):
        try:
            with open(har_path, encoding="utf-8", errors="replace") as f:
                har = json.load(f)
            hits += [dict(h, file=har_path) for h in echo_candidates_in_har(har)]
        except (json.JSONDecodeError, OSError) as e:
            parse_error = f"{har_path}: {e}"
    if html_path and os.path.isfile(html_path):
        try:
            with open(html_path, encoding="utf-8", errors="replace") as f:
                hits += [dict(h, file=html_path)
                         for h in echo_candidates_in_text(f.read())]
        except OSError as e:
            parse_error = f"{html_path}: {e}"
    ips = {h["ip"] for h in hits}
    ips.update(ip for ip in (extra_ips or []) + configured_ips() if _is_public(ip))
    return {"ips": sorted(ips), "evidence": hits, "parse_error": parse_error}


def count_occurrences(path: str, ips: list[str]) -> int:
    """The known pass: exact occurrences of every address anywhere in the file."""
    if not ips or not os.path.isfile(path):
        return 0
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    return sum(text.count(ip) for ip in ips)


def redact_file(path: str, ips: list[str], *, keep_original: bool = False) -> dict:
    """Replace every exact occurrence of each address in a text file.

    A HAR is re-parsed after substitution and the write is abandoned if it no
    longer parses. With ``keep_original`` the untouched bytes are kept beside
    the file as ``<name>.original-unredacted<ext>`` (never overwritten), for
    stores where a timestamp already binds the original.
    """
    if not ips or not os.path.isfile(path):
        return {"file": path, "replacements": 0, "skipped": True}
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    n = sum(text.count(ip) for ip in ips)
    if n == 0:
        return {"file": path, "replacements": 0, "skipped": True}
    new = text
    for ip in sorted(ips, key=len, reverse=True):  # longest first: no partial hits
        new = new.replace(ip, REDACTION_MARKER)
    if path.endswith(".har"):
        json.loads(new)  # raises before anything is written
    original = None
    if keep_original:
        base, ext = os.path.splitext(path)
        original = f"{base}.original-unredacted{ext}"
        if not os.path.exists(original):
            os.replace(path, original)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    remaining = sum(open(path, encoding="utf-8").read().count(ip) for ip in ips)
    return {"file": path, "replacements": n, "remaining": remaining,
            "original_kept_as": original, "skipped": False}


def scan_capture(har_path: str | None, html_path: str | None, *,
                 redact: bool, extra_ips: list[str] | None = None,
                 keep_original: bool = False) -> dict:
    """Discover, then (optionally) redact, one capture's HAR and HTML.

    Returns a JSON-serialisable summary suitable for storing on the snapshot
    row. ``screenshot_may_show_ip`` is set when the page body itself printed
    an address: pixels cannot be scanned, so that is a flag for a human.
    """
    disc = discover(har_path, html_path, extra_ips)
    files = [p for p in (har_path, html_path) if p and os.path.isfile(p)]
    occurrences = {p: count_occurrences(p, disc["ips"]) for p in files}
    result = {
        "ips": disc["ips"],
        "sources": sorted({h["where"] for h in disc["evidence"]}),
        "occurrences": sum(occurrences.values()),
        "files_affected": [p for p, n in occurrences.items() if n],
        "screenshot_may_show_ip": any(
            h["where"] == "text" and h.get("file") == html_path for h in disc["evidence"]),
        "redacted": False,
        "parse_error": disc["parse_error"],
    }
    if redact and result["files_affected"]:
        result["redaction"] = [redact_file(p, disc["ips"], keep_original=keep_original)
                               for p in result["files_affected"]]
        result["redacted"] = all(r["remaining"] == 0 for r in result["redaction"])
    return result
