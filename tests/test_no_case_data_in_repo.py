"""No identifier from a live investigation may appear in a tracked file.

This repository is public. It nonetheless carried, for months, the domains
under investigation, the tracking IDs and ad accounts binding them, and the
conclusions drawn from them — not as data files, which .gitignore can stop,
but as text inside source: real domains used as illustrative examples in
comments, and real domains used as fixtures in tests.

The comments were half-defensible. Recording WHY a threshold exists is what
stops the next person deleting it as unnecessary complexity. But the number
and the shape carry that reasoning; the real name never added anything. In the
tests there was no argument at all — a test needs *a* domain, not *that* one.

Care is not a control. This is the control: if anything in the live case
database or the cross-case index turns up in a tracked file, this test fails
before the commit is pushed, whoever wrote it.

It is a no-op on a machine with no case database, so it does not make the
suite depend on the analyst's private data.
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Public adtech infrastructure and standards bodies. These appear all over the
# code as adsystem identifiers and vendor hosts — they are what the tool
# ANALYSES, not who it is investigating, and a case database naturally
# contains them because the sites under investigation monetise through them.
VENDORS = frozenset({
    "google.com", "googletagmanager.com", "google-analytics.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "gstatic.com", "googleapis.com", "facebook.com", "facebook.net",
    "clickforce.com.tw", "breaktime.com.tw", "tenmax.io", "gliacloud.com",
    "gliastudios.com", "criteo.com", "taboola.com", "outbrain.com",
    "pubmatic.com", "rubiconproject.com", "openx.com", "appnexus.com",
    "smaato.com", "inmobi.com", "ucfunnel.com", "aralego.com", "innity.com",
    "kargo.com", "teads.tv", "media.net", "lijit.com", "adform.com",
    "yahoo.com", "contextweb.com", "smartadserver.com", "indexexchange.com",
    "sharethrough.com", "spotxchange.com", "onetag.com", "unrulymedia.com",
    "themediagrid.com", "improvedigital.com", "mgid.com", "adnxs.com",
    "casalemedia.com", "clarity.ms", "line.me", "cloudflare.com",
    "amazon-adsystem.com", "example.com", "archive.org", "urlscan.io",
    "github.com", "w3.org", "iabtechlab.com", "arxiv.org", "appier.net",
})

# Placeholder families the redaction introduced, plus synthetic fixture names.
_PLACEHOLDER = re.compile(
    r"^(redacted\d+|farm\d+|newfind\d+|sibling\d+|triplet\d+|family\d+|"
    r"visitor-landing|crawler-landing\d*|hub-site|satellite\d*-site|"
    r"operator-hub|blocked-site|sibling-site|private-cdn\d*|private-infra\d*|"
    r"bigpublisher\d+|callee-site|caller-site|news\d+|regional-news)"
    r"(\.|$)")


def _live_identifiers() -> set[str]:
    """Domains and tracking IDs from the analyst's own databases."""
    from kwara.config import DB_PATH, INDEX_DB_PATH
    from kwara.utils.domain import extract_domain_from_url

    out: set[str] = set()
    if os.path.isfile(DB_PATH):
        db = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        for (u,) in db.execute("SELECT original_url FROM url_artifacts"):
            out.add(extract_domain_from_url(u or ""))
        for (u,) in db.execute(
                "SELECT final_url FROM scan_runs WHERE final_url IS NOT NULL"):
            out.add(extract_domain_from_url(u or ""))
        db.close()
    if os.path.isfile(INDEX_DB_PATH):
        idx = sqlite3.connect(f"file:{INDEX_DB_PATH}?mode=ro", uri=True)
        for (d,) in idx.execute("SELECT DISTINCT final_domain FROM signals"):
            if d:
                out.add(extract_domain_from_url(d))
        for (v,) in idx.execute(
                "SELECT DISTINCT signal_value FROM signals "
                "WHERE signal_type IN ('tracking_id', 'gtm_container')"):
            if v:
                out.add(str(v))
        idx.close()

    return {x for x in out
            if x and x not in VENDORS and not _PLACEHOLDER.match(x)}


def _grep(needle: str) -> list[str]:
    """Tracked files containing `needle`, as a fixed string."""
    r = subprocess.run(["git", "grep", "-l", "--fixed-strings", "--", needle],
                       cwd=REPO, capture_output=True, text=True)
    return [f for f in r.stdout.split() if f]


@pytest.fixture(scope="module")
def identifiers():
    if not os.path.isdir(os.path.join(REPO, ".git")):
        pytest.skip("not a git checkout")
    ids = _live_identifiers()
    if not ids:
        pytest.skip("no live case database on this machine — nothing to leak")
    return ids


def test_no_live_domain_or_tracking_id_is_in_a_tracked_file(identifiers):
    """The whole point. A real identifier in tracked source is a disclosure,
    and this repository is public."""
    found = {}
    for ident in sorted(identifiers):
        hits = _grep(ident)
        if hits:
            found[ident] = hits
    assert not found, (
        "investigation identifiers are present in tracked files:\n"
        + "\n".join(f"  {k} → {', '.join(v)}" for k, v in found.items())
        + "\n\nUse a placeholder. The reasoning a comment records lives in the "
          "numbers and the shape, not in the name.")


def test_bare_site_names_are_caught_too(identifiers):
    """`blockedsite.com` redacted but `blockedsite` left behind is still a name. The
    first pass of this redaction missed exactly that."""
    # The stem of the REGISTRABLE domain, not of whatever subdomain happened
    # to be recorded: `redacted139.<site>.com` would otherwise contribute the
    # ordinary English word "redacted139" and flag every file that uses it.
    from kwara.utils.domain import extract_domain_from_url

    stems = set()
    for d in identifiers:
        apex = extract_domain_from_url(d) or d
        stem = apex.split(".")[0]
        if len(stem) >= 5:
            stems.add(stem)
    stems -= {v.split(".")[0] for v in VENDORS}
    # Ordinary words that happen to be somebody's domain. Matching these says
    # nothing about a disclosure and would make the guard unusable.
    stems -= {"redacted139", "news", "video", "health", "travel", "search",
              "share", "media", "daily", "world", "online", "mobile",
              "digital", "content", "network", "public", "server", "static"}
    found = {}
    for stem in sorted(stems):
        hits = [f for f in _grep(stem)
                # A stem that only appears as part of a longer word is not a
                # reference to the site.
                if _mentions_stem(os.path.join(REPO, f), stem)]
        if hits:
            found[stem] = hits
    assert not found, (
        "bare investigation site names are present in tracked files:\n"
        + "\n".join(f"  {k} → {', '.join(v)}" for k, v in found.items()))


def _mentions_stem(path: str, stem: str) -> bool:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return False
    return bool(re.search(r"(?<![A-Za-z0-9-])" + re.escape(stem)
                          + r"(?![A-Za-z0-9-])", text, re.IGNORECASE))


def test_no_evidence_file_is_tracked():
    """.gitignore covered kwara/data/*.db, snapshots/ and exports/ — but not
    `acquisitions/`, added on 2026-08-12 to retain response bytes. Three real
    sites' ads.txt bodies were committed before an audit caught it. A pattern
    list only protects the directories someone remembered."""
    if not os.path.isdir(os.path.join(REPO, ".git")):
        pytest.skip("not a git checkout")
    r = subprocess.run(["git", "ls-files", "kwara/data/", "discovery/"],
                       cwd=REPO, capture_output=True, text=True)
    assert not r.stdout.split(), (
        "evidence files are tracked: " + r.stdout)


def test_the_guard_can_actually_fail():
    """A check that cannot fail is not a check.

    The absent needle is assembled at runtime: written as a literal it would
    be IN this file, so the guard would correctly find it and the test would
    fail for the one reason that proves nothing.
    """
    assert _grep("kwara"), "git grep found nothing at all — is it working?"
    absent = "zz" + "not-present-anywhere" + "-" + str(0xDEADBEEF)
    assert not _grep(absent)
