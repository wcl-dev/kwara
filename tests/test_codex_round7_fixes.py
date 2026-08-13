"""Regressions from the 2026-08-07 codex review (round 7).

Grouped here because they share a theme: each was a place where the tool
claimed more than the data supported, or where a guard meant to protect
evidence could damage it.
"""
import json
import os
import tempfile

import pytest

from kwara import prevalence
from kwara.discovery import VERDICT_TEMPLATE_MATCH, build_prevalence, screen_ads_txt
from kwara.utils.domain import extract_domain_from_url


# ── #2 registrable domain ──────────────────────────────────────────────────

def test_hosting_tenants_are_not_collapsed_into_one_asset():
    """tldextract excludes the PSL private section by default, so two unrelated
    GitHub Pages tenants both reduced to github.io. That let an off-site
    redirect pass the same-domain check, merged unrelated tenants when counting
    an account's footprint, and let operator_cross_links report a tenancy
    coincidence as a threshold-free link."""
    assert extract_domain_from_url("alice.github.io") != \
        extract_domain_from_url("bob.github.io")
    assert extract_domain_from_url("a.blogspot.com") != \
        extract_domain_from_url("b.blogspot.com")
    # ordinary sites are unaffected
    assert extract_domain_from_url("www.foo.com") == "foo.com"
    assert extract_domain_from_url("static.cdn-host.com") == "cdn-host.com"


def test_unicode_and_punycode_forms_are_one_host():
    """A Unicode name and the ASCII form a library produced for the same site
    must compare equal, or an on-site redirect reads as off-site."""
    assert extract_domain_from_url("bücher.de") == \
        extract_domain_from_url("xn--bcher-kva.de")


# ── #4 truncation ──────────────────────────────────────────────────────────

def test_truncated_body_cannot_claim_byte_identity():
    """Template matching treats an equal sha256 as byte-identity — the
    strongest claim this tool makes. A hash over a 256 KB prefix is not the
    file's hash, so a truncated read reports no hash rather than a wrong one."""
    known = {"SHA_FARM": ["visitor-landing.example"]}
    truncated = {"status": "ok", "raw_sha256": None, "truncated": True,
                 "status_code": 200, "records": [{"a": 1}]}
    assert screen_ads_txt(truncated, known)["verdict"] != VERDICT_TEMPLATE_MATCH


# ── #9 prevalence counting ─────────────────────────────────────────────────

def test_prevalence_counts_sites_not_observations():
    """A domain banked twice — a resumed sweep, two concatenated runs —
    inflated its accounts while site_count deduplicated, giving ratios above
    1.0 and demoting genuinely rare accounts to manager."""
    table = build_prevalence([
        {"domain": "a.com", "status": "ok", "accounts": [["x.com", "1"]]},
        {"domain": "a.com", "status": "ok", "accounts": [["x.com", "1"]]},
        {"domain": "b.com", "status": "ok", "accounts": []},
    ])
    assert table["site_count"] == 2
    assert table["accounts"]["x.com|1"] == 1      # one SITE carries it


# ── #13 corrupt table must degrade, not crash ─────────────────────────────

def _table(accounts, site_count=100):
    path = os.path.join(tempfile.mkdtemp(), "prev.json")
    with open(path, "w") as fh:
        json.dump({"schema": prevalence.SCHEMA, "site_count": site_count,
                   "accounts": accounts}, fh)
    return path


@pytest.mark.parametrize("accounts", [
    {"x.com|1": "10"},        # string where an int belongs
    {"x.com|1": -5},          # negative
    {"x.com|1": 500},         # more carriers than sites
    {"x.com|1": True},        # bool is an int subclass; not a count
])
def test_schema_valid_but_nonsense_table_is_refused(accounts):
    """The promise is that a missing or corrupt table falls back to
    thresholds. Loading it and raising TypeError deep inside tier analysis is
    the opposite of that."""
    assert prevalence.load(_table(accounts)) is None


def test_a_sane_table_still_loads():
    p = prevalence.load(_table({"x.com|1": 30}, site_count=100))
    assert p is not None and p.ratio("x.com", "1") == 0.3


# ── #7 capture directories are allocated exclusively ──────────────────────

def test_capture_dirs_are_never_reused():
    """exist_ok=True silently accepted a collision between two captures in the
    same microsecond with the same 16-bit suffix; both then wrote the same
    fixed filenames and an older snapshot row pointed at overwritten bytes."""
    from kwara.snapshots import _per_capture_dir
    import shutil
    dirs = {_per_capture_dir(999999) for _ in range(25)}
    assert len(dirs) == 25
    shutil.rmtree(os.path.dirname(next(iter(dirs))))
