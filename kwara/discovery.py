"""Candidate screening — the cheap first stage of a discovery funnel.

kwara's full pipeline (Playwright, HAR, cloaking double-fetch, WHOIS, certs,
corroboration) costs seconds and megabytes per URL, so it cannot be pointed at
a large candidate population. This module is the discriminator that decides
which candidates are worth that cost.

WHY ads.txt IS THE DISCRIMINATOR
  Of every signal kwara collects, ads.txt is the only one that is served from
  a *predictable path* (`/ads.txt`), is plain text, is usually a few KB, and
  needs no browser — so it can be swept at high concurrency for a fraction of
  the cost of one screenshot. It is also the one artifact a programmatic
  content farm cannot omit: without it the inventory does not sell.

WHAT ACTUALLY DISCRIMINATES (measured 2026-08-05, 31 apexes in the case DB)
  Exact template match works, and nothing else does yet:

    - byte-identical ads.txt clustered 14 of 31 apexes into 5 sibling groups
      (visitorlanding/crawlerlanding.example/crawlerlanding2.example; family1/family2/family3; triplet1{,2,3};
      farm2/farm5/farm6; farm3/farm4). Same bytes = same
      deployer, which is the one ads.txt signal clusters.py trusts to bind an
      operator group.

    - "shared RARE account" scoring FAILED and is deliberately not implemented
      here. Rarity was measured against the investigation corpus, and an
      investigation corpus is all suspects and far too small: bigpublisher1.example and
      bigpublisher2.example came out sharing 216 "rare" accounts purely because they carry
      the two fattest ads.txt files (1409 and 860 accounts) in a 31-domain
      pool. Any account on those two and nowhere else scores as rare. Until an
      external reference population is wired up — the SSP's own sellers.json,
      whose `seller_type` states PUBLISHER vs INTERMEDIARY outright — account
      overlap cannot separate "same operator" from "both are big publishers".

  So screening is exact-match only: high precision, and recall limited to
  siblings of templates already seen. That is an honest MVP, not the finished
  funnel. Candidates that do not match are reported as `no_match`, NOT as
  cleared — this stage can only promote, never exonerate.

Pure functions take an already-fetched ads.txt result so the scoring is
unit-testable offline; only `screen_domain` touches the network.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Iterable

from adstxt import _fetch_ads_txt
from config import ADS_TXT_TIMEOUT
from index_db import SIGNAL_ADS_TXT_TEMPLATE

# Screening outcomes. `no_match` means "this stage found nothing", never
# "this domain is clean" — see the module docstring.
VERDICT_TEMPLATE_MATCH = "template_match"
VERDICT_NO_MATCH = "no_match"
VERDICT_NO_ADS_TXT = "no_ads_txt"
VERDICT_UNREACHABLE = "unreachable"


def known_templates(index_conn: sqlite3.Connection) -> dict[str, list[str]]:
    """ads.txt sha256 → the domains already known to serve it.

    Reads the cross-case index, so a template observed in ANY past
    investigation screens candidates in the next one. This is the longitudinal
    advantage a local single-analyst tool has over a per-case service.
    """
    rows = index_conn.execute(
        "SELECT signal_value, final_domain FROM signals WHERE signal_type = ?",
        (SIGNAL_ADS_TXT_TEMPLATE,),
    ).fetchall()
    out: dict[str, set] = {}
    for r in rows:
        sha = (r["signal_value"] or "").strip()
        domain = (r["final_domain"] or "").strip().lower()
        if not sha:
            continue
        out.setdefault(sha, set())
        if domain:
            out[sha].add(domain)
    return {sha: sorted(ds) for sha, ds in out.items()}


def screen_ads_txt(ads: dict[str, Any] | None,
                   known: dict[str, list[str]]) -> dict[str, Any]:
    """Score one already-fetched ads.txt result against known templates.

    `ads` is an adstxt.py result dict (status / raw_sha256 / records). Pure —
    no network, no DB — so the decision rule is testable in isolation.
    """
    if not isinstance(ads, dict) or not ads.get("status"):
        return {"verdict": VERDICT_UNREACHABLE, "matched_sha": None,
                "matched_domains": [], "record_count": 0}

    status = ads.get("status")
    records = ads.get("records") or []
    sha = (ads.get("raw_sha256") or "").strip()

    if status != "ok" or not records:
        # A 403/404/redirect is not a miss to hide — the status is itself an
        # OPSEC signal (a farm behind a challenge still matters), so it is
        # reported distinctly rather than folded into no_match.
        return {"verdict": VERDICT_NO_ADS_TXT if status != "error"
                else VERDICT_UNREACHABLE,
                "matched_sha": None, "matched_domains": [],
                "record_count": len(records), "status": status}

    hit = known.get(sha)
    if hit:
        return {"verdict": VERDICT_TEMPLATE_MATCH, "matched_sha": sha,
                "matched_domains": list(hit), "record_count": len(records),
                "status": status}
    return {"verdict": VERDICT_NO_MATCH, "matched_sha": None,
            "matched_domains": [], "record_count": len(records),
            "status": status}


def screen_domain(domain: str, known: dict[str, list[str]], *,
                  timeout: int = ADS_TXT_TIMEOUT) -> dict[str, Any]:
    """Fetch one candidate's /ads.txt and screen it.

    OUTBOUND: this contacts the candidate directly from the analyst's network,
    exactly as the scan pipeline's ads.txt step does. It is one small GET per
    candidate and carries none of the case's indicators, but it is still a
    visit the target can log — callers screening a large list should say so.
    """
    domain = (domain or "").strip().lower().rstrip("/")
    if not domain:
        return {"domain": domain, "verdict": VERDICT_UNREACHABLE,
                "matched_sha": None, "matched_domains": [], "record_count": 0}
    url = domain if "://" in domain else f"https://{domain}/"
    try:
        ads = _fetch_ads_txt(url, timeout)
    except Exception:                       # network layer already soft-fails;
        ads = None                          # this is the belt-and-braces case
    return {"domain": domain, **screen_ads_txt(ads, known)}


def screen_domains(domains: Iterable[str], known: dict[str, list[str]], *,
                   timeout: int = ADS_TXT_TIMEOUT) -> list[dict[str, Any]]:
    """Screen a candidate list, template matches first."""
    results = [screen_domain(d, known, timeout=timeout) for d in domains]
    order = {VERDICT_TEMPLATE_MATCH: 0, VERDICT_NO_MATCH: 1,
             VERDICT_NO_ADS_TXT: 2, VERDICT_UNREACHABLE: 3}
    results.sort(key=lambda r: (order.get(r["verdict"], 9), r["domain"]))
    return results
