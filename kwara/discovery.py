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

import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from adstxt import parse_ads_txt
from config import (
    ADS_TXT_MAX_BYTES,
    ADS_TXT_TIMEOUT,
    DISCOVERY_MAX_REDIRECTS,
    DISCOVERY_WORKERS,
    SCANNER_USER_AGENT,
)
from index_db import SIGNAL_ADS_TXT_TEMPLATE
from utils.domain import extract_domain_from_url

# Screening outcomes. `no_match` means "this stage found nothing", never
# "this domain is clean" — see the module docstring.
VERDICT_TEMPLATE_MATCH = "template_match"
VERDICT_NO_MATCH = "no_match"
VERDICT_NO_ADS_TXT = "no_ads_txt"
VERDICT_OFF_SITE = "off_site_redirect"
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
        verdict = {"error": VERDICT_UNREACHABLE,
                   "off_site_redirect": VERDICT_OFF_SITE}.get(
                       status, VERDICT_NO_ADS_TXT)
        return {"verdict": verdict, "matched_sha": None,
                "matched_domains": [], "record_count": len(records),
                "status": status}

    hit = known.get(sha)
    if hit:
        return {"verdict": VERDICT_TEMPLATE_MATCH, "matched_sha": sha,
                "matched_domains": list(hit), "record_count": len(records),
                "status": status}
    return {"verdict": VERDICT_NO_MATCH, "matched_sha": None,
            "matched_domains": [], "record_count": len(records),
            "status": status}


def fetch_for_screening(domain: str, *,
                        timeout: int = ADS_TXT_TIMEOUT) -> dict[str, Any]:
    """Fetch a bare candidate domain's /ads.txt.

    Deliberately NOT adstxt._fetch_ads_txt. That one sets
    allow_redirects=False under contract 9, because on the scan path the
    canonical final_url is already resolved and following further redirects
    would capture an ads.txt belonging to a different host.

    A screening candidate is not resolved: it is a bare registrable domain out
    of a sellers.json listing, where apex -> www and http -> https redirects
    are entirely routine. Refusing to follow them would report a large share of
    ordinary sites as having no ads.txt, and at screening scale that recall
    loss defeats the purpose of the stage.

    So redirects ARE followed, but the final host must stay on the SAME
    registrable domain — which is the hazard contract 9 actually guards
    against. A redirect off-site is reported as `off_site_redirect`, never
    parsed: a farm parking its ads.txt request onto someone else's domain must
    not inherit that domain's template.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    candidate_apex = extract_domain_from_url(domain)
    url = f"https://{domain.rstrip('/')}/ads.txt" if "://" not in domain \
        else f"{domain.rstrip('/')}/ads.txt"

    session = requests.Session()
    session.max_redirects = DISCOVERY_MAX_REDIRECTS
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True,
                           headers={"User-Agent": SCANNER_USER_AGENT},
                           stream=True)
        body = bytearray()
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = ADS_TXT_MAX_BYTES - len(body)
            if remaining <= 0:
                break
            body.extend(chunk[:remaining])
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": str(exc)[:200], "url": url,
                "fetched_at": now}
    finally:
        session.close()

    landed_apex = extract_domain_from_url(resp.url or "")
    if candidate_apex and landed_apex and landed_apex != candidate_apex:
        return {"status": "off_site_redirect", "url": url,
                "landed_on": resp.url, "records": [], "record_count": 0,
                "fetched_at": now}

    body_bytes = bytes(body)
    out: dict[str, Any] = {"url": url, "status_code": resp.status_code,
                           "fetched_at": now,
                           "raw_sha256": hashlib.sha256(body_bytes).hexdigest()}
    if resp.status_code != 200:
        out.update({"status": "non_200", "records": [], "record_count": 0})
        return out
    records, _vars = parse_ads_txt(body_bytes.decode("utf-8", errors="replace"))
    out.update({"status": "ok", "records": records,
                "record_count": len(records)})
    return out


def screen_domain(domain: str, known: dict[str, list[str]], *,
                  timeout: int = ADS_TXT_TIMEOUT) -> dict[str, Any]:
    """Fetch one candidate's /ads.txt and screen it.

    OUTBOUND: this contacts the candidate directly from the analyst's network.
    It is one small GET per candidate and carries none of the case's
    indicators, but it is still a visit the target can log — callers screening
    a large list should say so out loud before starting.
    """
    domain = (domain or "").strip().lower().rstrip("/")
    if not domain:
        return {"domain": domain, "verdict": VERDICT_UNREACHABLE,
                "matched_sha": None, "matched_domains": [], "record_count": 0}
    try:
        ads = fetch_for_screening(domain, timeout=timeout)
    except Exception:                       # network layer already soft-fails;
        ads = None                          # this is the belt-and-braces case
    return {"domain": domain, **screen_ads_txt(ads, known)}


def screen_domains(domains: Iterable[str], known: dict[str, list[str]], *,
                   timeout: int = ADS_TXT_TIMEOUT,
                   workers: int = DISCOVERY_WORKERS,
                   on_result=None) -> list[dict[str, Any]]:
    """Screen a candidate list concurrently, template matches first.

    Bounded concurrency is what makes this a screening stage rather than an
    afternoon: sequentially, a five-figure candidate list would take hours. The
    bound is equally deliberate — these are unrelated third-party sites and the
    tool has no business hammering them. `on_result` is called per completed
    candidate so a long run can report progress.
    """
    domains = [d for d in ({(x or "").strip().lower() for x in domains}) if d]
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(screen_domain, d, known, timeout=timeout)
                   for d in domains]
        # as_completed, NOT map: map yields in submission order, so one slow
        # candidate stalls every completed result behind it and a long sweep
        # reports nothing for minutes while it is in fact working.
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception as exc:        # a worker must never kill the run
                r = {"domain": "", "verdict": VERDICT_UNREACHABLE,
                     "matched_sha": None, "matched_domains": [],
                     "record_count": 0, "status": f"error: {str(exc)[:120]}"}
            results.append(r)
            if on_result is not None:
                on_result(r)
    order = {VERDICT_TEMPLATE_MATCH: 0, VERDICT_NO_MATCH: 1,
             VERDICT_NO_ADS_TXT: 2, VERDICT_OFF_SITE: 3, VERDICT_UNREACHABLE: 4}
    results.sort(key=lambda r: (order.get(r["verdict"], 9), r["domain"]))
    return results
