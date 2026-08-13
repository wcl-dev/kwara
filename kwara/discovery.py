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
import json
import os
import re
import secrets
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .adstxt import parse_ads_txt
from .config import (
    ADS_TXT_MAX_BYTES,
    ADS_TXT_PLATFORM_ACCOUNTS,
    ADS_TXT_TIMEOUT,
    DISCOVERY_MAX_REDIRECTS,
    DISCOVERY_WORKERS,
    SCANNER_USER_AGENT,
)
from .index_db import SIGNAL_ADS_TXT_TEMPLATE
from .utils.domain import extract_domain_from_url

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

    # status_code travels with every verdict: a 403 (an active block, often a
    # challenge page) and a 404 (simply no file) mean very different things,
    # and folding both into one bucket loses the OPSEC signal that motivated
    # separating them in the first place.
    base = {"status": status, "status_code": ads.get("status_code"),
            "owner_domain": ads.get("owner_domain"),
            "manager_domain": ads.get("manager_domain")}

    if status != "ok" or not records:
        # A 403/404/redirect is not a miss to hide — the status is itself an
        # OPSEC signal (a farm behind a challenge still matters), so it is
        # reported distinctly rather than folded into no_match.
        verdict = {"error": VERDICT_UNREACHABLE,
                   "off_site_redirect": VERDICT_OFF_SITE}.get(
                       status, VERDICT_NO_ADS_TXT)
        return {"verdict": verdict, "matched_sha": None,
                "matched_domains": [], "record_count": len(records), **base}

    hit = known.get(sha)
    if hit:
        return {"verdict": VERDICT_TEMPLATE_MATCH, "matched_sha": sha,
                "matched_domains": list(hit), "record_count": len(records),
                **base}
    return {"verdict": VERDICT_NO_MATCH, "matched_sha": None,
            "matched_domains": [], "record_count": len(records), **base}


def cluster_by_template(observations: Iterable[dict[str, Any]]) -> list[dict]:
    """Group candidates that serve a byte-identical ads.txt as EACH OTHER.

    Screening asks "does this candidate match something we already know",
    which is bounded by how big the known set is — 6 templates screening 9,501
    candidates found one sibling. This asks the self-referential question
    instead: which candidates share a file with one another? It needs no prior
    knowledge of any domain, and on the 2026-08-05 sweep it surfaced 54
    operator-portfolio clusters over 188 domains against that same one hit.

    Two guards, both learned the hard way on that data:

    empty templates — six clusters covering 121 domains shared a byte-identical
    ads.txt that declared NO DIRECT accounts. An empty or boilerplate file is
    common to countless unrelated parked domains and says nothing about a
    deployer, so those are dropped outright.

    platform-generated templates — 31 clusters carried 300+ accounts each.
    A byte-identical 900-account file across five sites is a monetisation
    platform emitting the same file for its clients, not one operator running
    five sites. Those are returned but flagged `platform`, because "same bytes
    = same deployer" holds while the deployer may be a platform rather than
    the site owner.

    `observations` are screening results carrying `domain`, `raw_sha256` and
    `records` (or `record_count`). Returns clusters of 2+ domains, largest
    first.
    """
    by_sha: dict[str, set] = defaultdict(set)
    accounts: dict[str, int] = {}
    for o in observations:
        sha = (o.get("raw_sha256") or o.get("sha") or "").strip()
        domain = (o.get("domain") or "").strip().lower()
        if not sha or not domain or o.get("status") != "ok":
            continue
        by_sha[sha].add(domain)
        recs = o.get("records")
        n = len(recs) if recs is not None else (o.get("record_count") or 0)
        accounts[sha] = max(accounts.get(sha, 0), n)

    out: list[dict] = []
    for sha, domains in by_sha.items():
        if len(domains) < 2 or accounts.get(sha, 0) < 1:
            continue                      # singleton, or a shared empty file
        out.append({
            "sha256": sha,
            "sha256_short": sha[:12],
            "domains": sorted(domains),
            "domain_count": len(domains),
            "account_count": accounts[sha],
            "kind": ("platform" if accounts[sha] >= ADS_TXT_PLATFORM_ACCOUNTS
                     else "portfolio"),
        })
    out.sort(key=lambda c: (c["kind"] != "portfolio", -c["domain_count"],
                            c["sha256"]))
    return out


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
        truncated = False
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = ADS_TXT_MAX_BYTES - len(body)
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                truncated = True
            body.extend(chunk[:remaining])
    except requests.exceptions.RequestException as exc:
        return {"status": "error", "error": str(exc)[:200], "url": url,
                "fetched_at": now}
    finally:
        session.close()

    landed_apex = extract_domain_from_url(resp.url or "")
    if candidate_apex and landed_apex and landed_apex != candidate_apex:
        return {"status": "off_site_redirect", "url": url,
                # Retained like any other response. A farm parking its ads.txt
                # request on someone else's domain is doing something worth
                # keeping the evidence of, and the body is what shows what it
                # served.
                "_body": bytes(body) if body else b"",
                "_final_url": getattr(resp, "url", url),
                "landed_on": resp.url, "records": [], "record_count": 0,
                "fetched_at": now}

    body_bytes = bytes(body)
    # A hash over a TRUNCATED body is not the file's hash. Template matching
    # treats an equal sha256 as byte-identity, the strongest claim this tool
    # makes about shared operation — two files sharing a 256 KB prefix and
    # differing after it would be reported as the same deployment. So a
    # truncated read reports no hash at all rather than a misleading one.
    out: dict[str, Any] = {"url": url, "status_code": resp.status_code,
                           "fetched_at": now, "truncated": truncated,
                           "raw_sha256": (None if truncated
                                          else hashlib.sha256(body_bytes).hexdigest()),
                           # Carried out so the caller can retain it. This is
                           # the path the blockedsite.example observation came down:
                           # the bytes were read, hashed, parsed and dropped,
                           # and the site began refusing requests the next day.
                           "_body": body_bytes,
                           "_final_url": getattr(resp, "url", url)}
    if resp.status_code != 200:
        out.update({"status": "non_200", "records": [], "record_count": 0})
        return out
    records, variables = parse_ads_txt(body_bytes.decode("utf-8", errors="replace"))
    out.update({"status": "ok", "records": records,
                "record_count": len(records),
                # ads.txt's own self-declared ownership fields. Kept because
                # they are a first-party claim about who runs and who monetises
                # the site — the one ownership lead left after sellers.json
                # turned out to redact or omit exactly the small operators.
                "owner_domain": variables.get("owner_domain"),
                "manager_domain": variables.get("manager_domain")})
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
                "matched_sha": None, "matched_domains": [], "record_count": 0,
                "raw_sha256": None, "accounts": []}
    try:
        ads = fetch_for_screening(domain, timeout=timeout)
    except Exception:                       # network layer already soft-fails;
        ads = None                          # this is the belt-and-braces case
    ads = ads or {}
    # The parsed accounts travel with the verdict rather than being dropped.
    # The sweep pays for this data either way — it is the reference population
    # and the input to self-clustering — and twice during the 2026-08-05 run it
    # was parsed and thrown away, costing a full re-sweep each time. Keeping it
    # must not depend on the caller remembering to ask.
    accounts = sorted({(str(r.get("adsystem") or "").lower(),
                        str(r.get("seller_id") or "").strip())
                       for r in (ads.get("records") or [])
                       if (r.get("relationship") or "").upper() == "DIRECT"
                       and r.get("adsystem") and r.get("seller_id")})
    return {"domain": domain, **screen_ads_txt(ads or None, known),
            "raw_sha256": ads.get("raw_sha256"),
            "accounts": [list(a) for a in accounts],
            "status_code": ads.get("status_code"),
            "fetched_at": ads.get("fetched_at"),
            "truncated": bool(ads.get("truncated")),
            "final_url": ads.get("_final_url"),
            # Stripped by the banking layer once written to disk; never
            # serialised into the JSONL.
            "_body": ads.get("_body")}


def bank_body(bank_path: str, domain: str, body: bytes) -> tuple[str, str]:
    """Write one screened response beside the run's JSONL.

    The bodies live in a sibling directory named for the run, so a run and its
    evidence move together. Returns (relative path, sha256 of what was
    written) for recording in the observation.
    """
    root = os.path.splitext(bank_path)[0] + ".bodies"
    os.makedirs(root, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:80] or "candidate"
    for _ in range(8):
        name = f"{safe}_{secrets.token_hex(3)}.body"
        path = os.path.join(root, name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
        return os.path.join(os.path.basename(root), name), \
            hashlib.sha256(body).hexdigest()
    raise RuntimeError(f"could not allocate a body file under {root}")


def reserve_run(bank: str | None = None):
    """Reserve a run file and RETURN THE OPEN HANDLE.

    `open_run` closes its exclusive descriptor and hands back a pathname, so a
    caller reopening that name races anything that swaps a symlink in between.
    Keeping the descriptor removes the window entirely: the writer holds the
    file it reserved, whatever later happens to the name.
    """
    path = open_run(bank)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND
                 | getattr(os, "O_NOFOLLOW", 0))
    return path, os.fdopen(fd, "w", encoding="utf-8")


def open_run(bank: str | None = None) -> str:
    """Allocate the directory a sweep writes into, BEFORE any request goes out.

    Two properties, both learned the hard way:

    * BANKING IS NOT OPTIONAL. `--bank` was documented as the default and was
      not one: omit it and the sweep's raw hashes and account lists were gone,
      leaving the clustering stage nothing to work with. The historical proof
      is on disk — `screen_results.jsonl` carries no `raw_sha256`, so
      clustering it today returns nothing, and round 1's 54 clusters survive
      only because a second file happened to be written separately.
    * A RUN IS IMMUTABLE. The old path opened the destination with mode "w",
      so pointing a second sweep at the same file silently destroyed the
      first. Naming a destination that already exists is now refused here, at
      allocation time — before a single candidate has been contacted, so the
      refusal costs no outbound requests.
    """
    if bank:
        parent = os.path.dirname(os.path.abspath(bank))
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            # Creating the file IS the reservation. Checking existence and then
            # opening leaves a window in which the file can appear — or be
            # replaced by a symlink pointing at something the sweep would then
            # overwrite. O_EXCL|O_NOFOLLOW closes both.
            os.close(os.open(bank, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o644))
        except FileExistsError:
            raise ValueError(
                f"{bank} already exists. A sweep is an immutable record; "
                f"name a new destination or omit --bank for an auto-named "
                f"run.") from None
        return bank

    from . import config as _cfg
    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S")
    root = os.path.join(_cfg.DATA_DIR, "discovery-runs")
    os.makedirs(root, exist_ok=True)
    for _ in range(8):
        path = os.path.join(root, f"{stamp}-{secrets.token_hex(3)}.jsonl")
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644))
        except FileExistsError:
            continue
        return path
    raise RuntimeError(f"could not allocate a run file under {root}")


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
    # Dedup while PRESERVING caller order. A set comprehension here silently
    # discarded it, so a caller that had deliberately put its most relevant
    # candidates first (e.g. .tw domains ahead of 9k international ones) got
    # them scattered at random through a half-hour sweep.
    seen: set[str] = set()
    ordered: list[str] = []
    for x in domains:
        d = (x or "").strip().lower()
        if d and d not in seen:
            seen.add(d)
            ordered.append(d)
    domains = ordered
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


def candidates_from_sellers_json(paths: Iterable[str]) -> list[str]:
    """Registrable domains listed as publishers in SSPs' sellers.json files.

    The candidate population for a sweep. sellers.json is the mirror image of
    ads.txt — it sits on the SSP and names the publishers it works with, so one
    public file yields thousands of candidates without a crawl.

    Choose the SSPs deliberately: on the 2026-08-05 sweeps the large exchanges
    served mainstream publishers alongside the targets and diluted the pool
    (9,501 candidates, 1 find), while a small regional SSP ran 39% .tw
    (666 candidates, 2 finds). Obscure and frequent in your known targets'
    ads.txt beats big.
    """
    out: set[str] = set()
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, ValueError):
            continue
        for seller in (blob.get("sellers") or []):
            raw = (seller.get("domain") or "").strip().lower()
            if not raw:
                continue                    # is_confidential entries land here
            apex = extract_domain_from_url(raw)
            if apex:
                out.add(apex)
    return sorted(out)


def build_prevalence(observations: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Reference table: how many sites carry each DIRECT account.

    Built from a sweep's own observations, so the population is whatever was
    swept — record that in `source` and keep it honest, because the table's
    whole job is to be an OUTSIDE population. Feeding it an investigation's own
    domains would rebuild the very bias it exists to remove.
    """
    # Count DISTINCT (site, account) pairs. Counting observations meant a
    # domain banked twice — a resumed sweep, two concatenated runs — inflated
    # its accounts while `site_count` deduplicated, producing ratios above 1.0
    # and silently demoting genuinely rare accounts to manager.
    seen: set[tuple[str, str]] = set()
    counts: dict[str, int] = defaultdict(int)
    sites: set[str] = set()
    for o in observations:
        if o.get("status") != "ok":
            continue
        domain = (o.get("domain") or "").strip().lower()
        if not domain:
            continue
        sites.add(domain)
        for acct in (o.get("accounts") or []):
            if len(acct) == 2 and all(acct):
                key = f"{str(acct[0]).lower()}|{str(acct[1]).strip()}"
                if (domain, key) in seen:
                    continue
                seen.add((domain, key))
                counts[key] += 1
    return {
        "schema": "kwara-ads-prevalence/1",
        "site_count": len(sites),
        "note": "count = number of reference sites carrying this DIRECT account",
        "accounts": dict(sorted(counts.items(), key=lambda kv: -kv[1])),
    }
