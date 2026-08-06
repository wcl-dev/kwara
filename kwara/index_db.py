"""Cross-case signal index (Phase 5.1).

A central SQLite DB (default ``~/.kwara/index.db``) that accumulates strong
operator-attribution signals across every case the analyst indexes — even
cases that live in *different* kwara DB files. It answers the question a
per-case tool cannot: **"have I seen this GA4 ID / cert serial / registrar /
ASN / domain before, and in which case?"**

This is the payoff for kwara's single-user-local-SQLite bet: an analyst's
accumulated history is something no multi-tenant SaaS can build, because it
requires *being* that analyst across every investigation.

Design notes
------------
* The index is a SEPARATE DB from any case DB, so it spans multiple case
  files. Provenance (``source_db`` path + ``case_id`` + ``scan_run_id``)
  points back to the originating evidence.
* Even SINGLETON signals are indexed — a value seen once in case A and once
  in case B is exactly the cross-case match we want. We do NOT pre-cluster.
* Indexing a case is a FULL REFRESH for that (source_db, case_id): prior
  rows are deleted then re-inserted, so re-indexing an updated case is
  idempotent and drops signals that no longer appear.
* Read-only on the case DB; only the index DB is written.

Known limitation — surveys indexed as investigations
----------------------------------------------------
The index assumes every case is an investigation: a set of URLs with a
provenance chain back to where a victim would have met them. It has no notion
of a SURVEY — a domain list swept for characterisation, with no source post
and no deep link. Case 5 in the QSH DB is one (45 bare homepages, zero
permalinks), and because its domains overlap the investigations it was built
from, the same observation lands under two case_ids and `recurring_signals`
reports it as a cross-case recurrence. Measured 2026-08-05: 99 of 119
recurring ads.txt accounts sat on a single domain that way, and cert_serial
showed 12 where only 2 were real.

Read `domain_count` to tell them apart — a signal on 2+ distinct domains has
genuinely resurfaced. Adding a case type would fix it properly, but this is a
stock problem rather than a flow one: since 2026-08-06 that kind of sweep runs
through `kwara discover`, which characterises a domain list without writing
into the case DB or this index at all.

Public surface:
  get_index_conn(path)                 connect + init the central index DB
  extract_case_signals(conn, case_id, source_db, case_title)
                                       pure extraction — list[signal dict]
  index_case(index_conn, case_conn, source_db, case_id, case_title)
                                       full-refresh upsert; returns row count
  lookup(index_conn, value, signal_type=None)
                                       every occurrence of a value
  recurring_signals(index_conn, min_cases=2)
                                       signals spanning >= min_cases cases
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from config import ADS_TXT_INDEX_MAX_CARRIER_ACCOUNTS, ADS_TXT_MANAGER_BREADTH
from clustering_infra import (MAJOR_AD_EXCHANGES, _is_noise_endpoint,
                              shared_ad_accounts)
from utils.domain import extract_domain_from_url
from sql import LATEST_DONE_SCAN_RUN, latest_usable_snapshot

# Signal type tags. Stable strings — stored in the DB and matched on lookup.
SIGNAL_TRACKING_ID     = "tracking_id"
SIGNAL_CERT_SERIAL     = "cert_serial"
SIGNAL_REGISTRAR       = "registrar"
SIGNAL_ASN             = "asn"
SIGNAL_FINAL_DOMAIN    = "final_domain"
SIGNAL_ADS_TXT_SELLER  = "ads_txt_seller"    # DIRECT account, operator-tier only
SIGNAL_ADS_TXT_TEMPLATE = "ads_txt_template"  # raw ads.txt sha256
SIGNAL_ADS_TXT_OWNER   = "ads_txt_owner"     # OWNERDOMAIN — declared site owner
SIGNAL_ADS_TXT_MANAGER = "ads_txt_manager"   # MANAGERDOMAIN — declared monetiser
SIGNAL_HAR_ENDPOINT    = "har_endpoint"      # third party a landing page called

# Every type this module emits. Kept complete because `index lookup --type`
# validates against it — a typo there used to return an empty result set that
# was indistinguishable from "never seen", which is the wrong answer to a
# question about whether evidence exists.
ALL_SIGNAL_TYPES = frozenset({
    SIGNAL_TRACKING_ID,
    SIGNAL_CERT_SERIAL,
    SIGNAL_REGISTRAR,
    SIGNAL_ASN,
    SIGNAL_FINAL_DOMAIN,
    SIGNAL_ADS_TXT_SELLER,
    SIGNAL_ADS_TXT_TEMPLATE,
    SIGNAL_ADS_TXT_OWNER,
    SIGNAL_ADS_TXT_MANAGER,
    SIGNAL_HAR_ENDPOINT,
})


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Index DB connection + schema
# ---------------------------------------------------------------------------

def get_index_conn(db_path: str) -> sqlite3.Connection:
    """Open (creating if needed) the central index DB and ensure its schema."""
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _init_index(conn)
    return conn


def _init_index(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS signals (
        signal_type   TEXT NOT NULL,
        signal_value  TEXT NOT NULL,
        platform      TEXT,            -- sub-type / context (GA4 / cert issuer / as_org)
        source_db     TEXT NOT NULL,   -- absolute path of the originating kwara DB
        case_id       INTEGER NOT NULL,
        case_title    TEXT,
        scan_run_id   INTEGER NOT NULL,
        final_domain  TEXT,            -- which landing this signal was seen on
        observed_at   TEXT,            -- when the evidence was captured (scan run_at)
        indexed_at    TEXT NOT NULL,
        PRIMARY KEY (signal_type, signal_value, source_db, case_id, scan_run_id)
    );
    CREATE INDEX IF NOT EXISTS idx_signal_lookup
        ON signals(signal_type, signal_value);
    CREATE INDEX IF NOT EXISTS idx_signal_value
        ON signals(signal_value);
    CREATE INDEX IF NOT EXISTS idx_signal_case
        ON signals(source_db, case_id);
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Extraction (pure read over a case DB — testable without the index)
# ---------------------------------------------------------------------------

def extract_case_signals(
    conn: sqlite3.Connection,
    case_id: int,
    source_db: str,
    case_title: str = "",
) -> list[dict]:
    """Extract every indexable signal for a case from its kwara DB.

    Returns a list of signal dicts ready for insertion. Singletons included —
    cross-case matching is the whole point. Pure read; no index DB involved.
    """
    out: list[dict] = []
    indexed_at = _now()

    def _emit(stype, value, *, platform, scan_run_id, final_domain, observed_at):
        value = (value or "").strip()
        if not value:
            return
        out.append({
            "signal_type":  stype,
            "signal_value": value,
            "platform":     (platform or "").strip() or None,
            "source_db":    source_db,
            "case_id":      case_id,
            "case_title":   case_title,
            "scan_run_id":  scan_run_id,
            "final_domain": (final_domain or "").strip() or None,
            "observed_at":  observed_at,
            "indexed_at":   indexed_at,
        })

    # ── scan_run-level signals: cert serial, registrar, ASN, final domain ──
    scan_rows = conn.execute(
        f"""SELECT sr.id AS scan_run_id, sr.run_at, sr.final_url,
                   sr.tls_info_json, sr.whois_registrar, sr.asn, sr.as_org
            FROM url_artifacts ua
            JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
            WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    for r in scan_rows:
        domain = (urlparse(r["final_url"] or "").hostname or "").lower()
        observed = r["run_at"]
        srid = r["scan_run_id"]

        # final domain
        _emit(SIGNAL_FINAL_DOMAIN, domain, platform=None,
              scan_run_id=srid, final_domain=domain, observed_at=observed)

        # registrar
        _emit(SIGNAL_REGISTRAR, r["whois_registrar"], platform=None,
              scan_run_id=srid, final_domain=domain, observed_at=observed)

        # ASN (platform = AS org for display)
        _emit(SIGNAL_ASN, r["asn"], platform=r["as_org"],
              scan_run_id=srid, final_domain=domain, observed_at=observed)

        # cert serial (platform = issuer)
        if r["tls_info_json"]:
            try:
                tls = json.loads(r["tls_info_json"])
            except (ValueError, TypeError):
                tls = None
            if isinstance(tls, dict):
                serial = (tls.get("serialNumber") or "").strip()
                issuer = _issuer_text(tls.get("issuer"))
                _emit(SIGNAL_CERT_SERIAL, serial, platform=issuer,
                      scan_run_id=srid, final_domain=domain, observed_at=observed)

    # ── snapshot-level signals: tracking IDs (latest usable snapshot) ──────
    pixel_rows = conn.execute(
        f"""SELECT sr.id AS scan_run_id, sr.run_at,
                   s.tracking_ids_json,
                   COALESCE(s.final_domain, '') AS final_domain
            FROM url_artifacts ua
            JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
            JOIN snapshots s ON s.id = {latest_usable_snapshot("tracking_ids_json")}
            WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    for r in pixel_rows:
        try:
            ids_by_platform = json.loads(r["tracking_ids_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(ids_by_platform, dict):
            continue
        domain = (r["final_domain"] or "").lower()
        for platform, ids in ids_by_platform.items():
            if not isinstance(ids, list):
                continue
            for ident in ids:
                _emit(SIGNAL_TRACKING_ID, ident, platform=platform,
                      scan_run_id=r["scan_run_id"], final_domain=domain,
                      observed_at=r["run_at"])

    # ── scan_run-level signals: ads.txt monetisation (Phase 8) ─────────────
    # Two signal kinds:
    #   ads_txt_seller   — DIRECT seller account, but ONLY operator-tier ones.
    #                      A handful of accounts shared by *every* domain is a
    #                      shared monetisation manager; indexing those would
    #                      flood recurring_signals with manager-wide noise.
    #                      Rare accounts (incl. case-singletons) ARE indexed —
    #                      cross-case recurrence of a rare money account is
    #                      exactly the operator signal we want — but only when
    #                      their CARRIER is not itself running a full
    #                      programmatic stack (floor D below). A singleton is
    #                      invisible to the tier machinery, so without that
    #                      floor a large publisher's whole supply chain enters
    #                      the index as "rare".
    #   ads_txt_template — the raw ads.txt sha256, one per domain. Cross-case
    #                      identical templates = operator reused the same file.
    #   ads_txt_owner    — OWNERDOMAIN, ads.txt's own declaration of who owns
    #   ads_txt_manager  — MANAGERDOMAIN, and of who monetises the inventory.
    #                      Both are hubs in the same sense a tracking ID is:
    #                      one value spanning many domains, stable across
    #                      cases, and stated by a first party. Ungated —
    #                      a site declares at most one of each and only ~14%
    #                      declare any, so there is no flood to guard against,
    #                      unlike the accounts above.
    # ── snapshot-level signals: third-party endpoints from HAR ─────────────
    # A hostname a landing page called is an IDENTIFIER, so unlike a cloaking
    # verdict or an OPSEC level it can match across cases at all. Stored as the
    # REGISTRABLE domain, not the hostname: SSPs and CDNs hand out per-request
    # subdomains (UUID-prefixed `t.ssp.*`, `rr2---sn-*.googlevideo.com`), which
    # are rare by construction and meaningless. Normalising collapsed 402
    # hostnames to 180 apexes on the 2026-08-06 corpus and removed that noise
    # class entirely.
    #
    # HONEST LIMIT: most of what this records is ad-tech a page happened to
    # load, not operator-run infrastructure. Rarity does not separate the two —
    # an investigation corpus is all suspects, and the endpoints that look rare
    # here are simply DSPs only one landing page happened to call. The index
    # remembers; judging is the analyst's, at query time, with domain_count.
    for r in conn.execute(
        f"""SELECT s.final_domain, s.request_domains_json, sr.id AS scan_run_id,
                   sr.run_at
              FROM url_artifacts ua
              JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
              JOIN snapshots s ON s.scan_run_id = sr.id
             WHERE ua.case_id = ?
               AND s.request_domains_json IS NOT NULL
               AND TRIM(s.request_domains_json) != ''""",
        (case_id,),
    ).fetchall():
        landing = (r["final_domain"] or "").lower()
        landing_apex = extract_domain_from_url(landing)
        if not landing_apex:
            continue
        try:
            hosts = json.loads(r["request_domains_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(hosts, list):
            continue
        for raw in hosts:
            host = (raw or "").strip().lower()
            if not host or _is_noise_endpoint(host):
                continue
            ep = extract_domain_from_url(host)
            # Self-reference by APEX — the hostname test in shared_endpoints
            # misses statics.hubsite.example when the landing is www.hubsite.example.
            if not ep or ep == landing_apex:
                continue
            _emit(SIGNAL_HAR_ENDPOINT, ep, platform=None,
                  scan_run_id=r["scan_run_id"], final_domain=landing,
                  observed_at=r["run_at"])

    ads_rows = conn.execute(
        f"""SELECT sr.id AS scan_run_id, sr.run_at, sr.final_url, sr.ads_txt_json
            FROM url_artifacts ua
            JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
            WHERE ua.case_id = ?
              AND sr.ads_txt_json IS NOT NULL
              AND TRIM(sr.ads_txt_json) != ''""",
        (case_id,),
    ).fetchall()

    # First pass: per-account domain breadth across the case.
    parsed_ads: list[tuple] = []  # (scan_run_id, run_at, domain, ads_dict)
    case_ads_domains: set[str] = set()
    account_domains: dict[tuple[str, str], set] = defaultdict(set)
    domain_accounts: dict[str, set] = defaultdict(set)   # carrier breadth
    for r in ads_rows:
        try:
            ads = json.loads(r["ads_txt_json"])
        except (ValueError, TypeError):
            continue
        if not isinstance(ads, dict):
            continue
        domain = (urlparse(r["final_url"] or "").hostname or "").lower()
        if not domain:
            continue
        parsed_ads.append((r["scan_run_id"], r["run_at"], domain, ads))
        records = ads.get("records") or []
        if ads.get("status") == "ok" and records:
            case_ads_domains.add(domain)
        for rec in records:
            if (rec.get("relationship") or "").upper() != "DIRECT":
                continue
            adsystem = (rec.get("adsystem") or "").lower()
            seller_id = (rec.get("seller_id") or "").strip()
            if adsystem and seller_id:
                account_domains[(adsystem, seller_id)].add(domain)
                domain_accounts[domain].add((adsystem, seller_id))

    denom = len(case_ads_domains) or 1

    # Operator-tier filter — defer to shared_ad_accounts (single source of
    # truth: breadth + major-exchange floor + template-overlap demotion). Any
    # multi-domain account it did NOT call operator is excluded here too, so
    # the index never recurs MFA/reseller noise (criteo/openx/…) across cases.
    _ads_clusters = shared_ad_accounts(conn, case_id)
    _demoted_multi = {(a["adsystem"], a["seller_id"])
                      for a in _ads_clusters["by_account"]
                      if a["tier"] != "operator"}

    # Second pass: emit, applying the operator-tier filter to accounts.
    for srid, run_at, domain, ads in parsed_ads:
        sha = (ads.get("raw_sha256") or "").strip()
        if sha and ads.get("status") == "ok" and (ads.get("records") or []):
            _emit(SIGNAL_ADS_TXT_TEMPLATE, sha, platform=None,
                  scan_run_id=srid, final_domain=domain, observed_at=run_at)
        for stype, key in ((SIGNAL_ADS_TXT_OWNER, "owner_domain"),
                           (SIGNAL_ADS_TXT_MANAGER, "manager_domain")):
            declared = (ads.get(key) or "").strip().lower()
            if declared and ads.get("status") == "ok":
                _emit(stype, declared, platform=None, scan_run_id=srid,
                      final_domain=domain, observed_at=run_at)
        # Floor D — carrier breadth. A domain declaring hundreds of DIRECT
        # accounts runs a full programmatic stack, so none of them singles out
        # an operator. Gates the ACCOUNT signals only (the template hash above
        # is already emitted): without it, case-singletons bypass every tier
        # demotion and two large publishers supplied 83% of the index's
        # seller values.
        if len(domain_accounts[domain]) >= ADS_TXT_INDEX_MAX_CARRIER_ACCOUNTS:
            continue
        seen_accounts: set[tuple[str, str]] = set()
        for rec in ads.get("records") or []:
            if (rec.get("relationship") or "").upper() != "DIRECT":
                continue
            adsystem = (rec.get("adsystem") or "").lower()
            seller_id = (rec.get("seller_id") or "").strip()
            if not adsystem or not seller_id:
                continue
            key = (adsystem, seller_id)
            if key in seen_accounts:
                continue
            seen_accounts.add(key)
            # Floor A — major exchange (also catches case-singletons that
            # shared_ad_accounts can't see). _demoted_multi — anything it
            # demoted (breadth / template). breadth — belt for singletons.
            if adsystem in MAJOR_AD_EXCHANGES:
                continue
            if key in _demoted_multi:
                continue
            breadth = len(account_domains[key]) / denom
            if breadth >= ADS_TXT_MANAGER_BREADTH:
                continue  # manager-wide account — don't pollute the index
            _emit(SIGNAL_ADS_TXT_SELLER, seller_id, platform=adsystem,
                  scan_run_id=srid, final_domain=domain, observed_at=run_at)

    return out



def operator_cross_links(index_conn: sqlite3.Connection) -> list[dict]:
    """Third-party endpoints that are THEMSELVES landing domains in the index.

    The sharpest read available on HAR endpoints, and the only one that needs
    no threshold. Most of what the endpoint index records is ad-tech a page
    happened to load, and rarity cannot separate that from operator-run
    infrastructure — an investigation corpus is all suspects, so a DSP only one
    landing page called looks exactly as rare as a private asset host. This cut
    sidesteps the question: if a landing page fetches resources from a host
    that is itself a domain under investigation, the two are wired together,
    whatever either one's ads.txt says.

    Found on the first run, from captures taken in May 2026: hubsite.example,
    satellitesite.example and satellite2site.example (QSH) all load from statics.privatecdn.example and
    s1.privatecdn2.example — the 01-family cluster's private CDN. That link had been in
    the HAR for three months and contradicted a conclusion drawn from ads.txt
    account overlap, which was correct about the account layer and wrong to be
    read as "no link at all".

    Returns one row per endpoint, with who calls it and where it appears as a
    landing itself, so both sides of the link are visible.
    """
    landing_apex: dict[str, set] = defaultdict(set)
    for r in index_conn.execute(
        "SELECT DISTINCT signal_value, case_id, case_title FROM signals "
        "WHERE signal_type = ?", (SIGNAL_FINAL_DOMAIN,),
    ):
        apex = extract_domain_from_url(r["signal_value"] or "")
        if apex:
            landing_apex[apex].add((r["case_id"], r["case_title"] or ""))

    out: list[dict] = []
    for r in index_conn.execute(
        """SELECT signal_value,
                  COUNT(DISTINCT final_domain) AS caller_count,
                  COUNT(DISTINCT case_id) AS case_count
             FROM signals WHERE signal_type = ?
            GROUP BY signal_value""", (SIGNAL_HAR_ENDPOINT,),
    ).fetchall():
        endpoint = r["signal_value"]
        if endpoint not in landing_apex:
            continue
        callers = [c["final_domain"] for c in index_conn.execute(
            "SELECT DISTINCT final_domain FROM signals "
            "WHERE signal_type = ? AND signal_value = ? AND final_domain IS NOT NULL "
            "ORDER BY final_domain", (SIGNAL_HAR_ENDPOINT, endpoint))]
        # A domain loading its own apex's assets is not a cross-link.
        callers = [c for c in callers
                   if extract_domain_from_url(c or "") != endpoint]
        if not callers:
            continue
        out.append({
            "endpoint":      endpoint,
            "called_by":     callers,
            "caller_count":  len(callers),
            "case_count":    r["case_count"],
            "investigated_as_landing_in": sorted(
                [{"case_id": cid, "case_title": title}
                 for cid, title in landing_apex[endpoint]],
                key=lambda x: x["case_id"]),
        })
    out.sort(key=lambda x: (-x["caller_count"], x["endpoint"]))
    return out


def _issuer_text(issuer) -> str:
    """Best-effort short issuer label from a cert issuer DN dict."""
    if not isinstance(issuer, dict):
        return ""
    for key in ("organizationName", "commonName"):
        v = issuer.get(key)
        if isinstance(v, list):
            v = v[0] if v else ""
        if v:
            return str(v)
    return ""


# ---------------------------------------------------------------------------
# Indexing (write to the central index)
# ---------------------------------------------------------------------------

def index_case(
    index_conn: sqlite3.Connection,
    case_conn: sqlite3.Connection,
    source_db: str,
    case_id: int,
    case_title: str = "",
) -> int:
    """Full-refresh the index for one (source_db, case_id).

    Deletes any prior rows for this case then inserts freshly-extracted
    signals — idempotent, and drops signals that no longer appear. Returns
    the number of signal rows written.
    """
    signals = extract_case_signals(case_conn, case_id, source_db, case_title)

    index_conn.execute(
        "DELETE FROM signals WHERE source_db = ? AND case_id = ?",
        (source_db, case_id),
    )
    index_conn.executemany(
        """INSERT OR REPLACE INTO signals
           (signal_type, signal_value, platform, source_db, case_id,
            case_title, scan_run_id, final_domain, observed_at, indexed_at)
           VALUES
           (:signal_type, :signal_value, :platform, :source_db, :case_id,
            :case_title, :scan_run_id, :final_domain, :observed_at, :indexed_at)""",
        signals,
    )
    index_conn.commit()
    return len(signals)


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

def lookup(
    index_conn: sqlite3.Connection,
    value: str,
    signal_type: str | None = None,
) -> list[dict]:
    """Every indexed occurrence of `value` (optionally constrained to a type).

    Returns rows sorted newest-observed first. Each row carries full
    provenance so the analyst can jump back to the originating case/scan.
    """
    value = (value or "").strip()
    if not value:
        return []
    sql = "SELECT * FROM signals WHERE signal_value = ?"
    params: list = [value]
    if signal_type:
        sql += " AND signal_type = ?"
        params.append(signal_type)
    sql += " ORDER BY observed_at DESC, source_db, case_id"
    return [dict(r) for r in index_conn.execute(sql, params).fetchall()]


def recurring_signals(
    index_conn: sqlite3.Connection,
    min_cases: int = 2,
    min_domains: int = 1,
) -> list[dict]:
    """Signals that appear across >= `min_cases` distinct cases.

    This is the headline cross-case report: the same operator account /
    cert / registrar / ASN / domain resurfacing across separate
    investigations. Returns one row per (signal_type, signal_value) with the
    distinct-case count and the list of cases it spans.

    READ `domain_count` BEFORE BELIEVING `case_count`. Cases overlap — an
    analyst who loads a consolidated case alongside the narrower ones it was
    built from has every signal in both, and `case_count` alone then reports
    the same single observation as a cross-case recurrence. Measured on the
    2026-08-05 index: 99 of 119 recurring ads.txt accounts sat on ONE domain
    and merely spanned overlapping cases; only 20 crossed domains. A signal on
    2+ distinct domains has genuinely resurfaced; one on a single domain has
    only been indexed twice.

    `min_domains` filters on that directly. It defaults to 1 because the test
    is not meaningful for every signal type — `final_domain` is by definition
    one domain, and the same site turning up in two investigations is exactly
    what that signal is for. Rows are ordered by domain_count first, so real
    recurrences rank above bookkeeping ones whatever the filter.
    """
    rows = index_conn.execute(
        """SELECT signal_type, signal_value,
                  COUNT(DISTINCT source_db || '|' || case_id) AS case_count,
                  COUNT(DISTINCT final_domain) AS domain_count,
                  COUNT(*) AS hit_count
           FROM signals
           GROUP BY signal_type, signal_value
           HAVING case_count >= ? AND domain_count >= ?
           ORDER BY domain_count DESC, case_count DESC, hit_count DESC""",
        (min_cases, min_domains),
    ).fetchall()

    out: list[dict] = []
    for r in rows:
        cases = index_conn.execute(
            """SELECT DISTINCT source_db, case_id, case_title, platform
               FROM signals
               WHERE signal_type = ? AND signal_value = ?
               ORDER BY source_db, case_id""",
            (r["signal_type"], r["signal_value"]),
        ).fetchall()
        out.append({
            "signal_type":  r["signal_type"],
            "signal_value": r["signal_value"],
            "case_count":   r["case_count"],
            "domain_count": r["domain_count"],
            "hit_count":    r["hit_count"],
            "platform":     next((c["platform"] for c in cases if c["platform"]), None),
            "cases":        [
                {"source_db": c["source_db"], "case_id": c["case_id"],
                 "case_title": c["case_title"]}
                for c in cases
            ],
        })
    return out
