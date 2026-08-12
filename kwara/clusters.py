"""Operator-cluster model (UI-redesign, group-centric rebuild).

The reframe: a case is NOT one verdict — it is N operator groups. Real data
proves it (case 3's shared tracking IDs partition into 3 disjoint groups =
the α/β/γ of the analyst report). This module is the single source of truth
for that partition; every group-centric view renders objects it produces.

Model (faithful to kwara_0513.pdf's intellectual structure):
  • HARD signals (shared tracking ID / TLS cert / byte-identical ads.txt /
    rare ads.txt account) BIND domains into a group. Connected components
    over these = the groups. Each group is tier 確證 by construction.
  • WEAK signals (cross-domain header templates, batch cert timing) are
    frequency-weighted and shown as 相關未證實 links BETWEEN groups — they
    never merge groups (otherwise "server: cloudflare" across 16 domains
    would fuse everything into one meaningless blob).
  • BEHAVIOUR observations (content cloaking, fake versions, OPSEC) describe
    conduct, not grouping; attached per-domain where known, else case-level,
    and always framed as 待複核 (pending human review), never asserted.

Every signal instance is NAMED (the identifier + the domains it links) and
carries its disposition channel (which platform/host a takedown or records
request would go to). Pure functions only — unit-testable, export-ready.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from collections import defaultdict

from .palette import GROUP_PALETTE

from .clustering_infra import (
    shared_ad_accounts,
    shared_certificates,
    shared_tracking_ids,
)
from .header_analysis import cross_domain_shared_template, detect_fake_versions
from .insights import _count_cloaking_suspects
from . import acquisition as _acq
from .opsec import compute_opsec_profile
from .sql import browser_capture_exists

# ── Confidence tiers (neutral; from the report) ───────────────────────────
TIER_CONFIRMED = "確證同群"      # bound by a shared hard identifier
TIER_RELATED = "相關未證實"      # correlated but not proven same group
TIER_BEHAVIOUR = "行為觀察"      # observed conduct, not a grouping signal

# Frequency-weighting for weak header signals: a value on >= this fraction of
# the case's landing domains is ubiquitous infrastructure (e.g. "server:
# cloudflare"), not attribution. Reuses the 0.8 breadth philosophy of the
# ads.txt manager-tier rule (contract 5), not tuned to any dataset.
WEAK_GENERIC_BREADTH = float(os.environ.get("KWARA_WEAK_GENERIC_BREADTH", "0.8"))

# Floor under the breadth heuristic: on SMALL cases the breadth denominator is
# tiny, so ratios are coarse and a universal CDN/server token can slip through
# (the 2026-06-11 independent-batch validation caught "server: cloudflare" at
# 3/4 = 0.75 < 0.8). These bare tokens are objectively never attribution,
# regardless of case — a floor that COMPLEMENTS breadth, not a case-derived
# denylist. Only matches exact bare tokens; a distinctive value like
# "Apache/2.5.1 (impossible)" is NOT here and is kept.
_UNIVERSAL_INFRA = frozenset({
    "cloudflare", "nginx", "apache", "akamai", "amazons3", "amazon",
    "microsoft-iis", "litespeed", "openresty", "gws", "gse", "ecs",
})


def _is_generic_weak(value: str, breadth: float) -> bool:
    """A weak header value carries no attribution if it is breadth-ubiquitous
    OR a universal infra token. Pure → unit-testable."""
    return breadth >= WEAK_GENERIC_BREADTH or value.strip().lower() in _UNIVERSAL_INFRA


# ── Disposition channels: signal → where a request/complaint goes ─────────
def _channel(signal_type: str, platform: str = "") -> str:
    p = (platform or "").lower()
    if signal_type == "tracking":
        if "adsense" in p:
            return "Google（AdSense 發布商帳戶）"
        if "tag manager" in p:
            return "Google（GTM 容器帳戶）"
        if "analytics" in p:
            return "Google（Analytics 後台帳戶 / 政策違規）"
        if "google ads" in p:
            return "Google（Ads 帳戶）"
        if "meta" in p or "facebook" in p:
            return "Meta（Pixel / 粉專管理權限）"
        if "tiktok" in p:
            return "TikTok（Pixel / 廣告帳戶）"
        if "line" in p:
            return "LINE（Tag 帳戶）"
        if "x /" in p or "twitter" in p:
            return "X / Twitter（Pixel 帳戶）"
        return "對應追蹤平台後台帳戶"
    if signal_type == "cert":
        return "Cloudflare / 簽發 CA（憑證帳戶）"
    if signal_type in ("ads_template", "ads_account"):
        return "SSP / 收款方（ads.txt DIRECT 帳戶）"
    return ""


def _short_serial(serial: str) -> str:
    s = (serial or "").replace(":", "").replace(" ", "")
    return (s[:12] + "…") if len(s) > 12 else s


# ── Union-find over domains, edges = hard signals ─────────────────────────
class _UF:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _hard_signals(conn: sqlite3.Connection, case_id: int) -> list[dict]:
    """Every NAMED hard signal: {type, label, value, domains, channel}."""
    out: list[dict] = []

    for c in shared_tracking_ids(conn, case_id):
        out.append({
            "type": "tracking", "label": c["platform"], "value": c["tracking_id"],
            "domains": sorted(set(c["domains"])),
            "channel": _channel("tracking", c["platform"]),
        })
    certs = shared_certificates(conn, case_id)
    for c in certs.get("by_cert", []):
        out.append({
            "type": "cert", "label": "TLS 憑證", "value": _short_serial(c["serial"]),
            "domains": sorted(set(c["domains"])),
            "channel": _channel("cert"),
        })
    ads = shared_ad_accounts(conn, case_id)
    for c in ads.get("by_template", []):
        # Only a cluster whose every member's response bytes are still on disk
        # AND still hash to what the derived record claims may merge operator
        # groups. Anything else stays visible — it is real historical evidence
        # — but as a non-binding observation, because byte-identity is the
        # whole claim and we cannot currently show the bytes were identical.
        #
        # Before 2026-08-12 this labelling existed and nothing read it: every
        # by_template row became a hard edge regardless, so an altered or
        # never-retained observation merged groups exactly as a verified one
        # did.
        if c.get("verification") != _acq.VERIFIED:
            continue
        out.append({
            "type": "ads_template", "label": "ads.txt 模板",
            "value": c.get("sha256_short") or (c.get("sha256", "")[:12]),
            "domains": sorted(set(c["domains"])),
            "channel": _channel("ads_template"),
        })
    # NOTE: shared ads.txt DIRECT *accounts* (by_account) are deliberately NOT
    # a group-forming hard signal. The 2026-06-11 mega-case load (45 domains
    # incl. 22 famous, independent TW content farms) proved they over-merge:
    # MFA farms share many ad networks at moderate overlap, fusing 29 distinct
    # operators into one blob. Even operator-tier accounts (after the
    # breadth/template/floor demotion) are too noisy to bind groups. Only the
    # byte-identical ads.txt TEMPLATE (sha256 above) is strong enough — same
    # exact file = same deployer. Per-domain accounts stay visible in the
    # network-detail view as corroborating, non-binding evidence.
    return out


def _components(signals: list[dict]) -> list[list[str]]:
    """Connected components of domains, joined by shared hard signals."""
    uf = _UF()
    for s in signals:
        doms = s["domains"]
        for d in doms:
            uf.find(d)
        for d in doms[1:]:
            uf.union(doms[0], d)
    comps: dict[str, list[str]] = defaultdict(list)
    for d in uf.parent:
        comps[uf.find(d)].append(d)
    return [sorted(v) for v in comps.values()]


def _case_domain_count(conn, case_id: int) -> int:
    """Distinct landing domains in the case — the breadth denominator."""
    return conn.execute(
        """SELECT COUNT(DISTINCT LOWER(s.final_domain)) AS n
           FROM snapshots s
           JOIN scan_runs sr ON sr.id = s.scan_run_id
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE ua.case_id = ? AND s.final_domain IS NOT NULL
             AND TRIM(s.final_domain) != ''""",
        (case_id,),
    ).fetchone()["n"]


def _weak_links(conn, case_id, domain_to_group: dict[str, int]) -> list[dict]:
    """Cross-domain header templates as 相關未證實 links, frequency-weighted.

    A value on >= WEAK_GENERIC_BREADTH of the case's landing domains is
    ubiquitous infrastructure (e.g. "server: cloudflare") and dropped — by
    BREADTH, not a hardcoded value list, so it generalises. Everything kept
    carries its breadth_ratio so the renderer shows distinctiveness instead
    of over-claiming. Most distinctive (lowest breadth) first.
    """
    denom = _case_domain_count(conn, case_id) or 1
    out: list[dict] = []
    for t in cross_domain_shared_template(conn, case_id):
        value = (t.get("value") or "").strip()
        domains = sorted(set(t.get("domains") or []))
        if len(domains) < 2:
            continue
        breadth = len(domains) / denom
        if _is_generic_weak(value, breadth):   # ubiquitous infra → not attribution
            continue
        groups = sorted({domain_to_group[d] for d in domains
                         if d in domain_to_group})
        out.append({
            "type": "hdr_template", "tier": TIER_RELATED,
            "header": t.get("header"), "value": value,
            "domains": domains, "domain_count": len(domains),
            "breadth_ratio": round(breadth, 3),
            "spans_groups": groups,
        })
    out.sort(key=lambda x: x["breadth_ratio"])   # most distinctive first
    return out


def _completeness(conn, case_id, n_urls, scanned) -> dict:
    """Discrete data-completeness (低/中/高) + which evidence types are present.

    Replaces the misleading 0-100 coverage bar: this measures how much of the
    evidence chain has been collected, not how 'guilty' the case is.
    """
    def _exists(sql):
        return conn.execute(sql, (case_id,)).fetchone()["n"] > 0

    present = {
        "scanned": scanned > 0,
        # "A snapshots row exists" is not "a page was captured": the
        # browser-free pass writes a row for every URL. Until 2026-08-11 this
        # reported page_captured=True — and therefore no gap, completeness
        # 高 — for five cases in which no browser had ever rendered a page.
        "page_captured": _exists(
            f"""SELECT COUNT(*) AS n FROM scan_runs sr
                JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                WHERE ua.case_id = ? AND {browser_capture_exists()}"""),
        "tls": _exists(
            """SELECT COUNT(*) AS n FROM scan_runs sr
               JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
               WHERE ua.case_id = ? AND sr.tls_info_json IS NOT NULL
                 AND TRIM(sr.tls_info_json) != ''"""),
        "ads_txt": _exists(
            """SELECT COUNT(*) AS n FROM scan_runs sr
               JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
               WHERE ua.case_id = ? AND sr.ads_txt_json IS NOT NULL
                 AND TRIM(sr.ads_txt_json) != ''"""),
    }
    score = sum(present.values())
    level = "高" if score >= 4 else "中" if score >= 2 else "低"
    gaps = [k for k, v in present.items() if not v]
    return {"level": level, "present": present, "gaps": gaps,
            "n_urls": n_urls, "scanned": scanned}


def case_counts(conn: sqlite3.Connection, case_id: int) -> tuple[int, int]:
    url_count = conn.execute(
        "SELECT COUNT(*) AS n FROM url_artifacts WHERE case_id = ?",
        (case_id,),
    ).fetchone()["n"]
    scanned = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                            ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? AND sr.status = 'done'""",
        (case_id,),
    ).fetchone()["n"]
    return url_count, scanned


def case_clusters(conn: sqlite3.Connection, case_id: int) -> dict:
    """The group-centric model for a case.

    Returns:
      groups       — [{gid, label, domains, domain_count, signals, signal_count,
                       tier, channels, fake_versions}], sorted by domain_count desc
      weak_links   — 相關未證實 header-template links (generic values removed)
      behaviour    — case-level conduct counts, framed for 待複核
      completeness — discrete 低/中/高 + evidence-type presence + gaps
      n_urls, scanned
    """
    n_urls, scanned = case_counts(conn, case_id)
    signals = _hard_signals(conn, case_id)
    comps = _components(signals)

    # Stable ordering: largest group first.
    comps.sort(key=lambda c: (-len(c), c[0] if c else ""))

    domain_to_group: dict[str, int] = {}
    for gid, doms in enumerate(comps, start=1):
        for d in doms:
            domain_to_group[d] = gid

    # Per-domain fake versions, to attach to groups.
    fake_by_domain: dict[str, list[dict]] = defaultdict(list)
    for fv in detect_fake_versions(conn, case_id):
        fake_by_domain[(fv.get("domain") or "").lower()].append(fv)

    groups: list[dict] = []
    for gid, doms in enumerate(comps, start=1):
        domset = set(doms)
        g_signals = [s for s in signals if set(s["domains"]) & domset]
        channels = sorted({s["channel"] for s in g_signals if s["channel"]})
        fakes = [fv for d in doms for fv in fake_by_domain.get(d, [])]
        groups.append({
            "gid": gid, "label": f"群組 {gid}",
            "domains": doms, "domain_count": len(doms),
            "signals": g_signals, "signal_count": len(g_signals),
            "tier": TIER_CONFIRMED,           # built from hard signals
            "channels": channels,
            "fake_versions": fakes,
        })

    weak_links = _weak_links(conn, case_id, domain_to_group)

    behaviour = {
        "cloaking_pending": _count_cloaking_suspects(conn, case_id),
        "opsec_strong": len([r for r in compute_opsec_profile(conn, case_id)
                             if r["level"] == "strong"]),
        "fake_versions": len(detect_fake_versions(conn, case_id)),
    }

    return {
        "groups": groups,
        "weak_links": weak_links,
        "behaviour": behaviour,
        "completeness": _completeness(conn, case_id, n_urls, scanned),
        "n_urls": n_urls, "scanned": scanned,
    }


def group_color(gid: int) -> str:
    """Stable, colour-blind-aware palette for group gid (1-based)."""
    return GROUP_PALETTE[(gid - 1) % len(GROUP_PALETTE)]


def node_id(prefix: str, value: str) -> str:
    """Stable DOT-safe node id (SHA-256, reproducible across processes)."""
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{h}"
