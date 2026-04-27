"""
Rule-based case insights from existing clustering outputs (auditable, no LLM).
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from typing import Any

from clustering import (
    OWNER_KIND_GENERIC,
    OWNER_KIND_PLATFORM,
    asn_clusters,
    shared_certificates,
    shared_destinations,
    shared_param_keys,
    shared_params,
    shared_tracking_ids,
)


def _bullet_owner_note(row: dict) -> str:
    """Build the parenthetical 'attributed to X' fragment for a param bullet.

    Mirrors views._shared.localize_owner() but kept inline here to avoid a
    circular dependency (insights.py is not a view layer).
    """
    kind = row.get("owner_kind", "")
    if kind == OWNER_KIND_PLATFORM:
        owner = row.get("owner") or ""
        return t("insights.bullet_param_owner", owner=owner) if owner else ""
    if kind == OWNER_KIND_GENERIC:
        return t("insights.bullet_param_owner", owner=t("param.unattributed_tracker"))
    return ""
from i18n import t

# Risk tag keys used for label lookup via t("risk.<tag>").
_RISK_TAGS = (
    "multi_hop", "no_https", "new_domain", "suspicious_download",
    "high_tracker_count", "url_shortener_chain", "capture_error",
)


def case_insights(conn: sqlite3.Connection, case_id: int) -> dict[str, Any]:
    destinations, unresolved = shared_destinations(conn, case_id)
    params = shared_params(conn, case_id)
    param_keys = shared_param_keys(conn, case_id)
    asn_data = asn_clusters(conn, case_id)
    certs = shared_certificates(conn, case_id)
    tracking_ids = shared_tracking_ids(conn, case_id)

    url_count = conn.execute(
        "SELECT COUNT(*) AS n FROM url_artifacts WHERE case_id = ?",
        (case_id,),
    ).fetchone()["n"]
    scanned = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND sr.status = 'done'""",
        (case_id,),
    ).fetchone()["n"]
    no_intel = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND sr.status = 'done'
             AND sr.final_url IS NOT NULL
             AND (sr.domain_enriched_at IS NULL OR TRIM(sr.domain_enriched_at) = '')""",
        (case_id,),
    ).fetchone()["n"]
    no_snap = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = (
                   SELECT id FROM snapshots WHERE scan_run_id = sr.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND sr.status = 'done'
             AND sr.final_url IS NOT NULL AND s.id IS NULL""",
        (case_id,),
    ).fetchone()["n"]

    no_tls = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND sr.status = 'done'
             AND sr.final_url LIKE 'https%%'
             AND (sr.tls_info_json IS NULL OR TRIM(sr.tls_info_json) = '')""",
        (case_id,),
    ).fetchone()["n"]
    no_corr = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (
                   SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                   ORDER BY id DESC LIMIT 1
               )
           WHERE ua.case_id = ? AND sr.status = 'done'
             AND (sr.corroboration_json IS NULL OR TRIM(sr.corroboration_json) = '')""",
        (case_id,),
    ).fetchone()["n"]

    headline = _build_headline(url_count, scanned, destinations, unresolved, params, asn_data)
    bullets = _build_bullets(destinations, unresolved, params, param_keys, asn_data, certs, tracking_ids, scanned)
    gaps = _build_gaps(no_intel, no_snap, no_tls, no_corr, scanned, url_count)

    return {
        "headline": headline,
        "bullets": bullets,
        "gaps": gaps,
    }


def _build_headline(
    url_count: int,
    scanned: int,
    destinations: list,
    unresolved: list,
    params: list,
    asn_data: list,
) -> str:
    if url_count == 0:
        return t("insights.headline_none")
    n_dest = len(destinations)
    n_un = len(unresolved)
    parts = [t("insights.headline_counts", url_count=url_count, scanned=scanned)]
    if n_dest or n_un:
        s = t("insights.headline_dest", n_dest=n_dest)
        if n_un:
            s += t("insights.headline_dest_unresolved", n_un=n_un)
        else:
            s += "."
        parts.append(s)
    if params:
        parts.append(t("insights.headline_params", n=len(params)))
    if asn_data:
        parts.append(t("insights.headline_asn", n=len(asn_data)))
    return " ".join(parts)


def _build_bullets(
    destinations: list,
    unresolved: list,
    params: list,
    param_keys: list,
    asn_data: list,
    certs: dict,
    tracking_ids: list,
    scanned: int,
) -> list[str]:
    out: list[str] = []
    if destinations:
        top = sorted(destinations, key=lambda d: (-d["post_count"], -d["url_count"]))[:3]
        bits = ", ".join(
            t("insights.bullet_landing_item",
              domain=d["final_domain"], posts=d["post_count"], urls=d["url_count"])
            for d in top
        )
        out.append(t("insights.bullet_landing", bits=bits))
    # Risk tag summary across all destinations
    if destinations:
        all_tags: Counter[str] = Counter()
        for d in destinations:
            for tag, cnt in d.get("tag_counts", {}).items():
                all_tags[tag] += cnt
        if all_tags:
            parts = ", ".join(
                t("insights.bullet_risk_item",
                  tag=tag, label=t(f"risk.{tag}"), cnt=cnt)
                for tag, cnt in all_tags.most_common()
            )
            total_flagged = sum(d.get("flagged_url_count", 0) for d in destinations)
            out.append(t("insights.bullet_risk", flagged=total_flagged, parts=parts))
    if unresolved:
        out.append(t("insights.bullet_unresolved", n=len(unresolved)))
    if params:
        p0 = params[0]
        out.append(t("insights.bullet_param",
                      key=p0["param_key"], value=str(p0["param_value"])[:80],
                      owner=_bullet_owner_note(p0), posts=p0.get("post_count", 0)))
        if len(params) > 1:
            p1 = params[1]
            out.append(t("insights.bullet_param2",
                          key=p1["param_key"], value=str(p1["param_value"])[:80],
                          owner=_bullet_owner_note(p1), posts=p1.get("post_count", 0)))
    if param_keys:
        pk0 = param_keys[0]
        out.append(t("insights.bullet_param_key",
                      key=pk0["param_key"], owner=_bullet_owner_note(pk0),
                      posts=pk0["distinct_posts"], values=pk0["distinct_values"],
                      domains=pk0["distinct_domains"]))
    if tracking_ids:
        t0 = tracking_ids[0]
        out.append(t("insights.bullet_tracking_id",
                     n=len(tracking_ids),
                     platform=t0["platform"],
                     tracking_id=t0["tracking_id"],
                     domains=t0["domain_count"]))
    by_cert = certs.get("by_cert") or []
    by_issuance = certs.get("by_issuance") or []
    if by_cert:
        c0 = by_cert[0]
        out.append(t("insights.bullet_tls_cert",
                      n_certs=len(by_cert),
                      domains=c0["domain_count"],
                      issuer=c0["issuer"]))
    if by_issuance:
        w0 = by_issuance[0]
        out.append(t("insights.bullet_tls_window",
                      n_windows=len(by_issuance),
                      domains=w0["domain_count"],
                      certs=w0["cert_count"]))
    if asn_data:
        a0 = asn_data[0]
        out.append(t("insights.bullet_infra",
                      asn=a0["asn"], org=a0["as_org"],
                      domains=a0["domain_count"], urls=a0["url_count"]))
    if scanned == 0 and not out:
        out.append(t("insights.bullet_no_scans"))
    return out[:11]


def _build_gaps(no_intel: int, no_snap: int, no_tls: int, no_corr: int,
                scanned: int, url_count: int) -> list[str]:
    g: list[str] = []
    if no_intel and scanned:
        g.append(t("insights.gap_intel", n=no_intel))
    if no_snap and scanned:
        g.append(t("insights.gap_snap", n=no_snap))
    if no_tls and scanned:
        g.append(t("insights.gap_tls", n=no_tls))
    if no_corr and scanned:
        g.append(t("insights.gap_corr", n=no_corr))
    if url_count and scanned < url_count:
        g.append(t("insights.gap_unscanned", n=url_count - scanned))
    return g
