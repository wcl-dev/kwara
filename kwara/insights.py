"""
Rule-based case insights from existing clustering outputs (auditable, no LLM).
"""
from __future__ import annotations

import sqlite3
from typing import Any

from clustering import asn_clusters, shared_destinations, shared_params


def case_insights(conn: sqlite3.Connection, case_id: int) -> dict[str, Any]:
    destinations, unresolved = shared_destinations(conn, case_id)
    params = shared_params(conn, case_id)
    asn_data = asn_clusters(conn, case_id)

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

    headline = _build_headline(url_count, scanned, destinations, unresolved, params, asn_data)
    bullets = _build_bullets(destinations, unresolved, params, asn_data, scanned)
    gaps = _build_gaps(no_intel, no_snap, scanned, url_count)

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
        return "此案件尚無 URL，請先在 Input 匯入內容。"
    n_dest = len(destinations)
    n_un = len(unresolved)
    parts = [
        f"共 **{url_count}** 個短連結／URL，其中 **{scanned}** 筆已完成掃描（redirect 解析）。"
    ]
    if n_dest or n_un:
        parts.append(
            f"可辨識的落地網域 **{n_dest}** 個"
            + (f"；另有 **{n_un}** 個目的地仍停在短連結服務本身（未穿透）。" if n_un else "。")
        )
    if params:
        parts.append(f"偵測到 **{len(params)}** 組跨貼文重複的 URL 參數（可能與追蹤或投放有關）。")
    if asn_data:
        parts.append(f"託管／ASN 叢集 **{len(asn_data)}** 組（來自已解析 ASN 的落地網域）。")
    return " ".join(parts)


def _build_bullets(
    destinations: list,
    unresolved: list,
    params: list,
    asn_data: list,
    scanned: int,
) -> list[str]:
    out: list[str] = []
    if destinations:
        top = sorted(destinations, key=lambda d: (-d["post_count"], -d["url_count"]))[:3]
        bits = [
            f"`{d['final_domain']}`（{d['post_count']} 則貼文、{d['url_count']} 條 URL）"
            for d in top
        ]
        out.append("**落地集中度：** 貼文覆蓋最高的目的地為 " + "、".join(bits) + "。")
    if unresolved:
        out.append(
            f"**短連結未穿透：** {len(unresolved)} 個落地網域仍為已知短連結服務，"
            "真實目的地未知——建議重新掃描或手動開啟連結確認。"
        )
    if params:
        p0 = params[0]
        out.append(
            f"**跨貼文參數：** 最常重複的是 `{p0['param_key']}={str(p0['param_value'])[:80]}`"
            + (f"（出現在 {p0['post_count']} 則不同貼文）。" if p0.get("post_count") else "。")
        )
        if len(params) > 1:
            p1 = params[1]
            out.append(
                f"其次為 `{p1['param_key']}={str(p1['param_value'])[:80]}`"
                f"（{p1.get('post_count', 0)} 則貼文）。"
            )
    if asn_data:
        a0 = asn_data[0]
        out.append(
            f"**基礎設施：** 以流量／URL 量來看，**AS{a0['asn']}**（{a0['as_org']}）"
            f"涵蓋最多落地網域與短連結（{a0['domain_count']} 網域、{a0['url_count']} 條 URL）。"
        )
    if scanned == 0 and not out:
        out.append("尚無完成掃描的 URL——請到 **Scan** 分頁執行掃描後，此處會出現模式摘要。")
    return out[:7]


def _build_gaps(no_intel: int, no_snap: int, scanned: int, url_count: int) -> list[str]:
    g: list[str] = []
    if no_intel and scanned:
        g.append(
            f"**{no_intel}** 筆已完成掃描但尚未執行網域情資（WHOIS／ASN）——可在 Investigate 使用「只查 WHOIS/ASN」不必截圖。"
        )
    if no_snap and scanned:
        g.append(
            f"**{no_snap}** 筆尚無 snapshot 列（可能未截圖或僅有情資）；若需頁面證據請補截圖或手動上傳。"
        )
    if url_count and scanned < url_count:
        g.append(f"**{url_count - scanned}** 條 URL 尚未完成掃描或最新一次掃描未標記為 done。")
    return g
