"""Plain-language case narrative (UI-redesign prototype).

The translation layer the prototype was missing — written to the register of
the analyst report (kwara_0513.pdf): neutral, evidence-led, tiered claims;
no emoji, no colloquial or emotive wording, no motive attribution.

Tone rules borrowed from that report:
  • Tiered confidence, not assertion — 強訊號(可確定同群體) /
    弱訊號 / 行為觀察, never "極可能是詐騙集團".
  • Every claim scoped to the digital-asset layer ("就數位資產層而言"),
    never extended to content, social behaviour, or subjective intent.
  • Distinguish 同群體 (same infrastructure cluster — provable here) from
    同操作者 (same actor — a higher bar needing content-layer verification).
  • State the observation + what it can be USED for (申訴/追金流 依據),
    not the inferred motive. Cloaking is an observed behaviour, not proof
    the operator "knows they are breaking the law".
  • A standing scope/limitation note travels with every verdict.

Pure functions only (no Streamlit) so the wording is unit-testable and can
also feed a PDF/export later.
"""
from __future__ import annotations

import sqlite3

from .config import COVERAGE_CLASS_CAP, COVERAGE_WEIGHTS

from .clustering_infra import (
    shared_ad_accounts,
    shared_certificates,
    shared_tracking_ids,
)
from .header_analysis import cross_domain_shared_template, detect_fake_versions
from .insights import _count_cloaking_suspects
from .opsec import compute_opsec_profile

# Standing limitation — shown with every verdict; mirrors the report's
# 「重要限制／範圍聲明」.
SCOPE_NOTE = (
    "範圍說明：以上判斷限於**數位資產層**訊號（追蹤碼、TLS 憑證、DNS／IP、"
    "HTTP header）。「同群體」指共用基礎設施可確定屬同一群；是否為**單一操作者**、"
    "是否具**主觀犯意**，須再結合內容層分析（版型、文案、社群行為）與正式調查程序。"
    "本頁為調查線索，非最終操作者歸屬論斷。"
)

# Tier vocabulary (neutral palette — evidence weight, not guilt).
_TIER = {
    "strong":    ("強訊號", "#2c5f8a"),    # can determine same cluster
    "behaviour": ("行為觀察", "#b7791f"),  # observed behaviour, intent unproven
    "support":   ("輔助訊號", "#5b6770"),  # supporting / money-trail
}


# ---------------------------------------------------------------------------
# Signal gathering (single source of truth — page_overview imports these too)
# ---------------------------------------------------------------------------
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


def signal_summary(conn: sqlite3.Connection, case_id: int) -> dict:
    """The hard-signal counts that drive both the tiles and the narrative."""
    ads = shared_ad_accounts(conn, case_id)
    ads_operator = len([a for a in ads.get("by_account", [])
                        if a.get("tier") == "operator"])
    ads_template = len(ads.get("by_template", []))
    return {
        "tracking":     len(shared_tracking_ids(conn, case_id)),
        "certs":        len(shared_certificates(conn, case_id).get("by_cert", [])),
        "hdr_tmpl":     len(cross_domain_shared_template(conn, case_id)),
        "cloaking":     _count_cloaking_suspects(conn, case_id),
        "fake_ver":     len(detect_fake_versions(conn, case_id)),
        "opsec":        len([r for r in compute_opsec_profile(conn, case_id)
                            if r["level"] == "strong"]),
        "ads_operator": ads_operator,
        "ads_template": ads_template,
    }


def evidence_coverage(grouping_n: int, behaviour_n: int, money_n: int) -> int:
    """Evidence coverage 0–100 — how much evidence is on the table, NOT how
    guilty the operator is.

    Each class saturates at COVERAGE_CLASS_CAP instances and holds a fixed
    share of the figure (see config.COVERAGE_WEIGHTS), so no single class can
    own it. The previous raw weighted count let the weakest class — ads.txt
    accounts — reach 1544 on a 100 ceiling by itself, which made the figure
    identical for every well-populated case.
    """
    counts = {"grouping": grouping_n, "behaviour": behaviour_n, "money": money_n}
    cap = max(1, COVERAGE_CLASS_CAP)
    full = sum(COVERAGE_WEIGHTS.values()) * cap
    if not full:
        return 0
    score = sum(w * min(max(counts.get(k, 0), 0), cap)
                for k, w in COVERAGE_WEIGHTS.items())
    return round(100 * score / full)


def verdict(sig: dict) -> dict:
    """Tiered, scope-bounded verdict — no motive attribution.

    Returns:
      grouping       — "strong" | "none": strength of the same-cluster
                       determination at the digital-asset layer
      behaviour      — bool: was content-cloaking / evasion observed
      group_line     — neutral one-liner for the grouping determination
      behaviour_line — neutral one-liner for observed behaviour (or "")
      colour, coverage — header styling + an evidence-coverage figure
    """
    grouping_n = sig["tracking"] + sig["certs"] + sig["hdr_tmpl"] + sig["ads_template"]
    behaviour_n = sig["cloaking"] + sig["fake_ver"] + sig["opsec"]
    money_n = sig["ads_operator"]

    grouping = "strong" if grouping_n else "none"
    behaviour = behaviour_n > 0

    coverage = evidence_coverage(grouping_n, behaviour_n, money_n)

    if grouping == "strong":
        colour = "#2c5f8a"
        group_line = "數位資產層：多個網站共用關鍵識別資產，可確定屬同一基礎設施群體"
    else:
        colour = "#7f8c8d"
        group_line = "數位資產層：尚未發現足以確定同群體的跨站共用訊號"

    behaviour_line = ""
    if behaviour:
        behaviour_line = "另觀察到內容偽裝／反偵測行為（屬行為觀察，是否為刻意規避需內容層驗證）"

    return {
        "grouping": grouping, "behaviour": behaviour,
        "group_line": group_line, "behaviour_line": behaviour_line,
        "colour": colour, "coverage": coverage, "money": money_n,
    }


# ---------------------------------------------------------------------------
# Plain-language narrative
# ---------------------------------------------------------------------------
def _summary_sentence(v: dict, n_urls: int) -> str:
    scope = f"本案追查 {n_urls} 個可疑連結。"
    if v["grouping"] == "strong" and v["behaviour"]:
        return (f"{scope}就數位資產層（追蹤碼、TLS 憑證、伺服器指紋）而言，"
                f"其中多個網站可確定屬同一基礎設施群體；另觀察到部分連結具內容偽裝行為。"
                f"以下逐項列出證據及其強度。")
    if v["grouping"] == "strong":
        return (f"{scope}就數位資產層而言，其中多個網站共用關鍵識別資產，"
                f"可確定屬同一基礎設施群體。是否為單一操作者，仍須內容層交叉驗證。")
    if v["behaviour"]:
        return (f"{scope}觀察到內容偽裝／反偵測行為，惟跨站共用訊號"
                f"尚不足以確定屬同一群體。")
    return (f"{scope}現有數位資產層訊號不足以判斷跨站歸屬，"
            f"宜先完成掃描與頁面擷取。")


def _reasons(sig: dict) -> list[dict]:
    """Each present hard signal — observation + evidentiary use, tiered.

    Returns [{tier, tier_label, tier_colour, heading, observation, use}].
    Only signals that actually fired. No motive attribution, no emoji.
    """
    out: list[dict] = []

    def add(tier, heading, observation, use):
        lbl, colour = _TIER[tier]
        out.append({
            "tier": tier, "tier_label": lbl, "tier_colour": colour,
            "heading": heading, "observation": observation, "use": use,
        })

    # ── Strong: same-cluster determination ────────────────────────────
    if sig["tracking"]:
        add("strong", "跨網站共用同一追蹤帳號",
            f"有 {sig['tracking']} 組追蹤碼（GA4、Meta Pixel 這類記錄訪客的帳號）"
            f"同時出現在不同網站上。這類識別碼對應單一後台帳戶、又寫在網頁原始碼裡，"
            f"很難偽造，也不太可能剛好雷同。",
            "可判定這些網站在數位資產層上屬於同一群；這組帳號指向同一個 Google／Meta "
            "後台，能作為向平台檢舉的依據。")
    if sig["certs"]:
        add("strong", "多個網站共用同一張 TLS 憑證",
            f"有 {sig['certs']} 組網站用的是同一張 TLS 憑證（同一簽發者、同一序號），"
            f"代表它們其實架在同一台伺服器、或同一批一起申請的。",
            "可作為同一群基礎設施的證據；憑證指向同一個簽發帳戶，"
            "能作為向主機或憑證服務商反映的依據。")
    if sig["hdr_tmpl"]:
        add("strong", "跨網站伺服器標頭特徵一致",
            f"有 {sig['hdr_tmpl']} 組網站的伺服器回應特徵一模一樣，"
            f"看得出是用同一套模板一次佈出來的。",
            "可作為同一群的佐證；單獨來看力道比憑證、追蹤碼弱，適合和其他訊號一起參酌。")
    if sig["ads_template"]:
        add("strong", "廣告授權檔（ads.txt）一字不差",
            f"有 {sig['ads_template']} 組網站的 ads.txt 內容完全相同、一字不差，"
            f"是同一份檔案複製出去的。",
            "可作為同一群的證據；裡面的 DIRECT 帳號指向同一個收款方，能作為追金流的線索。")

    # ── Behaviour observed (intent unproven) ──────────────────────────
    if sig["cloaking"]:
        add("behaviour", "出現內容偽裝",
            f"有 {sig['cloaking']} 個連結，會依照網址有沒有帶 tracking 參數回傳不同內容——"
            f"也就是同一個網址，對不同來路的訪客給不一樣的頁面。",
            "這是觀察到的行為，能作為向平台或服務商反映的依據；"
            "至於是不是刻意規避偵測，需要再做內容層比對，這裡先不下定論。")
    if sig["fake_ver"]:
        add("behaviour", "伺服器版本資訊對不上",
            f"有 {sig['fake_ver']} 個網站回報的伺服器版本，和它實際用的技術對不起來。",
            "屬於指紋訊號之一，可作為同一群的佐證；不單憑這點推斷動機。")
    if sig["opsec"]:
        add("behaviour", "對自動化檢測有防備",
            f"有 {sig['opsec']} 個網站對自動化工具的反應，和一般瀏覽器明顯不同。",
            "是行為上的觀察，顯示存取門檻較高；不單獨拿來當歸屬依據。")

    # ── Support: money trail ──────────────────────────────────────────
    if sig["ads_operator"]:
        add("support", "共用同一個廣告分潤帳號",
            f"有 {sig['ads_operator']} 組網站用同一個廣告分潤（DIRECT）帳號收款。",
            "金流指向同一個收款方，能作為追金流、釐清受益人的線索。")

    return out


def case_narrative(conn: sqlite3.Connection, case_id: int) -> dict:
    """Full neutral narrative for the Overview hero block."""
    n_urls, scanned = case_counts(conn, case_id)
    sig = signal_summary(conn, case_id)
    v = verdict(sig)
    reasons = _reasons(sig)

    note = ""
    if scanned < n_urls:
        note = f"（目前結論基於已掃描的 {scanned}／{n_urls} 個連結）"

    return {
        "colour": v["colour"], "coverage": v["coverage"],
        "group_line": v["group_line"], "behaviour_line": v["behaviour_line"],
        "summary": _summary_sentence(v, n_urls),
        "reasons": reasons,
        "scope_note": SCOPE_NOTE,
        "scanned_note": note,
        "has_signal": bool(reasons),
        "sig": sig,
        "n_urls": n_urls, "scanned": scanned,
    }
