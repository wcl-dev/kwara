"""OPSEC profile sub-tab (Phase 4.3) — lightweight vs Playwright per domain.

Read-only over already-captured snapshots — no new probing. Highlights
domains where the lightweight path is blocked (likely UA gating) while
Playwright works fine. Independent of GA4 / TLS / parameter clustering;
when both signals point at the same operator split, evidence weight
compounds.
"""
import streamlit as st

from i18n import t
from opsec import compute_opsec_profile


def _rate_cell(ok: int, total: int) -> str:
    if total == 0:
        return t("opsec.cell_rate_empty")
    pct = f"{ok / total:.0%}"
    return t("opsec.cell_rate", ok=ok, total=total, pct=pct)


def _level_label(level: str) -> str:
    return {
        "low":           t("opsec.level_low"),
        "medium":        t("opsec.level_medium"),
        "strong":        t("opsec.level_strong"),
        "indeterminate": t("opsec.level_indeterminate"),
    }.get(level, level)


def render(conn, case_id):
    st.caption(t("opsec.help"))
    rows = compute_opsec_profile(conn, case_id)
    if not rows:
        st.info(t("opsec.no_data"))
        return

    table = []
    for r in rows:
        table.append({
            t("opsec.col_domain"):      r["domain"],
            t("opsec.col_lightweight"): _rate_cell(r["lw_ok"], r["lw_total"]),
            t("opsec.col_playwright"):  _rate_cell(r["pw_ok"], r["pw_total"]),
            t("opsec.col_level"):       _level_label(r["level"]),
        })
    st.dataframe(table, hide_index=True, use_container_width=True)
    st.caption(t("opsec.diff_caption"))
