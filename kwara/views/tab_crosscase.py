"""Cross-case index tab (Phase 5.1).

The one view that is NOT scoped to the current case: it spans every case the
analyst has indexed, across every kwara DB file. Three things:

  1. Index the current case  — push its strong signals into the central index.
  2. Look up a value         — "where have I seen this GA4 ID / cert / domain?"
  3. Recurring signals       — operators resurfacing across separate cases.

The index is a separate DB (config.INDEX_DB_PATH); this view is the only
writer to it, and only when the analyst clicks "index".
"""
import streamlit as st

from config import DB_PATH, INDEX_DB_PATH
from i18n import t
from index_db import (
    get_index_conn,
    index_case,
    lookup,
    recurring_signals,
)

_TYPE_LABELS = {
    "tracking_id":  "crosscase.type_tracking_id",
    "cert_serial":  "crosscase.type_cert_serial",
    "registrar":    "crosscase.type_registrar",
    "asn":          "crosscase.type_asn",
    "final_domain": "crosscase.type_final_domain",
}


def _type_label(stype: str) -> str:
    key = _TYPE_LABELS.get(stype)
    return t(key) if key else stype


def _case_title(conn, case_id: int) -> str:
    row = conn.execute(
        "SELECT title FROM cases WHERE id = ?", (case_id,)
    ).fetchone()
    return (row["title"] if row else "") or f"case #{case_id}"


def render(conn, case_id):
    st.caption(t("crosscase.help"))

    try:
        idx = get_index_conn(INDEX_DB_PATH)
    except OSError as e:
        st.error(t("crosscase.index_open_error", path=INDEX_DB_PATH, err=str(e)))
        return

    st.caption(t("crosscase.index_location", path=INDEX_DB_PATH))

    # ── 1. Index the current case ──────────────────────────────────────
    if case_id is not None:
        title = _case_title(conn, case_id)
        if st.button(t("crosscase.index_button", title=title)):
            n = index_case(idx, conn, DB_PATH, case_id, title)
            st.success(t("crosscase.index_done", n=n, title=title))

    st.divider()

    # ── 2. Look up a value ─────────────────────────────────────────────
    st.subheader(t("crosscase.lookup_header"))
    value = st.text_input(
        t("crosscase.lookup_label"),
        placeholder=t("crosscase.lookup_placeholder"),
    )
    if value:
        hits = lookup(idx, value)
        if not hits:
            st.info(t("crosscase.no_hits", value=value))
        else:
            st.write(t("crosscase.hits_count", n=len(hits), value=value))
            st.dataframe(
                [{
                    t("crosscase.col_type"):     _type_label(h["signal_type"]),
                    t("crosscase.col_platform"): h["platform"] or "—",
                    t("crosscase.col_case"):     h["case_title"] or f"#{h['case_id']}",
                    t("crosscase.col_domain"):   h["final_domain"] or "—",
                    t("crosscase.col_observed"): h["observed_at"] or "—",
                    t("crosscase.col_db"):       h["source_db"],
                } for h in hits],
                hide_index=True, use_container_width=True,
            )

    st.divider()

    # ── 3. Recurring signals across cases ──────────────────────────────
    st.subheader(t("crosscase.recurring_header"))
    st.caption(t("crosscase.recurring_help"))
    recurring = recurring_signals(idx, min_cases=2)
    if not recurring:
        st.info(t("crosscase.no_recurring"))
        return
    for r in recurring:
        label = t(
            "crosscase.recurring_item",
            type=_type_label(r["signal_type"]),
            value=r["signal_value"],
            platform=f" ({r['platform']})" if r["platform"] else "",
            cases=r["case_count"],
        )
        with st.expander(label):
            st.dataframe(
                [{
                    t("crosscase.col_case"): c["case_title"] or f"#{c['case_id']}",
                    t("crosscase.col_db"):   c["source_db"],
                } for c in r["cases"]],
                hide_index=True, use_container_width=True,
            )
