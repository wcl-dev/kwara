"""Cloaking sub-tab (Phase 4.1) — crawlerlanding-style conditional cloakers.

Operators that gate behaviour on a tracking parameter (e.g. ?uid=) leak
their gating logic when you compare with-param vs without-param fetches.
This view summarises the per-URL verdict, lets the analyst drill into
the diff, and re-run on demand.

Read-only data layer + i18n in the view (matches the corroboration
sub-tab pattern); the kwara contract that data modules don't depend on
i18n stays intact.
"""
import json

import streamlit as st

from i18n import t
from pipeline import run_cloaking
from views._shared import fetch_evidence_rows, url_selector


_VERDICT_KEYS = {
    "no_tracking_params": "cloak.verdict_no_tracking_params",
    "fetch_error":        "cloak.verdict_fetch_error",
    "no_cloaking":        "cloak.verdict_no_cloaking",
    "cloaking_suspect":   "cloak.verdict_suspect",
}


def _render_fetch_block(label: str, summary: dict):
    with st.container(border=True):
        st.markdown(f"**{label}**")
        if not summary:
            return
        if summary.get("error"):
            st.caption(t("cloak.fetch_error_label", msg=summary["error"]))
            return
        st.caption(t(
            "cloak.fetch_status",
            sc=summary.get("status_code", "—"),
            dom=summary.get("final_domain", "—"),
            size=summary.get("body_size", 0),
        ))
        if summary.get("final_url"):
            st.caption(f"`{summary['final_url']}`")


def _render_diffs(payload: dict):
    diffs = payload.get("diffs", [])
    a = payload.get("with_params", {}) or {}
    b = payload.get("without_params", {}) or {}
    for diff in diffs:
        if diff == "status_code":
            st.markdown("- " + t("cloak.diff_status_code",
                                 a=a.get("status_code", "?"),
                                 b=b.get("status_code", "?")))
        elif diff == "final_domain":
            st.markdown("- " + t("cloak.diff_final_domain",
                                 a=a.get("final_domain", "?"),
                                 b=b.get("final_domain", "?")))
        elif diff == "body_content":
            st.markdown("- " + t("cloak.diff_body_content"))
        elif diff == "body_size":
            st.markdown("- " + t("cloak.diff_body_size",
                                 a=a.get("body_size", 0),
                                 b=b.get("body_size", 0)))


def render(conn, case_id):
    st.caption(t("cloak.help"))

    rows = fetch_evidence_rows(conn, case_id)
    scanned = [r for r in rows if r["scan_status"] == "done"]

    suspect = 0
    clean = 0
    pending = 0
    for r in scanned:
        raw = r["sr_cloaking_signal_json"]
        if not raw:
            pending += 1
            continue
        try:
            verdict = json.loads(raw).get("verdict", "")
        except (TypeError, ValueError):
            verdict = ""
        if verdict == "cloaking_suspect":
            suspect += 1
        elif verdict == "no_cloaking":
            clean += 1
        else:
            pending += 1

    m1, m2, m3 = st.columns(3)
    m1.metric(t("cloak.metric_suspect"), suspect)
    m2.metric(t("cloak.metric_clean"), clean)
    m3.metric(t("cloak.metric_pending"), pending)

    if not scanned:
        st.info(t("cloak.no_data"))
        return

    st.divider()
    sel = url_selector(rows, key_suffix="_cloak")
    if not sel["scan_run_id"] or sel["scan_status"] != "done":
        st.info(t("corr.not_scanned"))
        return

    raw = sel["sr_cloaking_signal_json"]
    payload = json.loads(raw) if raw else None

    if st.button(
        t("cloak.retry") if payload else t("cloak.run"),
        key="btn_cloak",
        type="primary" if not payload else "secondary",
    ):
        st.session_state["inv_last_ua_id"] = sel["ua_id"]
        with st.spinner(t("cloak.spinner")):
            run_cloaking(conn, sel["scan_run_id"], force=bool(payload))
        st.rerun()

    if not payload:
        return

    verdict_key = _VERDICT_KEYS.get(payload.get("verdict"), "cloak.verdict_no_cloaking")
    if payload.get("verdict") == "cloaking_suspect":
        st.error(t(verdict_key))
    elif payload.get("verdict") == "no_cloaking":
        st.success(t(verdict_key))
    else:
        st.info(t(verdict_key))

    if payload.get("stripped_params"):
        st.caption(t("cloak.stripped_params",
                     params=", ".join(payload["stripped_params"])))
    if payload.get("stripped_url"):
        st.caption(t("cloak.stripped_url", url=payload["stripped_url"]))

    if payload.get("diffs"):
        _render_diffs(payload)

    if payload.get("with_params") or payload.get("without_params"):
        c1, c2 = st.columns(2)
        with c1:
            _render_fetch_block(t("cloak.with_params_label"), payload.get("with_params", {}))
        with c2:
            _render_fetch_block(t("cloak.without_params_label"), payload.get("without_params", {}))
