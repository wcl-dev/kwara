"""Corroboration sub-tab — third-party evidence (Wayback, urlscan.io, RFC 3161)."""
import json

import streamlit as st

from i18n import t
from pipeline import run_corroborate
from views._shared import fetch_evidence_rows, url_selector


def render(conn, case_id):
    st.caption(t("corr.help"))

    rows = fetch_evidence_rows(conn, case_id)
    scanned = [r for r in rows if r["scan_status"] == "done"]
    has_corr = sum(1 for r in scanned if r["sr_corroboration_json"])
    pending = len(scanned) - has_corr

    m1, m2, m3 = st.columns(3)
    m1.metric(t("corr.done"), has_corr)
    m2.metric(t("corr.pending"), pending)
    m3.metric(t("corr.not_scanned"), len(rows) - len(scanned))

    if not scanned:
        st.info(t("corr.scan_first"))
        return

    st.divider()
    sel = url_selector(rows, key_suffix="_corr")

    if not sel["scan_run_id"] or sel["scan_status"] != "done":
        st.info(t("corr.not_scanned"))
        return

    try:
        _corr_raw = sel["sr_corroboration_json"]
    except (IndexError, KeyError):
        _corr_raw = None
    _corr = json.loads(_corr_raw) if _corr_raw else None

    # ── Action button ───────────────────────────────────────────
    if st.button(
        t("corr.retry") if _corr else t("corr.run"),
        key="btn_corroborate",
        type="primary" if not _corr else "secondary",
    ):
        st.session_state["inv_last_ua_id"] = sel["ua_id"]
        with st.spinner(t("corr.spinner")):
            run_corroborate(conn, sel["scan_run_id"])
        st.rerun()

    if not _corr:
        st.info(t("corr.none"))
        return

    # ── Results ─────────────────────────────────────────────────
    _us = _corr.get("urlscan", {})
    _wb = _corr.get("wayback", {})
    _ts = _corr.get("timestamp", {})

    with st.container(border=True):
        st.markdown(f"**archive.org**")
        if _wb.get("permalink"):
            st.write(t("corr.wayback", url=_wb["permalink"], at=_wb.get("saved_at", "—")))
        elif _wb.get("error"):
            st.caption(f"Error: {_wb['error']}")

    with st.container(border=True):
        st.markdown(f"**urlscan.io**")
        if _us.get("permalink"):
            st.write(t("corr.urlscan", url=_us["permalink"], at=_us.get("submitted_at", "—")))
        elif _us.get("skipped"):
            st.caption(t("corr.urlscan_skip"))
        elif _us.get("error"):
            st.caption(f"Error: {_us['error']}")

    with st.container(border=True):
        st.markdown(f"**RFC 3161 Timestamp**")
        if _ts.get("token_b64"):
            st.write(t("corr.timestamp", tsa=_ts.get("tsa_url", "—"), at=_ts.get("requested_at", "—")))
            st.caption(t("corr.timestamp_digest", digest=_ts.get("digest_sha256", "—")))
        elif _ts.get("error"):
            st.caption(f"Error: {_ts['error']}")

    st.caption(t("corr.at", at=_corr.get("corroborated_at", "—")))
