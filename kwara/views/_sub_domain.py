"""Domain sub-tab — WHOIS, ASN, IP, domain intelligence."""
import json
from urllib.parse import urlparse as _urlparse

import streamlit as st

from clustering import _merge_risk_tags
from i18n import t
from pipeline import run_domain_intel_batch, run_domain_intel_only
from views._shared import TAG_COLORS, fetch_evidence_rows, url_selector


def render(conn, case_id):
    st.caption(t("domain.help"))

    rows = fetch_evidence_rows(conn, case_id)
    scanned = [r for r in rows if r["scan_status"] == "done"]
    has_intel = sum(1 for r in scanned if r["sr_domain_enriched_at"] and str(r["sr_domain_enriched_at"]).strip())
    pending = len(scanned) - has_intel

    m1, m2, m3 = st.columns(3)
    m1.metric(t("domain.enriched"), has_intel)
    m2.metric(t("domain.pending"), pending)
    m3.metric(t("domain.not_scanned"), len(rows) - len(scanned))

    # Batch WHOIS/ASN button
    pending_rows = [
        r for r in scanned
        if not r["sr_domain_enriched_at"] or not str(r["sr_domain_enriched_at"]).strip()
    ]
    if pending_rows:
        if st.button(t("domain.btn_batch", n=len(pending_rows)), type="primary"):
            with st.spinner(t("domain.spinner_batch")):
                run_domain_intel_batch(conn, [r["scan_run_id"] for r in pending_rows])
            st.rerun()

    if not scanned:
        st.info(t("domain.scan_first"))
        return

    st.divider()
    sel = url_selector(rows, key_suffix="_dom")

    if not sel["scan_run_id"] or sel["scan_status"] != "done":
        st.info(t("domain.not_scanned"))
        return

    snap = conn.execute(
        "SELECT * FROM snapshots WHERE scan_run_id = ? ORDER BY id DESC LIMIT 1",
        (sel["scan_run_id"],),
    ).fetchone()

    def _coalesce(snap_key, sr_key):
        if snap and snap[snap_key]:
            return snap[snap_key]
        return sel[sr_key] if sel[sr_key] else None

    # ── Domain info ─────────────────────────────────────────────
    col_l, col_r = st.columns(2)
    with col_l:
        fd = (snap["final_domain"] if snap and snap["final_domain"] else None) or (_urlparse(sel["final_url"]).hostname or "—")
        st.write(t("domain.final_domain", v=fd))
        st.write(t("domain.ip_address", v=_coalesce('ip_address', 'sr_ip_address') or '—'))
        asn_v = _coalesce("asn", "sr_asn")
        asn_str = (
            f"AS{asn_v}  {_coalesce('as_org', 'sr_as_org') or ''}  "
            f"({_coalesce('as_country', 'sr_as_country') or '—'})"
            if asn_v else "—"
        )
        st.write(t("domain.asn_hosting", v=asn_str))
    with col_r:
        st.write(t("domain.registrar", v=_coalesce('whois_registrar', 'sr_whois_registrar') or '—'))
        st.write(t("domain.domain_created", v=_coalesce('whois_creation_date', 'sr_whois_creation_date') or '—'))
        if sel["sr_domain_enriched_at"]:
            st.caption(t("domain.intel_updated", ts=sel['sr_domain_enriched_at']))

    tags = _merge_risk_tags(
        snap["risk_tags"] if snap else None,
        sel["sr_intel_risk_tags"],
    )
    tag_str = "  ".join(f"{TAG_COLORS.get(tg,'⚪')} `{tg}`" for tg in tags)
    st.write(t("domain.risk_flags", v=tag_str or '—'))

    # Single-URL WHOIS button
    if st.button(t("domain.btn_intel"), key="btn_intel_only_dom", help=t("domain.btn_intel_help")):
        st.session_state["inv_last_ua_id"] = sel["ua_id"]
        with st.spinner(t("domain.spinner")):
            try:
                run_domain_intel_only(conn, sel["scan_run_id"])
            except Exception as e:
                st.error(t("domain.error", e=e))
                st.stop()
        st.rerun()
