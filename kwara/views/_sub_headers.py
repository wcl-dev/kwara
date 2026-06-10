"""Header forensics sub-tab (Phase 4.2C).

Surface the four orthogonal lenses from `header_analysis`:
  - per-domain constants (backend leak via stable headers)
  - cross-domain template reuse (same operator)
  - fabricated version strings (active anti-forensic)
  - Set-Cookie domain leaks + shared cookie attribute templates

Read-only — pulls already-captured headers out of redirect_hops. No
new probing.
"""
import streamlit as st

from header_analysis import (
    cookie_origin_signals,
    cross_domain_shared_template,
    detect_fake_versions,
    per_domain_constants,
)
from i18n import t


def _flag_summary(httponly: bool, secure: bool) -> str:
    bits: list[str] = []
    if httponly:
        bits.append("HttpOnly")
    if secure:
        bits.append("Secure")
    return " | ".join(bits) if bits else "—"


def render(conn, case_id):
    st.caption(t("hdr.help"))

    # ── 1. per-domain constants ────────────────────────────────────────
    constants = per_domain_constants(conn, case_id)
    st.subheader(t("hdr.section_constants"))
    st.caption(t("hdr.section_constants_caption"))
    if not constants:
        st.info(t("hdr.empty_section"))
    else:
        rows = []
        for domain in sorted(constants):
            for header_name, value in sorted(constants[domain].items()):
                rows.append({
                    t("hdr.col_domain"): domain,
                    t("hdr.col_header"): header_name,
                    t("hdr.col_value"):  value,
                })
        st.dataframe(rows, hide_index=True, width='stretch')

    # ── 2. cross-domain template ──────────────────────────────────────
    templates = cross_domain_shared_template(conn, case_id)
    st.subheader(t("hdr.section_template"))
    st.caption(t("hdr.section_template_caption"))
    if not templates:
        st.info(t("hdr.empty_section"))
    else:
        rows = [{
            t("hdr.col_header"):  r["header"],
            t("hdr.col_value"):   r["value"],
            t("hdr.col_domains"): ", ".join(r["domains"]),
        } for r in templates]
        st.dataframe(rows, hide_index=True, width='stretch')

    # ── 3. fake versions ──────────────────────────────────────────────
    fakes = detect_fake_versions(conn, case_id)
    st.subheader(t("hdr.section_fake"))
    st.caption(t("hdr.section_fake_caption"))
    if not fakes:
        st.info(t("hdr.empty_section"))
    else:
        rows = [{
            t("hdr.col_domain"): r["domain"],
            t("hdr.col_header"): r["header"],
            t("hdr.col_value"):  r["value"],
            t("hdr.col_reason"): r["reason"],
        } for r in fakes]
        st.dataframe(rows, hide_index=True, width='stretch')

    # ── 4. cookie origin leaks + shared templates ─────────────────────
    cookies = cookie_origin_signals(conn, case_id)

    st.subheader(t("hdr.section_cookie_leak"))
    st.caption(t("hdr.section_cookie_leak_caption"))
    if not cookies["origin_leaks"]:
        st.info(t("hdr.empty_section"))
    else:
        rows = [{
            t("hdr.col_response_domain"): r["response_domain"],
            t("hdr.col_cookie_domain"):   r["cookie_domain"],
        } for r in cookies["origin_leaks"]]
        st.dataframe(rows, hide_index=True, width='stretch')

    st.subheader(t("hdr.section_cookie_template"))
    st.caption(t("hdr.section_cookie_template_caption"))
    if not cookies["shared_templates"]:
        st.info(t("hdr.empty_section"))
    else:
        rows = [{
            t("hdr.col_path"):     r["path"] or "—",
            t("hdr.col_flags"):    _flag_summary(r["httponly"], r["secure"]),
            t("hdr.col_samesite"): r["samesite"] or "—",
            t("hdr.col_domains"):  ", ".join(r["domains"]),
        } for r in cookies["shared_templates"]]
        st.dataframe(rows, hide_index=True, width='stretch')
