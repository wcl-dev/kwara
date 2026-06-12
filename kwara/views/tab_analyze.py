"""Analyze top-level tab — cross-URL views of already-collected data.

Sub-tabs (all read-only — no new probing except cloaking, which makes
two extra HTTP fetches and is opt-in via the Cloaking sub-tab button):
  Insights         — clustering across destinations, params, TLS, ASN
  Providers        — accountability lens: shortlinks, registrars,
                     hosting, CAs, ad/tracking platforms
  Cloaking         — conditional cloaker (with-param vs without-param)
  Headers          — per-hop response-header forensics (constants /
                     cross-domain template / fake versions / cookies)
  OPSEC            — lightweight vs Playwright success-rate per domain
"""
import streamlit as st

from i18n import t
from views import (
    _sub_cloaking,
    _sub_headers,
    _sub_insights,
    _sub_opsec,
    tab_providers,
)


def render(conn, case_id):
    t1, t2, t3, t4, t5 = st.tabs([
        t("tab.insights"),
        t("tab.providers"),
        t("cloak.tab_label"),
        t("hdr.tab_label"),
        t("opsec.tab_label"),
    ])
    with t1:
        _sub_insights.render(conn, case_id)
    with t2:
        tab_providers.render(conn, case_id)
    with t3:
        _sub_cloaking.render(conn, case_id)
    with t4:
        _sub_headers.render(conn, case_id)
    with t5:
        _sub_opsec.render(conn, case_id)
