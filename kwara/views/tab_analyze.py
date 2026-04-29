"""Analyze top-level tab — cross-URL views of already-collected data.

Sub-tabs (all read-only — no new probing except cloaking, which makes
two extra HTTP fetches and is opt-in via the Cloaking sub-tab button):
  Insights         — clustering across destinations, params, TLS, ASN
  Account Patterns — poster × content pivot
  Providers        — accountability lens: shortlinks, registrars,
                     hosting, CAs, ad/tracking platforms
  Cloaking         — conditional cloaker (with-param vs without-param)
"""
import streamlit as st

from i18n import t
from views import _sub_account_patterns, _sub_cloaking, _sub_insights, tab_providers


def render(conn, case_id):
    t1, t2, t3, t4 = st.tabs([
        t("tab.insights"),
        t("tab.account_patterns"),
        t("tab.providers"),
        t("cloak.tab_label"),
    ])
    with t1:
        _sub_insights.render(conn, case_id)
    with t2:
        _sub_account_patterns.render(conn, case_id)
    with t3:
        tab_providers.render(conn, case_id)
    with t4:
        _sub_cloaking.render(conn, case_id)
