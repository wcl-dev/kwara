"""Analyze top-level tab — cross-URL views of already-collected data.

Sub-tabs (all read-only — no new probing):
  Insights         — clustering across destinations, params, TLS, ASN
  Account Patterns — poster × content pivot
  Providers        — accountability lens: shortlinks, registrars,
                     hosting, CAs, ad/tracking platforms
"""
import streamlit as st

from i18n import t
from views import _sub_account_patterns, _sub_insights, tab_providers


def render(conn, case_id):
    t1, t2, t3 = st.tabs([
        t("tab.insights"),
        t("tab.account_patterns"),
        t("tab.providers"),
    ])
    with t1:
        _sub_insights.render(conn, case_id)
    with t2:
        _sub_account_patterns.render(conn, case_id)
    with t3:
        tab_providers.render(conn, case_id)
