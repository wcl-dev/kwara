"""Investigate top-level tab — active probing of the URLs themselves.

Sub-tabs:
  Scan     — fire redirect-chain scans, capture TLS, headers
  Network  — view scan results (TLS cert details, redirect hops, headers)
  Domain   — WHOIS / ASN / IP enrichment
"""
import streamlit as st

from i18n import t
from views import _sub_domain, _sub_network, _sub_scan


def render(conn, case_id):
    t1, t2, t3 = st.tabs([
        t("tab.scan"),
        t("tab.network"),
        t("tab.domain"),
    ])
    with t1:
        _sub_scan.render(conn, case_id)
    with t2:
        _sub_network.render(conn, case_id)
    with t3:
        _sub_domain.render(conn, case_id)
