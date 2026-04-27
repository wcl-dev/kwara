"""Preserve top-level tab — lock down evidence so it can't disappear.

Sub-tabs:
  Page          — browser screenshots, HTML, HAR network log
  Corroboration — Wayback archive, urlscan.io, RFC 3161 timestamps
"""
import streamlit as st

from i18n import t
from views import _sub_corroboration, _sub_page


def render(conn, case_id, case_locale=None, case_tz=None):
    t1, t2 = st.tabs([
        t("tab.page"),
        t("tab.corroboration"),
    ])
    with t1:
        _sub_page.render(conn, case_id, case_locale=case_locale, case_tz=case_tz)
    with t2:
        _sub_corroboration.render(conn, case_id)
