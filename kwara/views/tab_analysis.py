"""Analysis tab — routes to evidence-chain sub-tabs."""
import streamlit as st

from i18n import t
from views import (
    _sub_account_patterns,
    _sub_corroboration,
    _sub_domain,
    _sub_insights,
    _sub_network,
    _sub_page,
    _sub_scan,
)


def render(conn, case_id, case_locale=None, case_tz=None):
    t1, t2, t3, t4, t5, t6, t7 = st.tabs([
        t("tab.scan"),
        t("tab.network"),
        t("tab.domain"),
        t("tab.page"),
        t("tab.corroboration"),
        t("tab.insights"),
        t("tab.account_patterns"),
    ])

    with t1:
        _sub_scan.render(conn, case_id)
    with t2:
        _sub_network.render(conn, case_id)
    with t3:
        _sub_domain.render(conn, case_id)
    with t4:
        _sub_page.render(conn, case_id, case_locale=case_locale, case_tz=case_tz)
    with t5:
        _sub_corroboration.render(conn, case_id)
    with t6:
        _sub_insights.render(conn, case_id)
    with t7:
        _sub_account_patterns.render(conn, case_id)
