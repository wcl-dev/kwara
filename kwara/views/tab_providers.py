"""Providers tab — shortlink services and domain registrars."""
import json
from urllib.parse import urlparse as _urlparse

import pandas as pd
import streamlit as st

from config import KNOWN_SHORTLINK_DOMAINS
from i18n import t
from views._shared import TAG_COLORS, scan_flags


def render(conn, case_id):
    st.subheader(t("prov.shortlinks"))
    st.caption(t("prov.shortlinks_caption"))

    all_domains = conn.execute(
        """SELECT ua.domain AS provider, COUNT(*) AS url_count
           FROM url_artifacts ua
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? AND ua.domain IS NOT NULL
           GROUP BY ua.domain ORDER BY url_count DESC""",
        (case_id,),
    ).fetchall()

    detected_redirectors = set()
    redir_rows = conn.execute(
        """SELECT DISTINCT ua.domain
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id AND sr.status = 'done'
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? AND ua.domain IS NOT NULL
             AND sr.final_url IS NOT NULL AND sr.hop_count >= 2""",
        (case_id,),
    ).fetchall()
    for r in redir_rows:
        detected_redirectors.add(r["domain"])

    providers = [
        r for r in all_domains
        if r["provider"] in KNOWN_SHORTLINK_DOMAINS or r["provider"] in detected_redirectors
    ]

    if providers:
        df_prov = pd.DataFrame([dict(r) for r in providers])
        st.dataframe(df_prov, use_container_width=True, hide_index=True)

        sel_prov = st.selectbox(
            t("prov.drill"),
            [p["provider"] for p in providers],
            key="prov_sel",
        )
        prov_urls = conn.execute(
            """SELECT ua.id, ua.original_url,
                      sr.status AS scan_status, sr.final_url, sr.hop_count,
                      s.risk_tags AS snapshot_risk_tags
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               LEFT JOIN snapshots s ON s.scan_run_id = sr.id
                   AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? AND ua.domain = ?
               ORDER BY ua.id""",
            (case_id, sel_prov),
        ).fetchall()

        def _prov_tags(r):
            if r["snapshot_risk_tags"]:
                try:
                    return json.loads(r["snapshot_risk_tags"])
                except (ValueError, TypeError):
                    pass
            return scan_flags(r["final_url"], r["hop_count"])

        prov_rows_tagged = sorted(
            [{"url": r["original_url"], "tags": _prov_tags(r)} for r in prov_urls],
            key=lambda x: -len(x["tags"]),
        )
        flagged_count = sum(1 for x in prov_rows_tagged if x["tags"])
        _prov_show_all_key = f"prov_show_all_{sel_prov}"
        _prov_show_all = st.session_state.get(_prov_show_all_key, False)
        _PROV_PREVIEW = 5

        with st.container(border=True):
            to_show = prov_rows_tagged if _prov_show_all else prov_rows_tagged[:_PROV_PREVIEW]
            st.write(t("prov.urls_provider", total=len(prov_rows_tagged), flagged=flagged_count))
            prov_df_rows = []
            for x in to_show:
                tag_str = "  ".join(f"{TAG_COLORS.get(tg, '⚪')} {tg}" for tg in x["tags"]) if x["tags"] else "—"
                prov_df_rows.append({"risk_flags": tag_str, "original_url": x["url"]})
            st.dataframe(pd.DataFrame(prov_df_rows), use_container_width=True, hide_index=True)
            if len(prov_rows_tagged) > _PROV_PREVIEW:
                if _prov_show_all:
                    if st.button(t("clusters.btn_less"), key=f"prov_less_{sel_prov}"):
                        st.session_state[_prov_show_all_key] = False
                        st.rerun()
                else:
                    if st.button(t("clusters.btn_all", n=len(prov_rows_tagged)), key=f"prov_more_{sel_prov}"):
                        st.session_state[_prov_show_all_key] = True
                        st.rerun()
    else:
        st.info(t("prov.no_providers"))

    st.divider()

    st.subheader(t("prov.registrars"))
    st.caption(t("prov.registrars_caption"))

    registrars = conn.execute(
        """SELECT COALESCE(NULLIF(TRIM(sr.whois_registrar), ''), s.whois_registrar) AS registrar,
                  s.final_domain AS snap_domain,
                  sr.final_url AS scan_final_url,
                  COALESCE(sr.whois_creation_date, s.whois_creation_date) AS domain_created
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1
           )
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ?
             AND COALESCE(NULLIF(TRIM(sr.whois_registrar), ''), s.whois_registrar) IS NOT NULL
             AND TRIM(COALESCE(NULLIF(TRIM(sr.whois_registrar), ''), s.whois_registrar, '')) != ''
           ORDER BY registrar, snap_domain, scan_final_url""",
        (case_id,),
    ).fetchall()

    reg_rows = []
    for r in registrars:
        dom = r["snap_domain"] or (_urlparse(r["scan_final_url"] or "").hostname or "—")
        reg_rows.append({"registrar": r["registrar"], "domain": dom, "domain_created": r["domain_created"]})

    if reg_rows:
        st.dataframe(pd.DataFrame(reg_rows), use_container_width=True, hide_index=True)
    else:
        st.info(t("prov.no_registrars"))
