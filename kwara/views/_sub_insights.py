"""Insights sub-tab — case summary, destination clusters, shared params, ASN infra."""
import pandas as pd
import streamlit as st

from clustering import asn_clusters, shared_destinations, shared_params
from i18n import t
from insights import case_insights
from views._shared import TAG_COLORS


def render(conn, case_id):
    st.caption(t("insights_tab.help"))

    destinations, unresolved_dests = shared_destinations(conn, case_id)
    params = shared_params(conn, case_id)
    asn_data = asn_clusters(conn, case_id)

    # ── Case Insights ───────────────────────────────────────────
    ci = case_insights(conn, case_id)
    with st.container(border=True):
        st.markdown(ci["headline"])
        if ci["bullets"]:
            for b in ci["bullets"]:
                st.markdown(f"- {b}")
        if ci["gaps"]:
            st.caption(t("clusters.data_gaps"))
            for g in ci["gaps"]:
                st.markdown(f"- {g}")

    with st.expander(t("clusters.legend")):
        st.markdown(t("clusters.legend_table"))

    st.divider()

    # ── Scanned Destinations ────────────────────────────────────
    st.subheader(t("clusters.destinations"))

    if unresolved_dests:
        names = ", ".join(f"`{d['final_domain']}`" for d in unresolved_dests)
        st.info(t("clusters.info_unresolved", n=len(unresolved_dests), names=names))

    if not destinations:
        st.info(t("clusters.no_data"))
    else:
        summary_rows = []
        for d in destinations:
            tag_str = "  ".join(
                f"{TAG_COLORS.get(tg, '⚪')} {tg} ×{d['tag_counts'][tg]}"
                for tg in sorted(d["tag_counts"])
            ) if d["tag_counts"] else "—"
            summary_rows.append({
                "final_domain": d["final_domain"],
                "urls":         d["url_count"],
                "flagged_urls": d["flagged_url_count"] if d["flagged_url_count"] else "—",
                "posts":        d["post_count"],
                "risk_flags":   tag_str,
            })
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

        sel_domain = st.selectbox(
            t("clusters.drill_dest"),
            [d["final_domain"] for d in destinations],
            key="cluster_dest_sel",
        )
        sel_d = next(d for d in destinations if d["final_domain"] == sel_domain)
        _show_all_key = f"cluster_show_all_{sel_domain}"
        show_all = st.session_state.get(_show_all_key, False)
        _PREVIEW = 5

        with st.container(border=True):
            urls_sorted = sorted(sel_d["urls"], key=lambda u: -len(u["risk_tags"]))
            urls_to_show = urls_sorted if show_all else urls_sorted[:_PREVIEW]
            flagged = sel_d["flagged_url_count"]
            st.write(t("clusters.shortlinks_here", total=len(sel_d['urls']), flagged=flagged))
            url_df_rows = []
            for u in urls_to_show:
                tag_str = "  ".join(f"{TAG_COLORS.get(tg, '⚪')} {tg}" for tg in u["risk_tags"]) if u["risk_tags"] else "—"
                url_df_rows.append({"risk_flags": tag_str, "original_url": u["original_url"]})
            st.dataframe(pd.DataFrame(url_df_rows), use_container_width=True, hide_index=True)
            if len(sel_d["urls"]) > _PREVIEW:
                if show_all:
                    if st.button(t("clusters.btn_less"), key=f"cluster_less_{sel_domain}"):
                        st.session_state[_show_all_key] = False
                        st.rerun()
                else:
                    if st.button(t("clusters.btn_all", n=len(sel_d['urls'])), key=f"cluster_more_{sel_domain}"):
                        st.session_state[_show_all_key] = True
                        st.rerun()

            st.write(t("clusters.found_in_posts"))
            posts_to_show = sel_d["posts"] if show_all else sel_d["posts"][:_PREVIEW]
            st.dataframe(pd.DataFrame(posts_to_show), use_container_width=True, hide_index=True)
            if len(sel_d["posts"]) > _PREVIEW and not show_all:
                st.caption(t("clusters.preview_posts", preview=_PREVIEW, total=len(sel_d['posts'])))

    st.divider()

    # ── Shared URL Parameters ───────────────────────────────────
    st.subheader(t("clusters.params"))
    st.caption(t("clusters.params_caption"))

    if not params:
        st.info(t("clusters.no_params"))
    else:
        st.dataframe(pd.DataFrame(params), use_container_width=True, hide_index=True)

    st.divider()

    # ── Hosting Infrastructure ──────────────────────────────────
    st.subheader(t("clusters.infra"))
    st.caption(t("clusters.infra_caption"))

    if not asn_data:
        st.info(t("clusters.no_asn"))
    else:
        asn_summary = []
        for a in asn_data:
            tag_str = "  ".join(
                f"{TAG_COLORS.get(tg, '⚪')} {tg} ×{a['tag_counts'][tg]}"
                for tg in sorted(a["tag_counts"])
            ) if a["tag_counts"] else "—"
            asn_summary.append({
                "asn":          a["asn"],
                "as_org":       a["as_org"],
                "country":      a["as_country"],
                "domains":      a["domain_count"],
                "urls":         a["url_count"],
                "flagged_urls": a["flagged_url_count"] if a["flagged_url_count"] else "—",
                "posts":        a["post_count"],
                "risk_flags":   tag_str,
            })
        st.dataframe(pd.DataFrame(asn_summary), use_container_width=True, hide_index=True)

        sel_asn = st.selectbox(
            t("clusters.drill_asn"),
            [a["asn"] for a in asn_data],
            format_func=lambda x: f"AS{x}  {next(a['as_org'] for a in asn_data if a['asn'] == x)}",
            key="cluster_asn_sel",
        )
        sel_a = next(a for a in asn_data if a["asn"] == sel_asn)
        _asn_show_key = f"cluster_asn_show_{sel_asn}"
        _asn_show_all = st.session_state.get(_asn_show_key, False)
        _ASN_PREVIEW = 5

        with st.container(border=True):
            st.write(t("clusters.domains_asn", asn=sel_asn, n=len(sel_a['domains'])))
            domains_show = sel_a["domains"] if _asn_show_all else sel_a["domains"][:_ASN_PREVIEW]
            st.dataframe(pd.DataFrame(domains_show), use_container_width=True, hide_index=True)

            st.write(t("clusters.shortlinks_asn", total=len(sel_a['urls']), flagged=sel_a['flagged_url_count']))
            urls_sorted = sorted(sel_a["urls"], key=lambda u: -len(u["risk_tags"]))
            urls_show = urls_sorted if _asn_show_all else urls_sorted[:_ASN_PREVIEW]
            asn_url_rows = []
            for u in urls_show:
                tag_str = "  ".join(f"{TAG_COLORS.get(tg, '⚪')} {tg}" for tg in u["risk_tags"]) if u["risk_tags"] else "—"
                asn_url_rows.append({"risk_flags": tag_str, "original_url": u["original_url"]})
            st.dataframe(pd.DataFrame(asn_url_rows), use_container_width=True, hide_index=True)

            total_items = max(len(sel_a["domains"]), len(sel_a["urls"]))
            if total_items > _ASN_PREVIEW:
                if _asn_show_all:
                    if st.button(t("clusters.btn_less"), key=f"asn_less_{sel_asn}"):
                        st.session_state[_asn_show_key] = False
                        st.rerun()
                else:
                    if st.button(t("clusters.btn_all", n=total_items), key=f"asn_more_{sel_asn}"):
                        st.session_state[_asn_show_key] = True
                        st.rerun()
