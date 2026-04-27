"""Insights sub-tab — case summary, destination clusters, shared params, ASN infra."""
import pandas as pd
import streamlit as st

from clustering_infra import (
    asn_clusters,
    shared_certificates,
    shared_endpoints,
    shared_tracking_ids,
)
from clustering_url import (
    shared_destinations,
    shared_param_keys,
    shared_params,
    wrapper_relationships,
)
from i18n import t
from insights import case_insights
from views._shared import TAG_COLORS, localize_owner, localize_purpose


def _short_serial(serial: str, head: int = 8, tail: int = 4) -> str:
    """Truncate a long cert serial for table display while keeping it identifiable."""
    if not serial or len(serial) <= head + tail + 1:
        return serial
    return f"{serial[:head]}…{serial[-tail:]}"


def render(conn, case_id):
    st.caption(t("insights_tab.help"))

    destinations, unresolved_dests = shared_destinations(conn, case_id)
    wrappers = wrapper_relationships(conn, case_id)
    params = shared_params(conn, case_id)
    param_keys = shared_param_keys(conn, case_id)
    asn_data = asn_clusters(conn, case_id)
    certs = shared_certificates(conn, case_id)
    tracking_ids = shared_tracking_ids(conn, case_id)
    endpoints = shared_endpoints(conn, case_id)

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

    # ── Wrapper Domains (original_url → final_url crosses domain) ─
    st.subheader(t("clusters.wrappers"))
    st.caption(t("clusters.wrappers_caption"))

    if not wrappers:
        st.info(t("clusters.no_wrappers"))
    else:
        wrap_rows = []
        for w in wrappers:
            wrap_rows.append({
                "wrapper":      w["original_domain"],
                "redirects_to": w["final_domain"],
                "url_count":    w["url_count"],
                "post_count":   w["post_count"],
                "min_hops":     w["min_hops"],
                "max_hops":     w["max_hops"],
                "sample_urls":  ", ".join(u[:60] for u in w["sample_urls"]),
            })
        st.dataframe(pd.DataFrame(wrap_rows), use_container_width=True, hide_index=True)

    st.divider()

    # ── Shared URL Parameters ───────────────────────────────────
    st.subheader(t("clusters.params"))
    st.caption(t("clusters.params_caption"))

    if not params:
        st.info(t("clusters.no_params"))
    else:
        param_rows = []
        for p in params:
            param_rows.append({
                "param_key":   p["param_key"],
                "param_value": p["param_value"],
                "owner":       localize_owner(p),
                "purpose":     localize_purpose(p),
                "domains":     p["domains"],
                "post_count":  p["post_count"],
                "url_count":   p["url_count"],
            })
        st.dataframe(pd.DataFrame(param_rows), use_container_width=True, hide_index=True)

    st.divider()

    # ── Operator-level Param Patterns (key shared, values vary) ─
    st.subheader(t("clusters.param_keys"))
    st.caption(t("clusters.param_keys_caption"))

    if not param_keys:
        st.info(t("clusters.no_param_keys"))
    else:
        pk_rows = []
        for pk in param_keys:
            pk_rows.append({
                "param_key":        pk["param_key"],
                "owner":            localize_owner(pk),
                "purpose":          localize_purpose(pk),
                "distinct_posts":   pk["distinct_posts"],
                "distinct_values":  pk["distinct_values"],
                "distinct_domains": pk["distinct_domains"],
                "top_values":       ", ".join(str(v)[:40] for v in pk["top_values"]),
                "domains":          ", ".join(pk["domains"]),
            })
        st.dataframe(pd.DataFrame(pk_rows), use_container_width=True, hide_index=True)

    st.divider()

    # ── Shared Tracking IDs (HTML-embedded — strongest signal) ──
    st.subheader(t("clusters.tracking_ids"))
    st.caption(t("clusters.tracking_ids_caption"))

    if not tracking_ids:
        st.info(t("clusters.no_tracking_ids"))
    else:
        tid_rows = []
        for r in tracking_ids:
            tid_rows.append({
                "platform":     r["platform"],
                "tracking_id":  r["tracking_id"],
                "domains":      r["domain_count"],
                "urls":         r["url_count"],
                "posts":        r["post_count"],
                "domain_list":  ", ".join(r["domains"]),
            })
        st.dataframe(pd.DataFrame(tid_rows), use_container_width=True, hide_index=True)

    st.divider()

    # ── Shared TLS Certificates ─────────────────────────────────
    st.subheader(t("clusters.tls"))
    st.caption(t("clusters.tls_caption"))

    by_cert = certs.get("by_cert") or []
    by_issuance = certs.get("by_issuance") or []

    if not by_cert and not by_issuance:
        st.info(t("clusters.no_tls"))
    else:
        if by_cert:
            st.markdown(f"**{t('clusters.tls_by_cert')}**")
            cert_rows = []
            for c in by_cert:
                cert_rows.append({
                    "issuer":       c["issuer"],
                    "serial":       _short_serial(c["serial"]),
                    "domains":      c["domain_count"],
                    "san_total":    c["san_count"],
                    "not_before":   c["not_before"],
                    "posts":        c["post_count"],
                    "domain_list":  ", ".join(c["domains"]),
                })
            st.dataframe(pd.DataFrame(cert_rows), use_container_width=True, hide_index=True)

        if by_issuance:
            st.markdown(f"**{t('clusters.tls_by_window')}**")
            win_rows = []
            for w in by_issuance:
                win_rows.append({
                    "window_start": w["window_start"],
                    "window_end":   w["window_end"],
                    "certs":        w["cert_count"],
                    "domains":      w["domain_count"],
                    "issuers":      w["issuers"],
                    "domain_list":  ", ".join(w["domains"]),
                })
            st.dataframe(pd.DataFrame(win_rows), use_container_width=True, hide_index=True)

    st.divider()

    # ── Shared Third-Party Endpoints (HAR-derived) ──────────────
    st.subheader(t("clusters.endpoints"))
    st.caption(t("clusters.endpoints_caption"))

    if not endpoints:
        st.info(t("clusters.no_endpoints"))
    else:
        ep_rows = []
        for ep in endpoints:
            ep_rows.append({
                "endpoint":      ep["endpoint"],
                "direct_ip":     "yes" if ep["is_direct_ip"] else "",
                "domains":       ep["domain_count"],
                "domain_list":   ", ".join(ep["domains"]),
            })
        st.dataframe(pd.DataFrame(ep_rows), use_container_width=True, hide_index=True)

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
