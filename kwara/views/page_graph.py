"""Relationship graph page (group-centric rebuild).

The whole-case infrastructure graph, COLOURED BY GROUP. This is the Maltego
view done right: each connected component (operator group) gets its own
colour, so the partition the Overview asserts is visible at a glance. Nodes
are domains + their named shared signals; edges mean "this domain carries
this signal". Group colours and node ids come from clusters.py (the single
source of truth), so the graph, the Overview, and the dossier all agree.

Rendered client-side from a DOT string via st.graphviz_chart — no new
dependency, fully offline. A group filter lets the analyst focus on one
cluster instead of reading the whole hairball.

The DOT builder itself lives in graph.py (core, UI-free) so the CLI and MCP
server emit exactly the same graph this page shows.
"""
import streamlit as st

from clusters import case_clusters, group_color
from graph import build_dot  # noqa: F401 — re-exported for existing callers


def render(conn, case_id):
    st.subheader("基礎設施關聯圖")
    st.caption(
        "域名（橢圓）透過共用識別資產（色塊）連在一起。"
        "**圖的大小隨內容多寡**——群內訊號少就小，複雜的群才會變大。"
        "預設顯示一個群組，要比對全部再開「顯示全部群組」。"
    )

    m = case_clusters(conn, case_id)
    groups = m["groups"]
    if not groups:
        if m["scanned"] > 0:
            st.info(
                "已掃描，但這些網站彼此獨立、沒有共用的識別資產，因此沒有可畫的關聯——"
                "這是正常結果，不是錯誤。關聯圖需要 2 個以上網站共用硬訊號才會出現。"
            )
        else:
            st.info("尚未歸因。請到「蒐證 → 進件」加入 URL，系統會自動歸因（免截圖）。")
        return

    # Default to ONE group, rendered at its NATURAL size (width='content',
    # not 'stretch'). Stretch blew a 3-node group up to full width; content
    # lets a simple group stay small and a complex one grow on its own.
    labels = {g["gid"]: f'{g["label"]}（{g["domain_count"]} 域名 · {g["signal_count"]} 訊號）'
              for g in groups}
    sel_col, all_col = st.columns([3, 1])
    show_all = (len(groups) > 1) and all_col.toggle(
        "顯示全部群組", value=False, key="graph_show_all")
    if show_all:
        # One small graph per group, laid out in a multi-column grid so the
        # space is used instead of a tall single-column strip.
        st.caption("每個群組一張小圖，多欄並排。要細看某一群就關掉此開關、用上方下拉選。")
        ncol = 3 if len(groups) >= 4 else 2
        cols = st.columns(ncol)
        for i, g in enumerate(groups):
            with cols[i % ncol]:
                clr = group_color(g["gid"])
                st.markdown(
                    f'<span style="color:{clr};font-weight:700">■</span> '
                    f'**{g["label"]}** · {g["domain_count"]}域 · {g["signal_count"]}訊號',
                    unsafe_allow_html=True)
                st.graphviz_chart(build_dot([g]), width='stretch')
        present = {s["type"] for g in groups for s in g["signals"]}
    else:
        active = st.session_state.get("active_group", groups[0]["gid"])
        gids = list(labels)
        idx = gids.index(active) if active in gids else 0
        gid = sel_col.selectbox("選擇群組", gids, index=idx,
                                format_func=lambda x: labels[x], key="graph_pick")
        st.session_state["active_group"] = gid
        g = next(x for x in groups if x["gid"] == gid)
        st.graphviz_chart(build_dot([g]), width='content')
        present = {s["type"] for s in g["signals"]}

    # Shape legend — only the signal types actually present.
    _shape_desc = {
        "tracking": "方塊＝追蹤碼", "cert": "八角＝TLS 憑證",
        "ads_template": "資料夾＝ads.txt 模板", "ads_account": "便箋＝ads.txt 帳號",
    }
    desc = "、".join(_shape_desc[t] for t in
                    ("tracking", "cert", "ads_template", "ads_account")
                    if t in present)
    if desc:
        st.caption("形狀：" + desc + "。")
