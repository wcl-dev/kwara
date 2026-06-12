"""Group dossier page (group-centric rebuild) — the heart of the product.

One operator group, in full: its domains, its NAMED shared signals (with the
disposition channel each implies), behaviour observations, a sub-graph of
just this group, and — critically — a one-click path from every domain to its
preserved artifacts (screenshot / HTML / HAR). That verdict→artifact
traceability is what makes the tool evidentiary rather than a dashboard.
"""
import os

import streamlit as st

from clusters import case_clusters, group_color, node_id
from ui_tokens import GRAPH_EDGE, INK, MUTED, NEUTRAL_FILL

_SIG_SHAPE = {
    "tracking":     "box",
    "cert":         "octagon",
    "ads_template": "folder",
    "ads_account":  "note",
}


def _group_dot(g) -> str:
    """A small DOT graph for one group: its domains + its shared signals."""
    clr = group_color(g["gid"])
    lines = [
        "digraph grp {", "  rankdir=LR;", '  bgcolor="transparent";',
        '  node [fontname="Helvetica", fontsize=10];',
        f'  edge [color="{GRAPH_EDGE}", arrowhead=none];',
    ]
    for d in g["domains"]:
        lines.append(
            f'  {node_id("dom", d)} [label="{d}", shape=ellipse, '
            f'style=filled, fillcolor="{NEUTRAL_FILL}", color="{INK}"];'
        )
    for i, s in enumerate(g["signals"]):
        sid = node_id("sig", f"{s['type']}:{s['value']}:{i}")
        shape = _SIG_SHAPE.get(s["type"], "box")
        label = f"{s['label']}\\n{s['value']}"
        lines.append(
            f'  {sid} [label="{label}", shape={shape}, style=filled, '
            f'fillcolor="{clr}", fontcolor="white"];'
        )
        for d in s["domains"]:
            lines.append(f'  {sid} -> {node_id("dom", d)};')
    lines.append("}")
    return "\n".join(lines)


def _domain_artifacts(conn, case_id, domain):
    """Latest preserved snapshot for a landing domain → artifact paths."""
    return conn.execute(
        """SELECT s.final_url, s.captured_at, s.screenshot_path, s.html_path,
                  s.har_path
           FROM snapshots s
           JOIN scan_runs sr ON sr.id = s.scan_run_id
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE ua.case_id = ? AND LOWER(s.final_domain) = ?
           ORDER BY s.id DESC LIMIT 1""",
        (case_id, (domain or "").lower()),
    ).fetchone()


def _artifact_line(label, path):
    if path and os.path.exists(path):
        return f"{label}：`{os.path.basename(path)}`"
    if path:
        return f"{label}：（紀錄存在，檔案不在原路徑）"
    return f"{label}：—"


def render(conn, case_id):
    m = case_clusters(conn, case_id)
    groups = m["groups"]
    st.subheader("群組卷宗")
    st.caption("單一基礎設施群組的完整證據：成員域名、共用識別資產與處置渠道、"
               "行為觀察，以及每個域名的保全物證（截圖／HTML／HAR）。")

    if not groups:
        st.info("本案目前尚無基礎設施群組。請先於「蒐證」完成掃描與頁面擷取。")
        return

    labels = [f"{g['label']}（{g['domain_count']} 域名）" for g in groups]
    active = st.session_state.get("active_group", groups[0]["gid"])
    idx = next((i for i, g in enumerate(groups) if g["gid"] == active), 0)
    pick = st.selectbox("選擇群組", range(len(groups)),
                        index=idx, format_func=lambda i: labels[i])
    g = groups[pick]
    st.session_state["active_group"] = g["gid"]

    clr = group_color(g["gid"])
    st.markdown(
        f'<span style="background:{clr};color:white;font-weight:700;'
        f'padding:2px 10px">{g["label"]}</span> '
        f'&nbsp;<span style="background:{INK};color:white;font-size:0.75rem;'
        f'padding:2px 8px">{g["tier"]}</span> '
        f'&nbsp;<span style="color:{MUTED}">{g["domain_count"]} 個域名 · '
        f'{g["signal_count"]} 項共用訊號</span>',
        unsafe_allow_html=True,
    )
    if g["channels"]:
        st.caption("處置渠道：" + "　·　".join(g["channels"]))

    # ── Named shared signals ───────────────────────────────────────────
    st.markdown("##### 共用識別資產")
    st.dataframe(
        [{
            "類型": {"tracking": "追蹤碼", "cert": "TLS 憑證",
                    "ads_template": "ads.txt 模板",
                    "ads_account": "ads.txt 帳號"}.get(s["type"], s["type"]),
            "平台／來源": s["label"],
            "識別碼": s["value"],
            "連結域名數": len(s["domains"]),
            "處置渠道": s["channel"],
        } for s in g["signals"]],
        hide_index=True, width='stretch',
    )

    # ── Sub-graph of just this group ───────────────────────────────────
    st.markdown("##### 群組關聯圖")
    st.graphviz_chart(_group_dot(g), width='stretch')

    # ── Behaviour observations on this group's domains ─────────────────
    if g["fake_versions"]:
        st.markdown("##### 行為觀察（本群域名，待複核）")
        seen = set()
        for fv in g["fake_versions"]:
            key = (fv.get("domain"), fv.get("header"), fv.get("value"))
            if key in seen:
                continue
            seen.add(key)
            st.markdown(
                f"- `{fv.get('domain')}` — `{fv.get('header')}: {fv.get('value')}`"
                f"（{fv.get('reason')}）")

    # ── Per-domain drill-down to preserved artifacts ───────────────────
    st.markdown("##### 域名與物證")
    st.caption("每個域名連到最近一次保全的截圖／HTML／HAR，供溯源核對。")
    for d in g["domains"]:
        art = _domain_artifacts(conn, case_id, d)
        with st.expander(d):
            if art is None:
                st.caption("尚無保全快照 — 請於「蒐證」擷取頁面。")
                continue
            st.markdown(f"最終網址：`{art['final_url'] or '—'}`")
            st.caption(f"擷取時間：{art['captured_at'] or '—'}")
            st.markdown(_artifact_line("截圖", art["screenshot_path"]))
            st.markdown(_artifact_line("HTML", art["html_path"]))
            st.markdown(_artifact_line("HAR", art["har_path"]))
            shot = art["screenshot_path"]
            if shot and os.path.exists(shot):
                st.image(shot, width='stretch')
