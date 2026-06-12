"""Overview page (group-centric rebuild).

The primary object is the operator GROUP, not the case. A case resolves into
N infrastructure groups (proven by connected-components over shared hard
signals — case 3 = 3 groups = the report's α/β/γ). This page leads with that
breakdown: how many groups, how strong, named lead evidence, and a link into
each group's full dossier.

Register: neutral, tiered, scope-bounded, evidence-named, no emoji. Heuristic
counts (cloaking) are framed as 待複核, never asserted.
"""
import streamlit as st

from clusters import case_clusters, group_color
from insights import case_insights
from ui_tokens import ACCENT, FAINT, INK, MUTED

_SCOPE = (
    "本頁判斷限於**數位資產層**訊號（追蹤碼、TLS 憑證、ads.txt、HTTP header）。"
    "「群組」指共用硬識別資產、可確定屬同一基礎設施群；是否為**單一操作者**、"
    "是否涉及特定法律責任，須再結合內容層分析與正式調查程序判斷。本頁為調查線索，"
    "非最終操作者歸屬論斷。"
)


def _determination(n_groups: int) -> tuple[str, str]:
    if n_groups == 0:
        return MUTED, "尚未發現足以確定同群體的跨站共用訊號"
    if n_groups == 1:
        return ACCENT, "數位資產層：可確定屬同一基礎設施群組"
    return ACCENT, f"數位資產層：可分出 {n_groups} 個獨立基礎設施群組"


def render(conn, case_id, goto_group=None):
    row = conn.execute(
        "SELECT title FROM cases WHERE id = ?", (case_id,)
    ).fetchone()
    title = (row["title"] if row else "") or f"case #{case_id}"

    m = case_clusters(conn, case_id)
    groups = m["groups"]
    comp = m["completeness"]
    colour, line = _determination(len(groups))

    st.caption("全案研判：這批可疑連結在數位資產層可分出幾個基礎設施群組，"
               "各群的具名證據、處置渠道與資料完整性。")

    # ── Determination header ───────────────────────────────────────────
    st.markdown(
        f"""
        <div style="border-left:5px solid {colour};padding:0.6rem 1rem;
                    background:rgba(127,127,127,0.05)">
          <div style="font-size:0.8rem;color:{FAINT};letter-spacing:0.05em">案件</div>
          <div style="font-size:1.2rem;font-weight:700;margin-bottom:0.3rem">{title}</div>
          <div style="font-size:1.05rem;color:{colour};font-weight:600">{line}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Facts first (auditable basis) ──────────────────────────────────
    with st.container(border=True):
        a, b, c, d = st.columns(4)
        a.metric("可疑連結", m["n_urls"])
        b.metric("已掃描", m["scanned"])
        c.metric("基礎設施群組", len(groups))
        d.metric("資料完整性", comp["level"])
    if comp["gaps"]:
        _gap_names = {"scanned": "掃描", "page_captured": "頁面擷取",
                      "tls": "TLS 憑證", "ads_txt": "ads.txt"}
        st.caption("尚缺：" + "、".join(_gap_names.get(g, g) for g in comp["gaps"]))

    # ── Fixed scope/limitation block (not a caption) ───────────────────
    with st.container(border=True):
        st.markdown("**範圍與限制**")
        st.markdown(_SCOPE)

    # ── Group breakdown (the hero) ─────────────────────────────────────
    st.markdown("#### 基礎設施群組")
    if not groups:
        if m["scanned"] > 0:
            st.info(
                f"已掃描 {m['scanned']} 個連結，但這些網站在數位資產層**彼此獨立**——"
                "沒有共用的追蹤碼、TLS 憑證或 ads.txt 帳號。這是**正常結果**（代表它們"
                "不是同一組基礎設施），不是錯誤。群組與關聯圖需要 2 個以上網站共用硬訊號才會出現。"
                "\n\n單一網站的證據（截圖、TLS、headers、ads.txt）仍可在「蒐證 → 網路詳情／頁面擷取」逐一查看。"
            )
        else:
            st.info(
                "尚未歸因。請到「蒐證 → 進件」加入 URL——系統會**自動歸因（免截圖）**，"
                "群組就會浮現。要更多訊號／保全證據再用「頁面擷取」截圖。"
            )
    for g in groups:
        clr = group_color(g["gid"])
        with st.container(border=True):
            head_l, head_r = st.columns([3, 1])
            with head_l:
                st.markdown(
                    f'<span style="background:{clr};color:white;font-weight:700;'
                    f'padding:1px 9px">{g["label"]}</span> '
                    f'&nbsp;<span style="background:{INK};color:white;font-size:0.72rem;'
                    f'padding:1px 7px">{g["tier"]}</span> '
                    f'&nbsp;<span style="color:{MUTED}">{g["domain_count"]} 個域名 · '
                    f'{g["signal_count"]} 項共用訊號</span>',
                    unsafe_allow_html=True,
                )
            with head_r:
                if st.button("查看卷宗 →", key=f"goto_{g['gid']}",
                             width='stretch'):
                    st.session_state["active_group"] = g["gid"]
                    if goto_group is not None:
                        try:
                            st.switch_page(goto_group)
                        except Exception:
                            st.info("請於左側切到「群組卷宗」查看。")

            # lead named signals (the concrete evidence, not just counts)
            for s in g["signals"][:3]:
                st.markdown(
                    f"- **{s['label']} `{s['value']}`** — 連結 {len(s['domains'])} 個域名"
                    f"　·　處置渠道：{s['channel']}"
                )
            if g["signal_count"] > 3:
                st.caption(f"…另有 {g['signal_count'] - 3} 項共用訊號（見卷宗）")
            st.caption("域名：" + "、".join(g["domains"][:6])
                       + ("…" if g["domain_count"] > 6 else ""))

    # ── Behaviour observations (pending review, never asserted) ────────
    beh = m["behaviour"]
    if beh["cloaking_pending"] or beh["fake_versions"] or beh["opsec_strong"]:
        st.markdown("#### 行為觀察（待人工複核）")
        with st.container(border=True):
            if beh["cloaking_pending"]:
                st.markdown(
                    f"- **內容偽裝樣態：{beh['cloaking_pending']} 例待複核** — "
                    "連結對「帶／不帶 tracking 參數」的請求回傳不同內容。"
                    "是否為刻意規避，須內容層交叉驗證。")
            if beh["fake_versions"]:
                st.markdown(
                    f"- **伺服器版本資訊不符：{beh['fake_versions']} 例** — "
                    "回報的 server 版本與實際技術對不上。")
            if beh["opsec_strong"]:
                st.markdown(
                    f"- **自動化檢測回應差異：{beh['opsec_strong']} 個域名**。")

    # ── Weak links (correlated, unproven) ──────────────────────────────
    weak = m["weak_links"]
    if weak:
        with st.expander(f"相關未證實訊號（{len(weak)} 項，頻率加權後）"):
            st.caption("跨域共用的 HTTP header 特徵；已濾除泛用值（cloudflare 等）。"
                       "力道較弱，僅供與其他訊號併參，不單獨作為同群依據。")
            for w in weak:
                st.markdown(
                    f"- `{w['header']}: {w['value']}` — {w['domain_count']} 個域名")

    st.divider()
    with st.expander("分析師摘要（technical）", expanded=False):
        ins = case_insights(conn, case_id)
        if ins.get("headline"):
            st.write(ins["headline"])
        for b in (ins.get("bullets") or [])[:8]:
            st.markdown(f"- {b}")
