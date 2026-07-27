"""kwara — Digital Evidence Collection & Corroboration Toolkit (Streamlit UI)

Group-centric left-rail navigation (st.navigation):
  • an Overview verdict page as the default landing surface
  • a Group dossier and an Operator Graph drawn from the shared-signal
    clustering engines
  • Collection (add URLs → auto-attribution → optional screenshots) and
    Analysis grouped by analytic question

The sidebar owns case lifecycle (create / select / delete) plus language
and settings. Page bodies reuse the existing views/ render() functions.
"""
import os
import sys
from datetime import datetime, timezone

import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

import cases
from config import DB_PATH
from db import get_conn, init_db, migrate_db
from i18n import t, set_lang, get_lang, LANGUAGES

st.set_page_config(page_title="kwara", layout="wide")


@st.cache_resource
def _init_db_once():
    conn = get_conn(DB_PATH)
    init_db(conn)
    migrate_db(conn)
    conn.close()


_init_db_once()
conn = get_conn(DB_PATH)
migrate_db(conn)


def now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@st.dialog("kwara")
def _show_guide():
    st.markdown(t("guide.content"))


_LOCALE_PRESETS = {
    "Taiwan (zh-TW)": ("zh-TW", "Asia/Taipei"),
    "US (en-US)": ("en-US", "America/New_York"),
    "UK (en-GB)": ("en-GB", "Europe/London"),
    "Japan (ja-JP)": ("ja-JP", "Asia/Tokyo"),
    "Korea (ko-KR)": ("ko-KR", "Asia/Seoul"),
    "Germany (de-DE)": ("de-DE", "Europe/Berlin"),
    "Custom": ("", ""),
}


# ---------------------------------------------------------------------------
# Sidebar — language, case lifecycle (create / select / delete), settings.
# The navigation rail is auto-added by st.navigation below.
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title(t("sidebar.title"))

    lang_options = list(LANGUAGES.keys())
    current_idx = lang_options.index(get_lang()) if get_lang() in lang_options else 0
    sel_lang = st.selectbox("🌐", lang_options, index=current_idx, format_func=lambda x: LANGUAGES[x], key="lang_sel", label_visibility="collapsed", help="Interface language / 介面語言")
    if sel_lang != get_lang():
        set_lang(sel_lang)
        st.rerun()

    if st.button(t("sidebar.btn_guide"), key="btn_guide", width='stretch'):
        _show_guide()
    st.divider()

    with st.expander(t("sidebar.new_case"), expanded=False):
        new_title = st.text_input(t("sidebar.label_title"), key="new_case_title")
        new_desc  = st.text_area(t("sidebar.label_desc"), key="new_case_desc", height=80)
        _locale_label = st.selectbox(
            t("sidebar.victim_locale"), list(_LOCALE_PRESETS.keys()), key="new_case_locale",
            help=t("sidebar.victim_locale_help"),
        )
        _lp = _LOCALE_PRESETS[_locale_label]
        if _locale_label == "Custom":
            _custom_loc = st.text_input(t("sidebar.custom_locale"), key="new_case_custom_loc", placeholder="e.g. en-GB")
            _custom_tz  = st.text_input(t("sidebar.custom_tz"), key="new_case_custom_tz", placeholder="e.g. Europe/London")
        else:
            _custom_loc, _custom_tz = _lp

        if st.button(t("sidebar.btn_create"), key="btn_create_case"):
            if new_title.strip():
                _final_loc = (_custom_loc or _lp[0]).strip() or None
                _final_tz  = (_custom_tz or _lp[1]).strip() or None
                cases.create_case(
                    conn,
                    title=new_title,
                    description=new_desc,
                    browser_locale=_final_loc,
                    browser_timezone=_final_tz,
                )
                st.success(t("sidebar.success_created", title=new_title.strip()))
                st.rerun()
            else:
                st.warning(t("sidebar.warn_title"))

    st.divider()
    cases = conn.execute("SELECT id, title FROM cases ORDER BY id DESC").fetchall()
    if cases:
        case_options    = {f"[{r['id']}] {r['title']}": r["id"] for r in cases}
        selected_label  = st.selectbox(t("sidebar.active_case"), list(case_options.keys()))
        current_case_id = case_options[selected_label]

        with st.expander(t("sidebar.delete_case"), expanded=False):
            st.warning(t("sidebar.delete_warn"))
            _confirm = st.text_input(t("sidebar.delete_confirm"), key="delete_confirm_input")
            if st.button(t("sidebar.delete_btn"), key="btn_delete_case", type="primary"):
                if _confirm == "DELETE":
                    cases.delete_case(conn, current_case_id, confirm="DELETE")
                    st.success(t("sidebar.delete_done"))
                    st.rerun()
                else:
                    st.error(t("sidebar.delete_type_confirm"))
    else:
        st.info(t("sidebar.info_no_cases"))
        current_case_id = None

    st.divider()
    with st.expander(t("sidebar.settings")):
        from config import HTTP_TIMEOUT, MAX_HOPS, NEW_DOMAIN_DAYS, HIGH_TRACKER_THRESHOLD
        _def_locale = os.environ.get("KWARA_BROWSER_LOCALE", "zh-TW")
        _def_tz = os.environ.get("KWARA_BROWSER_TIMEZONE", "Asia/Taipei")
        _settings = [
            (t("settings.scanner_timeout"), f"{HTTP_TIMEOUT}s"),
            (t("settings.max_hops"), str(MAX_HOPS)),
            (t("settings.new_domain_days"), f"{NEW_DOMAIN_DAYS} days"),
            (t("settings.tracker_threshold"), str(HIGH_TRACKER_THRESHOLD)),
            (t("settings.default_locale"), _def_locale),
            (t("settings.default_timezone"), _def_tz),
        ]
        for label, val in _settings:
            st.caption(f"**{label}:** {val}")

    st.divider()
    st.caption(f"DB: `{os.path.basename(DB_PATH)}`")


# Per-case locale (needed by the Preserve / Page capture view).
_case_locale = _case_tz = None
if current_case_id is not None:
    _r = conn.execute(
        "SELECT browser_locale, browser_timezone FROM cases WHERE id = ?",
        (current_case_id,),
    ).fetchone()
    _case_locale = _r["browser_locale"] if _r and _r["browser_locale"] else None
    _case_tz = _r["browser_timezone"] if _r and _r["browser_timezone"] else None


# ---------------------------------------------------------------------------
# Page bodies — closures over conn + current_case_id (st.Page wants a no-arg
# callable). Each reuses existing render() functions; the two NEW pages
# (Overview, Graph) live in views/page_*.py.
# ---------------------------------------------------------------------------
from views import (
    _sub_cloaking,
    _sub_corroboration,
    _sub_domain,
    _sub_headers,
    _sub_insights,
    _sub_network,
    _sub_opsec,
    _sub_page,
    _sub_scan,
    page_graph,
    page_group,
    page_crosscase,
    page_overview,
    tab_crosscase,
    tab_evidence,
    tab_export,
    tab_input,
    tab_providers,
)


def _need_case():
    if current_case_id is None:
        st.warning("先在側欄選一個案件。Select a case in the sidebar.")
        return False
    return True


def pg_overview():
    if _need_case():
        page_overview.render(conn, current_case_id, goto_group=_PAGE_GROUP)


def pg_group():
    if _need_case():
        page_group.render(conn, current_case_id)


# Collection flow. The principle (per user): adding URLs auto-runs the cheap
# no-screenshot attribution; screenshots are an opt-in "get more" step.
_COLLECT = ["進件", "頁面擷取", "掃描", "佐證", "網路詳情", "網域情報"]
_COLLECT_HELP = {
    "進件":     "貼上 FB 貼文／留言或匯入 CSV → 抽出連結並**自動歸因（免截圖）**，群組與關聯圖隨即浮現。",
    "頁面擷取": "（取得更多）對重點 URL 以瀏覽器擷取截圖／HTML／HAR——補上 JS 注入的追蹤碼，並作為保全證據。",
    "掃描":     "（進階／手動）重新追蹤跳轉鏈、記錄 TLS 憑證與 HTTP 標頭。",
    "佐證":     "將落地頁存檔到 Wayback、提交 urlscan.io、取得 RFC 3161 受信時間戳。",
    "網路詳情": "檢視掃描結果：憑證、跳轉路徑、回應標頭、ads.txt。",
    "網域情報": "查詢 WHOIS 註冊資訊、IP 與 ASN 託管。",
}

_AUTO_ATTR_CAP = 20   # auto-run for modest batches; a big paste is an explicit click


def _auto_fast_attribution():
    """After URLs are added, attribute them automatically (no screenshots) so
    groups appear without the analyst clicking anything. Runs once per new
    batch; a large batch becomes an explicit button (a long blocking render
    on auto would feel like a hang)."""
    import pipeline
    pending = pipeline._artifacts_needing_scan(conn, current_case_id)
    if not pending:
        return
    sig = (current_case_id, len(pending))

    def _run(force=False):
        with st.status("自動歸因中（免截圖：掃描 → 追蹤碼 → ads.txt → WHOIS）…") as s:
            summary = pipeline.run_fast_attribution(conn, current_case_id, force=force)
            s.update(label="歸因完成", state="complete")
        st.session_state["auto_attr_sig"] = sig
        st.success(
            f"已自動歸因 {len(pending)} 個連結 → 到「總覽」「關聯圖」看群組。"
            "想要更多訊號（JS 注入的追蹤碼）就到「頁面擷取」截圖。"
        )
        if summary["errors"]:
            st.caption(f"（{len(summary['errors'])} 個被站點擋掉，已略過）")

    st.divider()
    if len(pending) > _AUTO_ATTR_CAP:
        st.info(f"有 **{len(pending)}** 個連結待歸因（批量較大，手動啟動以免畫面卡住）。")
        if st.button(f"歸因這 {len(pending)} 個（免截圖）", type="primary", key="big_attr"):
            _run()
    elif st.session_state.get("auto_attr_sig") != sig:
        _run()


def pg_collection():
    if not _need_case():
        return
    st.subheader("蒐證")
    st.caption("加入 URL 會**自動歸因（免截圖）**看關聯；要更多訊號／保全證據再到「頁面擷取」截圖。")
    step = st.segmented_control(
        "step", _COLLECT, default="進件", label_visibility="collapsed",
    )
    st.caption(_COLLECT_HELP.get(step, ""))
    st.divider()
    if step == "進件":
        tab_input.render(conn, current_case_id)
        _auto_fast_attribution()          # input → auto no-screenshot analysis
        st.divider()
        tab_evidence.render(conn, current_case_id)
    elif step == "頁面擷取":
        _sub_page.render(conn, current_case_id, case_locale=_case_locale, case_tz=_case_tz)
    elif step == "掃描":
        _sub_scan.render(conn, current_case_id)
    elif step == "佐證":
        _sub_corroboration.render(conn, current_case_id)
    elif step == "網路詳情":
        _sub_network.render(conn, current_case_id)
    else:
        _sub_domain.render(conn, current_case_id)


# Analysis grouped by analytic purpose (neutral, nominal headings).
_ANALYSIS_Q = {
    "歸因與基礎設施": ["insights", "providers"],
    "行為觀察":       ["cloaking", "opsec"],
    "伺服器標頭鑑識": ["headers"],
}
_ANALYSIS_HELP = {
    "歸因與基礎設施": "跨網站共用訊號的聚類，與課責對象（註冊商、託管、CA、廣告帳號）。",
    "行為觀察":       "內容偽裝（cloaking）偵測，與自動化檢測回應差異（OPSEC）。",
    "伺服器標頭鑑識": "逐跳 HTTP 回應標頭：常數、跨域模板、偽造版本、cookie 網域。",
}


def pg_analysis():
    if not _need_case():
        return
    st.subheader("分析")
    st.caption("總覽與卷宗以外的進階交叉分析，供分析師深入檢視。")
    q = st.segmented_control(
        "question", list(_ANALYSIS_Q.keys()),
        default=list(_ANALYSIS_Q.keys())[0], label_visibility="collapsed",
    )
    st.caption(_ANALYSIS_HELP.get(q, ""))
    st.divider()
    panels = _ANALYSIS_Q[q]
    if "insights" in panels:
        _sub_insights.render(conn, current_case_id)
        st.divider()
    if "cloaking" in panels:
        _sub_cloaking.render(conn, current_case_id)
        st.divider()
    if "opsec" in panels:
        _sub_opsec.render(conn, current_case_id)
        st.divider()
    if "headers" in panels:
        _sub_headers.render(conn, current_case_id)
        st.divider()
    if "providers" in panels:
        tab_providers.render(conn, current_case_id)


def pg_graph():
    if _need_case():
        page_graph.render(conn, current_case_id)


def pg_crosscase():
    page_crosscase.render(conn, current_case_id)


def pg_export():
    if not _need_case():
        return
    st.subheader("匯出")
    st.caption("打包整案為 ZIP 證據封包：CSV、截圖、HTML、HAR、稽核紀錄、"
               "SHA-256 manifest 與可選 HMAC 簽章。")
    tab_export.render(conn, current_case_id)


# ---------------------------------------------------------------------------
# Navigation rail — grouped sections (Logz/Grafana style).
# Group-centric: Overview (group breakdown) → Group dossier → Collection.
# ---------------------------------------------------------------------------
# Page objects created first so pg_overview's "查看卷宗" can st.switch_page to
# the dossier (referenced via the module global _PAGE_GROUP at call time).
_PAGE_GROUP = st.Page(pg_group, title="群組卷宗 Dossier", icon=":material/folder_open:")

nav = st.navigation({
    "案件 Case": [
        st.Page(pg_overview,    title="總覽 Overview",     icon=":material/assessment:", default=True),
        _PAGE_GROUP,
        st.Page(pg_collection,  title="蒐證 Collection",   icon=":material/travel_explore:"),
    ],
    "分析 Analysis": [
        st.Page(pg_analysis,    title="分析 Analysis",     icon=":material/analytics:"),
        st.Page(pg_graph,       title="關聯圖 Graph",      icon=":material/hub:"),
    ],
    "全域 Global": [
        st.Page(pg_crosscase,   title="跨案件 Cross-case", icon=":material/public:"),
        st.Page(pg_export,      title="匯出 Export",       icon=":material/download:"),
    ],
})
nav.run()
