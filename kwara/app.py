"""kwara — Digital Evidence Collection & Corroboration Toolkit (Streamlit UI)

This file handles only the sidebar (language, cases, settings) and tab routing.
Each tab's content lives in pages/tab_*.py for easier maintenance.
"""
import json
import os
import shutil
import sys
from datetime import datetime, timezone

import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

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


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
_LOCALE_PRESETS = {
    "Taiwan (zh-TW)": ("zh-TW", "Asia/Taipei"),
    "US (en-US)": ("en-US", "America/New_York"),
    "UK (en-GB)": ("en-GB", "Europe/London"),
    "Japan (ja-JP)": ("ja-JP", "Asia/Tokyo"),
    "Korea (ko-KR)": ("ko-KR", "Asia/Seoul"),
    "Germany (de-DE)": ("de-DE", "Europe/Berlin"),
    "Custom": ("", ""),
}

with st.sidebar:
    st.title(t("sidebar.title"))

    lang_options = list(LANGUAGES.keys())
    current_idx = lang_options.index(get_lang()) if get_lang() in lang_options else 0
    sel_lang = st.selectbox("🌐", lang_options, index=current_idx, format_func=lambda x: LANGUAGES[x], key="lang_sel", label_visibility="collapsed", help="Interface language / 介面語言")
    if sel_lang != get_lang():
        set_lang(sel_lang)
        st.rerun()

    if st.button(t("sidebar.btn_guide"), key="btn_guide", use_container_width=True):
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
                now = now_utc()
                _final_loc = (_custom_loc or _lp[0]).strip() or None
                _final_tz  = (_custom_tz or _lp[1]).strip() or None
                conn.execute(
                    "INSERT INTO cases (title, description, created_at, updated_at, browser_locale, browser_timezone) VALUES (?, ?, ?, ?, ?, ?)",
                    (new_title.strip(), new_desc.strip(), now, now, _final_loc, _final_tz),
                )
                conn.commit()
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
                    _snap_rows = conn.execute(
                        """SELECT s.screenshot_path, s.html_path, s.har_path
                           FROM snapshots s JOIN scan_runs sr ON sr.id = s.scan_run_id
                           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                           WHERE ua.case_id = ?""",
                        (current_case_id,),
                    ).fetchall()
                    # Confine cleanup to the snapshot data root (codex review
                    # #6). Without this, a corrupted/crafted DB row could
                    # supply an arbitrary path to shutil.rmtree.
                    _SNAP_ROOT = os.path.realpath(os.path.join(
                        os.path.dirname(__file__), "data", "snapshots"
                    ))
                    _dirs_to_clean = set()
                    for _sr in _snap_rows:
                        for _col in ("screenshot_path", "html_path", "har_path"):
                            _p = _sr[_col]
                            if not _p or not os.path.exists(_p):
                                continue
                            _real = os.path.realpath(os.path.dirname(_p))
                            if _real == _SNAP_ROOT or _real.startswith(_SNAP_ROOT + os.sep):
                                _dirs_to_clean.add(_real)
                    for _d in _dirs_to_clean:
                        shutil.rmtree(_d, ignore_errors=True)
                    conn.execute("DELETE FROM audit_log WHERE case_id = ?", (current_case_id,))
                    conn.execute("DELETE FROM export_runs WHERE case_id = ?", (current_case_id,))
                    conn.execute(
                        """DELETE FROM snapshots WHERE scan_run_id IN
                           (SELECT sr.id FROM scan_runs sr JOIN url_artifacts ua ON ua.id = sr.url_artifact_id WHERE ua.case_id = ?)""",
                        (current_case_id,),
                    )
                    conn.execute(
                        """DELETE FROM redirect_hops WHERE scan_run_id IN
                           (SELECT sr.id FROM scan_runs sr JOIN url_artifacts ua ON ua.id = sr.url_artifact_id WHERE ua.case_id = ?)""",
                        (current_case_id,),
                    )
                    conn.execute(
                        """DELETE FROM scan_runs WHERE url_artifact_id IN
                           (SELECT id FROM url_artifacts WHERE case_id = ?)""",
                        (current_case_id,),
                    )
                    conn.execute("DELETE FROM url_artifacts WHERE case_id = ?", (current_case_id,))
                    conn.execute("DELETE FROM message_evidence WHERE case_id = ?", (current_case_id,))
                    conn.execute("DELETE FROM report_status WHERE case_id = ?", (current_case_id,))
                    conn.execute("DELETE FROM cases WHERE id = ?", (current_case_id,))
                    conn.commit()
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

# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------
st.markdown(t("page.header"))

if current_case_id is None:
    st.warning(t("page.warn_select"))
    st.stop()

# Read per-case locale
_case_row = conn.execute(
    "SELECT browser_locale, browser_timezone FROM cases WHERE id = ?",
    (current_case_id,),
).fetchone()
_case_locale = (_case_row["browser_locale"] if _case_row and _case_row["browser_locale"] else None)
_case_tz = (_case_row["browser_timezone"] if _case_row and _case_row["browser_timezone"] else None)

# ---------------------------------------------------------------------------
# Tabs — each delegates to its own module in views/
# Three-stage workflow: Investigate → Preserve → Analyze.
# ---------------------------------------------------------------------------
from views import (
    tab_analyze,
    tab_evidence,
    tab_export,
    tab_input,
    tab_investigate,
    tab_preserve,
)

tab_in, tab_ev, tab_iv, tab_pv, tab_az, tab_ex = st.tabs([
    t("tab.input"),
    t("tab.collected"),
    t("tab.investigate"),
    t("tab.preserve"),
    t("tab.analyze"),
    t("tab.export"),
])

with tab_in:
    tab_input.render(conn, current_case_id)

with tab_ev:
    tab_evidence.render(conn, current_case_id)

with tab_iv:
    tab_investigate.render(conn, current_case_id)

with tab_pv:
    tab_preserve.render(conn, current_case_id, case_locale=_case_locale, case_tz=_case_tz)

with tab_az:
    tab_analyze.render(conn, current_case_id)

with tab_ex:
    tab_export.render(conn, current_case_id)
