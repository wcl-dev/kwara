import json
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse as _urlparse

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

from db import get_conn, init_db, migrate_db
from i18n import t, set_lang, get_lang, LANGUAGES
from ingestion import ingest_message, ingest_csv
from pipeline import (
    run_domain_intel_batch,
    run_domain_intel_only,
    run_scan_only,
    run_snapshot,
    run_snapshot_batch,
)
from clustering import (
    _merge_risk_tags,
    asn_clusters,
    shared_destinations,
    shared_params,
    KNOWN_SHORTLINK_DOMAINS,
)
from insights import case_insights
from snapshots import SUSPICIOUS_EXTS as _SUSP_EXTS, failed_capture_urls_csv
from exporter import export_case

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "kwara.db")

st.set_page_config(page_title="kwara", layout="wide")


@st.cache_resource
def _init_db_once():
    conn = get_conn(DB_PATH)
    init_db(conn)
    migrate_db(conn)
    conn.close()


_init_db_once()
conn = get_conn(DB_PATH)
# Migrations must run on this connection: @st.cache_resource can skip re-running
# _init_db_only when only db.migrate_db() changes, leaving new columns missing.
migrate_db(conn)


def now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@st.dialog("kwara")
def _show_guide():
    st.markdown(t("guide.content"))


TAG_COLORS = {
    "multi_hop":           "🔴",
    "suspicious_download": "🔴",
    "new_domain":          "🔴",
    "no_https":            "🟠",
    "high_tracker_count":  "🟡",
    "url_shortener_chain": "🟡",
    "capture_error":       "⚫",
}

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title(t("sidebar.title"))

    lang_options = list(LANGUAGES.keys())
    lang_labels = list(LANGUAGES.values())
    current_idx = lang_options.index(get_lang()) if get_lang() in lang_options else 0
    sel_lang = st.selectbox("🌐", lang_options, index=current_idx, format_func=lambda x: LANGUAGES[x], key="lang_sel", label_visibility="collapsed")
    if sel_lang != get_lang():
        set_lang(sel_lang)
        st.rerun()

    if st.button(t("sidebar.btn_guide"), key="btn_guide", use_container_width=True):
        _show_guide()
    st.divider()

    with st.expander(t("sidebar.new_case"), expanded=False):
        new_title = st.text_input(t("sidebar.label_title"), key="new_case_title")
        new_desc  = st.text_area(t("sidebar.label_desc"), key="new_case_desc", height=80)
        if st.button(t("sidebar.btn_create"), key="btn_create_case"):
            if new_title.strip():
                now = now_utc()
                conn.execute(
                    "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (new_title.strip(), new_desc.strip(), now, now),
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
    else:
        st.info(t("sidebar.info_no_cases"))
        current_case_id = None

# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------
st.markdown(t("page.header"))

if current_case_id is None:
    st.warning(t("page.warn_select"))
    st.stop()

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
def _scan_flags(final_url, hop_count):
    """Risk signals derivable from scan data alone, before snapshot."""
    flags = []
    fu = final_url or ""
    if not fu:
        return flags
    p = _urlparse(fu)
    if (hop_count or 0) >= 3:
        flags.append("multi_hop")
    if p.scheme == "http":
        flags.append("no_https")
    if any(p.path.lower().endswith(e) for e in _SUSP_EXTS):
        flags.append("suspicious_download")
    if (p.hostname or "") in KNOWN_SHORTLINK_DOMAINS:
        flags.append("url_shortener_chain")
    return flags


tab_input, tab_evidence, tab_analysis, tab_providers, tab_export = st.tabs(
    [t("tab.input"), t("tab.collected"), t("tab.analysis"), t("tab.providers"), t("tab.export")]
)

# ===========================================================================
# INPUT
# ===========================================================================
with tab_input:
    mode = st.radio("", [t("input.single_post"), t("input.csv_batch")], horizontal=True, key="input_mode")
    st.divider()

    # ── Single Post ─────────────────────────────────────────────────────────
    if mode == t("input.single_post"):
        c1, c2 = st.columns(2)
        with c1:
            platform   = st.text_input(t("input.platform"), key="p_platform", placeholder=t("input.platform_ph"))
            permalink  = st.text_input(t("input.permalink"), key="p_permalink")
        with c2:
            actor      = st.text_input(t("input.actor"), key="p_actor", placeholder=t("input.actor_ph"))
            posted_at  = st.text_input(t("input.posted_at"), key="p_posted_at", placeholder=t("input.posted_at_ph"))
        message_text = st.text_area(t("input.message"), height=150, key="p_text")
        screenshot   = st.file_uploader(t("input.screenshot"), type=["png", "jpg", "jpeg", "webp"], key="p_screenshot")

        if st.button(t("input.btn_submit"), type="primary", key="btn_submit_post"):
            if not message_text.strip():
                st.warning(t("input.warn_message"))
            else:
                screenshot_path = ""
                if screenshot:
                    save_dir = os.path.join(os.path.dirname(__file__), "data", "screenshots")
                    os.makedirs(save_dir, exist_ok=True)
                    screenshot_path = os.path.join(save_dir, screenshot.name)
                    with open(screenshot_path, "wb") as f:
                        f.write(screenshot.read())

                msg_id, urls = ingest_message(
                    conn, current_case_id,
                    message_text=message_text, platform=platform,
                    permalink=permalink, actor_label=actor,
                    posted_at=posted_at, screenshot_path=screenshot_path,
                )
                st.success(t("input.success_saved", n=len(urls)))
                for u in urls:
                    st.code(u)

    # ── CSV Batch ───────────────────────────────────────────────────────────
    else:
        st.caption(t("input.csv_caption"))
        uploaded_csv = st.file_uploader(t("input.csv_upload"), type=["csv"], key="csv_upload")

        if uploaded_csv:
            try:
                df_preview = pd.read_csv(uploaded_csv)
                st.write(t("input.csv_preview"))
                st.dataframe(df_preview.head(5), use_container_width=True)
                uploaded_csv.seek(0)
            except Exception as e:
                st.error(t("input.csv_error", e=e))
                df_preview = None

            if st.button(t("input.btn_import"), type="primary", key="btn_submit_csv"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="wb") as tmp:
                    tmp.write(uploaded_csv.read())
                    tmp_path = tmp.name
                try:
                    results   = ingest_csv(conn, current_case_id, tmp_path)
                    total_urls = sum(r["url_count"] for r in results)
                    st.success(t("input.csv_success", posts=len(results), urls=total_urls))
                except Exception as e:
                    st.error(t("input.csv_fail", e=e))
                finally:
                    os.unlink(tmp_path)

# ===========================================================================
# EVIDENCE
# ===========================================================================
with tab_evidence:
    # ── Source Posts ─────────────────────────────────────────────────────────
    st.subheader(t("evidence.posts"))

    messages = conn.execute(
        """SELECT id, platform, actor_label AS actor, posted_at,
                  permalink, substr(message_text, 1, 100) AS message_preview,
                  ingested_at
           FROM message_evidence WHERE case_id = ? ORDER BY id DESC""",
        (current_case_id,),
    ).fetchall()

    if messages:
        st.dataframe(pd.DataFrame([dict(r) for r in messages]), use_container_width=True, hide_index=True)
    else:
        st.info(t("evidence.no_posts"))

    st.divider()

    # ── Extracted URLs ───────────────────────────────────────────────────────
    st.subheader(t("evidence.urls"))
    artifacts = conn.execute(
        """SELECT ua.id, ua.original_url AS url, ua.domain,
                  ua.message_id AS source_post_id,
                  sr.status AS scan_status, sr.final_url
           FROM url_artifacts ua
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ?
           ORDER BY ua.message_id, ua.url_order""",
        (current_case_id,),
    ).fetchall()

    if artifacts:
        st.dataframe(pd.DataFrame([dict(r) for r in artifacts]), use_container_width=True, hide_index=True)
    else:
        st.info(t("evidence.no_urls"))

# ===========================================================================
# ANALYSIS
# ===========================================================================
with tab_analysis:
    sub_scan, sub_investigate, sub_clusters = st.tabs([t("tab.scan"), t("tab.investigate"), t("tab.clusters")])

    # ── Scan ─────────────────────────────────────────────────────────────────
    with sub_scan:
        url_rows = conn.execute(
            """SELECT ua.id, ua.original_url, ua.domain,
                      sr.id AS scan_run_id, sr.status, sr.hop_count, sr.final_url
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? ORDER BY ua.id""",
            (current_case_id,),
        ).fetchall()

        if not url_rows:
            st.info(t("scan.no_urls"))
        else:
            unscanned    = [r for r in url_rows if r["scan_run_id"] is None]
            stuck        = [r for r in url_rows if r["status"] == "running"]
            done_count   = sum(1 for r in url_rows if r["status"] == "done")
            failed_count = sum(1 for r in url_rows if r["status"] not in (None, "done", "running"))

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric(t("scan.total"),     len(url_rows))
            m2.metric(t("scan.unscanned"), len(unscanned))
            m3.metric(t("scan.done"),      done_count)
            m4.metric(t("scan.failed"),    failed_count)
            m5.metric(t("scan.stuck"),     len(stuck))

            if stuck:
                st.warning(t("scan.warn_stuck", n=len(stuck)))
                if st.button(t("scan.btn_reset", n=len(stuck)), key="btn_reset_stuck"):
                    for r in stuck:
                        conn.execute("UPDATE scan_runs SET status='error', notes='interrupted' WHERE id=?", (r["scan_run_id"],))
                    conn.commit()
                    st.rerun()

            def _scan_worker(ua_id: int):
                import random, time
                time.sleep(random.uniform(0, 2))
                c = get_conn(DB_PATH)
                try:
                    run_scan_only(c, ua_id)
                except Exception as e:
                    return ua_id, str(e)
                finally:
                    c.close()
                return ua_id, "ok"

            if st.button(t("scan.btn_all", n=len(unscanned)), disabled=len(unscanned) == 0, type="primary"):
                prog  = st.progress(0.0, text=t("scan.progress_start"))
                total = len(unscanned)
                done  = 0
                with ThreadPoolExecutor(max_workers=8) as ex:
                    futs = {ex.submit(_scan_worker, r["id"]): r for r in unscanned}
                    for fut in as_completed(futs):
                        done += 1
                        url  = futs[fut]["original_url"]
                        prog.progress(done / total, text=t("scan.progress_url", done=done, total=total, url=url[:70]))
                prog.progress(1.0, text=t("scan.progress_done", total=total))
                st.rerun()

            st.divider()

            # Compact dataframe — avoids rendering N×4 Streamlit elements
            df_scan = pd.DataFrame([{
                "url":    r["original_url"],
                "domain": r["domain"] or "—",
                "status": r["status"] or "unscanned",
                "hops":   r["hop_count"] if r["hop_count"] is not None else "—",
                "final":  r["final_url"] or "—",
            } for r in url_rows])
            st.dataframe(df_scan, use_container_width=True, hide_index=True)

            with st.expander(t("scan.expander_individual", n=len(url_rows))):
                for r in url_rows:
                    c_url, c_btn = st.columns([8, 1])
                    with c_url:
                        st.code(r["original_url"], language=None)
                    with c_btn:
                        label = t("scan.btn_scan") if r["scan_run_id"] is None else t("scan.btn_rescan")
                        if st.button(label, key=f"scan_{r['id']}"):
                            with st.spinner(t("scan.spinner")):
                                run_scan_only(conn, r["id"])
                            st.rerun()

    # ── Investigate ──────────────────────────────────────────────────────────
    with sub_investigate:
        inv_rows = conn.execute(
            """SELECT ua.id AS ua_id, ua.original_url, ua.domain,
                      sr.id AS scan_run_id, sr.status AS scan_status,
                      sr.final_url, sr.hop_count,
                      sr.whois_registrar AS sr_whois_registrar,
                      sr.whois_creation_date AS sr_whois_creation_date,
                      sr.ip_address AS sr_ip_address,
                      sr.asn AS sr_asn,
                      sr.as_org AS sr_as_org,
                      sr.as_country AS sr_as_country,
                      sr.intel_risk_tags AS sr_intel_risk_tags,
                      sr.domain_enriched_at AS sr_domain_enriched_at,
                      s.id   AS snapshot_id,
                      s.risk_tags AS snapshot_risk_tags
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               LEFT JOIN snapshots s ON s.scan_run_id = sr.id
                   AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? ORDER BY ua.id""",
            (current_case_id,),
        ).fetchall()

        if not inv_rows:
            st.info(t("scan.no_urls"))
        else:
            # ── Priority Queue ────────────────────────────────────────────
            pending_snap = [
                r for r in inv_rows
                if r["scan_run_id"] and r["final_url"] and not r["snapshot_id"]
            ]
            pending_intel_only = [
                r for r in inv_rows
                if r["scan_run_id"] and r["final_url"]
                and (r["sr_domain_enriched_at"] is None or not str(r["sr_domain_enriched_at"]).strip())
            ]
            if pending_intel_only:
                st.subheader(t("inv.intel_queue", n=len(pending_intel_only)))
                st.caption(t("inv.intel_caption"))
                if st.button(
                    t("inv.btn_intel_all", n=len(pending_intel_only)),
                    key="btn_intel_all",
                ):
                    with st.spinner(t("inv.spinner_intel")):
                        run_domain_intel_batch(conn, [r["scan_run_id"] for r in pending_intel_only])
                    st.rerun()
                st.divider()

            if pending_snap:
                priority_rows = []
                for r in pending_snap:
                    flags = _scan_flags(r["final_url"], r["hop_count"])
                    priority_rows.append({
                        "url":          r["original_url"],
                        "final_domain": (_urlparse(r["final_url"]).hostname or "—"),
                        "hops":         r["hop_count"] or "—",
                        "scan_flags":   ", ".join(flags) if flags else "—",
                        "flag_count":   len(flags),
                    })
                priority_rows.sort(key=lambda x: -x["flag_count"])

                st.subheader(t("inv.snap_queue", n=len(pending_snap)))
                st.caption(t("inv.snap_caption"))
                df_priority = pd.DataFrame([{k: v for k, v in r.items() if k != "flag_count"} for r in priority_rows])
                st.dataframe(df_priority, use_container_width=True, hide_index=True)

                st.warning(
                    t("inv.warn_snap_time",
                      n=len(pending_snap),
                      lo=len(pending_snap) * 15 // 60,
                      hi=len(pending_snap) * 30 // 60)
                )
                if st.button(t("inv.btn_snap_all", n=len(pending_snap)), key="btn_snap_all"):
                    total = len(pending_snap)
                    prog = st.progress(0.0, text=t("inv.snap_progress_start"))
                    all_snapshot_ids = []
                    BATCH = 5
                    for batch_start in range(0, total, BATCH):
                        batch = pending_snap[batch_start:batch_start + BATCH]
                        batch_end = min(batch_start + BATCH, total)
                        prog.progress(
                            batch_start / total,
                            text=t("inv.snap_progress", start=batch_start + 1, end=batch_end, total=total),
                        )
                        sr_ids = [r["scan_run_id"] for r in batch]
                        sids = run_snapshot_batch(conn, sr_ids)
                        all_snapshot_ids.extend(sids)
                    prog.progress(1.0, text=t("inv.snap_done", n=len(all_snapshot_ids)))
                    st.rerun()

                st.divider()

            # Always visible — lets users download failed/missing captures
            # even after the priority queue is cleared.
            st.download_button(
                label=t("inv.btn_dl_failed"),
                data=failed_capture_urls_csv(conn, current_case_id),
                file_name=f"kwara_failed_snapshots_case_{current_case_id}.csv",
                mime="text/csv",
                key="dl_failed_snapshots_csv",
            )

            st.divider()

            # ── URL selector ─────────────────────────────────────────────
            def _label(r):
                scan = r["scan_status"] or "not scanned"
                snap = "snap ✓" if r["snapshot_id"] else "no snap"
                if r["snapshot_id"]:
                    flags = json.loads(r["snapshot_risk_tags"] or "[]")
                else:
                    flags = list(_scan_flags(r["final_url"], r["hop_count"]))
                    try:
                        intel = json.loads(r["sr_intel_risk_tags"] or "[]")
                    except (ValueError, TypeError):
                        intel = []
                    for t in intel:
                        if t not in flags:
                            flags.append(t)
                flag_str = " · " + ", ".join(flags) if flags else ""
                return f"{r['original_url']}  [{scan} · {snap}{flag_str}]"

            def _flag_count(r):
                if r["snapshot_id"]:
                    return len(json.loads(r["snapshot_risk_tags"] or "[]"))
                flags = list(_scan_flags(r["final_url"], r["hop_count"]))
                try:
                    intel = json.loads(r["sr_intel_risk_tags"] or "[]")
                except (ValueError, TypeError):
                    intel = []
                for t in intel:
                    if t not in flags:
                        flags.append(t)
                return len(flags)

            sorted_rows = sorted(inv_rows, key=lambda r: (_flag_count(r), r["ua_id"]), reverse=True)
            # Deduplicate by ua_id (keep all unique artifacts, even if same original_url)
            _seen_ua = set()
            _unique_rows = []
            for r in sorted_rows:
                if r["ua_id"] not in _seen_ua:
                    _seen_ua.add(r["ua_id"])
                    _unique_rows.append(r)
            _label_map = {f"[{r['ua_id']}] {_label(r)}": r for r in _unique_rows}

            # After a snapshot, restore the previously selected ua_id
            _preferred = st.session_state.get("inv_last_ua_id")
            _default = 0
            _keys = list(_label_map.keys())
            if _preferred:
                for i, k in enumerate(_keys):
                    if _label_map[k]["ua_id"] == _preferred:
                        _default = i
                        break

            sel = _label_map[st.selectbox(t("inv.select_url"), _keys, index=_default, key="inv_select")]
            st.divider()

            col_l, col_r = st.columns(2)

            with col_l:
                st.subheader(t("inv.chain"))
                if not sel["scan_run_id"]:
                    st.info(t("inv.not_scanned"))
                else:
                    st.caption(t("inv.chain_caption", final_url=sel['final_url'], hops=sel['hop_count'], status=sel['scan_status']))
                    hops = conn.execute(
                        "SELECT hop_order, url, status_code, location FROM redirect_hops WHERE scan_run_id = ? ORDER BY hop_order",
                        (sel["scan_run_id"],),
                    ).fetchall()
                    if hops:
                        st.dataframe(pd.DataFrame([dict(h) for h in hops]), use_container_width=True, hide_index=True)

            with col_r:
                st.subheader(t("inv.whois_header"))
                if not sel["scan_run_id"] or not sel["final_url"]:
                    st.info(t("inv.scan_first"))
                else:
                    snap = conn.execute(
                        "SELECT * FROM snapshots WHERE scan_run_id = ? ORDER BY id DESC LIMIT 1",
                        (sel["scan_run_id"],),
                    ).fetchone()

                    def _coalesce_snap(key: str, sr_key: str):
                        if snap and snap[key]:
                            return snap[key]
                        return sel[sr_key] if sel[sr_key] else None

                    c_intel, c_cap = st.columns(2)
                    with c_intel:
                        if st.button(t("inv.btn_intel_only"), key="btn_intel_only", help=t("inv.btn_intel_help")):
                            st.session_state["inv_last_ua_id"] = sel["ua_id"]
                            with st.spinner(t("inv.spinner_whois")):
                                try:
                                    run_domain_intel_only(conn, sel["scan_run_id"])
                                except Exception as e:
                                    st.error(t("inv.error_intel", e=e))
                                    st.stop()
                            st.rerun()
                    with c_cap:
                        if st.button(t("inv.btn_recapture") if snap else t("inv.btn_capture"), key="btn_snap"):
                            st.session_state["inv_last_ua_id"] = sel["ua_id"]
                            with st.spinner(t("inv.spinner_snapshot")):
                                try:
                                    run_snapshot(conn, sel["scan_run_id"])
                                except Exception as e:
                                    st.error(t("inv.error_snapshot", e=e))
                                    st.stop()
                            st.rerun()

                    fd = (
                        (snap["final_domain"] if snap and snap["final_domain"] else None)
                        or (_urlparse(sel["final_url"]).hostname or "—")
                    )
                    st.write(t("inv.final_domain", v=fd))
                    st.write(t("inv.ip_address", v=_coalesce_snap('ip_address', 'sr_ip_address') or '—'))
                    asn_v = _coalesce_snap("asn", "sr_asn")
                    _asn_str = (
                        f"AS{asn_v}  {_coalesce_snap('as_org', 'sr_as_org') or ''}  "
                        f"({_coalesce_snap('as_country', 'sr_as_country') or '—'})"
                        if asn_v else "—"
                    )
                    st.write(t("inv.asn_hosting", v=_asn_str))
                    st.write(t("inv.registrar", v=_coalesce_snap('whois_registrar', 'sr_whois_registrar') or '—'))
                    st.write(t("inv.domain_created", v=_coalesce_snap('whois_creation_date', 'sr_whois_creation_date') or '—'))
                    if sel["sr_domain_enriched_at"]:
                        st.caption(t("inv.intel_updated", ts=sel['sr_domain_enriched_at']))

                    tags = _merge_risk_tags(
                        snap["risk_tags"] if snap else None,
                        sel["sr_intel_risk_tags"],
                    )
                    tag_str = "  ".join(f"{TAG_COLORS.get(t,'⚪')} `{t}`" for t in tags)
                    st.write(t("inv.risk_flags", v=tag_str or '—'))

                st.divider()
                st.subheader(t("inv.snapshot_header"))
                if not sel["scan_run_id"] or not sel["final_url"]:
                    st.caption(t("inv.scan_first_snap"))
                else:
                    snap = conn.execute(
                        "SELECT * FROM snapshots WHERE scan_run_id = ? ORDER BY id DESC LIMIT 1",
                        (sel["scan_run_id"],),
                    ).fetchone()
                    if not snap:
                        st.info(t("inv.no_snapshot"))
                    else:
                        cap, cap_d = snap["capture_status"], snap["capture_detail"]
                        if cap or cap_d:
                            if cap_d:
                                st.caption(t("inv.capture_status_detail", status=cap or '—', detail=cap_d))
                            else:
                                st.caption(t("inv.capture_status", status=cap or '—'))

                        if snap["screenshot_path"] and os.path.exists(snap["screenshot_path"]):
                            st.image(snap["screenshot_path"], use_container_width=True)
                        else:
                            st.warning(t("inv.missing_screenshot"))

                        domains = json.loads(snap["request_domains_json"] or "[]")
                        with st.expander(t("inv.request_domains", n=len(domains))):
                            st.caption(t("inv.request_domains_caption"))
                            st.code("\n".join(domains[:50]) + ("\n..." if len(domains) > 50 else ""))

                        if snap["html_path"] and os.path.exists(snap["html_path"]):
                            with open(snap["html_path"], "rb") as f:
                                st.download_button(t("inv.btn_dl_html"), f.read(),
                                    file_name=f"snapshot_{sel['scan_run_id']}.html",
                                    mime="text/html", key="dl_html")

                        st.divider()
                        st.caption(t("inv.manual_caption"))
                        up_png = st.file_uploader(t("inv.upload_png"), type=["png"], key="manual_snap_png")
                        up_html = st.file_uploader(t("inv.upload_html"), type=["html", "htm"], key="manual_snap_html")
                        if st.button(t("inv.btn_save_manual"), key="btn_manual_snap"):
                            if not up_png:
                                st.warning(t("inv.warn_choose_png"))
                            else:
                                base = os.path.join(os.path.dirname(__file__), "data", "snapshots", str(sel["scan_run_id"]))
                                os.makedirs(base, exist_ok=True)
                                png_path = os.path.join(base, "screenshot.png")
                                with open(png_path, "wb") as f:
                                    f.write(up_png.getbuffer())
                                html_path = snap["html_path"] or os.path.join(base, "page.html")
                                if up_html:
                                    html_path = os.path.join(base, "page.html")
                                    with open(html_path, "wb") as f:
                                        f.write(up_html.getbuffer())
                                tags = [t for t in json.loads(snap["risk_tags"] or "[]") if t != "capture_error"]
                                conn.execute(
                                    """UPDATE snapshots SET screenshot_path=?, html_path=?,
                                           capture_status=?, capture_detail=?, risk_tags=?
                                       WHERE id=?""",
                                    (png_path, html_path, "manual", "user_upload", json.dumps(tags), snap["id"]),
                                )
                                conn.commit()
                                st.session_state["inv_last_ua_id"] = sel["ua_id"]
                                st.rerun()

    # Clusters
    with sub_clusters:
        destinations, unresolved_dests = shared_destinations(conn, current_case_id)
        params = shared_params(conn, current_case_id)
        asn_data = asn_clusters(conn, current_case_id)

        ci = case_insights(conn, current_case_id)
        with st.expander(t("clusters.insights"), expanded=True):
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

        # Scanned Destinations
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
                    f"{TAG_COLORS.get(t, '⚪')} {t} ×{d['tag_counts'][t]}"
                    for t in sorted(d["tag_counts"])
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
                    tag_str = "  ".join(f"{TAG_COLORS.get(t, '⚪')} {t}" for t in u["risk_tags"]) if u["risk_tags"] else "—"
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

        # Shared URL Parameters
        st.subheader(t("clusters.params"))
        st.caption(t("clusters.params_caption"))

        if not params:
            st.info(t("clusters.no_params"))
        else:
            st.dataframe(pd.DataFrame(params), use_container_width=True, hide_index=True)

        st.divider()

        # Hosting Infrastructure
        st.subheader(t("clusters.infra"))
        st.caption(t("clusters.infra_caption"))

        if not asn_data:
            st.info(t("clusters.no_asn"))
        else:
            asn_summary = []
            for a in asn_data:
                tag_str = "  ".join(
                    f"{TAG_COLORS.get(t, '⚪')} {t} ×{a['tag_counts'][t]}"
                    for t in sorted(a["tag_counts"])
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
                    tag_str = "  ".join(f"{TAG_COLORS.get(t, '⚪')} {t}" for t in u["risk_tags"]) if u["risk_tags"] else "—"
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

# ===========================================================================
# PROVIDERS
# ===========================================================================
with tab_providers:
    st.subheader(t("prov.shortlinks"))
    st.caption(t("prov.shortlinks_caption"))

    # Detect shortlink providers: domains in the known list OR domains whose
    # URLs redirect to a *different* domain (i.e. they act as redirectors).
    all_domains = conn.execute(
        """SELECT ua.domain AS provider, COUNT(*) AS url_count
           FROM url_artifacts ua
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? AND ua.domain IS NOT NULL
           GROUP BY ua.domain ORDER BY url_count DESC""",
        (current_case_id,),
    ).fetchall()

    detected_redirectors = set()
    redir_rows = conn.execute(
        """SELECT DISTINCT ua.domain
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.url_artifact_id = ua.id AND sr.status = 'done'
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? AND ua.domain IS NOT NULL
             AND sr.final_url IS NOT NULL AND sr.hop_count >= 2""",
        (current_case_id,),
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
            (current_case_id, sel_prov),
        ).fetchall()

        def _prov_tags(r):
            if r["snapshot_risk_tags"]:
                try:
                    return json.loads(r["snapshot_risk_tags"])
                except (ValueError, TypeError):
                    pass
            return _scan_flags(r["final_url"], r["hop_count"])

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
                tag_str = "  ".join(f"{TAG_COLORS.get(t, '⚪')} {t}" for t in x["tags"]) if x["tags"] else "—"
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
        (current_case_id,),
    ).fetchall()

    reg_rows = []
    for r in registrars:
        dom = r["snap_domain"] or (_urlparse(r["scan_final_url"] or "").hostname or "—")
        reg_rows.append({"registrar": r["registrar"], "domain": dom, "domain_created": r["domain_created"]})

    if reg_rows:
        st.dataframe(pd.DataFrame(reg_rows), use_container_width=True, hide_index=True)
    else:
        st.info(t("prov.no_registrars"))

# ===========================================================================
# EXPORT
# ===========================================================================
with tab_export:
    st.subheader(t("export.title"))
    st.caption(t("export.caption"))

    # Case summary
    counts = conn.execute(
        """SELECT
               (SELECT COUNT(*) FROM message_evidence WHERE case_id = :c)  AS messages,
               (SELECT COUNT(*) FROM url_artifacts    WHERE case_id = :c)  AS urls,
               (SELECT COUNT(*) FROM scan_runs sr
                JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                WHERE ua.case_id = :c)                                      AS scans,
               (SELECT COUNT(*) FROM snapshots s
                JOIN scan_runs sr ON sr.id = s.scan_run_id
                JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                WHERE ua.case_id = :c)                                      AS snapshots""",
        {"c": current_case_id},
    ).fetchone()

    m1, m2, m3, m4 = st.columns(4)
    m1.metric(t("export.posts"),     counts["messages"])
    m2.metric(t("export.urls"),      counts["urls"])
    m3.metric(t("export.scans"),     counts["scans"])
    m4.metric(t("export.snapshots"), counts["snapshots"])

    st.divider()

    if st.button(t("export.btn_export"), type="primary", key="btn_export"):
        with st.spinner(t("export.spinner")):
            zip_path = export_case(conn, current_case_id)
        st.success(t("export.success", name=os.path.basename(zip_path)))
        with open(zip_path, "rb") as f:
            st.download_button(
                label=t("export.btn_download"),
                data=f.read(),
                file_name=os.path.basename(zip_path),
                mime="application/zip",
                key="dl_zip_new",
            )

    st.divider()

    # Previous exports
    st.subheader(t("export.previous"))
    exports = conn.execute(
        "SELECT id, export_at, zip_path, manifest_json FROM export_runs WHERE case_id = ? ORDER BY id DESC",
        (current_case_id,),
    ).fetchall()

    if not exports:
        st.info(t("export.no_exports"))
    else:
        for ex in exports:
            meta  = json.loads(ex["manifest_json"] or "{}")
            label = f"{ex['export_at']}  —  {meta.get('file_count', '?')} files"
            if ex["zip_path"] and os.path.exists(ex["zip_path"]):
                with open(ex["zip_path"], "rb") as f:
                    st.download_button(
                        label=f"Download  {label}",
                        data=f.read(),
                        file_name=os.path.basename(ex["zip_path"]),
                        mime="application/zip",
                        key=f"dl_zip_{ex['id']}",
                    )
            else:
                st.write(f"{label}  _(file not found)_")
