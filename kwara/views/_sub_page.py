"""Page Evidence sub-tab — screenshot, HTML, HAR, request domains, manual upload."""
import json
import os
from datetime import datetime, timezone

import streamlit as st

from i18n import t
from pipeline import run_lightweight_fetch_batch, run_snapshot, run_snapshot_batch
from snapshots import failed_capture_urls_csv
from views._shared import fetch_evidence_rows, url_selector


def render(conn, case_id, case_locale=None, case_tz=None):
    st.caption(t("page.help"))

    rows = fetch_evidence_rows(conn, case_id)
    scanned = [r for r in rows if r["scan_status"] == "done"]
    has_snap = sum(1 for r in scanned if r["snapshot_id"])
    pending = len(scanned) - has_snap

    m1, m2, m3 = st.columns(3)
    m1.metric(t("page.captured"), has_snap)
    m2.metric(t("page.pending"), pending)
    m3.metric(t("page.not_scanned"), len(rows) - len(scanned))

    # Batch snapshot button
    pending_rows = [r for r in scanned if r["final_url"] and not r["snapshot_id"]]
    if pending_rows:
        st.warning(t("page.warn_time", n=len(pending_rows), lo=len(pending_rows) * 15 // 60, hi=len(pending_rows) * 30 // 60))
        if st.button(t("page.btn_batch", n=len(pending_rows)), type="primary"):
            total = len(pending_rows)
            prog = st.progress(0.0)
            all_ids = []
            BATCH = 5
            for i in range(0, total, BATCH):
                batch = pending_rows[i:i + BATCH]
                prog.progress(i / total)
                _env = {}
                if case_locale:
                    _env["KWARA_BROWSER_LOCALE"] = case_locale
                if case_tz:
                    _env["KWARA_BROWSER_TIMEZONE"] = case_tz
                sids = run_snapshot_batch(conn, [r["scan_run_id"] for r in batch], env_override=_env or None)
                all_ids.extend(sids)
            prog.progress(1.0)
            st.rerun()

    _failed_csv = failed_capture_urls_csv(conn, case_id)
    if _failed_csv.strip():
        st.download_button(t("page.btn_dl_failed"), _failed_csv,
            file_name=f"kwara_failed_case_{case_id}.csv", mime="text/csv", key="dl_failed_csv")

    # ── Lightweight HTML-only fetch (Phase 3 ticket C) ─────────
    # Fast alternative path: requests.get + fingerprint extraction, no
    # browser. Default target = scans without any snapshot yet. Scans
    # that already have a snapshot are gated behind an expander with
    # an explicit shadowing warning.
    st.divider()
    st.subheader(t("page.lightweight_header"))
    st.caption(t("page.lightweight_caption"))

    unsnapped = [r for r in scanned if r["final_url"] and not r["snapshot_id"]]
    snapped   = [r for r in scanned if r["final_url"] and r["snapshot_id"]]

    if unsnapped:
        if st.button(
            t("page.btn_lightweight", n=len(unsnapped)),
            key="btn_lightweight_unsnapped",
        ):
            sr_ids = [r["scan_run_id"] for r in unsnapped]
            run_lightweight_fetch_batch(conn, sr_ids)
            st.rerun()
    else:
        st.caption(t("page.lightweight_none_unsnapped"))

    if snapped:
        with st.expander(t("page.lightweight_advanced_expander", n=len(snapped))):
            st.warning(t("page.lightweight_shadow_warning"))
            if st.button(
                t("page.btn_lightweight_already_snapped", n=len(snapped)),
                key="btn_lightweight_snapped",
            ):
                sr_ids = [r["scan_run_id"] for r in snapped]
                run_lightweight_fetch_batch(conn, sr_ids)
                st.rerun()

    if not scanned:
        st.info(t("page.scan_first"))
        return

    st.divider()
    sel = url_selector(rows, key_suffix="_page")

    if not sel["scan_run_id"] or sel["scan_status"] != "done":
        st.info(t("page.not_scanned"))
        return

    snap = conn.execute(
        "SELECT * FROM snapshots WHERE scan_run_id = ? ORDER BY id DESC LIMIT 1",
        (sel["scan_run_id"],),
    ).fetchone()

    # Capture button
    if case_locale:
        st.caption(t("page.case_locale", locale=case_locale, tz=case_tz or "—"))

    if st.button(t("page.btn_recapture") if snap else t("page.btn_capture"), key="btn_page_snap"):
        st.session_state["inv_last_ua_id"] = sel["ua_id"]
        _env = {}
        if case_locale:
            _env["KWARA_BROWSER_LOCALE"] = case_locale
        if case_tz:
            _env["KWARA_BROWSER_TIMEZONE"] = case_tz
        with st.spinner(t("page.spinner")):
            try:
                run_snapshot(conn, sel["scan_run_id"], env_override=_env or None)
            except Exception as e:
                st.error(t("page.error", e=e))
                st.stop()
        st.rerun()

    if not snap:
        st.info(t("page.no_snapshot"))
        return

    # ── Screenshot ──────────────────────────────────────────────
    cap, cap_d = snap["capture_status"], snap["capture_detail"]
    if cap or cap_d:
        st.caption(f"Status: {cap or '—'}" + (f" — {cap_d}" if cap_d else ""))

    if snap["screenshot_path"] and os.path.exists(snap["screenshot_path"]):
        st.image(snap["screenshot_path"], use_container_width=True)
    else:
        st.warning(t("page.missing_screenshot"))

    # ── Downloads ───────────────────────────────────────────────
    dl1, dl2, dl3 = st.columns(3)
    with dl1:
        if snap["html_path"] and os.path.exists(snap["html_path"]):
            with open(snap["html_path"], "rb") as f:
                st.download_button(t("page.btn_dl_html"), f.read(),
                    file_name=f"snapshot_{sel['scan_run_id']}.html", mime="text/html", key="dl_html")
    with dl2:
        _har = snap["har_path"] if snap["har_path"] and os.path.exists(snap["har_path"] or "") else None
        if _har:
            with open(_har, "rb") as f:
                st.download_button(t("page.btn_dl_har"), f.read(),
                    file_name=f"traffic_{sel['scan_run_id']}.har", mime="application/json", key="dl_har")

    # ── Request Domains ─────────────────────────────────────────
    domains = json.loads(snap["request_domains_json"] or "[]")
    if domains:
        with st.expander(t("page.request_domains", n=len(domains))):
            st.caption(t("page.request_domains_caption"))
            st.code("\n".join(domains[:50]) + ("\n..." if len(domains) > 50 else ""))

    # ── Manual Upload ───────────────────────────────────────────
    with st.expander(t("page.manual_caption")):
        up_png = st.file_uploader(t("page.upload_png"), type=["png"], key="manual_snap_png")
        up_html = st.file_uploader(t("page.upload_html"), type=["html", "htm"], key="manual_snap_html")
        if st.button(t("page.btn_save_manual"), key="btn_manual_snap"):
            if not up_png:
                st.warning(t("page.warn_choose_png"))
            else:
                # Each upload creates a NEW snapshot row in a fresh
                # per-capture directory (codex review #1 round 5: manual
                # upload was silently overwriting fixed-path files and
                # mutating existing rows in place — broke the
                # immutable-evidence model). The latest-usable selector
                # picks the newest snapshot for display automatically.
                from snapshots import _per_capture_dir
                from lightweight_fetch import CAPTURE_METHOD_MANUAL
                base = _per_capture_dir(sel["scan_run_id"])
                png_path = os.path.join(base, "screenshot.png")
                with open(png_path, "wb") as f:
                    f.write(up_png.getbuffer())
                html_path = ""
                if up_html:
                    html_path = os.path.join(base, "page.html")
                    with open(html_path, "wb") as f:
                        f.write(up_html.getbuffer())
                # Best-effort: re-extract pixels from manually uploaded HTML
                from fingerprints import extract_tracking_ids_from_file
                tracking_ids = (
                    extract_tracking_ids_from_file(html_path) if html_path else {}
                )
                tracking_ids_json = (
                    json.dumps(tracking_ids, ensure_ascii=False)
                    if tracking_ids else None
                )
                conn.execute(
                    """INSERT INTO snapshots
                           (scan_run_id, final_url, final_domain,
                            screenshot_path, html_path, captured_at,
                            capture_status, capture_detail, tracking_ids_json,
                            capture_method)
                       VALUES (?, ?, ?, ?, ?, ?, 'manual', 'user_upload', ?, ?)""",
                    (
                        sel["scan_run_id"],
                        snap["final_url"], snap["final_domain"],
                        png_path, html_path or None,
                        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        tracking_ids_json,
                        CAPTURE_METHOD_MANUAL,
                    ),
                )
                conn.commit()
                st.session_state["inv_last_ua_id"] = sel["ua_id"]
                st.rerun()
