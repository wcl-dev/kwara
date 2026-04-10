"""Scan sub-tab — batch and individual URL redirect chain scanning."""
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import streamlit as st

from config import DB_PATH
from db import get_conn
from i18n import t
from pipeline import run_scan_only


def render(conn, case_id):
    st.caption(t("scan.help"))

    url_rows = conn.execute(
        """SELECT ua.id, ua.original_url, ua.domain,
                  sr.id AS scan_run_id, sr.status, sr.hop_count, sr.final_url
           FROM url_artifacts ua
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ? ORDER BY ua.id""",
        (case_id,),
    ).fetchall()

    if not url_rows:
        st.info(t("scan.no_urls"))
        return

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

    def _scan_worker(ua_id):
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
    df_scan = pd.DataFrame([{
        "url":    r["original_url"],
        "domain": r["domain"] or "—",
        "status": r["status"] or t("scan.status_unscanned"),
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
