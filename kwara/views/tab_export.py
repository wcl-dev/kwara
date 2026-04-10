"""Export tab — build and download evidence packs."""
import json
import os

import streamlit as st

from exporter import export_case
from i18n import t


def render(conn, case_id):
    st.subheader(t("export.title"))
    st.caption(t("export.caption"))

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
        {"c": case_id},
    ).fetchone()

    m1, m2, m3, m4 = st.columns(4)
    m1.metric(t("export.posts"),     counts["messages"])
    m2.metric(t("export.urls"),      counts["urls"])
    m3.metric(t("export.scans"),     counts["scans"])
    m4.metric(t("export.snapshots"), counts["snapshots"])

    st.divider()

    if st.button(t("export.btn_export"), type="primary", key="btn_export"):
        with st.spinner(t("export.spinner")):
            zip_path = export_case(conn, case_id)
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

    st.subheader(t("export.previous"))
    exports = conn.execute(
        "SELECT id, export_at, zip_path, manifest_json FROM export_runs WHERE case_id = ? ORDER BY id DESC",
        (case_id,),
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
                        label=t("export.dl_previous", label=label),
                        data=f.read(),
                        file_name=os.path.basename(ex["zip_path"]),
                        mime="application/zip",
                        key=f"dl_zip_{ex['id']}",
                    )
            else:
                st.caption(t("export.file_not_found", label=label))
