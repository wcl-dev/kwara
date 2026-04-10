"""Collected Evidence tab — source posts and extracted URLs."""
import pandas as pd
import streamlit as st

from i18n import t


def render(conn, case_id):
    st.subheader(t("evidence.posts"))
    messages = conn.execute(
        """SELECT id, platform, actor_label AS actor, posted_at,
                  permalink, substr(message_text, 1, 100) AS message_preview,
                  ingested_at
           FROM message_evidence WHERE case_id = ? ORDER BY id DESC""",
        (case_id,),
    ).fetchall()

    if messages:
        st.dataframe(pd.DataFrame([dict(r) for r in messages]), use_container_width=True, hide_index=True)
    else:
        st.info(t("evidence.no_posts"))

    st.divider()

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
        (case_id,),
    ).fetchall()

    if artifacts:
        st.dataframe(pd.DataFrame([dict(r) for r in artifacts]), use_container_width=True, hide_index=True)
    else:
        st.info(t("evidence.no_urls"))
