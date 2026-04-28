"""Input tab — ingest single posts or CSV batches."""
import os
import tempfile

import pandas as pd
import streamlit as st

from i18n import t
from ingestion import ingest_message, ingest_csv


def render(conn, case_id):
    mode = st.radio("", [t("input.single_post"), t("input.csv_batch")], horizontal=True, key="input_mode")
    st.divider()

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
                # Read into memory so we can name the file with the
                # eventual message_id and avoid filename collisions
                # between posts that uploaded screenshots with the
                # same basename (codex review #4).
                screenshot_bytes = screenshot.read() if screenshot else None
                screenshot_basename = os.path.basename(screenshot.name) if screenshot else ""

                msg_id, urls = ingest_message(
                    conn, case_id,
                    message_text=message_text, platform=platform,
                    permalink=permalink, actor_label=actor,
                    posted_at=posted_at, screenshot_path="",
                )

                screenshot_path = ""
                if screenshot_bytes is not None:
                    save_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "screenshots")
                    os.makedirs(save_dir, exist_ok=True)
                    # Prefix with message_id; preserve original basename for
                    # human readability of evidence packs.
                    screenshot_path = os.path.join(
                        save_dir, f"{msg_id}_{screenshot_basename}"
                    )
                    with open(screenshot_path, "wb") as f:
                        f.write(screenshot_bytes)
                    conn.execute(
                        "UPDATE message_evidence SET screenshot_path = ? WHERE id = ?",
                        (screenshot_path, msg_id),
                    )
                    conn.commit()
                st.success(t("input.success_saved", n=len(urls)))
                for u in urls:
                    st.code(u)

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
                    results   = ingest_csv(conn, case_id, tmp_path)
                    total_urls = sum(r["url_count"] for r in results)
                    st.success(t("input.csv_success", posts=len(results), urls=total_urls))
                except Exception as e:
                    st.error(t("input.csv_fail", e=e))
                finally:
                    os.unlink(tmp_path)
