"""Account Patterns sub-tab — poster × content pivot.

Deliberately descriptive: just pivots posts into a table. No thresholds,
no automatic 'coordinated' flags. The analyst reads the distribution.

A timing-distribution view was prototyped but removed — minute-level
posted_at resolution makes 'min_interval' a misleading artefact of
timestamp granularity rather than a real burst signal. The underlying
content_time_distribution() function is kept in clustering.py for
future visualisation work.
"""
import pandas as pd
import streamlit as st

from clustering_url import account_content_matrix
from i18n import t


def render(conn, case_id):
    st.caption(t("account_patterns.help"))

    matrix = account_content_matrix(conn, case_id)

    # ── Account × Content matrix ─────────────────────────────────
    st.subheader(t("account_patterns.matrix"))
    st.caption(t("account_patterns.matrix_caption"))

    if not matrix["actors"]:
        st.info(t("account_patterns.no_data"))
        return

    actors = matrix["actors"]
    contents = matrix["contents"]
    actor_totals = matrix["actor_totals"]
    content_totals = matrix["content_totals"]

    max_cols = st.slider(
        t("account_patterns.max_cols"),
        min_value=5, max_value=max(5, len(contents)),
        value=min(15, len(contents)),
        help=t("account_patterns.max_cols_help"),
    )
    shown_contents = contents[:max_cols]

    rows = []
    for actor in actors:
        row = {"actor": actor, "total": actor_totals[actor]}
        for cid in shown_contents:
            cnt = matrix["matrix"].get((actor, cid), 0)
            row[cid] = cnt if cnt else ""
        rows.append(row)

    # Footer row with column totals (across ALL actors, not just shown)
    footer = {"actor": "—Σ—", "total": sum(actor_totals.values())}
    for cid in shown_contents:
        footer[cid] = content_totals[cid]
    rows.append(footer)

    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )

    if len(contents) > max_cols:
        st.caption(t("account_patterns.cols_truncated",
                     shown=max_cols, total=len(contents)))
