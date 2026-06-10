"""Shared SQL subquery fragments for the analysis layer.

Several analysis queries need to pin "the one scan_run / snapshot row that
counts" for a url_artifact. Two idioms recur across clustering_url,
clustering_infra and insights, and were previously copy-pasted ~10 times.
When codex round-6 fix #2 tightened the snapshot rule (prefer the latest
*usable* capture, not merely the latest), the change had to be hand-applied
to each copy — exactly the drift this module removes.

Centralised here so the upcoming cross-case index reuses the same idiom
instead of copy-pasting an 11th variant, and so a future rule change lands
in one place.

SCOPE — these cover only the *analysis* idioms (latest done scan + latest
usable snapshot). The view/display layer deliberately fetches the latest
snapshot of *any* status (so the analyst still sees failed captures); those
sites are intentional and are NOT replaced by these constants.

Usage — interpolate into a larger query with an f-string. The fragments
reference the outer aliases `ua` (url_artifacts) and `sr` (scan_runs), so
the enclosing query must use those aliases:

    f\"\"\"SELECT ... FROM url_artifacts ua
        JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
        ...\"\"\"

The fragments contain only static SQL — no user input is ever interpolated,
so f-string composition is safe.
"""
from __future__ import annotations

# The latest scan_run for a url_artifact whose status is 'done'. This is the
# canonical "use the completed scan, not an in-progress / errored one" pick
# that every cross-URL analysis aggregation shares.
LATEST_DONE_SCAN_RUN = (
    "(SELECT id FROM scan_runs "
    "WHERE url_artifact_id = ua.id AND status = 'done' "
    "ORDER BY id DESC LIMIT 1)"
)


def latest_usable_snapshot(non_null_col: str) -> str:
    """Subquery for the latest *usable* snapshot of scan_run `sr`.

    "Usable" = capture succeeded (``capture_status = 'ok'``) AND the column
    the caller needs is populated. This is the codex round-6 fix #2 rule:
    a later failed re-capture (Cloudflare challenge, timeout, empty HTML)
    must not shadow an earlier good snapshot's data.

    `non_null_col` is a hard-coded column name supplied by analysis code
    (e.g. ``"tracking_ids_json"``, ``"request_domains_json"``) — never user
    input. Validated against an allow-list to keep the f-string composition
    obviously injection-free.
    """
    if non_null_col not in _USABLE_SNAPSHOT_COLS:
        raise ValueError(f"unknown snapshot column: {non_null_col!r}")
    return (
        "(SELECT id FROM snapshots "
        f"WHERE scan_run_id = sr.id AND capture_status = 'ok' "
        f"AND {non_null_col} IS NOT NULL AND TRIM({non_null_col}) != '' "
        "ORDER BY id DESC LIMIT 1)"
    )


# Columns the usable-snapshot idiom is allowed to gate on. Extend when a new
# analysis layer needs a different populated column.
_USABLE_SNAPSHOT_COLS = frozenset({
    "tracking_ids_json",
    "request_domains_json",
})
