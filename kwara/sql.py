"""Shared SQL subquery fragments for the analysis layer.

Several analysis queries need to pin "which rows count" for a url_artifact.
The idioms here recur across clustering_url, clustering_infra, clusters,
index_db and the CLI, and were previously copy-pasted ~10 times. Every time
the rule was tightened it had to be hand-applied to each copy — and twice it
was not, which is what this module exists to prevent:

  * codex round-6 fix #2 tightened "latest snapshot" to "latest *usable*
    snapshot", so a failed re-capture could not shadow an earlier good one.
  * 2026-08-08/11: four hand-written copies of "has this page been captured?"
    disagreed with each other, and all four understated missing work.

Usage — interpolate into a larger query with an f-string. The fragments
reference the outer aliases `ua` (url_artifacts) and `sr` (scan_runs), so the
enclosing query must use those aliases:

    f\"\"\"SELECT ... FROM url_artifacts ua
        JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN}
        JOIN snapshots s ON s.id IN {usable_snapshots("tracking_ids_json")}
        ...\"\"\"

SCOPE — these are the *analysis* idioms. The display layer deliberately
fetches the latest snapshot of any status (so the analyst still sees failed
captures); those sites are intentional and are NOT replaced by these.

The fragments contain only static SQL — no user input is ever interpolated,
so f-string composition is safe. `usable_snapshots` additionally validates its
column argument against an allow-list.
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

# Columns the usable-snapshot idiom is allowed to gate on. Extend when a new
# analysis layer needs a different populated column.
_USABLE_SNAPSHOT_COLS = frozenset({
    "tracking_ids_json",
    "request_domains_json",
})


def usable_snapshots(non_null_col: str) -> str:
    """EVERY usable snapshot of scan_run `sr` — the union across personas.

    THE attribution idiom. Use it wherever the question is "what did this site
    serve", never "what did one visitor see".

    2026-08-11, measured on the live database: for 252 of 469 scan_runs the
    visitor-facing capture and the crawler-facing one land on DIFFERENT
    DOMAINS — the same URL sends a browser to visitorlanding.example and a crawler to
    crawlerlanding.example. Both domains are assets of the same operation, and the Meta
    Page ID binding them appears under both personas. Picking either persona
    alone silently discards half the operation: preferring the crawler (which
    `ORDER BY id DESC` did, since the alt capture is always written last)
    missed 756 tracking-ID observations, and preferring the visitor dropped
    crawlerlanding.example/.org out of the case entirely. Cloaking means the personas
    differ *by design*, so attribution has to read all of them.

    Scope is one scan_run, which `LATEST_DONE_SCAN_RUN` has already pinned to
    a single moment — this unions personas and retries, never observations
    from different days.

    Failed captures stay excluded (contract 6): a Cloudflare interstitial is
    not something the site served, and a later failure must not shadow an
    earlier good capture.
    """
    if non_null_col not in _USABLE_SNAPSHOT_COLS:
        raise ValueError(f"unknown snapshot column: {non_null_col!r}")
    return (
        "(SELECT id FROM snapshots "
        f"WHERE scan_run_id = sr.id AND capture_status = 'ok' "
        f"AND {non_null_col} IS NOT NULL AND TRIM({non_null_col}) != '')"
    )


def browser_capture_exists(scan_run_expr: str = "sr.id") -> str:
    """Predicate: does this scan_run have a capture of the rendered page?

    THE definition of "captured", in one place. It was previously written out
    four times — cmd_run_snapshot, cmd_case_show, clusters._completeness and
    _run_pending — and on 2026-08-08/11 all four disagreed. Each divergence
    was a defect the analyst could not see:

      * "has any snapshots row" counted the browser-free pass, so
        `run snapshot` reported nothing pending after `run attribute`, and
        `case show` reported 0 pending for cases with work outstanding.
      * `_completeness` reported page_captured=True — and so no gap, and
        completeness 高 — for five cases in which no browser had ever
        rendered a page.

    Satisfied by a successful browser render, or by the analyst deliberately
    supplying the page another way (a manual upload, a Wayback substitute).
    NOT satisfied by the browser-free pass, and NOT by `cloaking_alt` alone:
    that is the crawler-facing persona, so on its own it means the page a
    visitor would have been served was never captured.

    Note the asymmetry with `usable_snapshots`, which is deliberate. Once
    captured, a cloaking_alt row is evidence like any other and attribution
    reads it. It just cannot *stand in for* the visitor-facing capture when
    deciding whether the capture still needs doing.

    `scan_run_expr` is the enclosing query's scan_run id expression; it is
    static SQL from calling code, never user input.
    """
    return (
        "EXISTS (SELECT 1 FROM snapshots bs "
        f"WHERE bs.scan_run_id = {scan_run_expr} AND ("
        "(bs.capture_method = 'playwright' AND bs.capture_status = 'ok') "
        "OR bs.capture_status IN ('manual', 'wayback') "
        # capture_method postdates the browser-free pass. db.py backfills NULL
        # to 'playwright' on migrate, on the grounds that everything written
        # before the column existed came from a browser — apply the same rule
        # here so an unmigrated database reads the same way.
        "OR (bs.capture_method IS NULL AND bs.capture_status = 'ok') "
        # Rows older still, predating capture_status: a recorded screenshot is
        # the only evidence they left that the capture happened.
        "OR ((bs.capture_status IS NULL OR bs.capture_status = '') "
        "AND bs.screenshot_path IS NOT NULL AND TRIM(bs.screenshot_path) != '')"
        "))"
    )
