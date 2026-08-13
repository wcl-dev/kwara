"""Phase 4.3 — OPSEC profile.

For each landing-page domain in a case, compare the success rate of
the lightweight (requests-based) fetch path vs the Playwright path.

Sites that block on User-Agent but render fine in a real Chromium have
deliberately deployed UA-discrimination — a same-operator clustering
signal independent of GA4 / TLS / parameter analysis. QSH 2026-04-28:

      lightweight     playwright    OPSEC level
  visitor-landing.example     23/23 (100%)    23/23 (100%)   low (no gate)
  hub-site.example   12/73 ( 16%)    73/73 (100%)   strong (UA gate)
  satellite-site.example  0/4 (  0%)      4/4 (100%)    strong (UA gate)

Read-only over `snapshots.capture_method` + `capture_status`. No schema
change.
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict
from typing import Any

from .config import OPSEC_LW_HIGH, OPSEC_LW_LOW, OPSEC_PW_MIN


# capture_status values that count as 'analyst got usable evidence'
OK_STATES = frozenset({"ok", "wayback", "manual"})


def _classify(lw_rate: float | None, pw_rate: float | None) -> str:
    """Map (lightweight_rate, playwright_rate) → OPSEC level.

    Levels (intentionally coarse — analyst confirms). Cutoffs sourced from
    config (KWARA_OPSEC_*) so reports can cite the thresholds in effect:
      low            playwright AND lightweight both succeed (>= OPSEC_LW_HIGH)
      medium         playwright fine; lightweight partial (LOW..HIGH)
      strong         playwright fine; lightweight nearly blocked (< OPSEC_LW_LOW)
      indeterminate  one path has no data, or playwright itself fails

    An indeterminate verdict is the common case, not the exception: the two
    paths are filled by different commands (`run attribute` does the
    lightweight fetch, `run snapshot` drives Playwright), so a case that ran
    only one of them can never produce a level. Callers must say WHY — see
    `_reason` — because a silent "indeterminate" reads as "we looked and found
    nothing" when the truth is "we never collected the other half".
    """
    if lw_rate is None or pw_rate is None:
        return "indeterminate"
    if pw_rate < OPSEC_PW_MIN:
        return "indeterminate"
    if lw_rate >= OPSEC_LW_HIGH:
        return "low"
    if lw_rate >= OPSEC_LW_LOW:
        return "medium"
    return "strong"


def _reason(lw_total: int, pw_total: int, pw_rate: float | None) -> str | None:
    """Why a row could not be classified. None when the level is real.

    Without this the analysis is silently empty on any case that ran one
    collection path: measured 2026-08-06, five of six cases in the QSH DB had
    every domain indeterminate purely because Playwright or the lightweight
    fetch had never been run, and nothing anywhere said so.
    """
    if not lw_total and not pw_total:
        return "no_capture"
    if not lw_total:
        return "no_lightweight"      # run attribute
    if not pw_total:
        return "no_playwright"       # run snapshot
    if pw_rate is not None and pw_rate < OPSEC_PW_MIN:
        # The browser path itself failed, so the comparison has no baseline —
        # this is a collection problem, not an observation about the site.
        return "playwright_unreliable"
    return None


def compute_opsec_profile(
    conn: sqlite3.Connection, case_id: int,
) -> list[dict[str, Any]]:
    """Per-domain success-rate comparison between lightweight and Playwright.

    Returns rows sorted by domain (deterministic for screenshots/diff).
    Each row carries the raw counters so the view can render
    "12 / 73 (16%)" without re-deriving anything.
    """
    rows = conn.execute(
        """SELECT s.final_domain, s.capture_method, s.capture_status
             FROM snapshots s
             JOIN scan_runs sr ON sr.id = s.scan_run_id
             JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
            WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    by_domain: dict[str, dict[str, int]] = defaultdict(
        lambda: {"lw_total": 0, "lw_ok": 0, "pw_total": 0, "pw_ok": 0}
    )
    for r in rows:
        domain = (r["final_domain"] or "").lower()
        if not domain:
            continue
        method = (r["capture_method"] or "").strip()
        ok = (r["capture_status"] or "") in OK_STATES
        c = by_domain[domain]
        if method == "http_only":
            c["lw_total"] += 1
            if ok:
                c["lw_ok"] += 1
        elif method == "playwright":
            c["pw_total"] += 1
            if ok:
                c["pw_ok"] += 1
        # capture_method == 'manual' is intentionally excluded — manual
        # uploads carry no UA-gate signal (analyst saved a screenshot
        # from their own browser session).

    out: list[dict[str, Any]] = []
    for domain in sorted(by_domain):
        c = by_domain[domain]
        lw_rate = c["lw_ok"] / c["lw_total"] if c["lw_total"] else None
        pw_rate = c["pw_ok"] / c["pw_total"] if c["pw_total"] else None
        level = _classify(lw_rate, pw_rate)
        reason = _reason(c["lw_total"], c["pw_total"], pw_rate)
        diff_above_50 = (
            lw_rate is not None
            and pw_rate is not None
            and abs(pw_rate - lw_rate) > 0.5
        )
        out.append({
            "domain":         domain,
            "lw_ok":          c["lw_ok"],
            "lw_total":       c["lw_total"],
            "lw_rate":        lw_rate,
            "pw_ok":          c["pw_ok"],
            "pw_total":       c["pw_total"],
            "pw_rate":        pw_rate,
            "indeterminate_reason": reason,
            "level":          level,
            "diff_above_50":  diff_above_50,
        })
    return out
