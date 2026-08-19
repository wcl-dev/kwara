"""
pipeline.py — 統一調度 scan → snapshot → whois
app.py 只呼叫這裡，不直接碰底層模組。
網域情資（WHOIS／ASN）可獨立於截圖寫入 scan_runs。
"""
import json
import sqlite3
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from .adstxt import fetch_and_store_ads_txt
from .cloaking import detect_and_store_cloaking
from .config import NEW_DOMAIN_DAYS
from .corroboration import corroborate_url
from .scanner import scan_url as _scan
from .snapshots import snapshot_url as _snapshot, snapshot_batch as _snapshot_batch
from .whois_lookup import query_whois, UNKNOWN
from .ip_lookup import lookup_ip

_POSTED_AT_FMTS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d-%m-%Y",
    "%m/%d/%Y",
]


def _parse_posted_at(raw: str):
    """Parse a posted_at string to a NAIVE UTC datetime, or None.

    Naive on purpose: the only caller subtracts a strptime()'d WHOIS creation
    date from the result, and mixing aware and naive datetimes raises
    TypeError, which that call site does not catch. An offset-bearing
    ISO-8601 value is therefore converted to UTC and stripped of tzinfo
    rather than returned as-is.
    """
    raw = (raw or "").strip().replace(" UTC", "")
    if not raw:
        return None

    # ISO-8601 first — the default output of essentially every API and export
    # tool, and so the likeliest thing to arrive at a public ingest surface.
    # fromisoformat() only learned to accept a trailing 'Z' in 3.11, and the
    # project supports 3.10, so normalise it by hand.
    iso = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        pass
    else:
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    for fmt in _POSTED_AT_FMTS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _intel_now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def run_scan_only(conn: sqlite3.Connection, url_artifact_id: int) -> int:
    """Pure scan — redirect chain + TLS + headers. No third-party network calls.

    Use run_scan_with_corroboration() to additionally submit to Wayback /
    urlscan / RFC 3161 in the same step, or call run_corroborate() later.
    """
    return _scan(conn, url_artifact_id)


def run_scan_with_corroboration(conn: sqlite3.Connection, url_artifact_id: int) -> int:
    """Scan, then best-effort third-party corroboration. Failures in
    corroboration do not surface — see _try_corroborate()."""
    scan_run_id = _scan(conn, url_artifact_id)
    _try_corroborate(conn, scan_run_id)
    return scan_run_id


def run_lightweight_fetch_batch(
    conn: sqlite3.Connection,
    scan_run_ids: list[int],
) -> list[int]:
    """Lightweight HTML-only fetch — no Playwright, no screenshot, no HAR.

    Wraps lightweight_fetch.fetch_html_only_batch(). See that module's
    docstring for trade-offs vs the full Playwright snapshot path.
    """
    from .lightweight_fetch import fetch_html_only_batch
    return fetch_html_only_batch(conn, scan_run_ids)


def _try_corroborate(conn: sqlite3.Connection, scan_run_id: int) -> None:
    """Best-effort third-party corroboration after a successful scan.

    Per-service failures (urlscan / Wayback / TSA outage) are already
    captured as `{"error": ...}` entries inside corroborate_url(). If the
    whole pipeline raises (import failure, networking layer crash, etc.)
    we still write a stub so the analyst can distinguish "never attempted"
    from "tried but the entire pipeline aborted" — leaving
    `corroboration_json` NULL on failure conflates the two.
    """
    row = conn.execute(
        "SELECT final_url, status, corroboration_json FROM scan_runs WHERE id = ?",
        (scan_run_id,),
    ).fetchone()
    if not row or row["status"] != "done" or not row["final_url"]:
        return
    if row["corroboration_json"]:
        return  # already corroborated
    try:
        results = corroborate_url(row["final_url"])
    except Exception as exc:
        err_label = f"pipeline aborted: {type(exc).__name__}"
        results = {
            "urlscan":   {"service": "urlscan.io",  "error": err_label},
            "wayback":   {"service": "archive.org", "error": err_label},
            "timestamp": {"service": "rfc3161",     "error": err_label},
            "_pipeline_error": str(exc)[:500],
            "_attempted_at":   _intel_now(),
        }
    conn.execute(
        "UPDATE scan_runs SET corroboration_json = ? WHERE id = ?",
        (json.dumps(results, ensure_ascii=False), scan_run_id),
    )
    conn.commit()


def _try_detect_cloaking(conn: sqlite3.Connection, scan_run_id: int) -> None:
    """Best-effort cloaking detection. Failures don't block the pipeline —
    the function itself records {"verdict": "fetch_error"} so the analyst
    sees what was attempted."""
    try:
        detect_and_store_cloaking(conn, scan_run_id)
    except Exception:
        # Defence-in-depth: detect_and_store_cloaking already swallows
        # per-fetch failures; this only catches schema/import-time
        # surprises so the snapshot pipeline never fails because of
        # a downstream cloaking detector glitch.
        pass


def run_cloaking(conn: sqlite3.Connection, scan_run_id: int,
                 *, force: bool = False) -> dict | None:
    """Force (re-)run cloaking detection from UI."""
    return detect_and_store_cloaking(conn, scan_run_id, force=force)


def _try_fetch_ads_txt(conn: sqlite3.Connection, scan_run_id: int) -> None:
    """Best-effort ads.txt fetch. Failures don't block the pipeline —
    fetch_and_store_ads_txt itself records {"status": "error"} so the
    analyst sees what was attempted."""
    try:
        fetch_and_store_ads_txt(conn, scan_run_id)
    except Exception:
        # Defence-in-depth: only catches schema/import surprises so the
        # snapshot pipeline never fails on a downstream ads.txt glitch.
        pass


def run_ads_txt(conn: sqlite3.Connection, scan_run_id: int,
                *, force: bool = False) -> dict | None:
    """Force (re-)fetch a scan run's ads.txt from UI."""
    return fetch_and_store_ads_txt(conn, scan_run_id, force=force)


def run_corroborate(conn: sqlite3.Connection, scan_run_id: int) -> dict | None:
    """Force (re-)corroborate a scan run. Called from UI retry button."""
    row = conn.execute(
        "SELECT final_url, status FROM scan_runs WHERE id = ?",
        (scan_run_id,),
    ).fetchone()
    if not row or row["status"] != "done" or not row["final_url"]:
        return None
    results = corroborate_url(row["final_url"])
    conn.execute(
        "UPDATE scan_runs SET corroboration_json = ? WHERE id = ?",
        (json.dumps(results, ensure_ascii=False), scan_run_id),
    )
    conn.commit()
    return results


def _latest_snapshot_id(conn: sqlite3.Connection, scan_run_id: int) -> int | None:
    row = conn.execute(
        """SELECT id FROM snapshots WHERE scan_run_id = ?
           ORDER BY id DESC LIMIT 1""",
        (scan_run_id,),
    ).fetchone()
    return row["id"] if row else None


def _enrich_domain_for_scan_run(
    conn: sqlite3.Connection,
    scan_run_id: int,
    snapshot_id: int | None = None,
) -> None:
    sr = conn.execute(
        "SELECT id, final_url, status FROM scan_runs WHERE id = ?",
        (scan_run_id,),
    ).fetchone()
    if not sr or (sr["status"] or "") != "done" or not sr["final_url"]:
        return

    final_domain = urlparse(sr["final_url"]).hostname or ""
    if not final_domain:
        return

    posted_row = conn.execute(
        """SELECT me.posted_at FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           JOIN message_evidence me ON me.id = ua.message_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    posted_at = posted_row["posted_at"] if posted_row else None

    registrar, creation_date, _ = query_whois(final_domain)
    data = lookup_ip(final_domain)
    ref_date = _parse_posted_at(posted_at) if posted_at else None
    if ref_date is None:
        # Falling back to now() widens the computed domain age, which can
        # suppress the new_domain tag — a silent downgrade of a signal, so a
        # posted_at that was present but unusable is reported rather than
        # swallowed. An absent posted_at is not an error and stays quiet.
        if posted_at:
            print(f"[warn] unparseable posted_at {posted_at!r} on scan_run "
                  f"{scan_run_id}; using now() as the domain-age reference",
                  file=sys.stderr)
        ref_date = datetime.now()

    intel_tags: list[str] = []
    if creation_date and creation_date != UNKNOWN:
        try:
            age = (ref_date - datetime.strptime(creation_date, "%Y-%m-%d")).days
            if age < NEW_DOMAIN_DAYS:
                intel_tags.append("new_domain")
        except ValueError:
            pass

    enriched_at = _intel_now()

    if snapshot_id is not None:
        snap = conn.execute(
            "SELECT id, risk_tags FROM snapshots WHERE id = ? AND scan_run_id = ?",
            (snapshot_id, scan_run_id),
        ).fetchone()
        if snap:
            tags = json.loads(snap["risk_tags"] or "[]")
            for t in intel_tags:
                if t not in tags:
                    tags.append(t)
            conn.execute(
                """UPDATE snapshots SET whois_registrar = ?, whois_creation_date = ?,
                       ip_address = ?, asn = ?, as_org = ?, as_country = ?, risk_tags = ?
                   WHERE id = ?""",
                (
                    registrar,
                    creation_date,
                    data["ip"],
                    data["asn"],
                    data["as_org"],
                    data["as_country"],
                    json.dumps(tags),
                    snapshot_id,
                ),
            )

    conn.execute(
        """UPDATE scan_runs SET whois_registrar = ?, whois_creation_date = ?,
               ip_address = ?, asn = ?, as_org = ?, as_country = ?,
               intel_risk_tags = ?, domain_enriched_at = ?
           WHERE id = ?""",
        (
            registrar,
            creation_date,
            data["ip"],
            data["asn"],
            data["as_org"],
            data["as_country"],
            json.dumps(intel_tags),
            enriched_at,
            scan_run_id,
        ),
    )
    conn.commit()


def run_domain_intel_only(conn: sqlite3.Connection, scan_run_id: int) -> None:
    """WHOIS / ASN only; no browser. Updates scan_runs; merges into snapshot row if present."""
    sid = _latest_snapshot_id(conn, scan_run_id)
    _enrich_domain_for_scan_run(conn, scan_run_id, snapshot_id=sid)


def run_domain_intel_batch(conn: sqlite3.Connection, scan_run_ids: list[int]) -> None:
    for sr_id in scan_run_ids:
        run_domain_intel_only(conn, sr_id)


def run_snapshot(conn: sqlite3.Connection, scan_run_id: int,
                 env_override: dict[str, str] | None = None) -> int:
    snapshot_id = _snapshot(conn, scan_run_id, env_override=env_override)
    _enrich_domain_for_scan_run(conn, scan_run_id, snapshot_id=snapshot_id)
    _try_corroborate(conn, scan_run_id)
    _try_detect_cloaking(conn, scan_run_id)
    _try_fetch_ads_txt(conn, scan_run_id)
    return snapshot_id


def run_snapshot_batch(conn: sqlite3.Connection, scan_run_ids: list[int],
                       env_override: dict[str, str] | None = None) -> list[int]:
    """Capture screenshots for multiple URLs in one subprocess, then enrich."""
    snapshot_ids = _snapshot_batch(conn, scan_run_ids, env_override=env_override)
    for sid in snapshot_ids:
        row = conn.execute(
            "SELECT scan_run_id FROM snapshots WHERE id = ?", (sid,)
        ).fetchone()
        if row:
            _enrich_domain_for_scan_run(conn, row["scan_run_id"], snapshot_id=sid)
            _try_detect_cloaking(conn, row["scan_run_id"])
            _try_fetch_ads_txt(conn, row["scan_run_id"])
    return snapshot_ids


# ---------------------------------------------------------------------------
# Fast attribution — populate operator-clustering signals WITHOUT Playwright.
# Decouples "are these linked?" (cheap: scan + lightweight HTML + ads.txt +
# WHOIS) from "preserve the evidence" (heavy: screenshots / HTML / HAR).
# ---------------------------------------------------------------------------
# A URL the case has not scanned yet, whichever artifact row carries it. The
# NOT EXISTS reaches through url_artifacts rather than testing sr.url_artifact_id
# directly, so a URL already scanned under a different post is recognised as
# scanned.
_URL_NOT_YET_SCANNED = """
    NOT EXISTS (SELECT 1 FROM scan_runs sr
                  JOIN url_artifacts ua_sib ON ua_sib.id = sr.url_artifact_id
                 WHERE ua_sib.case_id = ua.case_id
                   AND ua_sib.original_url = ua.original_url
                   AND sr.status = 'done')
"""


def _artifacts_needing_scan(conn: sqlite3.Connection, case_id: int) -> list[int]:
    """One artifact per distinct URL the case has not scanned yet (pure query).

    Deduplicated by URL, not by artifact row. A URL gets one url_artifacts row
    per post that carried it, and N accounts pushing one link is the finding
    this tool exists to surface — so the per-artifact version fired one request
    per account at a single target. On live case data that was 22 requests to
    one URL inside eleven minutes, from one egress, against a site under
    investigation.

    What makes this safe is that the analysis joins resolve a scan through any
    artifact in the case carrying the same URL (sql.LATEST_DONE_SCAN_RUN_FOR_URL).
    Without that, the artifacts skipped here would drop out of every INNER JOIN
    and take their posts with them — turning 22 coordinated accounts into 1.
    Do not reintroduce this dedup anywhere those joins do not reach.

    An analyst who deliberately wants a URL re-observed passes explicit
    --artifact ids, which bypasses this selection entirely.
    """
    return [r["id"] for r in conn.execute(
        f"""SELECT MIN(ua.id) AS id FROM url_artifacts ua
           WHERE ua.case_id = ? AND {_URL_NOT_YET_SCANNED}
           GROUP BY ua.original_url
           ORDER BY id""",
        (case_id,),
    ).fetchall()]


def _artifacts_covered_by_a_sibling(conn: sqlite3.Connection, case_id: int) -> int:
    """Artifacts this run will not fetch because another row carries their URL.

    Reported alongside the scan count so the saving reads as deduplication
    rather than under-collection — a smaller number with no explanation is how
    a silent cap looks from the outside.
    """
    # The comparison is against what a per-artifact selection would have
    # fetched — artifacts with no done scan OF THEIR OWN — not against the
    # per-URL predicate, which by construction already excludes them.
    would_have_fetched = conn.execute(
        """SELECT COUNT(*) AS n FROM url_artifacts ua
           WHERE ua.case_id = ?
             AND NOT EXISTS (SELECT 1 FROM scan_runs sr
                             WHERE sr.url_artifact_id = ua.id
                               AND sr.status = 'done')""",
        (case_id,),
    ).fetchone()["n"]
    return would_have_fetched - len(_artifacts_needing_scan(conn, case_id))


def _scan_runs_needing(conn: sqlite3.Connection, case_id: int,
                       force: bool = False) -> dict:
    """For each artifact's latest DONE scan_run, which cheap steps it still
    needs (pure query — the testable core of fast attribution):

      lightweight : default — no usable ('ok') snapshot of ANY kind yet.
                    force   — no FULL (playwright/manual) snapshot yet; a stale
                    'http_only' snapshot may be refreshed.
      ads / intel : default — empty; force — always re-run.

    Shadow guard (always on, both modes): a scan_run with a full
    playwright/manual 'ok' snapshot is NEVER a lightweight target, so richer
    evidence is never overwritten by a cheap HTML-only fetch. capture_method
    distinguishes them ('playwright'/'manual'/legacy-NULL = full;
    'http_only' = lightweight).
    """
    rows = conn.execute(
        """SELECT sr.id AS sid, sr.ads_txt_json, sr.domain_enriched_at,
                  (SELECT COUNT(*) FROM snapshots s
                   WHERE s.scan_run_id = sr.id AND s.capture_status = 'ok') AS ok_any,
                  (SELECT COUNT(*) FROM snapshots s
                   WHERE s.scan_run_id = sr.id AND s.capture_status = 'ok'
                     AND (s.capture_method IS NULL
                          OR s.capture_method IN ('playwright', 'manual'))) AS ok_full
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE ua.case_id = ?
             AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id
                          AND status = 'done' ORDER BY id DESC LIMIT 1)""",
        (case_id,),
    ).fetchall()
    out: dict[str, list[int]] = {"lightweight": [], "ads": [], "intel": []}
    for r in rows:
        need_lw = (r["ok_full"] == 0) if force else (r["ok_any"] == 0)
        if need_lw:
            out["lightweight"].append(r["sid"])
        if force or not ((r["ads_txt_json"] or "").strip()):
            out["ads"].append(r["sid"])
        if force or not (str(r["domain_enriched_at"] or "").strip()):
            out["intel"].append(r["sid"])
    return out


def run_fast_attribution(conn: sqlite3.Connection, case_id: int,
                         force: bool = False, progress=None) -> dict:
    """Cheap attribution pass: scan + lightweight HTML (static tracking IDs) +
    ads.txt + WHOIS/ASN, with NO Playwright screenshots/HAR. Populates the
    operator-clustering signals so groups / the relationship graph appear
    without the heavy evidence-capture step.

    Caveat: only STATIC, HTML-embedded tracking IDs are seen here. JS-injected
    IDs (e.g. GA4 loaded via GTM) need the full Playwright snapshot, so few or
    zero groups after this does NOT prove the domains are independent.

    Best-effort: per-item failures are collected in `errors`, never raised.
    Returns {scanned, attributed, ads, intel, errors}.
    """
    summary: dict = {"scanned": 0, "skipped_duplicate_urls":
                     _artifacts_covered_by_a_sibling(conn, case_id),
                     "attributed": 0, "ads": 0, "intel": 0, "errors": []}

    def _tick(msg):
        if progress:
            progress(msg)

    for aid in _artifacts_needing_scan(conn, case_id):
        _tick(f"掃描 artifact {aid}")
        try:
            run_scan_only(conn, aid)
            summary["scanned"] += 1
        except Exception as e:  # noqa: BLE001 — best-effort batch
            summary["errors"].append(f"scan {aid}: {e}")

    targets = _scan_runs_needing(conn, case_id, force=force)

    if targets["lightweight"]:
        _tick("輕量 HTML 擷取（靜態追蹤碼）")
        try:
            run_lightweight_fetch_batch(conn, targets["lightweight"])
            summary["attributed"] = len(targets["lightweight"])
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"lightweight: {e}")

    for sid in targets["ads"]:
        _tick(f"ads.txt（scan_run {sid}）")
        try:
            run_ads_txt(conn, sid, force=force)
            summary["ads"] += 1
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"ads {sid}: {e}")

    if targets["intel"]:
        _tick("WHOIS / ASN")
        try:
            run_domain_intel_batch(conn, targets["intel"])
            summary["intel"] = len(targets["intel"])
        except Exception as e:  # noqa: BLE001
            summary["errors"].append(f"intel: {e}")

    return summary
