import json
import os
import secrets
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from audit import write_audit
from config import (
    HIGH_TRACKER_THRESHOLD,
    KNOWN_SHORTLINK_DOMAINS,
    SUSPICIOUS_EXTS,
    TRACKER_DOMAINS,
)
from fingerprints import extract_tracking_ids_from_file
from lightweight_fetch import CAPTURE_METHOD_PLAYWRIGHT

CAPTURE_OK = "ok"
CAPTURE_CF = "cf_challenge"
CAPTURE_TIMEOUT = "timeout"
CAPTURE_FILE_MISSING = "file_missing"
CAPTURE_WAYBACK = "wayback"
CAPTURE_ERROR = "error"
CAPTURE_MANUAL = "manual"


CAPTURE_MANIFEST = "capture.json"


def _write_capture_manifest(base_dir: str, **meta) -> None:
    """Drop a small sidecar naming what this capture directory holds.

    The store is keyed by scan_run_id, so `data/snapshots/7/2026…_9fd1/` says
    nothing on its own about which site it captured — a 6.6 GB tree of integer
    directories readable only by querying the DB that sits beside it. That is
    the wrong shape for evidence whose stated promise is that a third party can
    reproduce what we saw WITHOUT trusting us: hand someone the folder and they
    should be able to tell what it is.

    Best-effort. A capture must never fail because its label could not be
    written — the artifacts are the evidence, this is only the caption.
    """
    payload = {k: v for k, v in meta.items() if v is not None}
    # captured_at is when the EVIDENCE was taken; described_at is when this
    # caption was written. They coincide on a live capture and must not on a
    # backfill — conflating them would put today's date on May's evidence.
    payload.setdefault("captured_at", _now())
    payload["described_at"] = _now()
    payload["_note"] = ("Describes the capture in this directory. Written by "
                        "kwara; the artifacts beside it are the evidence.")
    try:
        with open(os.path.join(base_dir, CAPTURE_MANIFEST), "w",
                  encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass


def _per_capture_dir(scan_run_id: int, *, final_url: str | None = None,
                     capture_method: str | None = None,
                     case_id: int | None = None) -> str:
    """Per-capture subdirectory under the scan_run's snapshot tree.

    Each capture call writes to a fresh timestamped+random directory so
    repeated captures (re-snapshot, lightweight fetch, manual upload) on
    the same scan_run do NOT overwrite older artifacts. Older snapshot
    rows in the DB keep pointing at their original files. Critical for
    forensic chain-of-custody (codex review: silent evidence corruption).

    Layout:
      data/snapshots/{scan_run_id}/{YYYYMMDDTHHMMSSffffff}_{rand4}/
    """
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    suffix = secrets.token_hex(2)  # 4 hex chars; defends against same-microsecond collisions
    base_dir = os.path.join(
        os.path.dirname(__file__),
        "data", "snapshots",
        str(scan_run_id),
        f"{ts}_{suffix}",
    )
    os.makedirs(base_dir, exist_ok=True)
    _write_capture_manifest(
        base_dir, scan_run_id=scan_run_id, case_id=case_id,
        final_url=final_url, capture_method=capture_method,
        final_domain=(urlparse(final_url).hostname or "") if final_url else None)
    return base_dir


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _apex(hostname: str) -> str:
    parts = (hostname or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (hostname or "")


def _risk_tags(final_url: str, hop_count: int, request_domains: list) -> list:
    tags = []
    parsed = urlparse(final_url)

    if hop_count >= 3:
        tags.append('multi_hop')

    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in SUSPICIOUS_EXTS):
        tags.append('suspicious_download')

    if parsed.scheme == 'http':
        tags.append('no_https')

    if (parsed.hostname or "") in KNOWN_SHORTLINK_DOMAINS:
        tags.append('url_shortener_chain')

    apexes = {_apex(d) for d in request_domains if d}
    if len(apexes & TRACKER_DOMAINS) >= HIGH_TRACKER_THRESHOLD:
        tags.append('high_tracker_count')

    return tags


def _round_robin_by_apex(jobs: list[dict]) -> list[dict]:
    """Spread same-apex URLs apart to reduce rate limits."""
    by_apex = defaultdict(list)
    for j in jobs:
        host = urlparse(j["final_url"]).hostname or ""
        by_apex[_apex(host)].append(j)
    out = []
    while any(by_apex.values()):
        for ax in list(by_apex.keys()):
            if by_apex[ax]:
                out.append(by_apex[ax].pop(0))
            if not by_apex[ax]:
                del by_apex[ax]
    return out


def _compute_subprocess_timeout(n: int, timeout: int, mode: str) -> int:
    if n <= 0:
        return 60
    if mode == "headless_only":
        per = timeout + 70 + 55
        return int(n * per + 420)
    if mode == "headed_only":
        per = timeout + 50 + 10
        return int(n * per + 480)
    return int(n * (timeout + 50) + 360)


def _run_worker_phase(urls_info: list[dict], timeout: int, mode: str,
                      env_override: dict[str, str] | None = None) -> list[dict]:
    import subprocess
    import tempfile

    if not urls_info:
        return []

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False,
                                     encoding='utf-8') as f_in:
        json.dump({"urls": urls_info, "timeout": timeout, "mode": mode}, f_in)
        input_file = f_in.name

    result_file = input_file.replace('.json', '_result.json')
    script = os.path.join(os.path.dirname(__file__), '_snapshot_worker.py')
    venv_python = os.path.join(os.path.dirname(__file__), '.venv', 'Scripts', 'python.exe')
    python_exe = venv_python if os.path.exists(venv_python) else sys.executable

    # Pass per-case locale to the subprocess via environment variables
    sub_env = dict(os.environ)
    if env_override:
        sub_env.update(env_override)

    overall_timeout = _compute_subprocess_timeout(len(urls_info), timeout, mode)
    proc = None
    try:
        proc = subprocess.run(
            [python_exe, script, input_file, result_file],
            timeout=overall_timeout,
            capture_output=True, text=True,
            env=sub_env,
        )
    except subprocess.TimeoutExpired:
        return _error_results(urls_info, "subprocess timed out")
    except Exception as exc:
        return _error_results(urls_info, f"subprocess error: {exc}")
    finally:
        try:
            os.unlink(input_file)
        except OSError:
            pass

    if not os.path.exists(result_file):
        stderr = (proc.stderr or "")[:500] if proc else ""
        return _error_results(urls_info, f"no result file; stderr: {stderr}")

    try:
        with open(result_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
    except Exception as exc:
        results = _error_results(urls_info, f"bad result file: {exc}")
    finally:
        try:
            os.unlink(result_file)
        except OSError:
            pass

    return results


def _capture_in_subprocess(urls_info: list[dict], timeout: int = 30,
                           env_override: dict[str, str] | None = None) -> list[dict]:
    """Two-phase: headless batch, then headed only for URLs still blocked."""
    if not urls_info:
        return []

    r1 = _run_worker_phase(urls_info, timeout, "headless_only", env_override=env_override)
    if len(r1) != len(urls_info):
        return r1

    retry_jobs = []
    for i, r in enumerate(r1):
        if r.get("headed_retry"):
            job = dict(urls_info[i])
            job["_batch_index"] = i
            retry_jobs.append(job)

    if retry_jobs:
        r2 = _run_worker_phase(retry_jobs, timeout, "headed_only", env_override=env_override)
        if len(r2) != len(retry_jobs):
            for i, r in enumerate(r1):
                if r.get("headed_retry"):
                    r["error"] = r.get("error") or "headed_phase_failed"
                    r["headed_retry"] = False
            return r1
        for j, job in enumerate(retry_jobs):
            idx = job["_batch_index"]
            upd = r2[j]
            r1[idx]["screenshot_path"] = upd.get("screenshot_path")
            r1[idx]["html_path"] = upd.get("html_path")
            r1[idx]["request_domains"] = upd.get("request_domains") or r1[idx].get("request_domains", [])
            r1[idx]["error"] = upd.get("error")
            r1[idx]["headed_retry"] = False

    for r in r1:
        r.pop("headed_retry", None)

    return r1


def _error_results(urls_info, msg):
    return [{"scan_run_id": u["scan_run_id"], "screenshot_path": None,
             "html_path": None, "request_domains": [],
             "error": msg} for u in urls_info]


def _validate_files(screenshot_path, html_path):
    """Return (ss_ok, html_ok)."""
    ss_ok = bool(
        screenshot_path and os.path.isfile(screenshot_path)
        and os.path.getsize(screenshot_path) > 0
    )
    html_ok = bool(
        html_path and os.path.isfile(html_path)
        and os.path.getsize(html_path) > 0
    )
    return ss_ok, html_ok


def _apply_wayback_if_needed(
    final_url: str,
    error_note: str | None,
    screenshot_path: str | None,
    html_path: str | None,
) -> tuple[str | None, str | None, str | None, bool]:
    """Returns (screenshot_path, html_path, error_note, used_wayback)."""
    from wayback_fallback import try_wayback_evidence

    ss_ok, html_ok = _validate_files(screenshot_path, html_path)
    if ss_ok and html_ok and not error_note:
        return screenshot_path, html_path, error_note, False

    need = (not html_ok) or (
        error_note and (
            "cf_blocked" in error_note
            or "subprocess timed out" in (error_note or "")
        )
    )
    if not need or not html_path:
        return screenshot_path, html_path, error_note, False

    ok, detail = try_wayback_evidence(final_url, html_path)
    if ok:
        return screenshot_path, html_path, None, True
    return screenshot_path, html_path, error_note, False


def _derive_capture_status(
    error_note: str | None,
    ss_ok: bool,
    html_ok: bool,
    used_wayback: bool,
) -> tuple[str, str | None]:
    detail = (error_note or "")[:500] or None
    if used_wayback and html_ok:
        extra = "screenshot_missing" if not ss_ok else None
        d = (detail + ";" + extra) if (detail and extra) else (detail or extra or "internet_archive_html")
        return CAPTURE_WAYBACK, d
    if error_note and "subprocess timed out" in error_note:
        return CAPTURE_TIMEOUT, detail
    if not ss_ok and not html_ok:
        return (CAPTURE_FILE_MISSING, detail or "no_screenshot_no_html")
    if not ss_ok and html_ok:
        if error_note and "cf_blocked" in error_note:
            return CAPTURE_CF, detail
        return CAPTURE_ERROR, detail or "screenshot_missing"
    if ss_ok and html_ok:
        if error_note and "cf_blocked" in error_note:
            return CAPTURE_CF, detail
        if error_note:
            return CAPTURE_ERROR, detail
        return CAPTURE_OK, None
    if ss_ok and not html_ok:
        return CAPTURE_ERROR, detail or "html_missing"
    return CAPTURE_ERROR, detail


def _prepare_insert_row(
    final_url: str,
    hop_count: int,
    r: dict,
) -> tuple:
    """Returns tuple for INSERT including capture_status, capture_detail."""
    request_domains = r.get("request_domains", [])
    error_note = r.get("error")
    screenshot_path = r.get("screenshot_path")
    html_path = r.get("html_path")

    screenshot_path, html_path, error_note, used_wb = _apply_wayback_if_needed(
        final_url, error_note, screenshot_path, html_path,
    )

    ss_ok, html_ok = _validate_files(screenshot_path, html_path)
    if screenshot_path and not ss_ok:
        screenshot_path = None
    if html_path and not html_ok:
        html_path = None

    ss_ok, html_ok = _validate_files(screenshot_path, html_path)

    if not ss_ok and r.get("screenshot_path") and not error_note:
        error_note = error_note or "screenshot file missing or empty after capture"

    cap_status, cap_detail = _derive_capture_status(error_note, ss_ok, html_ok, used_wb)

    tags = _risk_tags(final_url, hop_count, request_domains)
    if cap_status != CAPTURE_OK:
        if "capture_error" not in tags:
            tags.insert(0, 'capture_error')

    return (
        request_domains,
        error_note,
        screenshot_path,
        html_path,
        tags,
        cap_status,
        cap_detail,
    )


def snapshot_url(conn: sqlite3.Connection, scan_run_id: int, timeout: int = 30,
                 env_override: dict[str, str] | None = None) -> int:
    row = conn.execute(
        """SELECT sr.final_url, sr.hop_count, ua.case_id, ua.id AS url_artifact_id
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"scan_run_id {scan_run_id} not found")

    final_url = row['final_url']
    hop_count = row['hop_count'] or 0
    case_id = row['case_id']
    final_domain = urlparse(final_url).hostname or ''

    base_dir = _per_capture_dir(scan_run_id, final_url=final_url,
                                capture_method="playwright", case_id=case_id)
    screenshot_path = os.path.join(base_dir, 'screenshot.png')
    html_path = os.path.join(base_dir, 'page.html')

    results = _capture_in_subprocess([{
        "scan_run_id": scan_run_id,
        "final_url": final_url,
        "screenshot_path": screenshot_path,
        "html_path": html_path,
    }], timeout=timeout, env_override=env_override)
    r = results[0]

    (request_domains, error_note, screenshot_path, html_path, tags,
     cap_status, cap_detail) = _prepare_insert_row(final_url, hop_count, r)

    _har_path = r.get("har_path") if r.get("har_path") and os.path.exists(r.get("har_path", "")) else None
    tracking_ids = extract_tracking_ids_from_file(html_path)
    tracking_ids_json = json.dumps(tracking_ids, ensure_ascii=False) if tracking_ids else None
    conn.execute(
        """INSERT INTO snapshots
               (scan_run_id, final_url, final_domain,
                screenshot_path, html_path, har_path,
                request_domains_json, risk_tags, captured_at,
                capture_status, capture_detail, tracking_ids_json,
                capture_method)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_run_id, final_url, final_domain,
            screenshot_path, html_path, _har_path,
            json.dumps(request_domains),
            json.dumps(tags),
            _now(),
            cap_status,
            cap_detail,
            tracking_ids_json,
            CAPTURE_METHOD_PLAYWRIGHT,
        ),
    )
    conn.commit()
    snapshot_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    write_audit(
        conn, 'snapshot_url', case_id=case_id,
        meta={
            'scan_run_id': scan_run_id, 'snapshot_id': snapshot_id,
            'final_url': final_url, 'final_domain': final_domain,
            'hop_count': hop_count, 'risk_tags': tags,
            'request_domain_count': len(request_domains),
            'error': error_note,
            'capture_status': cap_status,
            'capture_detail': cap_detail,
            'tracking_id_platforms': sorted(tracking_ids.keys()),
        },
    )
    return snapshot_id


def snapshot_batch(conn: sqlite3.Connection, scan_run_ids: list[int],
                   timeout: int = 30,
                   env_override: dict[str, str] | None = None) -> list[int]:
    jobs = []
    meta_map = {}
    for sr_id in scan_run_ids:
        row = conn.execute(
            """SELECT sr.final_url, sr.hop_count, ua.case_id
               FROM scan_runs sr
               JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
               WHERE sr.id = ?""",
            (sr_id,),
        ).fetchone()
        if row is None:
            continue

        base_dir = _per_capture_dir(sr_id, final_url=row["final_url"],
                                    capture_method="playwright",
                                    case_id=row["case_id"])

        jobs.append({
            "scan_run_id": sr_id,
            "final_url": row["final_url"],
            "screenshot_path": os.path.join(base_dir, 'screenshot.png'),
            "html_path": os.path.join(base_dir, 'page.html'),
        })
        meta_map[sr_id] = {
            "final_url": row["final_url"],
            "hop_count": row["hop_count"] or 0,
            "case_id": row["case_id"],
            "final_domain": urlparse(row["final_url"]).hostname or '',
        }

    if not jobs:
        return []

    jobs = _round_robin_by_apex(jobs)
    results = _capture_in_subprocess(jobs, timeout=timeout, env_override=env_override)

    by_sr = {j["scan_run_id"]: r for j, r in zip(jobs, results)}
    snapshot_ids = []
    for sr_id in scan_run_ids:
        if sr_id not in by_sr:
            continue
        r = by_sr[sr_id]
        m = meta_map[sr_id]

        (request_domains, error_note, screenshot_path, html_path, tags,
         cap_status, cap_detail) = _prepare_insert_row(m["final_url"], m["hop_count"], r)

        _har_p = r.get("har_path") if r.get("har_path") and os.path.exists(r.get("har_path", "")) else None
        tracking_ids = extract_tracking_ids_from_file(html_path)
        tracking_ids_json = json.dumps(tracking_ids, ensure_ascii=False) if tracking_ids else None
        conn.execute(
            """INSERT INTO snapshots
                   (scan_run_id, final_url, final_domain,
                    screenshot_path, html_path, har_path,
                    request_domains_json, risk_tags, captured_at,
                    capture_status, capture_detail, tracking_ids_json,
                    capture_method)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sr_id, m["final_url"], m["final_domain"],
                screenshot_path, html_path, _har_p,
                json.dumps(request_domains), json.dumps(tags), _now(),
                cap_status, cap_detail, tracking_ids_json,
                CAPTURE_METHOD_PLAYWRIGHT,
            ),
        )
        conn.commit()
        snapshot_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        write_audit(
            conn, 'snapshot_url', case_id=m["case_id"],
            meta={
                'scan_run_id': sr_id, 'snapshot_id': snapshot_id,
                'final_url': m["final_url"], 'final_domain': m["final_domain"],
                'hop_count': m["hop_count"], 'risk_tags': tags,
                'request_domain_count': len(request_domains),
                'error': error_note,
                'capture_status': cap_status,
                'capture_detail': cap_detail,
                'tracking_id_platforms': sorted(tracking_ids.keys()),
            },
        )
        snapshot_ids.append(snapshot_id)

    return snapshot_ids


def _needs_manual_or_retry_capture(
    snap_id, capture_status: str | None, screenshot_path: str | None,
) -> bool:
    """Same rules as _run_pending.py for 'unfinished' targets."""
    if snap_id is None:
        return True
    st = capture_status
    if st in (CAPTURE_OK, CAPTURE_MANUAL, CAPTURE_WAYBACK):
        return False
    if st in (CAPTURE_CF, CAPTURE_ERROR, CAPTURE_TIMEOUT, CAPTURE_FILE_MISSING):
        return True
    if st is None or st == "":
        if screenshot_path and os.path.isfile(screenshot_path) and os.path.getsize(screenshot_path) > 0:
            return False
        return True
    return True


def failed_capture_urls_csv(conn: sqlite3.Connection, case_id: int) -> bytes:
    """CSV of scan runs that still need capture or manual follow-up (aligned with _run_pending)."""
    import csv
    import io

    rows = conn.execute(
        """SELECT sr.id AS scan_run_id, sr.final_url,
                  s.id AS snap_id, s.capture_status, s.capture_detail, s.screenshot_path
           FROM url_artifacts ua
           JOIN scan_runs sr ON sr.id = (
               SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1
           )
           LEFT JOIN snapshots s ON s.scan_run_id = sr.id
               AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["scan_run_id", "final_url", "capture_status", "capture_detail"])
    for r in rows:
        if not _needs_manual_or_retry_capture(
            r["snap_id"], r["capture_status"], r["screenshot_path"],
        ):
            continue
        cs = (r["capture_status"] or "").strip() or "pending"
        w.writerow([
            r["scan_run_id"],
            r["final_url"] or "",
            cs,
            (r["capture_detail"] or "")[:500],
        ])
    return buf.getvalue().encode("utf-8-sig")
