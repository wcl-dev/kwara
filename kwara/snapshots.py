import json
import os
import secrets
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from .audit import write_audit
from .config import (
    HIGH_TRACKER_THRESHOLD,
    KNOWN_SHORTLINK_DOMAINS,
    SUSPICIOUS_EXTS,
    TRACKER_DOMAINS,
)
from .fingerprints import extract_tracking_ids_from_file
from .lightweight_fetch import CAPTURE_METHOD_PLAYWRIGHT

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
    # This runs when the directory is ALLOCATED, before the capture starts —
    # a headed retry or a timeout can put minutes between the two. So the
    # sidecar records directory_created_at here and carries captured_at only
    # when a caller actually knows it (the backfill reads it from the DB).
    # Claiming allocation time as capture time would hand a third party two
    # different capture timestamps for the same artifact.
    payload["directory_created_at"] = _now()
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
    from . import config as _cfg          # call-time so tests can redirect it
    parent = os.path.join(_cfg.SNAPSHOT_ROOT, str(scan_run_id))
    os.makedirs(parent, exist_ok=True)
    # EXCLUSIVE creation, retried. exist_ok=True silently accepted a collision
    # between two captures that landed in the same microsecond with the same
    # 16-bit suffix, and both then wrote the same fixed filenames — an older
    # snapshot row would point at overwritten bytes, which invariant 7 exists
    # to prevent. Concurrency here is real: snapshot_batch runs captures in
    # parallel over one scan_run's URLs.
    base_dir = ""
    for _ in range(8):
        ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        candidate = os.path.join(parent, f"{ts}_{secrets.token_hex(2)}")
        try:
            os.mkdir(candidate)
            base_dir = candidate
            break
        except FileExistsError:
            continue
    if not base_dir:
        raise RuntimeError(
            f"could not allocate a fresh capture directory under {parent}")
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


def _screenshot_cap_sec(env: dict) -> float:
    """Mirror of _snapshot_worker._screenshot_timeout_sec, read from the child's
    environment so the parent's stall budget matches what the child will allow."""
    raw = (env.get("KWARA_SCREENSHOT_TIMEOUT") or "").strip()
    try:
        val = float(raw) if raw else 45.0
    except ValueError:
        val = 45.0
    return val if val > 0 else 45.0


def _per_url_stall_cap(timeout: int, mode: str, env: dict) -> int:
    """How long ONE url may go without the worker reporting it finished.

    Not a per-URL budget so much as a wedged-detector: it is derived from the
    worst legitimate path through the worker and then given generous headroom,
    because killing a slow-but-working capture costs evidence. What it buys is
    the guarantee that a single domain cannot hold the batch forever — before
    this, one infinite-scroll site stalled a 57-URL run past an hour and the
    only bound was the whole-batch timeout, 2.5 hours away, whose expiry would
    have thrown away every capture the run had already made.
    """
    ss = _screenshot_cap_sec(env)
    shot = ss * 4 / 3          # full page, then the viewport fallback
    if mode == "headed_only":
        worst = timeout + 25 + 8 + shot + 7
    else:
        # the CF path can run the whole capture twice with a 35-55s wait between
        worst = 2 * (timeout + 6 + 8 + shot) + 55 + 5
    return int(worst * 1.5) + 60


def _kill_process_tree(proc) -> None:
    """Kill the worker AND the browser it launched.

    proc.kill() reaches the Python process only. Its Chromium children outlive
    it — that is precisely the "程序仍活著" state the stall was reported in — so
    kill the group on POSIX and use taskkill /T on Windows.
    """
    import signal
    import subprocess

    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=30)
    except Exception:
        pass


def _read_progress(path: str) -> dict[int, dict]:
    """Entries the worker finished and flushed, keyed by position in its batch.

    Tolerates a truncated tail: the last line may be half-written if the worker
    was killed mid-append.
    """
    out: dict[int, dict] = {}
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("i"), int):
                    out[rec["i"]] = rec.get("entry") or {}
    except OSError:
        pass
    return out


def _launch_worker(urls_info: list[dict], timeout: int, mode: str,
                   sub_env: dict) -> tuple[list[dict] | None, dict[int, dict], int | None, str]:
    """Run the worker once over `urls_info`, watching it for a stall.

    Returns (results, progress, stalled_pos, note):
      results     — the worker's own result list when it exited normally, else None
      progress    — per-position entries it flushed before exiting
      stalled_pos — position of the URL that wedged it, or None
      note        — error text to use when results is None and nothing stalled
    """
    import subprocess
    import tempfile
    import time as _time

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False,
                                     encoding='utf-8') as f_in:
        input_file = f_in.name
    result_file = input_file.replace('.json', '_result.json')
    progress_file = input_file.replace('.json', '_progress.jsonl')

    with open(input_file, 'w', encoding='utf-8') as fh:
        json.dump({"urls": urls_info, "timeout": timeout, "mode": mode,
                   "progress_file": progress_file}, fh)

    script = os.path.join(os.path.dirname(__file__), '_snapshot_worker.py')
    venv_python = os.path.join(os.path.dirname(__file__), '.venv', 'Scripts', 'python.exe')
    python_exe = venv_python if os.path.exists(venv_python) else sys.executable

    overall_timeout = _compute_subprocess_timeout(len(urls_info), timeout, mode)
    stall_cap = _per_url_stall_cap(timeout, mode, sub_env)

    out_f = open(input_file + ".out", "w+", encoding="utf-8", errors="replace")
    popen_kw = dict(stdout=out_f, stderr=subprocess.STDOUT, env=sub_env)
    if os.name != "nt":
        # own process group, so _kill_process_tree can take the browser with it
        popen_kw["start_new_session"] = True

    results = None
    stalled_pos = None
    note = ""
    try:
        proc = subprocess.Popen([python_exe, script, input_file, result_file],
                                **popen_kw)
    except Exception as exc:
        out_f.close()
        _cleanup_files(input_file, result_file, progress_file, input_file + ".out")
        return None, {}, None, f"subprocess error: {exc}"

    started = _time.monotonic()
    last_change = started
    seen_count = 0
    try:
        while True:
            if proc.poll() is not None:
                break
            now = _time.monotonic()
            n = len(_read_progress(progress_file))
            if n > seen_count:
                seen_count = n
                last_change = now
            if now - last_change > stall_cap:
                stalled_pos = seen_count
                _kill_process_tree(proc)
                break
            if now - started > overall_timeout:
                note = "subprocess timed out"
                _kill_process_tree(proc)
                break
            _time.sleep(1.0)
    finally:
        progress = _read_progress(progress_file)
        try:
            out_f.flush()
            out_f.seek(0)
            child_output = out_f.read()[-500:]
        except Exception:
            child_output = ""
        out_f.close()

        if stalled_pos is None and not note:
            if os.path.exists(result_file):
                try:
                    with open(result_file, 'r', encoding='utf-8') as fh:
                        results = json.load(fh)
                except Exception as exc:
                    note = f"bad result file: {exc}"
            else:
                note = f"no result file; stderr: {child_output}"

        _cleanup_files(input_file, result_file, progress_file, input_file + ".out")

    return results, progress, stalled_pos, note


def _cleanup_files(*paths) -> None:
    for pth in paths:
        try:
            os.unlink(pth)
        except OSError:
            pass


def _run_worker_phase(urls_info: list[dict], timeout: int, mode: str,
                      env_override: dict[str, str] | None = None) -> list[dict]:
    """One capture phase, resumable past whichever URL brought the worker down.

    The worker reports each finished URL as it goes, so a launch that ends
    early still tells us how far it got. Whatever it flushed is kept, the URL
    it died on is recorded as a failed capture, and the URLs after it go to a
    fresh worker. Every restart advances by at least one position, so the loop
    cannot spin. Result order always matches urls_info.

    A launch that comes back with NOTHING — no results, no progress — is read
    as an environment failure rather than a bad URL, and the phase gives up
    instead of relaunching into the same wall.
    """
    if not urls_info:
        return []

    sub_env = dict(os.environ)
    if env_override:
        sub_env.update(env_override)

    by_index: dict[int, dict] = {}
    remaining = list(range(len(urls_info)))

    while remaining:
        chunk = [urls_info[i] for i in remaining]
        results, progress, stalled_pos, note = _launch_worker(
            chunk, timeout, mode, sub_env)

        if results is not None and len(results) == len(chunk):
            for pos, entry in enumerate(results):
                by_index[remaining[pos]] = entry
            break

        for pos, entry in progress.items():
            if 0 <= pos < len(chunk) and entry:
                by_index[remaining[pos]] = entry

        if note and "subprocess timed out" in note:
            # The whole-launch bound, not one URL. With the worker's own
            # watchdog in front of it this should never fire; if it does, the
            # problem is not the next URL and relaunching just burns the clock
            # again. Keep what was salvaged, stop.
            for pos, i in enumerate(remaining):
                by_index.setdefault(i, _error_results([chunk[pos]], note)[0])
            break

        if stalled_pos is not None:
            # The parent's own watchdog fired: the worker stopped reporting
            # and was killed, so it never got to name the URL itself.
            if 0 <= stalled_pos < len(chunk):
                by_index[remaining[stalled_pos]] = _error_results(
                    [chunk[stalled_pos]],
                    "capture stalled; worker killed after "
                    f"{_per_url_stall_cap(timeout, mode, sub_env)}s "
                    "with no progress",
                )[0]
            advance = stalled_pos + 1
        elif progress:
            # The worker died on its own — its watchdog, or a crash. Anything
            # it flushed is already recorded above; resume after the last one.
            advance = max(progress) + 1
            missing = advance - 1
            if missing < len(chunk) and missing not in progress:
                by_index[remaining[missing]] = _error_results(
                    [chunk[missing]], note or "worker exited early")[0]
        else:
            for pos, i in enumerate(remaining):
                by_index.setdefault(i, _error_results(
                    [chunk[pos]], note or "worker produced no results")[0])
            break

        remaining = remaining[advance:]

    return [by_index.get(i) or _error_results([urls_info[i]], "no result")[0]
            for i in range(len(urls_info))]


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
    from .wayback_fallback import try_wayback_evidence

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
    if error_note and ("subprocess timed out" in error_note
                       or "capture stalled" in error_note):
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

    # A screenshot that fell back to the viewport is still a usable capture, so
    # it must not become an 'error' row that `run snapshot` retries forever.
    # But an analyst reading a 1280x800 image of a page that scrolls for
    # kilometres deserves to know why it is cropped — that goes in the detail.
    shot_note = r.get("screenshot_note")
    if shot_note:
        cap_detail = f"{cap_detail}; {shot_note}" if cap_detail else shot_note
        cap_detail = cap_detail[:500]

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


def _record_capture(conn: sqlite3.Connection, scan_run_id: int,
                    meta: dict, r: dict) -> int:
    """Write one capture's snapshot row + audit entry, committed immediately.

    Shared by snapshot_url and snapshot_batch so a fix to how a capture is
    recorded cannot land on one path and miss the other.
    """
    (request_domains, error_note, screenshot_path, html_path, tags,
     cap_status, cap_detail) = _prepare_insert_row(
        meta["final_url"], meta["hop_count"], r)

    har = r.get("har_path")
    har_path = har if har and os.path.exists(har) else None
    tracking_ids = extract_tracking_ids_from_file(html_path)
    tracking_ids_json = (json.dumps(tracking_ids, ensure_ascii=False)
                         if tracking_ids else None)

    conn.execute(
        """INSERT INTO snapshots
               (scan_run_id, final_url, final_domain,
                screenshot_path, html_path, har_path,
                request_domains_json, risk_tags, captured_at,
                capture_status, capture_detail, tracking_ids_json,
                capture_method)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            scan_run_id, meta["final_url"], meta["final_domain"],
            screenshot_path, html_path, har_path,
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
        conn, 'snapshot_url', case_id=meta["case_id"],
        meta={
            'scan_run_id': scan_run_id, 'snapshot_id': snapshot_id,
            'final_url': meta["final_url"], 'final_domain': meta["final_domain"],
            'hop_count': meta["hop_count"], 'risk_tags': tags,
            'request_domain_count': len(request_domains),
            'error': error_note,
            'capture_status': cap_status,
            'capture_detail': cap_detail,
            'tracking_id_platforms': sorted(tracking_ids.keys()),
        },
    )
    return snapshot_id


def _scan_run_meta(conn: sqlite3.Connection, scan_run_id: int) -> dict | None:
    row = conn.execute(
        """SELECT sr.final_url, sr.hop_count, ua.case_id
           FROM scan_runs sr
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE sr.id = ?""",
        (scan_run_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "final_url": row["final_url"],
        "hop_count": row["hop_count"] or 0,
        "case_id": row["case_id"],
        "final_domain": urlparse(row["final_url"]).hostname or '',
    }


def snapshot_url(conn: sqlite3.Connection, scan_run_id: int, timeout: int = 30,
                 env_override: dict[str, str] | None = None) -> int:
    meta = _scan_run_meta(conn, scan_run_id)
    if meta is None:
        raise ValueError(f"scan_run_id {scan_run_id} not found")

    base_dir = _per_capture_dir(scan_run_id, final_url=meta["final_url"],
                                capture_method="playwright",
                                case_id=meta["case_id"])

    results = _capture_in_subprocess([{
        "scan_run_id": scan_run_id,
        "final_url": meta["final_url"],
        "screenshot_path": os.path.join(base_dir, 'screenshot.png'),
        "html_path": os.path.join(base_dir, 'page.html'),
    }], timeout=timeout, env_override=env_override)

    return _record_capture(conn, scan_run_id, meta, results[0])


def _snapshot_chunk_size() -> int:
    """URLs per capture subprocess. KWARA_SNAPSHOT_CHUNK overrides."""
    raw = os.environ.get("KWARA_SNAPSHOT_CHUNK", "").strip()
    try:
        n = int(raw) if raw else 5
    except ValueError:
        n = 5
    return max(1, n)


def snapshot_batch(conn: sqlite3.Connection, scan_run_ids: list[int],
                   timeout: int = 30,
                   env_override: dict[str, str] | None = None) -> list[int]:
    """Capture many URLs, in chunks, recording each chunk before the next starts.

    Two things used to happen once for the whole batch, and both were reasons a
    57-URL run that had to be killed left nothing behind but litter: every
    capture directory was allocated up front, and no snapshots row was written
    until the last URL came back. Kill it at URL 25 and you had 57 directories,
    25 sets of artifacts, and zero rows — the orphan directories reconcile
    reports (2,440 of them, 1.67 GB, as of 2026-08-25).

    Chunking fixes both: directories are allocated a chunk at a time, and each
    chunk's rows are committed before the next subprocess starts. An interrupted
    run now loses at most one chunk, and `run snapshot` picks the rest up as
    pending on the next invocation. The apex round-robin still runs over the
    WHOLE batch before chunking, so same-site URLs stay spread apart.
    """
    ordered: list[int] = []
    seen: set[int] = set()
    for sr_id in scan_run_ids:
        if sr_id not in seen:
            seen.add(sr_id)
            ordered.append(sr_id)

    meta_map: dict[int, dict] = {}
    for sr_id in ordered:
        meta = _scan_run_meta(conn, sr_id)
        if meta is not None:
            meta_map[sr_id] = meta

    if not meta_map:
        return []

    spread = _round_robin_by_apex([
        {"scan_run_id": sr_id, "final_url": meta_map[sr_id]["final_url"]}
        for sr_id in ordered if sr_id in meta_map
    ])
    targets = [j["scan_run_id"] for j in spread]

    chunk_size = _snapshot_chunk_size()
    ids_by_sr: dict[int, int] = {}

    for start in range(0, len(targets), chunk_size):
        batch = targets[start:start + chunk_size]
        jobs = []
        for sr_id in batch:
            m = meta_map[sr_id]
            base_dir = _per_capture_dir(sr_id, final_url=m["final_url"],
                                        capture_method="playwright",
                                        case_id=m["case_id"])
            jobs.append({
                "scan_run_id": sr_id,
                "final_url": m["final_url"],
                "screenshot_path": os.path.join(base_dir, 'screenshot.png'),
                "html_path": os.path.join(base_dir, 'page.html'),
            })

        results = _capture_in_subprocess(jobs, timeout=timeout,
                                         env_override=env_override)
        for job, r in zip(jobs, results):
            sr_id = job["scan_run_id"]
            ids_by_sr[sr_id] = _record_capture(conn, sr_id, meta_map[sr_id], r)

    return [ids_by_sr[sr_id] for sr_id in ordered if sr_id in ids_by_sr]


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
