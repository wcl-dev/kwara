"""Disk → database reconciliation for the capture store.

Every other integrity check in kwara runs database → disk: does the file this
row points at still exist? Nothing ran the other direction, and on 2026-08-11
a sweep of the live store found what that costs — 12,873 capture directories
no database knew about, holding 1.2 GB of real screenshots, page bodies and
HARs from cases still open. Captures from 2026-04-28 whose database was
replaced in May; captures whose row lost its path to a batch timeout; captures
a forced cloaking re-run abandoned by repointing the row at a fresh directory.
Nothing in the tool could have surfaced any of it.

WHAT THIS MODULE DOES NOT DO
    It never deletes, moves, or truncates anything. There is no call to
    os.remove, os.unlink, os.rmdir or shutil.rmtree in this file, and a test
    asserts that by reading the source. Deciding what to remove from an
    evidence store is the analyst's call, and this module exists to give them
    the facts to make it — not to make it for them.

WHY THE DATABASE SET MATTERS MORE THAN THE ALGORITHM
    "Orphan" is a statement about a set of databases, not about a directory.
    The live store holds 34 directories belonging to a second investigation in
    a database kept elsewhere on disk; judged against the primary database
    alone they look like debris, and a sweep driven by that verdict would
    destroy another case's evidence. So the database set is assembled from the
    cross-case index's `source_db` registry — the only record of which
    databases have ever seen this store — plus anything the caller names, and
    a database that is registered but unreadable makes the whole reconciliation
    UNSAFE rather than merely incomplete. `report()["safe"]` says so, and
    `attach()` refuses when it is false.

CLASSIFICATION IS DESCRIPTIVE, NOT A VERDICT
    Directories are described by what is structurally in them — a file whose
    bytes begin with the PNG signature, a HAR that parses with entries, a file
    that is one byte repeated to 5 MB. Deliberately NOT by searching contents
    for marker strings: an adversarial pass over this store showed that
    approach misfiling 27 genuine captures as test fixtures, because a real
    ad-player stylesheet contained `--floating-z-index: 99999999999999999999`
    and a test pixel id is a run of sixteen 9s.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
CAPTURE_MANIFEST = "capture.json"

# How much of a HAR to read when recovering the landing URL. The document
# request is the first entry; reading the whole file would mean reading 1.2 GB
# to caption a directory listing.
_HAR_SNIFF_BYTES = 256 * 1024
_URL_RE = re.compile(rb'"url"\s*:\s*"([^"]{1,2048})"')

# A capture directory is named {YYYYMMDDTHHMMSSffffff}_{rand4} by
# snapshots._per_capture_dir.
_DIR_TS_RE = re.compile(r"^(\d{8}T\d{6}\d{6})_[0-9a-fA-F]{4}$")

# Bucket directories are named for a scan_run id. ASCII only: str.isdigit() is
# true for superscripts (int() rejects '\u00b2' and the walk would crash) and for
# other scripts' decimal digits (int('\u0667') is 7, so a directory named in
# Arabic-Indic numerals would be silently attributed to scan_run 7).
_BUCKET_RE = re.compile(r"^[0-9]+$")

_HTML_SNIFF_CHARS = 64 * 1024
_CANONICAL_RE = re.compile(
    r"""<link[^>]+rel=['"]canonical['"][^>]+href=['"]([^'"]{1,2048})['"]""",
    re.I)
_OG_URL_RE = re.compile(
    r"""<meta[^>]+property=['"]og:url['"][^>]+content=['"]([^'"]{1,2048})['"]""",
    re.I)

# Filename → the capture_method that wrote it (snapshots.py / cloaking.py /
# lightweight_fetch.py all use fixed names inside the per-capture directory).
_METHOD_BY_FILE = {
    "page_http_only.html": "http_only",
    "page_cloaking_alt.html": "cloaking_alt",
}


def _ro_uri(path: str) -> str:
    """Read-only SQLite URI for a filesystem path.

    Percent-encoded, not concatenated. SQLite parses everything after the
    first '?' in a URI as query parameters and lets the FIRST value of a
    duplicated key win, so an f-string here means a database path containing
    '?' opens a different file — truncated at the '?' — in the caller's
    default read-WRITE mode. On an evidence store that is a write where the
    code says read-only.
    """
    return "file:" + quote(path, safe="/") + "?mode=ro"


def _within(root_real: str, candidate: str) -> bool:
    """Is `candidate` genuinely inside `root_real` after resolving links?"""
    real = os.path.realpath(candidate)
    return real == root_real or real.startswith(root_real + os.sep)


def _html_declared_url(path: str | None) -> str | None:
    """The URL a captured page declares for itself (canonical link / og:url).

    A second, independent corroboration source for captures that have no HAR,
    read from a bounded prefix of the file.
    """
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            head = fh.read(_HTML_SNIFF_CHARS)
    except OSError:
        return None
    for pattern in (_CANONICAL_RE, _OG_URL_RE):
        m = pattern.search(head)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Which databases could own a capture in this store
# ---------------------------------------------------------------------------

def known_databases(primary_db: str, *, index_db: str | None = None,
                    extra: tuple = ()) -> list[dict]:
    """Every kwara database that might own a capture in this store.

    The cross-case index records the absolute path of each database it has
    indexed, which is the only registry of its kind — it is how the second
    investigation's database was found at all. A registered database that has
    moved or been deleted is reported with exists=False, and that is what makes
    the reconciliation unsafe rather than silently narrower.
    """
    out: list[dict] = []
    seen: set[str] = set()

    def _add(path: str, source: str) -> None:
        if not path:
            return
        real = os.path.realpath(os.path.expanduser(path))
        if real in seen:
            return
        seen.add(real)
        out.append({"path": real, "source": source,
                    "exists": os.path.isfile(real)})

    _add(primary_db, "primary")
    if index_db and os.path.isfile(index_db):
        try:
            conn = sqlite3.connect(_ro_uri(index_db), uri=True)
            try:
                for (p,) in conn.execute("SELECT DISTINCT source_db FROM signals"):
                    _add(p, "cross-case index")
            finally:
                conn.close()
        except sqlite3.Error:
            pass
    for p in extra:
        _add(p, "named on the command line")
    return out


def referenced_directories(db_paths) -> dict[str, set]:
    """Capture directory → the databases whose rows point into it.

    Read-only on every database, including the primary: reconciliation must
    never be able to modify what it is measuring.
    """
    out: dict[str, set] = {}
    for path in db_paths:
        if not os.path.isfile(path):
            continue
        try:
            conn = sqlite3.connect(_ro_uri(path), uri=True)
        except sqlite3.Error:
            continue
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(snapshots)")}
            wanted = [c for c in ("screenshot_path", "html_path", "har_path")
                      if c in cols]
            if not wanted:
                continue
            sql = f"SELECT {', '.join(wanted)} FROM snapshots"
            for row in conn.execute(sql):
                for value in row:
                    if not value:
                        continue
                    d = os.path.realpath(os.path.dirname(str(value)))
                    out.setdefault(d, set()).add(path)
        except sqlite3.Error:
            continue
        finally:
            conn.close()
    return out


# ---------------------------------------------------------------------------
# What is actually on disk
# ---------------------------------------------------------------------------

def _is_single_byte_fill(path: str, size: int) -> bool:
    """One byte repeated for the whole file — the HTML-truncation fixture is
    5,242,880 bytes of the letter 'x'. Structural, so it cannot misfire on a
    real page the way a content search can."""
    if size < 4096:
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(65536)
            if not head or len(set(head)) != 1:
                return False
            fh.seek(max(0, size - 65536))
            tail = fh.read(65536)
        return len(set(tail)) == 1 and tail[:1] == head[:1]
    except OSError:
        return False


def _har_entry_count(path: str) -> int | None:
    """Entries in a HAR, or None if it does not parse as one."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        entries = data.get("log", {}).get("entries")
        return len(entries) if isinstance(entries, list) else None
    except (OSError, ValueError, AttributeError):
        return None


def _first_har_url(path: str) -> str | None:
    """The document request URL, from a bounded read of the head of the HAR."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(_HAR_SNIFF_BYTES)
    except OSError:
        return None
    m = _URL_RE.search(head)
    return m.group(1).decode("utf-8", "replace") if m else None


def describe_directory(path: str) -> dict:
    """Structural facts about one capture directory. No verdicts."""
    try:
        names = sorted(os.listdir(path))
    except OSError as exc:
        return {"path": path, "kind": "unreadable", "error": str(exc),
                "files": [], "bytes": 0}

    files, total = [], 0
    png_ok = har_entries = None
    filler = []
    for name in names:
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        total += size
        files.append({"name": name, "bytes": size})
        if name.endswith(".png"):
            try:
                with open(full, "rb") as fh:
                    png_ok = fh.read(8) == PNG_MAGIC
            except OSError:
                png_ok = False
        elif name.endswith(".har"):
            har_entries = _har_entry_count(full)
        elif name.endswith(".html") and _is_single_byte_fill(full, size):
            filler.append(name)

    artifacts = [f for f in files if f["name"] != CAPTURE_MANIFEST]
    if not files:
        kind = "empty"
    elif not artifacts:
        kind = "manifest_only"
    elif png_ok or (har_entries or 0) > 0:
        kind = "capture"
    else:
        kind = "partial"

    return {
        "path": path,
        "kind": kind,
        "files": files,
        "artifacts": len(artifacts),
        "bytes": total,
        "screenshot_is_png": png_ok,
        "har_entries": har_entries,
        "single_byte_fill": filler,
    }


def scan_store(root: str) -> dict:
    """Walk the capture store as it really is, not as the layout assumes.

    Two generations coexist: per-capture subdirectories at depth 2, and — in
    the oldest scan_run buckets — artifacts written directly into the bucket
    before per-capture directories existed. Those loose files are invisible to
    any depth-2 sweep, which means a cleanup written against the current layout
    would either miss them or, if it worked by path prefix, take them silently.
    """
    buckets, capture_dirs, loose, unexpected = [], [], [], []
    try:
        entries = sorted(os.listdir(root))
    except OSError as exc:
        return {"root": root, "error": str(exc), "buckets": [],
                "capture_dirs": [], "loose_files": [], "unexpected": []}

    # Resolved once: every path the walk keeps must still be inside this after
    # its own links are resolved. Without it a symlinked bucket makes the walk
    # describe — and attach — files anywhere on the machine, while reporting
    # them under a path that looks like it is in the store.
    root_real = os.path.realpath(root)

    for name in entries:
        bucket = os.path.join(root, name)
        if not os.path.isdir(bucket):
            unexpected.append(bucket)
            continue
        if not _BUCKET_RE.match(name) or not _within(root_real, bucket):
            unexpected.append(bucket)
            continue
        scan_run_id = int(name)
        buckets.append(scan_run_id)
        try:
            inner = sorted(os.listdir(bucket))
        except OSError:
            continue
        for child in inner:
            full = os.path.join(bucket, child)
            if not _within(root_real, full):
                unexpected.append(full)
                continue
            if os.path.isdir(full):
                capture_dirs.append({"path": os.path.realpath(full),
                                     "scan_run_id": scan_run_id,
                                     "captured_at": _dir_timestamp(child)})
            elif os.path.isfile(full):
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                loose.append({"path": os.path.realpath(full),
                              "scan_run_id": scan_run_id, "bytes": size})
    return {"root": root, "buckets": buckets, "capture_dirs": capture_dirs,
            "loose_files": loose, "unexpected": unexpected}


def _dir_timestamp(name: str) -> str | None:
    m = _DIR_TS_RE.match(name)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S%f")
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

def _empty_kind() -> dict:
    return {"directories": 0, "bytes": 0, "single_byte_fill": 0,
            "single_byte_fill_bytes": 0,
            "size_bands": {"zero": 0, "under_1kb": 0, "under_1mb": 0,
                           "over_1mb": 0}}


def report(root: str, primary_db: str, *, index_db: str | None = None,
           extra_dbs: tuple = (), describe: bool = True) -> dict:
    """Reconcile the capture store against every database that could own it."""
    dbs = known_databases(primary_db, index_db=index_db, extra=extra_dbs)
    missing = [d for d in dbs if not d["exists"]]
    referenced = referenced_directories([d["path"] for d in dbs if d["exists"]])
    store = scan_store(root)

    owned, orphans = [], []
    for entry in store["capture_dirs"]:
        owners = referenced.get(entry["path"])
        if owners:
            owned.append({**entry, "databases": sorted(owners)})
        else:
            orphans.append(dict(entry))

    by_kind: dict[str, dict] = {}
    if describe:
        for o in orphans:
            o.update(describe_directory(o["path"]))
            k = by_kind.setdefault(o["kind"], _empty_kind())
            k["directories"] += 1
            k["bytes"] += o.get("bytes", 0)
            # Size and fill are the facts that separate a real page body from a
            # test fixture without reading either for marker strings. `partial`
            # in particular mixes 5 MB of repeated 'x' from an HTML-truncation
            # fixture with genuine http_only captures of real pages, and the
            # analyst needs to see that split before deciding anything.
            if o.get("single_byte_fill"):
                k["single_byte_fill"] += 1
                k["single_byte_fill_bytes"] += o.get("bytes", 0)
            b = o.get("bytes", 0)
            band = ("zero" if b == 0 else "under_1kb" if b < 1024
                    else "under_1mb" if b < 1024 ** 2 else "over_1mb")
            k["size_bands"][band] += 1

    loose_orphans = [f for f in store["loose_files"]
                     if os.path.realpath(os.path.dirname(f["path"]))
                     not in referenced and f["path"] not in referenced]

    return {
        "root": root,
        "databases": dbs,
        # A registered database we cannot read makes every "orphan" verdict
        # provisional: its rows might be exactly what claims these directories.
        "safe": not missing,
        "unreadable_databases": [d["path"] for d in missing],
        "on_disk": len(store["capture_dirs"]),
        "referenced": len(owned),
        "orphans": len(orphans),
        "orphan_bytes": sum(o.get("bytes", 0) for o in orphans),
        "by_kind": by_kind,
        "loose_legacy_files": loose_orphans,
        "unexpected_paths": store["unexpected"],
        "orphan_details": orphans,
    }


# ---------------------------------------------------------------------------
# Putting recovered captures back
# ---------------------------------------------------------------------------

def _method_for(files: list) -> str:
    names = {f["name"] for f in files}
    for filename, method in _METHOD_BY_FILE.items():
        if filename in names:
            return method
    return "playwright"


def _manifest(path: str) -> dict:
    try:
        with open(os.path.join(path, CAPTURE_MANIFEST), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def attach(conn: sqlite3.Connection, rep: dict, *, dry_run: bool = True,
           force: bool = False, include_partial: bool = False) -> dict:
    """Write a snapshots row for each recovered capture, with its signals.

    A row that merely points at the files would leave the evidence still
    uncounted: clustering reads tracking_ids_json and request_domains_json, so
    recovery means re-deriving those from the recovered artifacts exactly as
    the capture path does — otherwise 1.2 GB stays invisible to every analysis
    while looking like it has been restored.

    Refuses when a registered database could not be read, because a directory
    that database owns would then be attached to the wrong case. `force`
    overrides, and the audit record says it was forced.
    """
    from .fingerprints import extract_tracking_ids_from_file

    if not rep.get("safe") and not force:
        return {"attached": 0, "refused": True,
                "reason": "a registered database could not be read; "
                          "orphan status is provisional",
                "unreadable_databases": rep.get("unreadable_databases", [])}

    from .utils.domain import extract_domain_from_url

    # Every domain the database has ALREADY observed for each scan_run. Not
    # just its final_url: a cloaked URL legitimately lands somewhere different
    # under a different persona — on this store, 252 scan_runs send a browser
    # to one domain and a crawler to another — and redirect hops are equally
    # real. Corroboration must accept anything the scan already saw, and only
    # that.
    expected: dict[int, set] = {}

    def _note(scan_run_id, value):
        d = extract_domain_from_url(value or "")
        if d:
            expected.setdefault(scan_run_id, set()).add(d)

    for row in conn.execute(
            """SELECT sr.id, sr.final_url, ua.original_url
                 FROM scan_runs sr
                 JOIN url_artifacts ua ON ua.id = sr.url_artifact_id"""):
        expected.setdefault(row[0], set())
        _note(row[0], row[1])
        _note(row[0], row[2])
    for row in conn.execute(
            "SELECT scan_run_id, final_domain, final_url FROM snapshots"):
        _note(row[0], row[1])
        _note(row[0], row[2])
    for row in conn.execute(
            "SELECT scan_run_id, url, resolved_url, location FROM redirect_hops"):
        for v in row[1:]:
            _note(row[0], v)

    ran_at = {r[0]: (r[1] or "") for r in
              conn.execute("SELECT id, run_at FROM scan_runs")}
    attached, skipped = [], []

    for o in rep.get("orphan_details", []):
        sr = o.get("scan_run_id")
        kinds = ("capture", "partial") if include_partial else ("capture",)
        if o.get("kind") not in kinds:
            skipped.append({"path": o["path"], "why": f"nothing to attach "
                                                      f"({o.get('kind')})"})
            continue
        if o.get("single_byte_fill"):
            skipped.append({"path": o["path"],
                            "why": "one byte repeated for the whole file"})
            continue
        if sr not in expected:
            # Almost certainly another database's capture: the bucket names a
            # scan_run this database has never had.
            skipped.append({"path": o["path"],
                            "why": f"scan_run {sr} is not in this database"})
            continue

        files = {f["name"]: f for f in o.get("files", [])}
        png = next((n for n in files if n.endswith(".png")), None)
        html = next((n for n in files if n.endswith(".html")), None)
        har = next((n for n in files if n.endswith(".har")), None)
        man = _manifest(o["path"])

        html_path = os.path.join(o["path"], html) if html else None
        har_path = os.path.join(o["path"], har) if har else None

        # CORROBORATION. A directory sitting in scan_run 7's bucket is a claim
        # that it captured scan_run 7, and a claim is not evidence. Check it
        # against what the database already says that scan_run reached.
        #
        # This is the only thing standing between the live database and the
        # test suite's leavings: runs against the real store deposited
        # fabricated captures of target.com, a.com and b.com into real
        # scan_run buckets, and an early dry run would have attached 1,702 rows
        # with those among them.
        #
        # EVERY BRANCH HERE FAILS CLOSED. An adversarial pass found the first
        # version skipping itself whenever either side was missing — an
        # unreadable domain, a scan_run with no resolved URL, a directory name
        # that missed the timestamp pattern — which is precisely the shape a
        # stray directory has. A check that abstains when it cannot see is not
        # a check.
        want = expected.get(sr) or set()
        # Derived from the ARTIFACTS. capture.json is written at directory
        # ALLOCATION time, before the capture runs, so it records what kwara
        # meant to fetch, not what it got; it cannot corroborate itself.
        from_artifacts = extract_domain_from_url(
            (_first_har_url(har_path) if har_path else None)
            or (_html_declared_url(html_path) if html_path else None) or "")
        from_manifest = extract_domain_from_url(
            man.get("final_domain") or man.get("final_url") or "")

        if from_artifacts and from_manifest and from_artifacts != from_manifest:
            skipped.append({"path": o["path"],
                            "why": f"capture.json says {from_manifest} but the "
                                   f"artifacts are {from_artifacts}"})
            continue
        got = from_artifacts or from_manifest
        if not want:
            skipped.append({"path": o["path"],
                            "why": f"scan_run {sr} has no resolved URL to "
                                   f"corroborate against"})
            continue
        if not got:
            skipped.append({"path": o["path"],
                            "why": "no landing domain recoverable from the "
                                   "artifacts or the manifest"})
            continue
        if got not in want:
            skipped.append({"path": o["path"],
                            "why": f"captured {got}, which scan_run {sr} has "
                                   f"never been observed reaching — does not "
                                   f"corroborate"})
            continue
        domain = got
        url = (_first_har_url(har_path) if har_path else None) or man.get("final_url")

        # A capture cannot predate the scan it belongs to. This is the check
        # that matters most here, because scan_run ids on disk are not stable
        # across databases: the database holding April's rows was replaced in
        # May, so bucket `1` on disk was written by a scan_run 1 that no longer
        # exists, and today's scan_run 1 is a different URL that merely
        # inherited the number. Domain agreement alone would happily attach
        # April's evidence to a May scan — on the live store this refused 43 of
        # the 44 candidates that had already passed the domain test.
        when, ran = o.get("captured_at"), ran_at.get(sr)
        if not when:
            skipped.append({"path": o["path"],
                            "why": "directory name carries no capture time, so "
                                   "it cannot be shown to postdate the scan"})
            continue
        if not ran:
            skipped.append({"path": o["path"],
                            "why": f"scan_run {sr} has no run_at to compare "
                                   f"the capture time against"})
            continue
        if when < ran:
            skipped.append({"path": o["path"],
                            "why": f"captured {when}, before scan_run {sr} ran "
                                   f"at {ran} — the id predates this database"})
            continue

        # TOCTOU: everything above was authorised from the report-time
        # description, and the row below is built by re-reading the files. Make
        # the two agree or refuse — an evidence row must describe bytes that
        # passed the checks.
        again = describe_directory(o["path"])
        if (again.get("kind") != o.get("kind")
                or again.get("single_byte_fill")
                or {f["name"]: f["bytes"] for f in again.get("files", [])}
                != {f["name"]: f["bytes"] for f in o.get("files", [])}):
            skipped.append({"path": o["path"],
                            "why": "directory changed between inspection and "
                                   "write"})
            continue

        tracking = extract_tracking_ids_from_file(html_path) if html_path else {}
        domains: list = []
        if har_path:
            try:
                with open(har_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                from urllib.parse import urlparse
                seen = set()
                for e in data.get("log", {}).get("entries", []):
                    h = urlparse(e.get("request", {}).get("url", "")).hostname
                    if h and h not in seen:
                        seen.add(h)
                        domains.append(h)
            except (OSError, ValueError, AttributeError):
                domains = []

        row = {
            "scan_run_id": sr,
            "final_url": url,
            "final_domain": domain,
            "screenshot_path": os.path.join(o["path"], png) if png else None,
            "html_path": html_path,
            "har_path": har_path,
            "request_domains_json": json.dumps(domains) if domains else None,
            "tracking_ids_json": json.dumps(tracking) if tracking else None,
            "captured_at": o.get("captured_at"),
            "capture_status": "ok",
            "capture_method": _method_for(o.get("files", [])),
            "capture_detail": "recovered from disk by evidence reconcile",
        }
        attached.append({"path": o["path"], "scan_run_id": sr,
                         "final_domain": domain,
                         "corroborated": bool(got),
                         "tracking_ids": sum(len(v) for v in tracking.values()),
                         "request_domains": len(domains),
                         "capture_method": row["capture_method"]})
        if not dry_run:
            cols = ", ".join(row)
            marks = ", ".join("?" for _ in row)
            conn.execute(f"INSERT INTO snapshots ({cols}) VALUES ({marks})",
                         tuple(row.values()))

    if not dry_run and attached:
        from .audit import write_audit
        conn.commit()
        write_audit(conn, "evidence.reconcile.attach", meta={
            "attached": len(attached), "forced": bool(force),
            "include_partial": bool(include_partial),
            "root": rep.get("root"),
            "databases_consulted": [d["path"] for d in rep.get("databases", [])],
        })

    reasons: dict[str, int] = {}
    for s_ in skipped:
        key = ("does not corroborate" if "corroborate" in s_["why"]
               else "not this database's scan_run"
               if "not in this database" in s_["why"]
               else "one byte repeated" if "one byte" in s_["why"]
               else "capture predates the scan_run" if "predates" in s_["why"]
               else s_["why"].split("(")[0].strip())
        reasons[key] = reasons.get(key, 0) + 1
    return {"attached": len(attached), "dry_run": bool(dry_run),
            "refused": False, "details": attached,
            "skipped": len(skipped), "skipped_reasons": reasons,
            "skipped_details": skipped[:50]}
