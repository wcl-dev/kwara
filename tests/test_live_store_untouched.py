"""The test suite must not be able to touch the analyst's evidence.

It could, and it did. For months the suite wrote fabricated captures into the
live store: 1,300 directories holding 14-byte files named screenshot.png whose
contents were the string PLAYWRIGHT_PNG, 5 MB of the letter x, and pages
claiming to be target.com. Nobody noticed because nothing looked.

`conftest` redirects the store per test, but a redirect is a convention and
conventions are what this codebase keeps discovering it had quietly broken. So
this module measures instead: it fingerprints the real database and the real
evidence tree at session start and again at session end, and fails if anything
moved.

It is deliberately cheap — row counts and a hash over the identifying columns,
not every byte of a 7 GB store — because a guard that is too slow to leave on
gets turned off.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3

import pytest

TRACKED_TABLES = ("cases", "message_evidence", "url_artifacts", "scan_runs",
                  "redirect_hops", "snapshots", "audit_log")


def _real_paths():
    """The live locations, read from the environment as the tool would see it
    WITHOUT any test redirection applied."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data = os.path.abspath(os.path.expanduser(
        os.environ.get("KWARA_REAL_DATA_DIR", os.path.join(here, "kwara", "data"))))
    return {
        "db": os.environ.get("KWARA_REAL_DB_PATH", os.path.join(data, "kwara.db")),
        "snapshots": os.path.join(data, "snapshots"),
        "acquisitions": os.path.join(data, "acquisitions"),
        "index": os.path.expanduser("~/.kwara/index.db"),
    }


def _db_fingerprint(path: str) -> str:
    if not os.path.isfile(path):
        return "absent"
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return f"unreadable:{exc}"
    d = hashlib.sha256()
    try:
        for table in TRACKED_TABLES:
            try:
                rows = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error:
                rows = "missing"
            d.update(f"{table}={rows};".encode())
        # Identifying columns only. Hashing every column of every row would
        # make this too slow to keep enabled, and the counts above already
        # catch insertion and deletion.
        for table, col in (("snapshots", "screenshot_path"),
                           ("scan_runs", "final_url")):
            try:
                for (v,) in conn.execute(
                        f"SELECT {col} FROM {table} ORDER BY id"):
                    d.update(repr(v).encode())
            except sqlite3.Error:
                pass
    finally:
        conn.close()
    return d.hexdigest()


def _tree_fingerprint(root: str) -> str:
    """Entry count and names, not contents — enough to see a test create,
    delete or rename anything under the evidence store."""
    if not os.path.isdir(root):
        return "absent"
    d = hashlib.sha256()
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames) + sorted(filenames):
            d.update(os.path.join(dirpath, name).encode())
            n += 1
    return f"{n}:{d.hexdigest()}"


def _snapshot_state() -> dict:
    p = _real_paths()
    return {
        "db": _db_fingerprint(p["db"]),
        "index": _db_fingerprint(p["index"]),
        "snapshots": _tree_fingerprint(p["snapshots"]),
        "acquisitions": _tree_fingerprint(p["acquisitions"]),
    }


def test_the_live_store_is_where_we_think_it_is(live_store_baseline):
    """A guard that measures the wrong path passes for the wrong reason.
    If the real store is not here, say so rather than silently vouching."""
    p = _real_paths()
    if not os.path.isfile(p["db"]):
        pytest.skip("no live database on this machine — nothing to protect")
    assert live_store_baseline["db"] not in ("absent", ""), p["db"]


def test_the_guard_would_notice(tmp_path):
    """A guard that cannot fail is not a guard. Prove the fingerprint moves
    when the store does, rather than trusting that it would."""
    import shutil

    src = _real_paths()["db"]
    if not os.path.isfile(src):
        pytest.skip("no live database on this machine")
    copy = str(tmp_path / "kwara.db")
    shutil.copy(src, copy)

    before = _db_fingerprint(copy)
    conn = sqlite3.connect(copy)
    conn.execute("INSERT INTO audit_log (case_id, actor, action, at, meta_json)"
                 " VALUES (1, 'x', 'tamper', '', NULL)")
    conn.commit()
    conn.close()
    assert _db_fingerprint(copy) != before


def test_a_tree_fingerprint_notices_a_new_file(tmp_path):
    root = tmp_path / "store"
    (root / "7").mkdir(parents=True)
    before = _tree_fingerprint(str(root))
    (root / "7" / "planted.png").write_bytes(b"x")
    assert _tree_fingerprint(str(root)) != before
