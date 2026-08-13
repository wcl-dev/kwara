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
                  "redirect_hops", "snapshots", "audit_log", "acquisitions",
                  # The cross-case index has none of the above — it holds
                  # `signals`. Fingerprinting only case tables left every
                  # index write invisible, which is the store a discovery run
                  # touches.
                  "signals")


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
    """Names, sizes and mtimes — not contents.

    Names alone missed a file REWRITTEN IN PLACE, which is exactly how the
    suite's fabricated captures would land: same path, different bytes. Size
    and mtime catch that at a fraction of the cost of hashing a 7 GB store,
    and a guard too slow to leave on gets turned off.
    """
    if not os.path.isdir(root):
        return "absent"
    d = hashlib.sha256()
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames):
            d.update(os.path.join(dirpath, name).encode())
            n += 1
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
                d.update(f"{full}|{st.st_size}|{st.st_mtime_ns}".encode())
            except OSError:
                d.update(f"{full}|gone".encode())
            n += 1
    return f"{n}:{d.hexdigest()}"


def _snapshot_state() -> dict:
    p = _real_paths()
    return {
        "db": _db_fingerprint(p["db"]),
        "index": _db_fingerprint(p["index"]),
        "snapshots": _tree_fingerprint(p["snapshots"]),
        "acquisitions": _tree_fingerprint(p["acquisitions"]),
        # "absent" is a state to protect too: a test CREATING a live store
        # where there was none is the same class of escape as one modifying it,
        # and skipping the guard when the DB is missing let that through.
        "db_exists": str(os.path.isfile(p["db"])),
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


def test_a_tree_fingerprint_notices_a_file_rewritten_in_place(tmp_path):
    """Names alone would not: same path, different bytes is exactly how a
    fabricated capture overwrites a real one."""
    root = tmp_path / "store"
    (root / "7").mkdir(parents=True)
    f = root / "7" / "screenshot.png"
    f.write_bytes(b"\x89PNG" + b"real" * 100)
    before = _tree_fingerprint(str(root))

    os.utime(f, (0, 0))                       # force a distinct mtime
    f.write_bytes(b"PLAYWRIGHT_PNG")
    assert _tree_fingerprint(str(root)) != before


def test_the_index_database_is_watched_too(tmp_path):
    """~/.kwara/index.db holds `signals` and none of the case tables. Watching
    only case tables left every discovery-index write invisible."""
    import sqlite3 as s3

    idx = str(tmp_path / "index.db")
    conn = s3.connect(idx)
    conn.execute("CREATE TABLE signals (id INTEGER PRIMARY KEY, "
                 "signal_type TEXT, signal_value TEXT)")
    conn.commit()
    before = _db_fingerprint(idx)
    conn.execute("INSERT INTO signals (signal_type, signal_value) "
                 "VALUES ('ads_txt_template', 'deadbeef')")
    conn.commit()
    conn.close()
    assert _db_fingerprint(idx) != before


def test_an_acquisition_row_write_is_noticed(tmp_path):
    """acquisitions holds the response bytes a finding rests on. It was not in
    TRACKED_TABLES, so a test inserting one was invisible."""
    import sqlite3 as s3

    from kwara.db import get_conn, init_db, migrate_db

    p = str(tmp_path / "k.db")
    conn = get_conn(p)
    init_db(conn)
    migrate_db(conn)
    conn.commit()
    before = _db_fingerprint(p)

    conn.execute("INSERT INTO acquisitions (kind, requested_url, status, "
                 "fetched_at) VALUES ('ads_txt', 'https://a/x', 'ok', '')")
    conn.commit()
    assert _db_fingerprint(p) != before


def test_creating_a_live_store_where_there_was_none_is_noticed(tmp_path,
                                                               monkeypatch):
    """A test that CREATES a store escapes as badly as one that modifies it.
    The guard used to skip entirely when the database was absent."""
    monkeypatch.setenv("KWARA_REAL_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KWARA_REAL_DB_PATH", str(tmp_path / "kwara.db"))

    before = _snapshot_state()
    assert before["db_exists"] == "False"

    from kwara.db import get_conn, init_db
    conn = get_conn(str(tmp_path / "kwara.db"))
    init_db(conn)
    conn.commit()

    after = _snapshot_state()
    assert after != before
    assert after["db_exists"] == "True"
