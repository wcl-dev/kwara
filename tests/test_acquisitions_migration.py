"""Rebuilding `acquisitions` on someone's only copy of an investigation.

The table shipped on 2026-08-12 with ON DELETE CASCADE, so `delete_case` —
which deletes scan_runs — silently deleted acquisition rows with them. An
append-only table that quietly loses rows is not append-only.

SQLite cannot alter a foreign key in place, so the table has to be rebuilt,
and a rebuild is the most dangerous thing this codebase does to a live
database. Every property that makes it safe is asserted here, including the
two defects the first version shipped with: it silently dropped both indexes,
and a process killed halfway left the database with no `acquisitions` table.
"""
import os
import sqlite3

import pytest

from kwara.db import _ACQ_TEMP, get_conn, init_db, migrate_db

# The table exactly as 4b076cd created it.
_OLD_DDL = """
CREATE TABLE acquisitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
    scan_run_id INTEGER, requested_url TEXT NOT NULL, final_url TEXT,
    redirect_chain_json TEXT, status TEXT NOT NULL, status_code INTEGER,
    fetched_at TEXT NOT NULL, response_headers_json TEXT, user_agent TEXT,
    tool_version TEXT, truncated INTEGER NOT NULL DEFAULT 0,
    captured_bytes INTEGER NOT NULL DEFAULT 0, body_path TEXT,
    captured_sha256 TEXT, complete_sha256 TEXT, error TEXT,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);
CREATE INDEX idx_acq_scan_run ON acquisitions(scan_run_id);
CREATE INDEX idx_acq_complete ON acquisitions(complete_sha256);
"""


def _clause(conn) -> str:
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' "
                       "AND name='acquisitions'").fetchone()[0].upper()
    return "CASCADE" if "ON DELETE CASCADE" in sql else "SET NULL"


def _indexes(conn, table="acquisitions") -> set:
    """Indexes attached to a TABLE, not merely names that exist.

    A rename carries indexes to the renamed table while their names stay
    taken, so matching on the name alone reports an index the live table does
    not have.
    """
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name = ? "
        "AND name NOT LIKE 'sqlite_%'", (table,))}


@pytest.fixture
def old_db(tmp_path):
    """A database as 4b076cd left it: cascading FK, rows, both indexes."""
    conn = get_conn(str(tmp_path / "old.db"))
    init_db(conn)
    migrate_db(conn)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DROP TABLE acquisitions")
    conn.executescript(_OLD_DDL)
    for q in (
        "INSERT INTO cases (title,description,created_at,updated_at)"
        " VALUES ('t','','','')",
        "INSERT INTO message_evidence (case_id,platform,permalink,actor_label,"
        "posted_at,message_text,screenshot_path,ingested_at)"
        " VALUES (1,'','','','','','','')",
        "INSERT INTO url_artifacts (message_id,case_id,original_url,domain,"
        "url_order,created_at) VALUES (1,1,'https://a.test/','',0,'')",
        "INSERT INTO scan_runs (url_artifact_id,run_at,final_url,hop_count,"
        "status) VALUES (1,'','https://a.test/',0,'done')",
    ):
        conn.execute(q)
    for i in range(3):
        conn.execute(
            "INSERT INTO acquisitions (kind,scan_run_id,requested_url,status,"
            "fetched_at,captured_sha256) VALUES ('ads_txt',1,?,'ok','',?)",
            (f"https://a.test/ads.txt?{i}", f"{i}" * 64))
    conn.commit()
    conn.execute("PRAGMA foreign_keys = ON")
    assert _clause(conn) == "CASCADE"
    return conn


def test_the_cascade_becomes_set_null(old_db):
    migrate_db(old_db)
    assert _clause(old_db) == "SET NULL"


def test_every_row_survives(old_db):
    before = old_db.execute(
        "SELECT id, requested_url, captured_sha256 FROM acquisitions "
        "ORDER BY id").fetchall()
    migrate_db(old_db)
    after = old_db.execute(
        "SELECT id, requested_url, captured_sha256 FROM acquisitions "
        "ORDER BY id").fetchall()
    assert [tuple(r) for r in after] == [tuple(r) for r in before]
    assert len(after) == 3


def test_both_indexes_survive(old_db):
    """The first version of this migration completed "successfully" and left
    the table with none. The rename carried them to the temp table, the
    IF NOT EXISTS create skipped the taken names, and the drop took them."""
    migrate_db(old_db)
    assert _indexes(old_db) == {"idx_acq_scan_run", "idx_acq_complete"}


def test_deleting_a_scan_run_nulls_the_reference_instead_of_the_row(old_db):
    """The whole point. Before: delete_case took the acquisitions with it."""
    migrate_db(old_db)
    old_db.execute("DELETE FROM scan_runs WHERE id = 1")
    old_db.commit()
    rows = old_db.execute("SELECT scan_run_id FROM acquisitions").fetchall()
    assert len(rows) == 3
    assert all(r[0] is None for r in rows)


def test_the_cascade_really_would_have_deleted_them(old_db):
    """A regression test for a data-loss bug is worth nothing unless the loss
    is demonstrated. Delete WITHOUT migrating first."""
    old_db.execute("DELETE FROM scan_runs WHERE id = 1")
    old_db.commit()
    assert old_db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0] == 0


def test_migrating_twice_changes_nothing(old_db):
    migrate_db(old_db)
    first = old_db.execute(
        "SELECT name, sql FROM sqlite_master WHERE name LIKE '%acq%' "
        "OR name='acquisitions' ORDER BY name").fetchall()
    migrate_db(old_db)
    second = old_db.execute(
        "SELECT name, sql FROM sqlite_master WHERE name LIKE '%acq%' "
        "OR name='acquisitions' ORDER BY name").fetchall()
    assert [tuple(r) for r in second] == [tuple(r) for r in first]
    assert _ACQ_TEMP not in {r[0] for r in second}


def test_an_already_correct_database_is_left_alone(tmp_path):
    conn = get_conn(str(tmp_path / "new.db"))
    init_db(conn)
    migrate_db(conn)
    before = conn.execute("SELECT sql FROM sqlite_master WHERE "
                          "name='acquisitions'").fetchone()[0]
    migrate_db(conn)
    assert conn.execute("SELECT sql FROM sqlite_master WHERE "
                        "name='acquisitions'").fetchone()[0] == before
    assert _indexes(conn) == {"idx_acq_scan_run", "idx_acq_complete"}


def test_an_interrupted_rebuild_rolls_back(old_db, monkeypatch):
    """A process killed mid-rebuild must leave the ORIGINAL table usable, not
    a database with a renamed table and no `acquisitions`."""
    import kwara.db as dbmod

    # Fail AFTER the rename and the table create, while copying rows — the
    # worst moment, where the original table no longer has its name and the
    # new one is not populated.
    broken = dbmod._ACQUISITIONS_DDL + ("SELECT raise_after_create();",)
    monkeypatch.setattr(dbmod, "_ACQUISITIONS_DDL", broken)

    with pytest.raises(sqlite3.OperationalError):
        dbmod._migrate_acquisitions_fk(old_db)

    tables = {r[0] for r in old_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "acquisitions" in tables, "the rebuild left no acquisitions table"
    assert _ACQ_TEMP not in tables, "a temp table was stranded"
    assert old_db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0] == 3


def test_a_stranded_temp_table_from_an_older_build_is_adopted(old_db):
    """The first version was not transactional, so an interruption could leave
    the rows reachable only under the temp name. Finish the job rather than
    leaving them unreachable."""
    old_db.execute("PRAGMA foreign_keys = OFF")
    old_db.execute(f"ALTER TABLE acquisitions RENAME TO {_ACQ_TEMP}")
    old_db.commit()
    old_db.execute("PRAGMA foreign_keys = ON")

    migrate_db(old_db)

    tables = {r[0] for r in old_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "acquisitions" in tables and _ACQ_TEMP not in tables
    assert old_db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0] == 3
    assert _clause(old_db) == "SET NULL"
    assert _indexes(old_db) == {"idx_acq_scan_run", "idx_acq_complete"}


# ── the two states the earlier non-transactional build could strand ───────

def test_a_stranded_temp_beside_an_empty_new_table_is_recovered(old_db):
    """The dangerous one. The earlier build could die between creating the new
    table and copying the rows, leaving BOTH tables — and because the new one
    passes the foreign-key check, a migration that only looked at the FK
    returned happily and left the rows behind forever."""
    old_db.execute("PRAGMA foreign_keys = OFF")
    old_db.execute(f"ALTER TABLE acquisitions RENAME TO {_ACQ_TEMP}")
    old_db.executescript(_OLD_DDL.replace("ON DELETE CASCADE",
                                          "ON DELETE SET NULL")
                         .replace("CREATE INDEX idx_acq_scan_run",
                                  "CREATE INDEX IF NOT EXISTS idx_x1")
                         .replace("CREATE INDEX idx_acq_complete",
                                  "CREATE INDEX IF NOT EXISTS idx_x2"))
    old_db.commit()
    old_db.execute("PRAGMA foreign_keys = ON")
    assert old_db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0] == 0
    assert old_db.execute(
        f"SELECT COUNT(*) FROM {_ACQ_TEMP}").fetchone()[0] == 3

    migrate_db(old_db)

    tables = {r[0] for r in old_db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert _ACQ_TEMP not in tables, "the temp table outlived its rows"
    assert old_db.execute(
        "SELECT COUNT(*) FROM acquisitions").fetchone()[0] == 3, \
        "the stranded rows were not recovered"


def test_recovery_merges_a_half_copied_state_without_conflict(old_db):
    """A copy that got partway through leaves overlapping ids. Recovery must
    converge rather than raise on the duplicates."""
    old_db.execute("PRAGMA foreign_keys = OFF")
    old_db.execute(f"ALTER TABLE acquisitions RENAME TO {_ACQ_TEMP}")
    old_db.executescript(_OLD_DDL.replace("ON DELETE CASCADE",
                                          "ON DELETE SET NULL")
                         .replace("CREATE INDEX idx_acq_scan_run",
                                  "CREATE INDEX IF NOT EXISTS idx_y1")
                         .replace("CREATE INDEX idx_acq_complete",
                                  "CREATE INDEX IF NOT EXISTS idx_y2"))
    cols = ", ".join(r[1] for r in old_db.execute(
        "PRAGMA table_info(acquisitions)"))
    old_db.execute(f"INSERT INTO acquisitions ({cols}) "
                   f"SELECT {cols} FROM {_ACQ_TEMP} WHERE id = 1")
    old_db.commit()
    old_db.execute("PRAGMA foreign_keys = ON")

    migrate_db(old_db)

    rows = old_db.execute("SELECT id FROM acquisitions ORDER BY id").fetchall()
    assert [r[0] for r in rows] == [1, 2, 3]


def test_a_custom_index_survives_the_rebuild(old_db):
    """The rebuild recreates kwara's two indexes. Anything the analyst added
    must be replayed rather than quietly dropped."""
    old_db.execute("CREATE INDEX idx_custom_url ON acquisitions(requested_url)")
    old_db.commit()

    migrate_db(old_db)

    assert "idx_custom_url" in {r[0] for r in old_db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND tbl_name='acquisitions'")}


def test_a_failed_begin_reports_its_own_error(old_db, monkeypatch):
    """An unconditional ROLLBACK replaced the real failure with "cannot
    rollback - no transaction is active", hiding what actually went wrong."""
    import kwara.db as dbmod

    other = sqlite3.connect(old_db.execute(
        "PRAGMA database_list").fetchone()[2], timeout=0)
    other.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(sqlite3.OperationalError) as exc:
            dbmod._migrate_acquisitions_fk(old_db)
        assert "cannot rollback" not in str(exc.value).lower(), \
            f"the real error was masked: {exc.value}"
    finally:
        other.execute("ROLLBACK")
        other.close()


def test_the_callers_foreign_key_setting_is_restored(old_db):
    """The migration turns foreign_keys off to rebuild. It must put back what
    the caller had, not switch it on unconditionally."""
    import kwara.db as dbmod

    old_db.execute("PRAGMA foreign_keys = OFF")
    dbmod._migrate_acquisitions_fk(old_db)
    assert old_db.execute("PRAGMA foreign_keys").fetchone()[0] == 0


# ── the recovery path repeats nothing the rebuild path fixed ──────────────
#
# It did: a failed BEGIN masked by an unconditional ROLLBACK, foreign_keys
# forced ON instead of restored, and indexes dropped with the temp table and
# never recreated. Writing the transaction twice is what allowed that, so both
# paths now share one helper — and both are tested for the same properties.

def _strand_temp_and_new(conn, *, copy_ids=()):
    """The dangerous durable state: temp holds the rows, the new table exists
    with the corrected FK and — as the interrupted run left it — no indexes,
    because their names were still held by the temp table."""
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute(f"ALTER TABLE acquisitions RENAME TO {_ACQ_TEMP}")
    conn.execute(_OLD_DDL.split(";")[0].replace("ON DELETE CASCADE",
                                                "ON DELETE SET NULL"))
    if copy_ids:
        cols = ", ".join(r[1] for r in conn.execute(
            "PRAGMA table_info(acquisitions)"))
        conn.execute(
            f"INSERT INTO acquisitions ({cols}) SELECT {cols} "
            f"FROM {_ACQ_TEMP} WHERE id IN ({','.join('?' * len(copy_ids))})",
            copy_ids)
    conn.commit()
    conn.execute("PRAGMA foreign_keys = ON")


def test_recovery_restores_the_canonical_indexes(old_db):
    """The interrupted run could not create them — the names were taken. If
    recovery does not, the table is left permanently unindexed."""
    _strand_temp_and_new(old_db)
    assert not _indexes(old_db), \
        "fixture is wrong: the interrupted run leaves the NEW table unindexed"
    assert _indexes(old_db, _ACQ_TEMP), "the temp table should still hold them"

    migrate_db(old_db)
    assert _indexes(old_db) == {"idx_acq_scan_run", "idx_acq_complete"}


def test_recovery_replays_an_analyst_added_index(old_db):
    old_db.execute("CREATE INDEX idx_custom_url ON acquisitions(requested_url)")
    old_db.commit()
    _strand_temp_and_new(old_db)

    migrate_db(old_db)
    names = {r[0] for r in old_db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' "
        "AND tbl_name='acquisitions'")}
    assert "idx_custom_url" in names
    assert {"idx_acq_scan_run", "idx_acq_complete"} <= names


def test_recovery_of_a_half_copied_state_keeps_its_indexes(old_db):
    _strand_temp_and_new(old_db, copy_ids=(1,))
    migrate_db(old_db)
    assert [r[0] for r in old_db.execute(
        "SELECT id FROM acquisitions ORDER BY id")] == [1, 2, 3]
    assert _indexes(old_db) == {"idx_acq_scan_run", "idx_acq_complete"}


def test_recovery_reports_a_failed_begin_rather_than_masking_it(old_db):
    import kwara.db as dbmod

    _strand_temp_and_new(old_db)
    other = sqlite3.connect(old_db.execute(
        "PRAGMA database_list").fetchone()[2], timeout=0)
    other.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(sqlite3.OperationalError) as exc:
            dbmod._migrate_acquisitions_fk(old_db)
        assert "cannot rollback" not in str(exc.value).lower(), \
            f"the real error was masked: {exc.value}"
    finally:
        other.execute("ROLLBACK")
        other.close()


def test_recovery_restores_the_callers_foreign_key_setting(old_db):
    import kwara.db as dbmod

    _strand_temp_and_new(old_db)
    old_db.execute("PRAGMA foreign_keys = OFF")
    dbmod._migrate_acquisitions_fk(old_db)
    assert old_db.execute("PRAGMA foreign_keys").fetchone()[0] == 0
