import contextlib
import os
import re
import sqlite3


def get_conn(db_path: str = "data/kwara.db") -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def migrate_db(conn: sqlite3.Connection) -> None:
    """Add columns introduced after initial schema creation.

    Note: column names are interpolated via f-string below. This is safe
    because the values come from hardcoded lists in this function, never
    from user input. SQLite does not support parameterized DDL.
    """
    new_cols = [
        ("ip_address", "TEXT"),
        ("asn",        "TEXT"),
        ("as_org",     "TEXT"),
        ("as_country", "TEXT"),
        ("capture_status", "TEXT"),
        ("capture_detail", "TEXT"),
        ("har_path", "TEXT"),
        ("tracking_ids_json", "TEXT"),
        ("capture_method", "TEXT"),
    ]
    for col, defn in new_cols:
        try:
            conn.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass  # column already exists
    # Backfill existing rows: anything pre-dating capture_method came from
    # the Playwright path. Idempotent — only fills NULLs.
    conn.execute(
        "UPDATE snapshots SET capture_method = 'playwright' "
        "WHERE capture_method IS NULL"
    )
    scan_run_cols = [
        ("whois_registrar", "TEXT"),
        ("whois_creation_date", "TEXT"),
        ("ip_address", "TEXT"),
        ("asn", "TEXT"),
        ("as_org", "TEXT"),
        ("as_country", "TEXT"),
        ("intel_risk_tags", "TEXT"),
        ("domain_enriched_at", "TEXT"),
        ("tls_info_json", "TEXT"),
        ("final_response_headers_json", "TEXT"),
        ("corroboration_json", "TEXT"),
        # Phase 4.1 — crawlerlanding-style conditional cloakers leak their
        # gating logic when you fetch the URL with vs without tracking
        # params. JSON shape: see cloaking.detect_cloaking().
        ("cloaking_signal_json", "TEXT"),
        # Phase 8 — the landing domain's /ads.txt: DIRECT monetisation
        # accounts + a sha256 of the raw file. JSON shape: see
        # adstxt.fetch_and_store_ads_txt().
        ("ads_txt_json", "TEXT"),
    ]
    for col, defn in scan_run_cols:
        try:
            conn.execute(f"ALTER TABLE scan_runs ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass
    cases_cols = [
        ("browser_locale", "TEXT"),
        ("browser_timezone", "TEXT"),
    ]
    for col, defn in cases_cols:
        try:
            conn.execute(f"ALTER TABLE cases ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass
    # Phase 4.2: per-hop response headers. Without this column, hop-level
    # OPSEC fingerprints (Server, Set-Cookie domain, x-powered-by, etc.)
    # are read in scanner and immediately dropped. Stored as a JSON list
    # of [key, value] pairs preserving duplicates (urllib3 raw headers,
    # see scanner._headers_to_json).
    redirect_hop_cols = [
        ("response_headers_json", "TEXT"),
    ]
    for col, defn in redirect_hop_cols:
        try:
            conn.execute(f"ALTER TABLE redirect_hops ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass
    _migrate_acquisitions_fk(conn)
    conn.commit()
    _backfill_legacy_capture_status(conn)


# The acquisitions table as it must be. Kept here as one string so the
# migration rebuilds EXACTLY what init_db creates — calling init_db from the
# migration is what silently dropped both indexes: the rename carried them to
# the temp table, `CREATE INDEX IF NOT EXISTS` saw the names still taken and
# skipped, and the drop then took them away.
# A TUPLE of statements, not a script: sqlite3.executescript implicitly
# COMMITs any pending transaction before running, which silently ended the
# transaction this rebuild depends on and left ROLLBACK with nothing to undo.
_ACQUISITIONS_DDL = ("""
CREATE TABLE acquisitions (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind                  TEXT NOT NULL,
    scan_run_id           INTEGER,
    requested_url         TEXT NOT NULL,
    final_url             TEXT,
    redirect_chain_json   TEXT,
    status                TEXT NOT NULL,
    status_code           INTEGER,
    fetched_at            TEXT NOT NULL,
    response_headers_json TEXT,
    user_agent            TEXT,
    tool_version          TEXT,
    truncated             INTEGER NOT NULL DEFAULT 0,
    captured_bytes        INTEGER NOT NULL DEFAULT 0,
    body_path             TEXT,
    captured_sha256       TEXT,
    complete_sha256       TEXT,
    error                 TEXT,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
)""",
    "CREATE INDEX idx_acq_scan_run ON acquisitions(scan_run_id)",
    "CREATE INDEX idx_acq_complete ON acquisitions(complete_sha256)",
)

_ACQ_TEMP = "acquisitions_cascade"


@contextlib.contextmanager
def _fk_off_transaction(conn: sqlite3.Connection):
    """One atomic rebuild step with foreign keys disabled.

    Shared by both the rebuild and the recovery path because writing it twice
    is exactly how the recovery path ended up repeating three defects the
    rebuild had already fixed: a failed BEGIN masked by an unconditional
    ROLLBACK, foreign_keys forced ON instead of restored, and no rollback
    boundary at all.

    `foreign_keys` is a no-op inside a transaction, so it is set outside and
    restored to whatever the CALLER had.
    """
    prior_fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    began = False
    try:
        conn.execute("BEGIN IMMEDIATE")
        began = True
        yield
        conn.execute("COMMIT")
    except BaseException:
        # Only if one began. Otherwise a failed BEGIN is replaced by
        # "cannot rollback - no transaction is active" and the real error
        # never surfaces.
        if began:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    finally:
        conn.execute(f"PRAGMA foreign_keys = {'ON' if prior_fk else 'OFF'}")


_CANONICAL_ACQ_INDEXES = ("idx_acq_scan_run", "idx_acq_complete")


def _custom_index_ddl(conn: sqlite3.Connection, table: str) -> list:
    """CREATE INDEX statements on `table` that are not kwara's own, retargeted
    at `acquisitions`.

    SQLite rewrites the table name inside an index's DDL when the table is
    renamed — and QUOTES it while doing so, producing
    `... ON "acquisitions_cascade"(col)`. A plain substring swap of the bare
    name therefore never matched, and replaying the captured DDL raised
    "no such table". Match either form.
    """
    pattern = re.compile(r'\bON\s+"?' + re.escape(table) + r'"?',
                         re.IGNORECASE)
    out = []
    for name, sql in conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='index' "
            "AND tbl_name = ? AND sql IS NOT NULL", (table,)).fetchall():
        if name in _CANONICAL_ACQ_INDEXES:
            continue
        out.append(pattern.sub("ON acquisitions", sql))
    return out


def _recover_stranded_acquisitions(conn: sqlite3.Connection, tables: set) -> set:
    """Finish a rebuild the earlier non-transactional migration left half-done.

    That version could die at two points, and BOTH leave a durable state:

      temp only — it died between the rename and the create. The rows are
      reachable only under the temp name.

      temp AND a new empty table — it died between the create and the copy.
      This is the dangerous one, because the new table passes the foreign-key
      check, so a migration that only looked at the FK returned happily and
      left the rows behind in the temp table forever. It also leaves the new
      table WITHOUT indexes, since their names were still held by the temp
      table when the interrupted run tried to create them.

    Neither table is dropped before its rows are safe. Rows merge by id with
    INSERT OR IGNORE, so a partially-completed copy converges.
    """
    if _ACQ_TEMP not in tables:
        return tables

    if "acquisitions" not in tables:
        conn.execute(f"ALTER TABLE {_ACQ_TEMP} RENAME TO acquisitions")
        conn.commit()
        return (tables - {_ACQ_TEMP}) | {"acquisitions"}

    cols = ", ".join(r[1] for r in conn.execute(
        "PRAGMA table_info(acquisitions)"))
    custom = _custom_index_ddl(conn, _ACQ_TEMP)

    with _fk_off_transaction(conn):
        conn.execute(f"INSERT OR IGNORE INTO acquisitions ({cols}) "
                     f"SELECT {cols} FROM {_ACQ_TEMP}")
        # Dropping the temp table frees the index names it still holds, which
        # is what stopped the interrupted run from creating them.
        conn.execute(f"DROP TABLE {_ACQ_TEMP}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_acq_scan_run "
                     "ON acquisitions(scan_run_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_acq_complete "
                     "ON acquisitions(complete_sha256)")
        for stmt in custom:
            conn.execute(stmt)
    return tables - {_ACQ_TEMP}


def _migrate_acquisitions_fk(conn: sqlite3.Connection) -> None:
    """Rebuild `acquisitions` if it still cascades from scan_runs.

    The table shipped on 2026-08-12 with ON DELETE CASCADE, so `delete_case` —
    which deletes scan_runs — silently deleted acquisition rows with them. An
    append-only table that quietly loses rows is not append-only.

    SQLite cannot alter a foreign key in place, so the table is rebuilt. Three
    things make that safe to run on someone's only copy of an investigation:

    ATOMIC. The rebuild is one transaction, so a process killed halfway rolls
    back to the original table rather than leaving a renamed table and no
    `acquisitions` at all.

    SELF-CONTAINED. The DDL lives here rather than calling init_db, which
    commits internally — breaking the transaction — and whose
    `CREATE INDEX IF NOT EXISTS` silently skipped both indexes, because the
    rename had carried the names to the temp table and the drop then removed
    them. An earlier build completed "successfully" and left no indexes.

    RECOVERABLE. Either state the earlier build could strand is finished
    first; see `_recover_stranded_acquisitions`.

    Indexes the analyst added are carried across by capturing their DDL BEFORE
    the rename and replaying it; kwara's own two come from the DDL below.
    """
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.Error:
        return

    tables = _recover_stranded_acquisitions(conn, tables)

    if "acquisitions" not in tables:
        return
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' "
        "AND name='acquisitions'").fetchone()
    # Match the CLAUSE, not the word: the corrected schema's own comment says
    # "NO CASCADE, deliberately", and matching bare "CASCADE" rebuilt the
    # table on every single migrate_db call.
    if not row or "ON DELETE CASCADE" not in (row[0] or "").upper():
        return

    cols = ", ".join(r[1] for r in conn.execute(
        "PRAGMA table_info(acquisitions)"))
    custom = _custom_index_ddl(conn, "acquisitions")

    with _fk_off_transaction(conn):
        conn.execute(f"ALTER TABLE acquisitions RENAME TO {_ACQ_TEMP}")
        # The rename carries the indexes across but NOT their names, which
        # stay taken — so recreating them raises "already exists". They belong
        # to the temp table and die with it either way.
        for (idx,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name = ? AND name NOT LIKE 'sqlite_%'",
                (_ACQ_TEMP,)).fetchall():
            conn.execute(f"DROP INDEX {idx}")
        for stmt in _ACQUISITIONS_DDL:
            conn.execute(stmt)
        for stmt in custom:
            conn.execute(stmt)
        conn.execute(f"INSERT INTO acquisitions ({cols}) "
                     f"SELECT {cols} FROM {_ACQ_TEMP}")
        conn.execute(f"DROP TABLE {_ACQ_TEMP}")


# Same signals as _snapshot_worker / snapshots for HTML challenge pages
_CF_HTML_SNIPPET = (
    "challenge-platform",
    "正在執行安全驗證",
    "Just a moment",
    "cf-turnstile-response",
)


def _backfill_legacy_capture_status(conn: sqlite3.Connection) -> None:
    """Set capture_status for rows where column was never filled (idempotent)."""
    rows = conn.execute(
        """SELECT id, screenshot_path, html_path FROM snapshots
           WHERE capture_status IS NULL OR TRIM(capture_status) = ''"""
    ).fetchall()
    if not rows:
        return
    for row in rows:
        sid = row["id"]
        sp, hp = row["screenshot_path"], row["html_path"]
        if not sp or not os.path.isfile(sp) or os.path.getsize(sp) == 0:
            continue
        looks_cf = False
        if hp and os.path.isfile(hp):
            try:
                with open(hp, encoding="utf-8", errors="ignore") as f:
                    snippet = f.read(8000)
            except OSError:
                snippet = ""
            looks_cf = any(sig in snippet for sig in _CF_HTML_SNIPPET)
        if looks_cf:
            conn.execute(
                """UPDATE snapshots SET capture_status = ?, capture_detail = ?
                   WHERE id = ?""",
                ("cf_challenge", "legacy_backfill_html_cf_signals", sid),
            )
        else:
            # Never clear capture_detail. This ran `capture_detail = NULL` on
            # every row it touched, and it runs on EVERY kwara command via
            # migrate_db — a read-only-looking command could erase a recorded
            # note. Write a marker only where the column is empty, so an 'ok'
            # that was INFERRED from a screenshot on disk stays distinguishable
            # from one that was observed at capture time.
            conn.execute(
                """UPDATE snapshots
                      SET capture_status = ?,
                          capture_detail = COALESCE(
                              NULLIF(TRIM(capture_detail), ''), ?)
                    WHERE id = ?""",
                ("ok", "legacy_backfill_screenshot_present", sid),
            )
    conn.commit()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS cases (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        title       TEXT NOT NULL,
        description TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS message_evidence (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id         INTEGER NOT NULL REFERENCES cases(id),
        platform        TEXT,
        permalink       TEXT,
        actor_label     TEXT,
        posted_at       TEXT,
        message_text    TEXT,
        screenshot_path TEXT,
        ingested_at     TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS url_artifacts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id   INTEGER NOT NULL REFERENCES message_evidence(id),
        case_id      INTEGER NOT NULL REFERENCES cases(id),
        original_url TEXT NOT NULL,
        domain       TEXT,
        url_order    INTEGER NOT NULL,
        created_at   TEXT NOT NULL,
        UNIQUE(message_id, original_url)
    );

    CREATE TABLE IF NOT EXISTS scan_runs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        url_artifact_id INTEGER REFERENCES url_artifacts(id),
        run_at          TEXT,
        final_url       TEXT,
        hop_count       INTEGER,
        status          TEXT,
        notes           TEXT
    );

    CREATE TABLE IF NOT EXISTS redirect_hops (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_run_id  INTEGER REFERENCES scan_runs(id),
        hop_order    INTEGER,
        url          TEXT,
        status_code  INTEGER,
        location     TEXT,
        resolved_url TEXT,
        fetched_at   TEXT
    );

    CREATE TABLE IF NOT EXISTS snapshots (
        id                   INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_run_id          INTEGER REFERENCES scan_runs(id),
        final_url            TEXT,
        final_domain         TEXT,
        screenshot_path      TEXT,
        html_path            TEXT,
        request_domains_json TEXT,
        risk_tags            TEXT,
        whois_registrar      TEXT,
        whois_creation_date  TEXT,
        captured_at          TEXT,
        capture_status       TEXT,
        capture_detail       TEXT
    );

    CREATE TABLE IF NOT EXISTS report_status (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id     INTEGER REFERENCES cases(id),
        target_type TEXT,
        target_id   INTEGER,
        status      TEXT,
        ticket_ref  TEXT,
        notes       TEXT,
        updated_at  TEXT
    );

    CREATE TABLE IF NOT EXISTS export_runs (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id       INTEGER REFERENCES cases(id),
        export_at     TEXT,
        zip_path      TEXT,
        manifest_json TEXT
    );

    -- Acquisition records: the response bytes an analysis was derived from.
    -- APPEND ONLY. A forced re-fetch inserts; nothing updates or deletes a
    -- row here, because a record describes one moment and a later moment is a
    -- different record. See kwara/acquisition.py.
    CREATE TABLE IF NOT EXISTS acquisitions (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        kind                  TEXT NOT NULL,
        scan_run_id           INTEGER,
        requested_url         TEXT NOT NULL,
        final_url             TEXT,
        redirect_chain_json   TEXT,
        status                TEXT NOT NULL,
        status_code           INTEGER,
        fetched_at            TEXT NOT NULL,
        -- [[name, value], ...] not a dict: a response may repeat a header and
        -- a mapping silently keeps only the last one.
        response_headers_json TEXT,
        user_agent            TEXT,
        tool_version          TEXT,
        truncated             INTEGER NOT NULL DEFAULT 0,
        captured_bytes        INTEGER NOT NULL DEFAULT 0,
        body_path             TEXT,
        -- Over the bytes actually written.
        captured_sha256       TEXT,
        -- Over the WHOLE response; NULL when truncated. Only this one may be
        -- compared for byte-identity.
        complete_sha256       TEXT,
        error                 TEXT,
        -- NO CASCADE, deliberately. `delete_case` deletes scan_runs, and a
        -- cascade here would silently delete acquisitions with them — an
        -- append-only table that quietly loses rows is not append-only. The
        -- scan_run reference may dangle; an orphaned acquisition is still a
        -- record that a fetch happened, and `evidence reconcile` is the tool
        -- for finding artifacts nothing points at.
        FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_acq_scan_run ON acquisitions(scan_run_id);
    CREATE INDEX IF NOT EXISTS idx_acq_complete ON acquisitions(complete_sha256);

    CREATE TABLE IF NOT EXISTS audit_log (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id   INTEGER,
        actor     TEXT DEFAULT 'user',
        action    TEXT NOT NULL,
        at        TEXT NOT NULL,
        meta_json TEXT
    );

    -- Every analysis aggregation pins "the latest done scan_run for this
    -- url_artifact" via a correlated subquery (sql.LATEST_DONE_SCAN_RUN).
    -- Without this index SQLite scans scan_runs once per url_artifact, which
    -- is O(artifacts x scan_runs) — fine at a hundred URLs, pathological at
    -- the scale a cross-case index is built for.
    CREATE INDEX IF NOT EXISTS idx_scan_runs_artifact_status
        ON scan_runs(url_artifact_id, status, id);
    -- sql.LATEST_DONE_SCAN_RUN_FOR_URL resolves a scan through every artifact
    -- in the case that carries the same URL, so the (case_id, original_url)
    -- lookup runs once per artifact row and needs to be an index seek.
    CREATE INDEX IF NOT EXISTS idx_url_artifacts_case_url
        ON url_artifacts(case_id, original_url, id);
    CREATE INDEX IF NOT EXISTS idx_snapshots_scan_run
        ON snapshots(scan_run_id, capture_status, id);
    CREATE INDEX IF NOT EXISTS idx_redirect_hops_scan_run
        ON redirect_hops(scan_run_id);
    """)
    conn.commit()
