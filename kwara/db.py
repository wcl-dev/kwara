import sqlite3
import os


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
    ]
    for col, defn in new_cols:
        try:
            conn.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass  # column already exists
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
    conn.commit()
    _backfill_legacy_capture_status(conn)


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
            conn.execute(
                """UPDATE snapshots SET capture_status = ?, capture_detail = NULL
                   WHERE id = ?""",
                ("ok", sid),
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

    CREATE TABLE IF NOT EXISTS audit_log (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id   INTEGER,
        actor     TEXT DEFAULT 'user',
        action    TEXT NOT NULL,
        at        TEXT NOT NULL,
        meta_json TEXT
    );
    """)
    conn.commit()
