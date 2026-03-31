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
    """Add columns introduced after initial schema creation."""
    new_cols = [
        ("ip_address", "TEXT"),
        ("asn",        "TEXT"),
        ("as_org",     "TEXT"),
        ("as_country", "TEXT"),
    ]
    for col, defn in new_cols:
        try:
            conn.execute(f"ALTER TABLE snapshots ADD COLUMN {col} {defn}")
        except sqlite3.OperationalError:
            pass  # column already exists
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
        captured_at          TEXT
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
