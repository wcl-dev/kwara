import json
import sqlite3
from datetime import datetime, timezone


def write_audit(
    conn: sqlite3.Connection,
    action: str,
    case_id: int = None,
    meta: dict = None,
) -> None:
    at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_json = json.dumps(meta, ensure_ascii=False) if meta else None
    conn.execute(
        "INSERT INTO audit_log (case_id, actor, action, at, meta_json) VALUES (?, 'user', ?, ?, ?)",
        (case_id, action, at, meta_json),
    )
    conn.commit()
