"""Case lifecycle — create / list / inspect / delete.

Extracted from the Streamlit sidebar so the CLI, the MCP server, and the UI
all create cases the same way. Before this module the only way to open a case
was to click a button in app.py, which made the toolkit unusable headlessly.

Nothing here imports streamlit. The delete path deliberately keeps the
directory-confinement guard from the original sidebar implementation: a
corrupted or crafted DB row must never be able to steer shutil.rmtree at an
arbitrary path.
"""
import os
import shutil
import sqlite3
from datetime import datetime, timezone

from .audit import write_audit

# Snapshot files live under kwara/data/snapshots/. Deletion may only ever
# touch directories at or below this root.
_SNAP_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "snapshots")
)

# Victim-locale presets. Screenshots are captured with the victim's locale so
# geo-cloaked pages render what they actually saw, not what the analyst sees.
LOCALE_PRESETS: dict[str, tuple[str, str]] = {
    "tw": ("zh-TW", "Asia/Taipei"),
    "us": ("en-US", "America/New_York"),
    "uk": ("en-GB", "Europe/London"),
    "jp": ("ja-JP", "Asia/Tokyo"),
    "kr": ("ko-KR", "Asia/Seoul"),
    "de": ("de-DE", "Europe/Berlin"),
}


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def resolve_locale(
    preset: str | None = None,
    locale: str | None = None,
    timezone_name: str | None = None,
) -> tuple[str | None, str | None]:
    """Turn (preset, explicit locale, explicit tz) into a (locale, tz) pair.

    Explicit values win over the preset, so `--locale-preset tw --timezone UTC`
    means "Taiwan locale, UTC clock" rather than silently ignoring one of them.
    """
    base = LOCALE_PRESETS.get((preset or "").strip().lower(), (None, None))
    loc = (locale or base[0] or "").strip() or None
    tz = (timezone_name or base[1] or "").strip() or None
    return loc, tz


def create_case(
    conn: sqlite3.Connection,
    title: str,
    description: str = "",
    browser_locale: str | None = None,
    browser_timezone: str | None = None,
) -> int:
    """Open a new case. Returns the new case_id."""
    title = (title or "").strip()
    if not title:
        raise ValueError("case title must not be empty")
    now = _now()
    cur = conn.execute(
        """INSERT INTO cases
           (title, description, created_at, updated_at, browser_locale, browser_timezone)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (title, (description or "").strip(), now, now, browser_locale, browser_timezone),
    )
    conn.commit()
    case_id = int(cur.lastrowid)
    write_audit(conn, "create_case", case_id=case_id, meta={"title": title})
    return case_id


def list_cases(conn: sqlite3.Connection) -> list[dict]:
    """Every case, newest first, with URL and scan counts."""
    rows = conn.execute(
        """SELECT c.id, c.title, c.description, c.created_at, c.updated_at,
                  c.browser_locale, c.browser_timezone,
                  (SELECT COUNT(*) FROM url_artifacts ua WHERE ua.case_id = c.id)
                      AS url_count,
                  (SELECT COUNT(*) FROM scan_runs sr
                     JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                    WHERE ua.case_id = c.id) AS scan_count
           FROM cases c
           ORDER BY c.id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_case(conn: sqlite3.Connection, case_id: int) -> dict | None:
    row = conn.execute(
        """SELECT id, title, description, created_at, updated_at,
                  browser_locale, browser_timezone
           FROM cases WHERE id = ?""",
        (case_id,),
    ).fetchone()
    return dict(row) if row else None


def require_case(conn: sqlite3.Connection, case_id: int) -> dict:
    """get_case() that raises instead of returning None.

    The CLI and MCP layers both need "fail loudly on a bad case id" — a
    silent empty result would read as "this case has no evidence", which is a
    dangerous thing to tell an analyst.
    """
    case = get_case(conn, case_id)
    if case is None:
        raise ValueError(f"case {case_id} does not exist")
    return case


def set_case_locale(
    conn: sqlite3.Connection,
    case_id: int,
    browser_locale: str | None,
    browser_timezone: str | None,
) -> None:
    require_case(conn, case_id)
    conn.execute(
        """UPDATE cases
           SET browser_locale = ?, browser_timezone = ?, updated_at = ?
           WHERE id = ?""",
        (browser_locale, browser_timezone, _now(), case_id),
    )
    conn.commit()
    write_audit(
        conn, "set_case_locale", case_id=case_id,
        meta={"browser_locale": browser_locale, "browser_timezone": browser_timezone},
    )


def _snapshot_dirs_for_case(conn: sqlite3.Connection, case_id: int) -> set[str]:
    """Snapshot directories belonging to a case, confined to _SNAP_ROOT.

    Any path that resolves outside the snapshot root is dropped rather than
    deleted — see the module docstring.
    """
    rows = conn.execute(
        """SELECT s.screenshot_path, s.html_path, s.har_path
           FROM snapshots s
           JOIN scan_runs sr ON sr.id = s.scan_run_id
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE ua.case_id = ?""",
        (case_id,),
    ).fetchall()
    dirs: set[str] = set()
    for row in rows:
        for col in ("screenshot_path", "html_path", "har_path"):
            path = row[col]
            if not path or not os.path.exists(path):
                continue
            real = os.path.realpath(os.path.dirname(path))
            if real == _SNAP_ROOT or real.startswith(_SNAP_ROOT + os.sep):
                dirs.add(real)
    return dirs


def delete_case(
    conn: sqlite3.Connection,
    case_id: int,
    *,
    confirm: str = "",
    delete_files: bool = True,
) -> dict:
    """Irreversibly delete a case, its scans, and its snapshot files.

    `confirm` must be the literal string "DELETE" — the same guard the UI
    uses. This is destructive and is intentionally NOT exposed over MCP; an
    agent should never be one tool call away from destroying evidence.
    """
    require_case(conn, case_id)
    if confirm != "DELETE":
        raise ValueError('refusing to delete: confirm must be the literal string "DELETE"')

    removed_dirs: list[str] = []
    if delete_files:
        for directory in _snapshot_dirs_for_case(conn, case_id):
            shutil.rmtree(directory, ignore_errors=True)
            removed_dirs.append(directory)

    conn.execute("DELETE FROM audit_log WHERE case_id = ?", (case_id,))
    conn.execute("DELETE FROM export_runs WHERE case_id = ?", (case_id,))
    conn.execute(
        """DELETE FROM snapshots WHERE scan_run_id IN
           (SELECT sr.id FROM scan_runs sr
              JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
            WHERE ua.case_id = ?)""",
        (case_id,),
    )
    conn.execute(
        """DELETE FROM redirect_hops WHERE scan_run_id IN
           (SELECT sr.id FROM scan_runs sr
              JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
            WHERE ua.case_id = ?)""",
        (case_id,),
    )
    conn.execute(
        """DELETE FROM scan_runs WHERE url_artifact_id IN
           (SELECT id FROM url_artifacts WHERE case_id = ?)""",
        (case_id,),
    )
    conn.execute("DELETE FROM url_artifacts WHERE case_id = ?", (case_id,))
    conn.execute("DELETE FROM message_evidence WHERE case_id = ?", (case_id,))
    conn.execute("DELETE FROM report_status WHERE case_id = ?", (case_id,))
    conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
    conn.commit()
    return {"case_id": case_id, "deleted": True, "removed_dirs": removed_dirs}
