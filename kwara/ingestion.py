import csv
import re
import sqlite3
from datetime import datetime, timezone

from .audit import write_audit
from .utils.domain import extract_domain_from_url

URL_RE = re.compile(r'https?://[^\s\'"<>\]\)]+')


def extract_urls_from_text(text: str) -> list[str]:
    """Extract http/https URLs from text, deduplicated preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for url in URL_RE.findall(text or ""):
        # Strip trailing punctuation that's unlikely to be part of the URL
        url = url.rstrip(".,;:!?)")
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


def ingest_message(
    conn: sqlite3.Connection,
    case_id: int,
    message_text: str,
    platform: str = "",
    permalink: str = "",
    actor_label: str = "",
    posted_at: str = "",
    screenshot_path: str = "",
) -> tuple[int, list[str]]:
    """
    Write a MessageEvidence row, extract URLs, write UrlArtifact rows.
    Returns (message_id, [url, ...]).
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    cur = conn.execute(
        """INSERT INTO message_evidence
           (case_id, platform, permalink, actor_label, posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (case_id, platform, permalink, actor_label, posted_at, message_text, screenshot_path, now),
    )
    message_id = cur.lastrowid

    urls = extract_urls_from_text(message_text)
    for order, url in enumerate(urls):
        domain = extract_domain_from_url(url)
        conn.execute(
            """INSERT OR IGNORE INTO url_artifacts
               (message_id, case_id, original_url, domain, url_order, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (message_id, case_id, url, domain, order, now),
        )

    conn.commit()
    write_audit(conn, "ingest_message", case_id=case_id, meta={"message_id": message_id, "url_count": len(urls)})
    return message_id, urls


def ingest_csv(conn: sqlite3.Connection, case_id: int, file_path: str) -> list[dict]:
    """
    Read CSV with columns: platform, permalink, actor_label, posted_at, message_text.
    Calls ingest_message for each row. Returns [{message_id, url_count}, ...].
    """
    results: list[dict] = []
    with open(file_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            message_id, urls = ingest_message(
                conn,
                case_id,
                message_text=row.get("message_text", ""),
                platform=row.get("platform", ""),
                permalink=row.get("permalink", ""),
                actor_label=row.get("actor_label", ""),
                posted_at=row.get("posted_at", ""),
            )
            results.append({"message_id": message_id, "url_count": len(urls)})

    write_audit(conn, "ingest_csv", case_id=case_id, meta={"row_count": len(results), "file": file_path})
    return results
