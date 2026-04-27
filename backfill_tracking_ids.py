"""
Re-extract HTML tracking IDs (Pixel/GA/GTM/Ads/TikTok) from existing
snapshots and populate the snapshots.tracking_ids_json column.

Usage:
    python backfill_tracking_ids.py            # uses kwara/data/kwara.db
    python backfill_tracking_ids.py --db PATH

The script is idempotent — running it multiple times re-extracts and
overwrites the column. Snapshots whose html_path is missing or empty
are skipped without error.
"""
import argparse
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KWARA_DIR = os.path.join(SCRIPT_DIR, "kwara")
DEFAULT_DB = os.path.join(KWARA_DIR, "data", "kwara.db")

sys.path.insert(0, KWARA_DIR)
from db import get_conn, migrate_db
from fingerprints import extract_tracking_ids_from_file


def backfill(db_path: str) -> tuple[int, int, int]:
    """Returns (snapshots_seen, snapshots_updated_with_ids, snapshots_skipped)."""
    if not os.path.exists(db_path):
        print(f"[!] DB not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    conn = get_conn(db_path)
    migrate_db(conn)

    rows = conn.execute(
        "SELECT id, html_path FROM snapshots WHERE html_path IS NOT NULL AND TRIM(html_path) != ''"
    ).fetchall()

    seen = updated = skipped = 0
    for r in rows:
        seen += 1
        sid, html_path = r["id"], r["html_path"]
        if not os.path.isfile(html_path) or os.path.getsize(html_path) == 0:
            skipped += 1
            continue
        ids = extract_tracking_ids_from_file(html_path)
        ids_json = json.dumps(ids, ensure_ascii=False) if ids else None
        conn.execute(
            "UPDATE snapshots SET tracking_ids_json = ? WHERE id = ?",
            (ids_json, sid),
        )
        if ids:
            updated += 1
            platforms = ", ".join(f"{k}={len(v)}" for k, v in ids.items())
            print(f"  snapshot {sid}: {platforms}")

    conn.commit()
    conn.close()
    return seen, updated, skipped


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=DEFAULT_DB, help=f"SQLite path (default: {DEFAULT_DB})")
    args = ap.parse_args()

    print(f"Backfilling tracking IDs from snapshots in {args.db}")
    seen, updated, skipped = backfill(args.db)
    print()
    print(f"Snapshots inspected:        {seen}")
    print(f"Snapshots with IDs found:   {updated}")
    print(f"Snapshots skipped (no html):{skipped}")


if __name__ == "__main__":
    main()
