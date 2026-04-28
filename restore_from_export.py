"""
Restore kwara SQLite DB + snapshot files from an evidence-pack export folder.

Usage:
    python restore_from_export.py <export_dir> [--case-title TITLE]

This reads the CSVs produced by exporter.py and reconstructs the DB at
kwara/data/kwara.db, plus copies snapshot files into kwara/data/snapshots/.
"""
import csv
import os
import shutil
import sqlite3
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KWARA_DIR = os.path.join(SCRIPT_DIR, "kwara")
DB_PATH = os.path.join(KWARA_DIR, "data", "kwara.db")
SNAP_DST = os.path.join(KWARA_DIR, "data", "snapshots")

sys.path.insert(0, KWARA_DIR)
from db import init_db, migrate_db, get_conn


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def restore(export_dir, case_title="Restored case"):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        print(f"[!] DB already exists: {DB_PATH}")
        print("    Delete it first if you want a fresh restore.")
        sys.exit(1)

    conn = get_conn(DB_PATH)
    init_db(conn)
    migrate_db(conn)

    # --- 1. case ---
    messages_csv = os.path.join(export_dir, "messages", "messages.csv")
    msgs = read_csv(messages_csv)
    first_ts = msgs[0]["ingested_at"] if msgs else "unknown"
    conn.execute(
        "INSERT INTO cases (id, title, description, created_at, updated_at) VALUES (?,?,?,?,?)",
        (1, case_title, f"Restored from export {os.path.basename(export_dir)}", first_ts, first_ts),
    )

    # --- 2. messages ---
    for m in msgs:
        conn.execute(
            """INSERT INTO message_evidence
               (id, case_id, platform, permalink, actor_label, posted_at, message_text, screenshot_path, ingested_at)
               VALUES (?,1,?,?,?,?,?,?,?)""",
            (m["id"], m.get("platform",""), m.get("permalink",""),
             m.get("actor_label",""), m.get("posted_at",""),
             m.get("message_text",""), "", m["ingested_at"]),
        )
    print(f"  messages: {len(msgs)}")

    # --- 3. urls + scan_runs ---
    urls_csv = os.path.join(export_dir, "urls", "urls.csv")
    urls = read_csv(urls_csv)
    seen_scan_runs = {}
    for u in urls:
        conn.execute(
            """INSERT INTO url_artifacts
               (id, message_id, case_id, original_url, domain, url_order, created_at)
               VALUES (?,?,1,?,?,?,?)""",
            (u["id"], u["message_id"], u["original_url"], u["domain"],
             u["url_order"], first_ts),
        )
        sr_id = u.get("scan_run_id")
        if sr_id and sr_id not in seen_scan_runs:
            seen_scan_runs[sr_id] = True
            conn.execute(
                """INSERT INTO scan_runs
                   (id, url_artifact_id, run_at, final_url, hop_count, status, notes,
                    whois_registrar, whois_creation_date, ip_address, asn, as_org, as_country,
                    intel_risk_tags, domain_enriched_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sr_id, u["id"], first_ts,
                 u.get("final_url",""), u.get("hop_count",""), u.get("scan_status",""), "",
                 u.get("whois_registrar",""), u.get("whois_creation_date",""),
                 u.get("ip_address",""), u.get("asn",""), u.get("as_org",""),
                 u.get("as_country",""), u.get("intel_risk_tags",""),
                 u.get("domain_enriched_at","")),
            )
    print(f"  urls: {len(urls)}, scan_runs: {len(seen_scan_runs)}")

    # --- 4. redirect_hops ---
    chains_dir = os.path.join(export_dir, "urls", "chains")
    hop_count = 0
    if os.path.isdir(chains_dir):
        for fname in os.listdir(chains_dir):
            if not fname.endswith("_hops.csv"):
                continue
            # url_{id}_hops.csv -> extract url_artifact_id
            parts = fname.replace("url_", "").replace("_hops.csv", "")
            url_id = parts
            # find the scan_run_id for this url
            sr_row = conn.execute(
                "SELECT id FROM scan_runs WHERE url_artifact_id = ?", (url_id,)
            ).fetchone()
            if not sr_row:
                continue
            sr_id = sr_row["id"]
            hops = read_csv(os.path.join(chains_dir, fname))
            for h in hops:
                conn.execute(
                    """INSERT INTO redirect_hops
                       (scan_run_id, hop_order, url, status_code, location, resolved_url, fetched_at)
                       VALUES (?,?,?,?,?,?,?)""",
                    (sr_id, h["hop_order"], h["url"], h.get("status_code",""),
                     h.get("location",""), h.get("resolved_url",""), h.get("fetched_at","")),
                )
                hop_count += 1
    print(f"  redirect_hops: {hop_count}")

    # --- 5. snapshots (metadata) ---
    # Export ZIP layout: snapshots/{snapshot_id}/{filename}. Restore copies
    # those into kwara/data/snapshots/{scan_run_id}/{snapshot_id}/{filename}
    # so restored evidence keeps its per-capture isolation.
    snap_csv = os.path.join(export_dir, "snapshots", "snapshots.csv")
    snaps = read_csv(snap_csv)
    for s in snaps:
        sr_id = s["scan_run_id"]
        snap_id = s.get("snapshot_id", "")
        # Build local paths for screenshot/html
        ss_src = s.get("screenshot_file", "")
        html_src = s.get("html_file", "")
        local_ss = (
            os.path.join(SNAP_DST, sr_id, snap_id or "legacy", os.path.basename(ss_src))
            if ss_src else ""
        )
        local_html = (
            os.path.join(SNAP_DST, sr_id, snap_id or "legacy", os.path.basename(html_src))
            if html_src else ""
        )

        conn.execute(
            """INSERT INTO snapshots
               (scan_run_id, final_url, final_domain, screenshot_path, html_path,
                request_domains_json, risk_tags, whois_registrar, whois_creation_date,
                captured_at, capture_status, capture_detail,
                ip_address, asn, as_org, as_country)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sr_id, s.get("final_url",""), s.get("final_domain",""),
             local_ss, local_html,
             s.get("request_domains",""), s.get("risk_tags",""),
             s.get("whois_registrar",""), s.get("whois_creation_date",""),
             s.get("captured_at",""), s.get("capture_status",""), s.get("capture_detail",""),
             s.get("ip_address",""), s.get("asn",""), s.get("as_org",""),
             s.get("as_country","")),
        )
    print(f"  snapshots: {len(snaps)}")

    # --- 6. audit_log ---
    audit_csv = os.path.join(export_dir, "audit.csv")
    if os.path.isfile(audit_csv):
        audits = read_csv(audit_csv)
        for a in audits:
            conn.execute(
                """INSERT INTO audit_log (id, case_id, actor, action, at, meta_json)
                   VALUES (?,?,?,?,?,?)""",
                (a["id"], a.get("case_id",""), a.get("actor","user"),
                 a["action"], a["at"], a.get("meta_json","")),
            )
        print(f"  audit_log: {len(audits)}")

    conn.commit()
    conn.close()

    # --- 7. Copy snapshot files ---
    snap_src_dir = os.path.join(export_dir, "snapshots")
    copied = 0
    for entry in os.listdir(snap_src_dir):
        src_path = os.path.join(snap_src_dir, entry)
        if not os.path.isdir(src_path) or entry == "screenshots":
            continue
        dst_path = os.path.join(SNAP_DST, entry)
        if os.path.exists(dst_path):
            continue
        shutil.copytree(src_path, dst_path)
        copied += 1
    print(f"  snapshot dirs copied: {copied}")
    print(f"\n[OK] DB restored to {DB_PATH}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <export_dir> [--case-title TITLE]")
        sys.exit(1)
    export_dir = sys.argv[1]
    title = "Restored case"
    if "--case-title" in sys.argv:
        idx = sys.argv.index("--case-title")
        title = sys.argv[idx + 1]
    restore(export_dir, title)
