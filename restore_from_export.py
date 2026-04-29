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

    # --- 3. urls ---
    urls_csv = os.path.join(export_dir, "urls", "urls.csv")
    urls = read_csv(urls_csv)
    for u in urls:
        conn.execute(
            """INSERT INTO url_artifacts
               (id, message_id, case_id, original_url, domain, url_order, created_at)
               VALUES (?,?,1,?,?,?,?)""",
            (u["id"], u["message_id"], u["original_url"], u["domain"],
             u["url_order"], first_ts),
        )
    print(f"  urls: {len(urls)}")

    # --- 3b. scan_runs (full history; codex round-6 critical) ---
    # Canonical source is urls/scan_runs.csv (v2+). Older exports only
    # flattened the latest scan_run into urls.csv; fall back to that to
    # preserve backward compatibility, but those packs lose any older
    # rescans on restore (and any snapshots referencing them would have
    # FK-failed — which is exactly the bug this fix exists to prevent
    # going forward).
    sr_csv = os.path.join(export_dir, "urls", "scan_runs.csv")
    if os.path.isfile(sr_csv):
        scan_runs = read_csv(sr_csv)
        for sr in scan_runs:
            conn.execute(
                """INSERT INTO scan_runs
                   (id, url_artifact_id, run_at, final_url, hop_count, status, notes,
                    whois_registrar, whois_creation_date, ip_address, asn, as_org, as_country,
                    intel_risk_tags, domain_enriched_at,
                    tls_info_json, final_response_headers_json,
                    corroboration_json, cloaking_signal_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sr["id"], sr["url_artifact_id"],
                 sr.get("run_at", "") or first_ts,
                 sr.get("final_url", ""), sr.get("hop_count", ""),
                 sr.get("status", ""), sr.get("notes", ""),
                 sr.get("whois_registrar", ""), sr.get("whois_creation_date", ""),
                 sr.get("ip_address", ""), sr.get("asn", ""),
                 sr.get("as_org", ""), sr.get("as_country", ""),
                 sr.get("intel_risk_tags", ""), sr.get("domain_enriched_at", ""),
                 sr.get("tls_info_json", "") or None,
                 sr.get("final_response_headers_json", "") or None,
                 sr.get("corroboration_json", "") or None,
                 sr.get("cloaking_signal_json", "") or None),
            )
        print(f"  scan_runs: {len(scan_runs)}")
    else:
        # Legacy export — flatten from urls.csv.
        legacy_count = 0
        for u in urls:
            sr_id = u.get("scan_run_id")
            if not sr_id:
                continue
            conn.execute(
                """INSERT INTO scan_runs
                   (id, url_artifact_id, run_at, final_url, hop_count, status, notes,
                    whois_registrar, whois_creation_date, ip_address, asn, as_org, as_country,
                    intel_risk_tags, domain_enriched_at,
                    tls_info_json, final_response_headers_json,
                    corroboration_json, cloaking_signal_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sr_id, u["id"], first_ts,
                 u.get("final_url", ""), u.get("hop_count", ""),
                 u.get("scan_status", ""), "",
                 u.get("whois_registrar", ""), u.get("whois_creation_date", ""),
                 u.get("ip_address", ""), u.get("asn", ""),
                 u.get("as_org", ""), u.get("as_country", ""),
                 u.get("intel_risk_tags", ""), u.get("domain_enriched_at", ""),
                 u.get("tls_info_json", "") or None,
                 u.get("final_response_headers_json", "") or None,
                 u.get("corroboration_json", "") or None,
                 u.get("cloaking_signal_json", "") or None),
            )
            legacy_count += 1
        print(f"  scan_runs (legacy flatten): {legacy_count}")

    # --- 4. redirect_hops ---
    # v2+ format: scan_run_{sr_id}_hops.csv (one file per scan_run).
    # Legacy format: url_{ua_id}_hops.csv (only the latest scan_run's hops).
    chains_dir = os.path.join(export_dir, "urls", "chains")
    hop_count = 0
    if os.path.isdir(chains_dir):
        for fname in os.listdir(chains_dir):
            if not fname.endswith("_hops.csv"):
                continue
            sr_id = None
            if fname.startswith("scan_run_"):
                # v2 format: scan_run_{sr_id}_hops.csv
                sr_id = fname[len("scan_run_"):-len("_hops.csv")]
            elif fname.startswith("url_"):
                # legacy format: url_{ua_id}_hops.csv → resolve to latest sr
                ua_id = fname[len("url_"):-len("_hops.csv")]
                sr_row = conn.execute(
                    "SELECT id FROM scan_runs WHERE url_artifact_id = ? "
                    "ORDER BY id DESC LIMIT 1", (ua_id,),
                ).fetchone()
                if sr_row:
                    sr_id = str(sr_row["id"])
            if not sr_id:
                continue
            hops = read_csv(os.path.join(chains_dir, fname))
            for h in hops:
                conn.execute(
                    """INSERT INTO redirect_hops
                       (scan_run_id, hop_order, url, status_code, location, resolved_url,
                        fetched_at, response_headers_json)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (sr_id, h["hop_order"], h["url"], h.get("status_code",""),
                     h.get("location",""), h.get("resolved_url",""),
                     h.get("fetched_at",""),
                     h.get("response_headers_json", "") or None),
                )
                hop_count += 1
    print(f"  redirect_hops: {hop_count}")

    # --- 5. snapshots (metadata) ---
    # Export ZIP layout: snapshots/{snapshot_id}/{filename}. Restore lays
    # files out at kwara/data/snapshots/{snapshot_id}/{filename} — flat
    # per-snapshot dirs, matching the ZIP. Live (non-restored) captures use
    # the per-scan_run/per-capture dir scheme; both layouts coexist fine
    # because each snapshot row stores its absolute path.
    snap_csv = os.path.join(export_dir, "snapshots", "snapshots.csv")
    snaps = read_csv(snap_csv)
    for s in snaps:
        sr_id = s["scan_run_id"]
        snap_id = s.get("snapshot_id", "") or "legacy"
        # Build local paths for screenshot / html / har
        ss_src = s.get("screenshot_file", "")
        html_src = s.get("html_file", "")
        har_src = s.get("har_file", "")
        local_ss = (
            os.path.join(SNAP_DST, snap_id, os.path.basename(ss_src))
            if ss_src else ""
        )
        local_html = (
            os.path.join(SNAP_DST, snap_id, os.path.basename(html_src))
            if html_src else ""
        )
        local_har = (
            os.path.join(SNAP_DST, snap_id, os.path.basename(har_src))
            if har_src else ""
        )

        conn.execute(
            """INSERT INTO snapshots
               (scan_run_id, final_url, final_domain, screenshot_path, html_path, har_path,
                request_domains_json, risk_tags, whois_registrar, whois_creation_date,
                captured_at, capture_status, capture_detail,
                ip_address, asn, as_org, as_country,
                tracking_ids_json, capture_method)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sr_id, s.get("final_url",""), s.get("final_domain",""),
             local_ss, local_html, local_har,
             s.get("request_domains",""), s.get("risk_tags",""),
             s.get("whois_registrar",""), s.get("whois_creation_date",""),
             s.get("captured_at",""), s.get("capture_status",""), s.get("capture_detail",""),
             s.get("ip_address",""), s.get("asn",""), s.get("as_org",""),
             s.get("as_country",""),
             s.get("tracking_ids_json", "") or None,
             s.get("capture_method", "") or None),
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
