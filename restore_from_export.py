"""
Restore kwara SQLite DB + snapshot files from an evidence-pack export folder.

Usage:
    python restore_from_export.py <export_dir> [--case-title TITLE]

This reads the CSVs produced by exporter.py and reconstructs the DB at
kwara/data/kwara.db, plus copies snapshot files into kwara/data/snapshots/.
"""
import csv
import os
import hashlib
import shutil
import sqlite3
import sys

# Imported as a package, and pointed at the configured data root. This used to
# insert kwara/ into sys.path and import `db` flatly, which survived the
# package refactor only because db.py happens to have no relative imports of
# its own — it would have broken silently the moment it gained one. The paths
# were also pinned beside the package, so a restore ignored KWARA_DATA_DIR and
# rebuilt the case somewhere the rest of the tool was not looking.
from kwara.config import DB_PATH, SNAPSHOT_ROOT
from kwara.db import init_db, migrate_db, get_conn

SNAP_DST = SNAPSHOT_ROOT


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
                    corroboration_json, cloaking_signal_json, ads_txt_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                 sr.get("cloaking_signal_json", "") or None,
                 # Carries raw_sha256 and acquisition_id: without it a restored
                 # database has the ads.txt bytes but no record naming them, so
                 # re-running the analysis cannot reproduce the clustering.
                 sr.get("ads_txt_json", "") or None),
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
                    corroboration_json, cloaking_signal_json, ads_txt_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                 u.get("cloaking_signal_json", "") or None,
                 # A legacy pack predates ads.txt retention entirely, so this
                 # is always absent — but the placeholder count has to match
                 # or every legacy restore raises.
                 u.get("ads_txt_json", "") or None),
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
    # A case with no captures produces no snapshots.csv — the exporter writes
    # it only when there is something to write. Restore crashed on those packs,
    # which is every ads.txt-only case.
    snap_csv = os.path.join(export_dir, "snapshots", "snapshots.csv")
    snaps = read_csv(snap_csv) if os.path.isfile(snap_csv) else []
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

    # --- 5b. acquisitions: the ads.txt response bytes ---
    # Restored so the recipient can re-derive a template match rather than
    # trust the number we shipped. Bodies land beside the database and each
    # row's path is rewritten to point there; a body whose hash no longer
    # matches is reported and the row is kept with its path cleared, because
    # a row pointing at wrong bytes is worse than a row pointing at none.
    acq_csv = os.path.join(export_dir, "acquisitions", "acquisitions.csv")
    if os.path.isfile(acq_csv):
        acq_dst = os.path.join(os.path.dirname(DB_PATH), "acquisitions",
                               "restored")
        os.makedirs(acq_dst, exist_ok=True)
        rows = read_csv(acq_csv)
        restored = mismatched = 0
        for a in rows:
            body_path = None
            arc = (a.get("body_file") or "").strip()
            if arc:
                src = os.path.join(export_dir, arc)
                if os.path.isfile(src):
                    with open(src, "rb") as fh:
                        data = fh.read()
                    if hashlib.sha256(data).hexdigest() == a.get("captured_sha256"):
                        dst = os.path.join(acq_dst, os.path.basename(arc))
                        with open(dst, "wb") as fh:
                            fh.write(data)
                        body_path = dst
                        restored += 1
                    else:
                        mismatched += 1
                        print(f"  ! acquisition {a['id']}: body hash mismatch, "
                              f"path left empty")
                else:
                    mismatched += 1
                    print(f"  ! acquisition {a['id']}: body missing from pack")
            conn.execute(
                """INSERT INTO acquisitions
                     (id, kind, scan_run_id, requested_url, final_url,
                      redirect_chain_json, status, status_code, fetched_at,
                      response_headers_json, user_agent, tool_version,
                      truncated, captured_bytes, body_path, captured_sha256,
                      complete_sha256, error)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (a["id"], a.get("kind", "ads_txt"), a.get("scan_run_id") or None,
                 a.get("requested_url", ""), a.get("final_url") or None,
                 a.get("redirect_chain_json") or None, a.get("status", ""),
                 a.get("status_code") or None, a.get("fetched_at", ""),
                 a.get("response_headers_json") or None,
                 a.get("user_agent") or None, a.get("tool_version") or None,
                 int(a.get("truncated") or 0), int(a.get("captured_bytes") or 0),
                 body_path, a.get("captured_sha256") or None,
                 a.get("complete_sha256") or None, a.get("error") or None),
            )
        print(f"  acquisitions: {len(rows)} ({restored} bodies verified"
              + (f", {mismatched} UNUSABLE" if mismatched else "") + ")")

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
    for entry in (os.listdir(snap_src_dir)
                  if os.path.isdir(snap_src_dir) else []):
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
