"""
exporter.py — Evidence Pack ZIP builder

export_case(conn, case_id) -> str
  Builds a ZIP at data/exports/case_{id}_{ts}.zip
  Writes to export_runs, calls write_audit.
  Returns the zip file path.
"""
import csv
import hashlib
import hmac
import io
import json
import os
import sqlite3
import zipfile
from datetime import datetime, timezone

from audit import write_audit
from config import HMAC_KEY

EXPORTS_DIR = os.path.join(os.path.dirname(__file__), "data", "exports")


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _csv_bytes(rows: list[dict], fieldnames: list[str]) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    # utf-8-sig: BOM so Excel on Windows opens Chinese/Latin text as UTF-8, not system code page
    return buf.getvalue().encode("utf-8-sig")


def export_case(conn: sqlite3.Connection, case_id: int) -> str:
    os.makedirs(EXPORTS_DIR, exist_ok=True)
    ts       = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    zip_name = f"case_{case_id}_{ts}.zip"
    zip_path = os.path.join(EXPORTS_DIR, zip_name)

    manifest = {}   # arcname -> sha256

    def add(zf: zipfile.ZipFile, arcname: str, data: bytes):
        zf.writestr(arcname, data)
        manifest[arcname] = _sha256(data)

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:

        # ── messages.csv ────────────────────────────────────────────────
        messages = conn.execute(
            """SELECT id, platform, actor_label, posted_at, permalink,
                      message_text, screenshot_path, ingested_at
               FROM message_evidence WHERE case_id = ? ORDER BY id""",
            (case_id,),
        ).fetchall()

        msg_fields = ["id", "platform", "actor_label", "posted_at", "permalink",
                      "message_text", "has_screenshot", "ingested_at"]
        msg_rows = []
        for r in messages:
            row = dict(r)
            row["has_screenshot"] = bool(r["screenshot_path"] and os.path.exists(r["screenshot_path"]))
            msg_rows.append(row)
        add(zf, "messages/messages.csv", _csv_bytes(msg_rows, msg_fields))

        # screenshots referenced by messages
        for r in messages:
            path = r["screenshot_path"]
            if path and os.path.exists(path):
                with open(path, "rb") as f:
                    data = f.read()
                arc = f"messages/screenshots/{r['id']}_{os.path.basename(path)}"
                add(zf, arc, data)

        # ── urls.csv ────────────────────────────────────────────────────
        urls = conn.execute(
            """SELECT ua.id, ua.original_url, ua.domain,
                      ua.message_id, ua.url_order,
                      sr.id AS scan_run_id, sr.status AS scan_status, sr.final_url, sr.hop_count,
                      sr.whois_registrar, sr.whois_creation_date,
                      sr.ip_address, sr.asn, sr.as_org, sr.as_country,
                      sr.domain_enriched_at, sr.intel_risk_tags,
                      sr.tls_info_json, sr.final_response_headers_json,
                      sr.corroboration_json
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? ORDER BY ua.id""",
            (case_id,),
        ).fetchall()

        url_fields = ["id", "original_url", "domain", "message_id",
                      "url_order", "scan_run_id", "scan_status", "final_url", "hop_count",
                      "whois_registrar", "whois_creation_date",
                      "ip_address", "asn", "as_org", "as_country",
                      "domain_enriched_at", "intel_risk_tags",
                      "tls_info_json", "final_response_headers_json",
                      "corroboration_json"]
        add(zf, "urls/urls.csv",
            _csv_bytes([dict(r) for r in urls], url_fields))

        # redirect chain per URL
        for u in urls:
            if not u["scan_run_id"]:
                continue
            hops = conn.execute(
                """SELECT hop_order, url, status_code, location, resolved_url, fetched_at
                   FROM redirect_hops WHERE scan_run_id = ? ORDER BY hop_order""",
                (u["scan_run_id"],),
            ).fetchall()
            if hops:
                hop_fields = ["hop_order", "url", "status_code", "location",
                              "resolved_url", "fetched_at"]
                add(zf, f"urls/chains/url_{u['id']}_hops.csv",
                    _csv_bytes([dict(h) for h in hops], hop_fields))

        # ── snapshots ───────────────────────────────────────────────────
        snaps = conn.execute(
            """SELECT s.id, s.scan_run_id, s.final_url, s.final_domain,
                      s.screenshot_path, s.html_path,
                      s.ip_address, s.asn, s.as_org, s.as_country,
                      s.whois_registrar, s.whois_creation_date,
                      s.risk_tags, s.request_domains_json, s.captured_at,
                      s.capture_status, s.capture_detail
               FROM snapshots s
               JOIN scan_runs sr ON sr.id = s.scan_run_id
               JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
               WHERE ua.case_id = ? ORDER BY s.id""",
            (case_id,),
        ).fetchall()

        snap_meta = []
        for s in snaps:
            # Archive path keyed on snapshot.id, not scan_run_id (codex review):
            # multiple snapshot rows for the same scan_run otherwise collide
            # in the ZIP, leaving the file content of only the last one
            # while exporting metadata for all of them.
            snap_id = s["id"]
            sr_id = s["scan_run_id"]
            sr_row = conn.execute(
                """SELECT whois_registrar, whois_creation_date, ip_address, asn, as_org, as_country
                   FROM scan_runs WHERE id = ?""",
                (sr_id,),
            ).fetchone()
            screenshot_arc = ""
            html_arc = ""
            if s["screenshot_path"] and os.path.exists(s["screenshot_path"]):
                screenshot_arc = f"snapshots/{snap_id}/{os.path.basename(s['screenshot_path'])}"
                with open(s["screenshot_path"], "rb") as f:
                    add(zf, screenshot_arc, f.read())
            if s["html_path"] and os.path.exists(s["html_path"]):
                html_arc = f"snapshots/{snap_id}/{os.path.basename(s['html_path'])}"
                with open(s["html_path"], "rb") as f:
                    add(zf, html_arc, f.read())

            def _coalesce_snap(k_snap: str, k_sr: str):
                v = s[k_snap]
                if v is not None and str(v).strip() != "":
                    return v
                if sr_row and sr_row[k_sr] is not None and str(sr_row[k_sr]).strip() != "":
                    return sr_row[k_sr]
                return v

            snap_meta.append({
                "snapshot_id":        snap_id,
                "scan_run_id":        sr_id,
                "final_url":          s["final_url"],
                "final_domain":       s["final_domain"],
                "ip_address":         _coalesce_snap("ip_address", "ip_address"),
                "asn":                _coalesce_snap("asn", "asn"),
                "as_org":             _coalesce_snap("as_org", "as_org"),
                "as_country":         _coalesce_snap("as_country", "as_country"),
                "whois_registrar":    _coalesce_snap("whois_registrar", "whois_registrar"),
                "whois_creation_date": _coalesce_snap("whois_creation_date", "whois_creation_date"),
                "risk_tags":          s["risk_tags"],
                "request_domains":    s["request_domains_json"],
                "screenshot_file":    screenshot_arc,
                "html_file":          html_arc,
                "captured_at":        s["captured_at"],
                "capture_status":     s["capture_status"] or "",
                "capture_detail":     s["capture_detail"] or "",
            })

        if snap_meta:
            snap_fields = ["snapshot_id", "scan_run_id", "final_url", "final_domain",
                           "ip_address", "asn", "as_org", "as_country",
                           "whois_registrar", "whois_creation_date",
                           "risk_tags", "request_domains",
                           "screenshot_file", "html_file", "captured_at",
                           "capture_status", "capture_detail"]
            add(zf, "snapshots/snapshots.csv",
                _csv_bytes(snap_meta, snap_fields))

        # ── audit.csv ───────────────────────────────────────────────────
        audit_rows = conn.execute(
            "SELECT id, case_id, actor, action, at, meta_json FROM audit_log WHERE case_id = ? ORDER BY id",
            (case_id,),
        ).fetchall()
        add(zf, "audit.csv",
            _csv_bytes([dict(r) for r in audit_rows],
                       ["id", "case_id", "actor", "action", "at", "meta_json"]))

        # ── README.txt ──────────────────────────────────────────────────
        snap_count    = len(snap_meta)
        has_snap_file = sum(1 for s in snap_meta if s["screenshot_file"])
        has_html_file = sum(1 for s in snap_meta if s["html_file"])
        msg_with_ss   = sum(1 for r in msg_rows if r["has_screenshot"])
        scanned_count = sum(1 for r in urls if r["scan_run_id"] is not None)

        readme = f"""kwara — Evidence Pack
Case ID  : {case_id}
Exported : {_now()}
ZIP file : {zip_name}

────────────────────────────────────────────────────────────
FILE STRUCTURE
────────────────────────────────────────────────────────────

messages/
  messages.csv
    All source posts ingested for this case.
    Columns: id, platform, actor_label, posted_at, permalink,
             message_text, has_screenshot, ingested_at
    has_screenshot = True means a screenshot file is present
    in messages/screenshots/ for that row.

  screenshots/  ({msg_with_ss} file(s))
    Post screenshots uploaded at ingestion time.
    Filename format: {{message_id}}_{{original_filename}}
    Only present for posts where has_screenshot = True.

urls/
  urls.csv
    All URLs extracted from source posts.
    Columns: id, original_url, domain, message_id, url_order,
             scan_run_id, scan_status, final_url, hop_count,
             whois_registrar, whois_creation_date,
             ip_address, asn, as_org, as_country,
             domain_enriched_at, intel_risk_tags,
             tls_info_json, final_response_headers_json
    tls_info_json: JSON with issuer, subject, notBefore, notAfter,
                   serialNumber, subjectAltName (from final landing page
                   TLS certificate); null if HTTP or handshake failed.
    final_response_headers_json: JSON array of [key, value] pairs for
                   all HTTP response headers from the final landing page
                   (preserves duplicates e.g. Set-Cookie); null if scan
                   terminated before reaching a non-3xx response.
    scan_run_id links to snapshots/snapshots.csv.
    scan_status values: done, error, timeout, ssl_error,
                        loop_detected, max_hops, or blank if unscanned.
    Total URLs : {len(urls)}
    Scanned    : {scanned_count}
    Unscanned  : {len(urls) - scanned_count}

  chains/
    One CSV per scanned URL showing every redirect hop.
    Filename format: url_{{url_artifact_id}}_hops.csv
    Columns: hop_order, url, status_code, location,
             resolved_url, fetched_at

snapshots/
  snapshots.csv  ({snap_count} record(s))
    Metadata for every snapshot attempt (including failed ones).
    One row per snapshot — multiple snapshots for the same scan_run
    are kept distinct via snapshot_id.
    Columns: snapshot_id, scan_run_id, final_url, final_domain,
             ip_address, asn, as_org, as_country,
             whois_registrar, whois_creation_date,
             risk_tags, request_domains,
             screenshot_file, html_file, captured_at
    screenshot_file / html_file contain the ZIP-relative path
    to the binary file, or are blank if capture failed.
    risk_tags values: multi_hop, no_https, new_domain,
                      suspicious_download, high_tracker_count,
                      url_shortener_chain, capture_error

  {{snapshot_id}}/
    Per-snapshot directory (one per snapshot.id). Multiple captures
    of the same scan are preserved as distinct directories so older
    evidence isn't overwritten.
    screenshot.png  ({has_snap_file} file(s))
      Full-page screenshot of the landing page.
      Only present where screenshot_file column is non-blank.
    page.html / page_http_only.html  ({has_html_file} file(s))
      Raw HTML at time of capture. page_http_only.html marks
      lightweight (requests.get-based) captures.
      Only present where html_file column is non-blank.

audit.csv
  Full action log for this case (ingestion, scans, snapshots, exports).
  Columns: id, case_id, actor, action, at, meta_json

manifest.json
  SHA-256 hash of every file in this ZIP (excluding the manifest
  files themselves). Use to verify integrity of the evidence pack.
  When KWARA_HMAC_KEY was not set at export time, contains an
  `integrity_warning` field making the lack of cryptographic
  signature explicit.

manifest.sha256
  SHA-256 of manifest.json itself, in `<hash>  manifest.json` format
  (compatible with `sha256sum -c`). Lets a reviewer verify the
  manifest hasn't been tampered with via an out-of-band channel
  (e.g. the hash printed on a report cover page).

manifest.sig  (present only when KWARA_HMAC_KEY is set)
  HMAC-SHA256 signature of manifest.json.
  Proves the evidence pack has not been tampered with since export.
  Verify: hmac.new(key_bytes, manifest_json_bytes, 'sha256').hexdigest()

────────────────────────────────────────────────────────────
CROSS-REFERENCE
────────────────────────────────────────────────────────────

  messages.csv  id
      └─ urls.csv  message_id  (URLs found in that post)
            └─ urls/chains/url_{{id}}_hops.csv  (redirect chain)
            └─ snapshots.csv  snapshot_id, scan_run_id  (landing page analysis)
                  └─ snapshots/{{snapshot_id}}/  (screenshot + HTML)

────────────────────────────────────────────────────────────
正體中文摘要
────────────────────────────────────────────────────────────

此 ZIP 為 kwara 證據封存包。
案件 ID：{case_id}　匯出時間：{_now()}

包含內容：
  messages/    — 來源貼文及截圖
  urls/        — 所有擷取的 URL、掃描結果、redirect chain
  snapshots/   — 落地頁截圖、HTML、WHOIS/ASN、風險旗標
  audit.csv    — 完整操作紀錄
  manifest.json — 所有檔案的 SHA-256 雜湊值（驗證完整性）
  manifest.sig  — HMAC 簽章（若有設定密鑰）

各 CSV 以 id / scan_run_id / message_id 互相對應，
詳細欄位說明請參閱上方英文段落。
"""
        add(zf, "README.txt", readme.encode("utf-8"))

        # ── manifest.json ───────────────────────────────────────────────
        # Codex review #3: the manifest hash list omits manifest.json and
        # manifest.sig themselves. Without HMAC_KEY, an attacker can replace
        # the manifest+sig pair to lie about every other file's hash.
        # We mitigate by:
        #   1. Always writing manifest.sha256 — a one-line companion file
        #      that hashes manifest.json itself. A reviewer can verify it
        #      out-of-band (e.g. printed on the cover page of the report).
        #   2. Writing the existing HMAC signature when HMAC_KEY is set —
        #      cryptographically anchors manifest.json to the export key.
        #   3. Embedding an integrity_warning field in manifest.json that
        #      makes the lack-of-key state explicit.
        manifest_payload = {
            "case_id":   case_id,
            "export_at": _now(),
            "zip_name":  zip_name,
            "files":     manifest,
        }
        if not HMAC_KEY:
            manifest_payload["integrity_warning"] = (
                "KWARA_HMAC_KEY was not set when this pack was exported. "
                "manifest.sha256 lets a reviewer verify manifest.json "
                "out-of-band, but no cryptographic signature is included. "
                "Export with KWARA_HMAC_KEY set for chain-of-custody-grade "
                "integrity."
            )
        manifest_data = json.dumps(
            manifest_payload, indent=2, ensure_ascii=False
        ).encode("utf-8")
        zf.writestr("manifest.json", manifest_data)
        manifest_sha = _sha256(manifest_data)
        zf.writestr("manifest.sha256", f"{manifest_sha}  manifest.json\n".encode("utf-8"))

        # ── manifest.sig (HMAC-SHA256, optional) ────────────────────
        if HMAC_KEY:
            sig = hmac.new(HMAC_KEY.encode("utf-8"), manifest_data, hashlib.sha256).hexdigest()
            sig_payload = json.dumps({
                "algorithm": "HMAC-SHA256",
                "signature": sig,
                "note": "Verify with: hmac.new(key, manifest_json_bytes, 'sha256').hexdigest()",
            }, indent=2).encode("utf-8")
            zf.writestr("manifest.sig", sig_payload)

    # Write export_runs record
    manifest_json = json.dumps({"zip_name": zip_name, "file_count": len(manifest)})
    conn.execute(
        "INSERT INTO export_runs (case_id, export_at, zip_path, manifest_json) VALUES (?, ?, ?, ?)",
        (case_id, _now(), zip_path, manifest_json),
    )
    conn.commit()

    write_audit(conn, "export_case", case_id=case_id,
                meta={"zip_name": zip_name, "file_count": len(manifest)})

    return zip_path
