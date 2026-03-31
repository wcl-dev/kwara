import json
import os
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse as _urlparse

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(__file__))

from db import get_conn, init_db, migrate_db
from ingestion import ingest_message, ingest_csv
from pipeline import run_scan_only, run_snapshot
from clustering import shared_destinations, shared_params, asn_clusters, KNOWN_SHORTLINK_DOMAINS
from snapshots import SUSPICIOUS_EXTS as _SUSP_EXTS
from exporter import export_case

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "kwara.db")

st.set_page_config(page_title="kwara", layout="wide")


@st.cache_resource
def _init_db_once():
    conn = get_conn(DB_PATH)
    init_db(conn)
    migrate_db(conn)
    conn.close()


_init_db_once()
conn = get_conn(DB_PATH)


def now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@st.dialog("How to Use kwara")
def _show_guide():
    st.markdown("""
**kwara** helps you collect, scan, and document URL shortener and domain abuse evidence.

---

#### 1. Input
Add evidence from a single post or bulk CSV.
- **Single Post** — paste text containing URLs, fill in platform/actor metadata, attach a screenshot.
- **CSV Batch** — upload a spreadsheet with columns: `platform`, `permalink`, `actor_label`, `posted_at`, `message_text`.

URLs are automatically extracted and deduplicated. All fields except Message Text are optional.

---

#### 2. Collected
Review everything ingested for the active case.
- **Source Posts** — original messages with metadata.
- **Extracted URLs** — all URLs found, with their domain, scan status, and final destination.

---

#### 3. Analysis

**Scan** — follow each URL's redirect chain hop by hop.
- Batch-scan all unscanned URLs at once (parallel, 8 workers).
- Scan individual URLs via the expander.
- If a scan was interrupted mid-run it will appear as **Stuck**. Use the Reset button to mark it failed and re-scan.

**Investigate** — deep-dive into any scanned URL.
- **Priority Queue** — URLs that have been scanned but not yet snapshotted, sorted by scan-time risk signals. Higher flag count = investigate first.
- **URL selector** — sorted by risk flag count; label shows scan status, snapshot status, and flags at a glance.
- **Snapshot & WHOIS All** — captures a headless browser screenshot and WHOIS for every pending URL in sequence. Slow (10–30 s each) — a warning shows the estimated time before you confirm.
- Per-URL detail: full redirect chain · landing page screenshot · WHOIS (registrar, domain creation date) · risk flags · request domains contacted during page load.

**Clusters** — factual groupings across scanned URLs:
- **Scanned Destinations** — all final domains reached. The table shows total URLs, how many are flagged, post count, and per-flag counts (e.g. `🔴 multi_hop ×2`). Drill in to see individual shortlinks sorted by flag severity. URLs where the scan stopped at the shortlink service itself (did not penetrate to the real destination) are listed separately.
- **Shared URL Parameters** — query parameter key=value pairs that appear in 2+ distinct posts, checked in both the original shortlink and the final URL.

---

#### 4. Providers
Surfaces the **service providers** relevant to the abuse:
- **Shortlink Providers** — known shortlink services (e.g. bit.ly, t.co) used in this case. Drill in to see all URLs for that provider, sorted by risk flags.
- **Domain Registrars** — registrars of the abuse landing domains (populated after capturing snapshots).

Use this tab to identify who to send abuse reports to.

---

#### 5. Export
Download a ZIP evidence pack. A **README.txt** at the root explains every file and column in plain language, including cross-reference keys between CSVs.

Contents: source posts · extracted URLs · redirect chains · snapshot metadata (WHOIS, risk flags, request domains) · landing page screenshots and HTML where capture succeeded · audit log · SHA-256 manifest.

`snapshots/snapshots.csv` lists all snapshot attempts. The `screenshot_file` and `html_file` columns show the ZIP-relative path to binary files, or are blank if capture failed — so you always know exactly what is and isn't present.
""")


TAG_COLORS = {
    "multi_hop":           "🔴",
    "suspicious_download": "🔴",
    "new_domain":          "🔴",
    "no_https":            "🟠",
    "high_tracker_count":  "🟡",
    "url_shortener_chain": "🟡",
    "capture_error":       "⚫",
}

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.title("kwara")
    if st.button("How to Use", key="btn_guide", use_container_width=True):
        _show_guide()
    st.divider()

    with st.expander("+ New Case", expanded=False):
        new_title = st.text_input("Title", key="new_case_title")
        new_desc  = st.text_area("Description", key="new_case_desc", height=80)
        if st.button("Create", key="btn_create_case"):
            if new_title.strip():
                now = now_utc()
                conn.execute(
                    "INSERT INTO cases (title, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (new_title.strip(), new_desc.strip(), now, now),
                )
                conn.commit()
                st.success(f"Case created: {new_title.strip()}")
                st.rerun()
            else:
                st.warning("Title is required.")

    st.divider()
    cases = conn.execute("SELECT id, title FROM cases ORDER BY id DESC").fetchall()
    if cases:
        case_options    = {f"[{r['id']}] {r['title']}": r["id"] for r in cases}
        selected_label  = st.selectbox("Active Case", list(case_options.keys()))
        current_case_id = case_options[selected_label]
    else:
        st.info("No cases yet. Create one above.")
        current_case_id = None

# ---------------------------------------------------------------------------
# Guard
# ---------------------------------------------------------------------------
st.markdown("#### kwara — URL Shortener and Domain Abuse Evidence Kit")

if current_case_id is None:
    st.warning("Create and select a case in the sidebar to get started.")
    st.stop()

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
def _scan_flags(final_url, hop_count):
    """Risk signals derivable from scan data alone, before snapshot."""
    flags = []
    fu = final_url or ""
    if not fu:
        return flags
    p = _urlparse(fu)
    if (hop_count or 0) >= 3:
        flags.append("multi_hop")
    if p.scheme == "http":
        flags.append("no_https")
    if any(p.path.lower().endswith(e) for e in _SUSP_EXTS):
        flags.append("suspicious_download")
    if (p.hostname or "") in KNOWN_SHORTLINK_DOMAINS:
        flags.append("url_shortener_chain")
    return flags


tab_input, tab_evidence, tab_analysis, tab_providers, tab_export = st.tabs(
    ["Input", "Collected", "Analysis", "Providers", "Export"]
)

# ===========================================================================
# INPUT
# ===========================================================================
with tab_input:
    mode = st.radio("", ["Single Post", "CSV Batch"], horizontal=True, key="input_mode")
    st.divider()

    # ── Single Post ─────────────────────────────────────────────────────────
    if mode == "Single Post":
        c1, c2 = st.columns(2)
        with c1:
            platform   = st.text_input("Platform", key="p_platform", placeholder="e.g. Twitter, Telegram")
            permalink  = st.text_input("Permalink", key="p_permalink")
        with c2:
            actor      = st.text_input("Actor Label", key="p_actor", placeholder="e.g. @username, channel name")
            posted_at  = st.text_input("Posted At", key="p_posted_at", placeholder="e.g. 2024-01-15 08:30")
        message_text = st.text_area("Message Text — paste content containing URLs", height=150, key="p_text")
        screenshot   = st.file_uploader("Screenshot (optional)", type=["png", "jpg", "jpeg", "webp"], key="p_screenshot")

        if st.button("Submit", type="primary", key="btn_submit_post"):
            if not message_text.strip():
                st.warning("Message Text is required.")
            else:
                screenshot_path = ""
                if screenshot:
                    save_dir = os.path.join(os.path.dirname(__file__), "data", "screenshots")
                    os.makedirs(save_dir, exist_ok=True)
                    screenshot_path = os.path.join(save_dir, screenshot.name)
                    with open(screenshot_path, "wb") as f:
                        f.write(screenshot.read())

                msg_id, urls = ingest_message(
                    conn, current_case_id,
                    message_text=message_text, platform=platform,
                    permalink=permalink, actor_label=actor,
                    posted_at=posted_at, screenshot_path=screenshot_path,
                )
                st.success(f"Saved — {len(urls)} URL(s) extracted.")
                for u in urls:
                    st.code(u)

    # ── CSV Batch ───────────────────────────────────────────────────────────
    else:
        st.caption("Required columns: `platform`, `permalink`, `actor_label`, `posted_at`, `message_text`")
        uploaded_csv = st.file_uploader("Upload .csv", type=["csv"], key="csv_upload")

        if uploaded_csv:
            try:
                df_preview = pd.read_csv(uploaded_csv)
                st.write("**Preview (first 5 rows):**")
                st.dataframe(df_preview.head(5), use_container_width=True)
                uploaded_csv.seek(0)
            except Exception as e:
                st.error(f"Cannot parse CSV: {e}")
                df_preview = None

            if st.button("Import", type="primary", key="btn_submit_csv"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="wb") as tmp:
                    tmp.write(uploaded_csv.read())
                    tmp_path = tmp.name
                try:
                    results   = ingest_csv(conn, current_case_id, tmp_path)
                    total_urls = sum(r["url_count"] for r in results)
                    st.success(f"Imported {len(results)} post(s), {total_urls} URL(s).")
                except Exception as e:
                    st.error(f"Import failed: {e}")
                finally:
                    os.unlink(tmp_path)

# ===========================================================================
# EVIDENCE
# ===========================================================================
with tab_evidence:
    # ── Source Posts ─────────────────────────────────────────────────────────
    st.subheader("Source Posts")

    messages = conn.execute(
        """SELECT id, platform, actor_label AS actor, posted_at,
                  permalink, substr(message_text, 1, 100) AS message_preview,
                  ingested_at
           FROM message_evidence WHERE case_id = ? ORDER BY id DESC""",
        (current_case_id,),
    ).fetchall()

    if messages:
        st.dataframe(pd.DataFrame([dict(r) for r in messages]), use_container_width=True, hide_index=True)
    else:
        st.info("No source posts yet. Add content in the Input tab.")

    st.divider()

    # ── Extracted URLs ───────────────────────────────────────────────────────
    st.subheader("Extracted URLs")
    artifacts = conn.execute(
        """SELECT ua.id, ua.original_url AS url, ua.domain,
                  ua.message_id AS source_post_id,
                  sr.status AS scan_status, sr.final_url
           FROM url_artifacts ua
           LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
               AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
           WHERE ua.case_id = ?
           ORDER BY ua.message_id, ua.url_order""",
        (current_case_id,),
    ).fetchall()

    if artifacts:
        st.dataframe(pd.DataFrame([dict(r) for r in artifacts]), use_container_width=True, hide_index=True)
    else:
        st.info("No URLs extracted yet.")

# ===========================================================================
# ANALYSIS
# ===========================================================================
with tab_analysis:
    sub_scan, sub_investigate, sub_clusters = st.tabs(["Scan", "Investigate", "Clusters"])

    # ── Scan ─────────────────────────────────────────────────────────────────
    with sub_scan:
        url_rows = conn.execute(
            """SELECT ua.id, ua.original_url, ua.domain,
                      sr.id AS scan_run_id, sr.status, sr.hop_count, sr.final_url
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? ORDER BY ua.id""",
            (current_case_id,),
        ).fetchall()

        if not url_rows:
            st.info("No URLs found. Add content in the Input tab.")
        else:
            unscanned    = [r for r in url_rows if r["scan_run_id"] is None]
            stuck        = [r for r in url_rows if r["status"] == "running"]
            done_count   = sum(1 for r in url_rows if r["status"] == "done")
            failed_count = sum(1 for r in url_rows if r["status"] not in (None, "done", "running"))

            m1, m2, m3, m4, m5 = st.columns(5)
            m1.metric("Total",     len(url_rows))
            m2.metric("Unscanned", len(unscanned))
            m3.metric("Done",      done_count)
            m4.metric("Failed",    failed_count)
            m5.metric("Stuck",     len(stuck))

            if stuck:
                st.warning(f"{len(stuck)} scan(s) stuck in 'running' — likely interrupted. Reset them to re-scan.")
                if st.button(f"Reset stuck ({len(stuck)})", key="btn_reset_stuck"):
                    for r in stuck:
                        conn.execute("UPDATE scan_runs SET status='error', notes='interrupted' WHERE id=?", (r["scan_run_id"],))
                    conn.commit()
                    st.rerun()

            def _scan_worker(ua_id: int):
                import random, time
                time.sleep(random.uniform(0, 2))
                c = get_conn(DB_PATH)
                try:
                    run_scan_only(c, ua_id)
                except Exception as e:
                    return ua_id, str(e)
                finally:
                    c.close()
                return ua_id, "ok"

            if st.button(f"Scan all unscanned ({len(unscanned)})", disabled=len(unscanned) == 0, type="primary"):
                prog  = st.progress(0.0, text="Starting…")
                total = len(unscanned)
                done  = 0
                with ThreadPoolExecutor(max_workers=8) as ex:
                    futs = {ex.submit(_scan_worker, r["id"]): r for r in unscanned}
                    for fut in as_completed(futs):
                        done += 1
                        url  = futs[fut]["original_url"]
                        prog.progress(done / total, text=f"{done}/{total} — {url[:70]}")
                prog.progress(1.0, text=f"Done — {total} URLs scanned")
                st.rerun()

            st.divider()

            # Compact dataframe — avoids rendering N×4 Streamlit elements
            df_scan = pd.DataFrame([{
                "url":    r["original_url"],
                "domain": r["domain"] or "—",
                "status": r["status"] or "unscanned",
                "hops":   r["hop_count"] if r["hop_count"] is not None else "—",
                "final":  r["final_url"] or "—",
            } for r in url_rows])
            st.dataframe(df_scan, use_container_width=True, hide_index=True)

            with st.expander(f"Scan individual URL ({len(url_rows)} total)"):
                for r in url_rows:
                    c_url, c_btn = st.columns([8, 1])
                    with c_url:
                        st.code(r["original_url"], language=None)
                    with c_btn:
                        label = "Scan" if r["scan_run_id"] is None else "Re-scan"
                        if st.button(label, key=f"scan_{r['id']}"):
                            with st.spinner("Scanning…"):
                                run_scan_only(conn, r["id"])
                            st.rerun()

    # ── Investigate ──────────────────────────────────────────────────────────
    with sub_investigate:
        inv_rows = conn.execute(
            """SELECT ua.id AS ua_id, ua.original_url, ua.domain,
                      sr.id AS scan_run_id, sr.status AS scan_status,
                      sr.final_url, sr.hop_count,
                      s.id   AS snapshot_id,
                      s.risk_tags AS snapshot_risk_tags
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               LEFT JOIN snapshots s ON s.scan_run_id = sr.id
                   AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? ORDER BY ua.id""",
            (current_case_id,),
        ).fetchall()

        if not inv_rows:
            st.info("No URLs found. Add content in the Input tab.")
        else:
            # ── Priority Queue ────────────────────────────────────────────
            pending_snap = [
                r for r in inv_rows
                if r["scan_run_id"] and r["final_url"] and not r["snapshot_id"]
            ]
            if pending_snap:
                priority_rows = []
                for r in pending_snap:
                    flags = _scan_flags(r["final_url"], r["hop_count"])
                    priority_rows.append({
                        "url":          r["original_url"],
                        "final_domain": (_urlparse(r["final_url"]).hostname or "—"),
                        "hops":         r["hop_count"] or "—",
                        "scan_flags":   ", ".join(flags) if flags else "—",
                        "flag_count":   len(flags),
                    })
                priority_rows.sort(key=lambda x: -x["flag_count"])

                st.subheader(f"Snapshot Priority Queue ({len(pending_snap)} pending)")
                st.caption("Scanned but not yet snapshotted — sorted by scan-time risk signals. Higher flag count = investigate first.")
                df_priority = pd.DataFrame([{k: v for k, v in r.items() if k != "flag_count"} for r in priority_rows])
                st.dataframe(df_priority, use_container_width=True, hide_index=True)

                st.warning(
                    "**Snapshot & WHOIS All** launches a headless browser for every pending URL sequentially. "
                    "This is slow (10–30 s per URL) and CPU-intensive. "
                    f"Estimated time for {len(pending_snap)} URLs: "
                    f"{len(pending_snap) * 15 // 60}–{len(pending_snap) * 30 // 60} minutes."
                )
                if st.button(f"Snapshot & WHOIS All ({len(pending_snap)} pending)", key="btn_snap_all"):
                    prog = st.progress(0.0, text="Starting…")
                    total = len(pending_snap)
                    for i, r in enumerate(pending_snap, 1):
                        prog.progress(i / total, text=f"{i}/{total} — {r['original_url'][:70]}")
                        run_snapshot(conn, r["scan_run_id"])
                    prog.progress(1.0, text=f"Done — {total} snapshots captured")
                    st.rerun()

                st.divider()

            # ── URL selector ─────────────────────────────────────────────
            def _label(r):
                scan = r["scan_status"] or "not scanned"
                snap = "snap ✓" if r["snapshot_id"] else "no snap"
                if r["snapshot_id"]:
                    flags = json.loads(r["snapshot_risk_tags"] or "[]")
                else:
                    flags = _scan_flags(r["final_url"], r["hop_count"])
                flag_str = " · " + ", ".join(flags) if flags else ""
                return f"{r['original_url']}  [{scan} · {snap}{flag_str}]"

            def _flag_count(r):
                if r["snapshot_id"]:
                    return len(json.loads(r["snapshot_risk_tags"] or "[]"))
                return len(_scan_flags(r["final_url"], r["hop_count"]))

            sorted_rows = sorted(inv_rows, key=lambda r: (_flag_count(r), r["ua_id"]), reverse=True)
            # Deduplicate by ua_id (keep all unique artifacts, even if same original_url)
            _seen_ua = set()
            _unique_rows = []
            for r in sorted_rows:
                if r["ua_id"] not in _seen_ua:
                    _seen_ua.add(r["ua_id"])
                    _unique_rows.append(r)
            _label_map = {f"[{r['ua_id']}] {_label(r)}": r for r in _unique_rows}

            # After a snapshot, restore the previously selected ua_id
            _preferred = st.session_state.get("inv_last_ua_id")
            _default = 0
            _keys = list(_label_map.keys())
            if _preferred:
                for i, k in enumerate(_keys):
                    if _label_map[k]["ua_id"] == _preferred:
                        _default = i
                        break

            sel = _label_map[st.selectbox("Select URL", _keys, index=_default, key="inv_select")]
            st.divider()

            col_l, col_r = st.columns(2)

            with col_l:
                st.subheader("Redirect Chain")
                if not sel["scan_run_id"]:
                    st.info("Not scanned yet. Go to the Scan tab.")
                else:
                    st.caption(f"Final URL: `{sel['final_url']}` · {sel['hop_count']} hops · {sel['scan_status']}")
                    hops = conn.execute(
                        "SELECT hop_order, url, status_code, location FROM redirect_hops WHERE scan_run_id = ? ORDER BY hop_order",
                        (sel["scan_run_id"],),
                    ).fetchall()
                    if hops:
                        st.dataframe(pd.DataFrame([dict(h) for h in hops]), use_container_width=True, hide_index=True)

            with col_r:
                st.subheader("Snapshot & WHOIS")
                if not sel["scan_run_id"] or not sel["final_url"]:
                    st.info("Complete a scan first.")
                else:
                    snap = conn.execute(
                        "SELECT * FROM snapshots WHERE scan_run_id = ? ORDER BY id DESC LIMIT 1",
                        (sel["scan_run_id"],),
                    ).fetchone()

                    if st.button("Re-capture" if snap else "Capture snapshot", key="btn_snap"):
                        st.session_state["inv_last_ua_id"] = sel["ua_id"]
                        with st.spinner("Capturing screenshot + WHOIS..."):
                            try:
                                run_snapshot(conn, sel["scan_run_id"])
                            except Exception as e:
                                st.error(f"Snapshot failed: {e}")
                                st.stop()
                        st.rerun()

                    if snap:
                        if snap["screenshot_path"] and os.path.exists(snap["screenshot_path"]):
                            st.image(snap["screenshot_path"], use_container_width=True)
                        else:
                            st.warning("Screenshot file missing.")

                        st.write(f"**Final Domain:** {snap['final_domain']}")
                        st.write(f"**IP Address:** {snap['ip_address'] or '—'}")
                        _asn_str = (
                            f"AS{snap['asn']}  {snap['as_org'] or ''}  ({snap['as_country'] or '—'})"
                            if snap["asn"] else "—"
                        )
                        st.write(f"**ASN / Hosting:** {_asn_str}")
                        st.write(f"**Registrar:** {snap['whois_registrar'] or '—'}")
                        st.write(f"**Domain Created:** {snap['whois_creation_date'] or '—'}")

                        tags = json.loads(snap["risk_tags"] or "[]")
                        tag_str = "  ".join(f"{TAG_COLORS.get(t,'⚪')} `{t}`" for t in tags)
                        st.write(f"**Risk Flags:** {tag_str or '—'}")
                        with st.expander("Risk flag legend"):
                            st.markdown(
                                "| Flag | Trigger |\n|------|---------|\n"
                                "| `multi_hop` | redirect chain >= 3 hops |\n"
                                "| `no_https` | final URL is http:// |\n"
                                "| `new_domain` | domain created < 180 days before post date |\n"
                                "| `suspicious_download` | final URL extension is .exe / .zip / .apk / .dmg etc. |\n"
                                "| `high_tracker_count` | page loaded >= 3 distinct third-party tracker domains |\n"
                                "| `url_shortener_chain` | final domain is itself a known shortlink service |\n"
                                "| `capture_error` | Playwright screenshot failed |"
                            )

                        domains = json.loads(snap["request_domains_json"] or "[]")
                        with st.expander(f"Request Domains ({len(domains)})"):
                            st.caption("All domains the browser contacted during page load — includes third-party scripts, ad networks, trackers, and CDNs. A high count indicates the landing page embeds many external services.")
                            st.code("\n".join(domains[:50]) + ("\n..." if len(domains) > 50 else ""))

                        if snap["html_path"] and os.path.exists(snap["html_path"]):
                            with open(snap["html_path"], "rb") as f:
                                st.download_button("Download HTML", f.read(),
                                    file_name=f"snapshot_{sel['scan_run_id']}.html",
                                    mime="text/html", key="dl_html")



    # Clusters
    with sub_clusters:
        destinations, unresolved_dests = shared_destinations(conn, current_case_id)
        params = shared_params(conn, current_case_id)
        asn_data = asn_clusters(conn, current_case_id)

        # Scanned Destinations
        st.subheader("Scanned Destinations")

        if unresolved_dests:
            names = ", ".join(f"`{d['final_domain']}`" for d in unresolved_dests)
            st.info(
                f"**{len(unresolved_dests)} URL(s) excluded from destination analysis:** "
                f"the scan stopped at the shortlink service itself ({names}) and did not reach the real destination. "
                f"Re-scan those URLs or check them manually."
            )

        if not destinations:
            st.info("No data yet. Scan URLs in the Scan tab first.")
        else:
            summary_rows = []
            for d in destinations:
                tag_str = "  ".join(
                    f"{TAG_COLORS.get(t, '⚪')} {t} ×{d['tag_counts'][t]}"
                    for t in sorted(d["tag_counts"])
                ) if d["tag_counts"] else "—"
                summary_rows.append({
                    "final_domain": d["final_domain"],
                    "urls":         d["url_count"],
                    "flagged_urls": d["flagged_url_count"] if d["flagged_url_count"] else "—",
                    "posts":        d["post_count"],
                    "risk_flags":   tag_str,
                })
            st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

            sel_domain = st.selectbox(
                "Drill into destination",
                [d["final_domain"] for d in destinations],
                key="cluster_dest_sel",
            )
            sel_d = next(d for d in destinations if d["final_domain"] == sel_domain)
            _show_all_key = f"cluster_show_all_{sel_domain}"
            show_all = st.session_state.get(_show_all_key, False)
            _PREVIEW = 5

            with st.container(border=True):
                urls_sorted = sorted(sel_d["urls"], key=lambda u: -len(u["risk_tags"]))
                urls_to_show = urls_sorted if show_all else urls_sorted[:_PREVIEW]
                flagged = sel_d["flagged_url_count"]
                st.write(f"**Shortlinks that resolved here ({len(sel_d['urls'])} total, {flagged} flagged):**")
                url_df_rows = []
                for u in urls_to_show:
                    tag_str = "  ".join(f"{TAG_COLORS.get(t, '⚪')} {t}" for t in u["risk_tags"]) if u["risk_tags"] else "—"
                    url_df_rows.append({"risk_flags": tag_str, "original_url": u["original_url"]})
                st.dataframe(pd.DataFrame(url_df_rows), use_container_width=True, hide_index=True)
                if len(sel_d["urls"]) > _PREVIEW:
                    if show_all:
                        if st.button("Show less", key=f"cluster_less_{sel_domain}"):
                            st.session_state[_show_all_key] = False
                            st.rerun()
                    else:
                        if st.button(f"Show all {len(sel_d['urls'])}", key=f"cluster_more_{sel_domain}"):
                            st.session_state[_show_all_key] = True
                            st.rerun()

                st.write("**Found in posts:**")
                posts_to_show = sel_d["posts"] if show_all else sel_d["posts"][:_PREVIEW]
                st.dataframe(pd.DataFrame(posts_to_show), use_container_width=True, hide_index=True)
                if len(sel_d["posts"]) > _PREVIEW and not show_all:
                    st.caption(f"Showing {_PREVIEW} of {len(sel_d['posts'])} posts — click 'Show all' above to expand.")

        st.divider()

        # Shared URL Parameters
        st.subheader("Shared URL Parameters")
        st.caption("Query parameter key+value pairs that appear in 2 or more distinct posts (checked in both the original shortlink and the final URL). Requires identical key=value across posts — a single post with multiple matching URLs does not qualify.")

        if not params:
            st.info("No shared parameters found across posts.")
        else:
            st.dataframe(pd.DataFrame(params), use_container_width=True, hide_index=True)

        st.divider()

        # Hosting Infrastructure
        st.subheader("Hosting Infrastructure")
        st.caption("Abuse landing domains grouped by ASN (hosting provider). Populated after capturing snapshots in the Investigate tab.")

        if not asn_data:
            st.info("No ASN data yet. Capture snapshots in the Investigate tab first.")
        else:
            asn_summary = []
            for a in asn_data:
                tag_str = "  ".join(
                    f"{TAG_COLORS.get(t, '⚪')} {t} ×{a['tag_counts'][t]}"
                    for t in sorted(a["tag_counts"])
                ) if a["tag_counts"] else "—"
                asn_summary.append({
                    "asn":          a["asn"],
                    "as_org":       a["as_org"],
                    "country":      a["as_country"],
                    "domains":      a["domain_count"],
                    "urls":         a["url_count"],
                    "flagged_urls": a["flagged_url_count"] if a["flagged_url_count"] else "—",
                    "posts":        a["post_count"],
                    "risk_flags":   tag_str,
                })
            st.dataframe(pd.DataFrame(asn_summary), use_container_width=True, hide_index=True)

            sel_asn = st.selectbox(
                "Drill into ASN",
                [a["asn"] for a in asn_data],
                format_func=lambda x: f"AS{x}  {next(a['as_org'] for a in asn_data if a['asn'] == x)}",
                key="cluster_asn_sel",
            )
            sel_a = next(a for a in asn_data if a["asn"] == sel_asn)
            _asn_show_key = f"cluster_asn_show_{sel_asn}"
            _asn_show_all = st.session_state.get(_asn_show_key, False)
            _ASN_PREVIEW = 5

            with st.container(border=True):
                st.write(f"**Domains hosted on AS{sel_asn} ({len(sel_a['domains'])} total):**")
                domains_show = sel_a["domains"] if _asn_show_all else sel_a["domains"][:_ASN_PREVIEW]
                st.dataframe(pd.DataFrame(domains_show), use_container_width=True, hide_index=True)

                st.write(f"**Shortlinks pointing to this infrastructure ({len(sel_a['urls'])} total, {sel_a['flagged_url_count']} flagged):**")
                urls_sorted = sorted(sel_a["urls"], key=lambda u: -len(u["risk_tags"]))
                urls_show = urls_sorted if _asn_show_all else urls_sorted[:_ASN_PREVIEW]
                asn_url_rows = []
                for u in urls_show:
                    tag_str = "  ".join(f"{TAG_COLORS.get(t, '⚪')} {t}" for t in u["risk_tags"]) if u["risk_tags"] else "—"
                    asn_url_rows.append({"risk_flags": tag_str, "original_url": u["original_url"]})
                st.dataframe(pd.DataFrame(asn_url_rows), use_container_width=True, hide_index=True)

                total_items = max(len(sel_a["domains"]), len(sel_a["urls"]))
                if total_items > _ASN_PREVIEW:
                    if _asn_show_all:
                        if st.button("Show less", key=f"asn_less_{sel_asn}"):
                            st.session_state[_asn_show_key] = False
                            st.rerun()
                    else:
                        if st.button(f"Show all", key=f"asn_more_{sel_asn}"):
                            st.session_state[_asn_show_key] = True
                            st.rerun()

# ===========================================================================
# PROVIDERS
# ===========================================================================
with tab_providers:
    st.subheader("Shortlink Providers")
    st.caption("Services whose customers are distributing abusive shortlinks.")

    all_domains = conn.execute(
        """SELECT domain AS provider, COUNT(*) AS url_count
           FROM url_artifacts
           WHERE case_id = ? AND domain IS NOT NULL
           GROUP BY domain ORDER BY url_count DESC""",
        (current_case_id,),
    ).fetchall()

    providers = [r for r in all_domains if r["provider"] in KNOWN_SHORTLINK_DOMAINS]

    if providers:
        df_prov = pd.DataFrame([dict(r) for r in providers])
        st.dataframe(df_prov, use_container_width=True, hide_index=True)

        sel_prov = st.selectbox(
            "Drill into provider",
            [p["provider"] for p in providers],
            key="prov_sel",
        )
        prov_urls = conn.execute(
            """SELECT ua.id, ua.original_url,
                      sr.status AS scan_status, sr.final_url, sr.hop_count,
                      s.risk_tags AS snapshot_risk_tags
               FROM url_artifacts ua
               LEFT JOIN scan_runs sr ON sr.url_artifact_id = ua.id
                   AND sr.id = (SELECT id FROM scan_runs WHERE url_artifact_id = ua.id ORDER BY id DESC LIMIT 1)
               LEFT JOIN snapshots s ON s.scan_run_id = sr.id
                   AND s.id = (SELECT id FROM snapshots WHERE scan_run_id = sr.id ORDER BY id DESC LIMIT 1)
               WHERE ua.case_id = ? AND ua.domain = ?
               ORDER BY ua.id""",
            (current_case_id, sel_prov),
        ).fetchall()

        def _prov_tags(r):
            if r["snapshot_risk_tags"]:
                try:
                    return json.loads(r["snapshot_risk_tags"])
                except (ValueError, TypeError):
                    pass
            return _scan_flags(r["final_url"], r["hop_count"])

        prov_rows_tagged = sorted(
            [{"url": r["original_url"], "tags": _prov_tags(r)} for r in prov_urls],
            key=lambda x: -len(x["tags"]),
        )
        flagged_count = sum(1 for x in prov_rows_tagged if x["tags"])
        _prov_show_all_key = f"prov_show_all_{sel_prov}"
        _prov_show_all = st.session_state.get(_prov_show_all_key, False)
        _PROV_PREVIEW = 5

        with st.container(border=True):
            to_show = prov_rows_tagged if _prov_show_all else prov_rows_tagged[:_PROV_PREVIEW]
            st.write(f"**URLs using this provider ({len(prov_rows_tagged)} total, {flagged_count} flagged):**")
            prov_df_rows = []
            for x in to_show:
                tag_str = "  ".join(f"{TAG_COLORS.get(t, '⚪')} {t}" for t in x["tags"]) if x["tags"] else "—"
                prov_df_rows.append({"risk_flags": tag_str, "original_url": x["url"]})
            st.dataframe(pd.DataFrame(prov_df_rows), use_container_width=True, hide_index=True)
            if len(prov_rows_tagged) > _PROV_PREVIEW:
                if _prov_show_all:
                    if st.button("Show less", key=f"prov_less_{sel_prov}"):
                        st.session_state[_prov_show_all_key] = False
                        st.rerun()
                else:
                    if st.button(f"Show all {len(prov_rows_tagged)}", key=f"prov_more_{sel_prov}"):
                        st.session_state[_prov_show_all_key] = True
                        st.rerun()
    else:
        st.info("No known shortlink providers identified yet. Add URLs containing services like bit.ly, t.co, tinyurl.com etc.")

    st.divider()

    st.subheader("Domain Registrars")
    st.caption("Registrars whose customers registered the abuse destination domains.")

    registrars = conn.execute(
        """SELECT s.whois_registrar AS registrar,
                  s.final_domain AS domain,
                  s.whois_creation_date AS domain_created
           FROM snapshots s
           JOIN scan_runs sr ON sr.id = s.scan_run_id
           JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
           WHERE ua.case_id = ? AND s.whois_registrar IS NOT NULL
           ORDER BY s.whois_registrar, s.final_domain""",
        (current_case_id,),
    ).fetchall()

    if registrars:
        st.dataframe(pd.DataFrame([dict(r) for r in registrars]), use_container_width=True, hide_index=True)
    else:
        st.info("No registrar data yet. Capture snapshots in the Analysis tab to populate WHOIS data.")

# ===========================================================================
# EXPORT
# ===========================================================================
with tab_export:
    st.subheader("Evidence Pack Export")
    st.caption("Download a ZIP containing all evidence for this case — messages, URLs, redirect chains, snapshots, WHOIS data, and a SHA-256 manifest.")

    # Case summary
    counts = conn.execute(
        """SELECT
               (SELECT COUNT(*) FROM message_evidence WHERE case_id = :c)  AS messages,
               (SELECT COUNT(*) FROM url_artifacts    WHERE case_id = :c)  AS urls,
               (SELECT COUNT(*) FROM scan_runs sr
                JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                WHERE ua.case_id = :c)                                      AS scans,
               (SELECT COUNT(*) FROM snapshots s
                JOIN scan_runs sr ON sr.id = s.scan_run_id
                JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                WHERE ua.case_id = :c)                                      AS snapshots""",
        {"c": current_case_id},
    ).fetchone()

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Source Posts",   counts["messages"])
    m2.metric("URLs",           counts["urls"])
    m3.metric("Scans",          counts["scans"])
    m4.metric("Snapshots",      counts["snapshots"])

    st.divider()

    if st.button("Export Evidence Pack", type="primary", key="btn_export"):
        with st.spinner("Building ZIP..."):
            zip_path = export_case(conn, current_case_id)
        st.success(f"Export complete: `{os.path.basename(zip_path)}`")
        with open(zip_path, "rb") as f:
            st.download_button(
                label="Download ZIP",
                data=f.read(),
                file_name=os.path.basename(zip_path),
                mime="application/zip",
                key="dl_zip_new",
            )

    st.divider()

    # Previous exports
    st.subheader("Previous Exports")
    exports = conn.execute(
        "SELECT id, export_at, zip_path, manifest_json FROM export_runs WHERE case_id = ? ORDER BY id DESC",
        (current_case_id,),
    ).fetchall()

    if not exports:
        st.info("No exports yet.")
    else:
        for ex in exports:
            meta  = json.loads(ex["manifest_json"] or "{}")
            label = f"{ex['export_at']}  —  {meta.get('file_count', '?')} files"
            if ex["zip_path"] and os.path.exists(ex["zip_path"]):
                with open(ex["zip_path"], "rb") as f:
                    st.download_button(
                        label=f"Download  {label}",
                        data=f.read(),
                        file_name=os.path.basename(ex["zip_path"]),
                        mime="application/zip",
                        key=f"dl_zip_{ex['id']}",
                    )
            else:
                st.write(f"{label}  _(file not found)_")
