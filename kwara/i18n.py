"""
Lightweight i18n for kwara Streamlit UI.

Usage:
    from i18n import t, set_lang, get_lang, LANGUAGES
    set_lang("zh-TW")
    st.write(t("sidebar.title"))
    st.write(t("scan.progress_text", done=5, total=10))

The default language is derived from config.LANG (env var KWARA_LANG).
Users can override it at runtime via the language selector in the sidebar,
which writes to st.session_state["lang"].
"""
from __future__ import annotations

import streamlit as st

from config import LANG as _CONFIG_LANG

LANGUAGES = {"en": "English", "zh-TW": "正體中文"}
# Map config.LANG ("zh"/"en") to an i18n key ("zh-TW"/"en").
_DEFAULT = "zh-TW" if _CONFIG_LANG == "zh" else "en"


def get_lang() -> str:
    return st.session_state.get("lang", _DEFAULT)


def set_lang(lang: str) -> None:
    st.session_state["lang"] = lang


def t(_key: str, **kwargs) -> str:
    """Look up *_key* in the active language dict, then .format(**kwargs)."""
    lang = get_lang()
    table = _TRANSLATIONS.get(lang, _TRANSLATIONS[_DEFAULT])
    text = table.get(_key)
    if text is None:
        text = _TRANSLATIONS[_DEFAULT].get(_key, _key)
    if kwargs:
        text = text.format(**kwargs)
    return text


# ---------------------------------------------------------------------------
# How-to-use guide (stored as single blocks per language)
# ---------------------------------------------------------------------------
_GUIDE_EN = """\
**kwara** collects, scans, and documents URL shortener and domain abuse evidence. Work through the tabs left to right — each step builds on the previous one.

---

#### 1. Input
Add source posts (single or CSV batch). URLs are extracted automatically.

#### 2. Collected
Review ingested posts and extracted URLs at a glance.

#### 3. Analysis — the evidence chain

Six sub-tabs guide you through the evidence collection workflow:

**Scan** — follow each URL's redirect chain to the real landing page. Batch-scan all at once or scan individually.

**Network** — view the redirect chain, TLS certificate (issuer, validity, SAN), and full HTTP response headers captured during the scan.

**Domain** — WHOIS registration (registrar, creation date), IP address, and ASN/hosting details. Batch-query all pending or query individually.

**Page** — browser screenshot, raw HTML, and HAR network log of the landing page. Batch-capture all pending or capture individually. Supports manual screenshot upload.

**Corroboration** — submit the landing page to third-party services for independent records: Internet Archive (Wayback Machine), urlscan.io, and RFC 3161 trusted timestamps.

**Insights** — rule-based case summary (no LLM): landing concentration, risk flag breakdown, cross-post parameter attribution, ASN infrastructure clusters, and data gap alerts (including TLS and corroboration coverage).

#### 4. Providers
Shortlink services and domain registrars involved. Use this to identify who to send abuse reports to.

#### 5. Export
Download a ZIP evidence pack with SHA-256 manifest, optional HMAC signature, and bilingual README. Contains all CSVs, screenshots, HTML, and audit log.\
"""

_GUIDE_ZH = """\
**kwara** 收集、掃描並記錄 URL 短連結與網域濫用的數位證據。從左到右依序操作各分頁，每一步建立在前一步的成果之上。

---

#### 1. 輸入（Input）
新增來源貼文（單篇或 CSV 批次匯入）。系統自動擷取 URL。

#### 2. 已收集（Collected）
一覽已匯入的貼文與擷取的 URL。

#### 3. 分析（Analysis）— 證據鏈

六個子分頁引導您完成蒐證工作流：

**掃描** — 追蹤每條 URL 的 redirect chain 至真實落地頁。可批次掃描或逐一掃描。

**網路路徑** — 檢視 redirect chain、TLS 憑證（簽發者、有效期、SAN）以及掃描時擷取的完整 HTTP 回應標頭。

**網域情報** — WHOIS 註冊資訊（註冊商、建立日期）、IP 位址、ASN / 託管資訊。可批次查詢或逐一查詢。

**頁面證據** — 落地頁的瀏覽器截圖、原始 HTML、HAR 網路流量紀錄。可批次截圖或逐一截圖，支援手動上傳截圖。

**第三方佐證** — 將落地頁提交至獨立第三方服務建立佐證紀錄：Internet Archive（Wayback Machine）、urlscan.io、RFC 3161 受信任時間戳。

**分析洞察** — 規則式案件摘要（非 LLM）：落地集中度、風險旗標統計、跨貼文參數歸屬、ASN 基礎設施聚合，以及資料缺口提示（含 TLS 與佐證覆蓋率）。

#### 4. 服務提供商（Providers）
列出涉案的短連結服務商與網域註冊商。用於識別濫用投訴對象。

#### 5. 匯出（Export）
下載 ZIP 證據封包，含 SHA-256 manifest、可選 HMAC 簽章、中英雙語 README。包含所有 CSV、截圖、HTML 與操作紀錄。

`snapshots/snapshots.csv` 列出所有快照嘗試。`screenshot_file` 和 `html_file` 欄位顯示 ZIP 內的相對路徑，空白代表截圖未成功。\
"""

# ---------------------------------------------------------------------------
# Risk flag legend table (per language)
# ---------------------------------------------------------------------------
_LEGEND_EN = (
    "| Flag | Trigger |\n|------|---------|\n"
    "| `multi_hop` | redirect chain >= 3 hops |\n"
    "| `no_https` | final URL is http:// |\n"
    "| `new_domain` | domain created < 180 days before post date |\n"
    "| `suspicious_download` | final URL extension is .exe / .zip / .apk / .dmg etc. |\n"
    "| `high_tracker_count` | page loaded >= 3 distinct third-party tracker domains |\n"
    "| `url_shortener_chain` | final domain is itself a known shortlink service |\n"
    "| `capture_error` | Playwright screenshot failed |"
)

_LEGEND_ZH = (
    "| 旗標 | 觸發條件 |\n|------|---------|\n"
    "| `multi_hop` | redirect chain >= 3 跳 |\n"
    "| `no_https` | 最終 URL 為 http://（未加密） |\n"
    "| `new_domain` | 網域建立日距貼文日不足 180 天 |\n"
    "| `suspicious_download` | 最終 URL 副檔名為 .exe / .zip / .apk / .dmg 等 |\n"
    "| `high_tracker_count` | 頁面載入時接觸 >= 3 個第三方追蹤器 |\n"
    "| `url_shortener_chain` | 最終網域本身為已知短連結服務 |\n"
    "| `capture_error` | Playwright 截圖失敗 |"
)

# ---------------------------------------------------------------------------
# Translation tables
# ---------------------------------------------------------------------------
_EN: dict[str, str] = {
    # ── Tabs ────────────────────────────────────────────────────────────────
    "tab.input": "Input",
    "tab.collected": "Collected",
    "tab.analysis": "Analysis",
    "tab.providers": "Providers",
    "tab.export": "Export",
    "tab.scan": "Scan",
    "tab.network": "Network",
    "tab.domain": "Domain",
    "tab.page": "Page",
    "tab.corroboration": "Corroboration",
    "tab.insights": "Insights",
    "tab.investigate": "Investigate",
    "tab.clusters": "Clusters",

    # ── Sub-tab help captions ──────────────────────────────────────────────
    "scan.help": "Follow each URL's redirect chain to find the real landing page.",
    "net.help": "Inspect the network path: redirect hops, TLS certificate, and HTTP headers collected during the scan.",
    "domain.help": "WHOIS registration, IP address, and ASN hosting details for the landing domain.",
    "page.help": "Browser screenshot, HTML source, and HAR network log of the landing page.",
    "corr.help": "Independent third-party records proving the URL content existed at a specific time.",
    "insights_tab.help": "Rule-based patterns and clusters derived from all scanned URLs in this case.",

    # ── Network sub-tab ────────────────────────────────────────────────────
    "net.scanned": "Scanned",
    "net.with_tls": "With TLS",
    "net.pending": "Pending",
    "net.scan_first": "Scan URLs first in the Scan tab.",
    "net.not_scanned": "This URL has not been scanned yet.",
    "net.chain": "Redirect Chain",
    "net.chain_caption": "Final: `{final}` ({hops} hops)",
    "net.tls": "TLS Certificate",
    "net.no_tls": "No TLS data (HTTP site or handshake failed).",
    "net.headers": "Response Headers",
    "net.headers_count": "{n} headers from the landing page response.",
    "net.no_headers": "No response headers recorded.",

    # ── Domain sub-tab ─────────────────────────────────────────────────────
    "domain.help_label": "Domain Intelligence",
    "domain.enriched": "With Intel",
    "domain.pending": "Pending",
    "domain.not_scanned": "Not Scanned",
    "domain.scan_first": "Scan URLs first.",
    "domain.btn_batch": "WHOIS/ASN all ({n} pending)",
    "domain.spinner_batch": "Querying WHOIS and ASN…",

    # ── Page sub-tab ───────────────────────────────────────────────────────
    "page.captured": "Captured",
    "page.pending": "Pending",
    "page.not_scanned": "Not Scanned",
    "page.scan_first": "Scan URLs first.",
    "page.btn_batch": "Capture all ({n} pending)",
    "page.warn_time": "Capturing {n} URLs takes roughly {lo}–{hi} minutes.",

    # ── Corroboration sub-tab ──────────────────────────────────────────────
    "corr.done": "Corroborated",
    "corr.pending": "Pending",
    "corr.not_scanned": "Not Scanned",
    "corr.scan_first": "Scan URLs first.",

    # ── Sidebar ─────────────────────────────────────────────────────────────
    "sidebar.title": "kwara",
    "sidebar.btn_guide": "How to Use",
    "sidebar.new_case": "+ New Case",
    "sidebar.label_title": "Title",
    "sidebar.label_desc": "Description",
    "sidebar.btn_create": "Create",
    "sidebar.victim_locale": "🌍 Victim Locale",
    "sidebar.victim_locale_help": "Browser locale used when capturing snapshots — affects Accept-Language and timezone sent to the target site. Set to match the victim's region so captured evidence reflects what they actually saw.",
    "sidebar.custom_locale": "Locale (BCP 47)",
    "sidebar.custom_tz": "Timezone (IANA)",
    "sidebar.success_created": "Case created: {title}",
    "sidebar.warn_title": "Title is required.",
    "sidebar.active_case": "Active Case",
    "sidebar.info_no_cases": "No cases yet. Create one above.",
    "sidebar.delete_case": "🗑 Delete Case",
    "sidebar.delete_warn": "This will permanently delete all data for this case including snapshots, scans, and exports. This action cannot be undone.",
    "sidebar.delete_confirm": "Type DELETE to confirm",
    "sidebar.delete_btn": "Delete Case",
    "sidebar.delete_done": "Case deleted.",
    "sidebar.delete_type_confirm": "Type DELETE to confirm deletion.",
    "sidebar.settings": "⚙ Settings",
    "settings.scanner_timeout": "Scanner timeout",
    "settings.max_hops": "Max redirect hops",
    "settings.new_domain_days": "New domain threshold",
    "settings.tracker_threshold": "High tracker threshold",
    "settings.default_locale": "Default browser locale",
    "settings.default_timezone": "Default browser timezone",

    # ── Page header / guard ─────────────────────────────────────────────────
    "page.header": "#### kwara — Digital Evidence Collection & Corroboration Toolkit",
    "page.warn_select": "Create and select a case in the sidebar to get started.",

    # ── Guide ───────────────────────────────────────────────────────────────
    "guide.dialog_title": "How to Use kwara",
    "guide.content": _GUIDE_EN,

    # ── Input ───────────────────────────────────────────────────────────────
    "input.single_post": "Single Post",
    "input.csv_batch": "CSV Batch",
    "input.platform": "Platform",
    "input.platform_ph": "e.g. Twitter, Telegram",
    "input.permalink": "Permalink",
    "input.actor": "Actor Label",
    "input.actor_ph": "e.g. @username, channel name",
    "input.posted_at": "Posted At",
    "input.posted_at_ph": "e.g. 2024-01-15 08:30",
    "input.message": "Message Text — paste content containing URLs",
    "input.screenshot": "Screenshot (optional)",
    "input.btn_submit": "Submit",
    "input.warn_message": "Message Text is required.",
    "input.success_saved": "Saved — {n} URL(s) extracted.",
    "input.csv_caption": "Columns: `platform`, `permalink`, `actor_label`, `posted_at`, `message_text` (only `message_text` is required)",
    "input.csv_upload": "Upload .csv",
    "input.csv_preview": "**Preview (first 5 rows):**",
    "input.csv_error": "Cannot parse CSV: {e}",
    "input.btn_import": "Import",
    "input.csv_success": "Imported {posts} post(s), {urls} URL(s).",
    "input.csv_fail": "Import failed: {e}",

    # ── Evidence ────────────────────────────────────────────────────────────
    "evidence.posts": "Source Posts",
    "evidence.no_posts": "No source posts yet. Add content in the Input tab.",
    "evidence.urls": "Extracted URLs",
    "evidence.no_urls": "No URLs extracted yet.",

    # ── Scan ────────────────────────────────────────────────────────────────
    "scan.no_urls": "No URLs found. Add content in the Input tab.",
    "scan.total": "Total",
    "scan.unscanned": "Unscanned",
    "scan.done": "Done",
    "scan.failed": "Failed",
    "scan.stuck": "Stuck",
    "scan.warn_stuck": "{n} scan(s) stuck in 'running' — likely interrupted. Reset them to re-scan.",
    "scan.btn_reset": "Reset stuck ({n})",
    "scan.btn_all": "Scan all unscanned ({n})",
    "scan.progress_start": "Starting…",
    "scan.progress_url": "{done}/{total} — {url}",
    "scan.progress_done": "Done — {total} URLs scanned",
    "scan.expander_individual": "Scan individual URL ({n} total)",
    "scan.btn_scan": "Scan",
    "scan.btn_rescan": "Re-scan",
    "scan.spinner": "Scanning…",

    # ── Investigate ─────────────────────────────────────────────────────────
    "inv.intel_queue": "Domain intel queue ({n} pending)",
    "inv.intel_caption": "Scanned URLs with no WHOIS/ASN on file yet. This is fast (no browser). Use this to populate Analysis **Hosting** and **Registrars** before screenshots.",
    "inv.btn_intel_all": "WHOIS / ASN only — all pending ({n})",
    "inv.spinner_intel": "Querying WHOIS and ASN…",
    "inv.snap_queue": "Snapshot Priority Queue ({n} pending)",
    "inv.snap_caption": "Scanned but not yet snapshotted — sorted by scan-time risk signals. Higher flag count = investigate first.",
    "inv.warn_snap_time": "**Snapshot & WHOIS All** launches a headless browser for every pending URL sequentially. This is slow (10–30 s per URL) and CPU-intensive. Estimated time for {n} URLs: {lo}–{hi} minutes.",
    "inv.btn_snap_all": "Snapshot & WHOIS All ({n} pending)",
    "inv.snap_progress_start": "Starting…",
    "inv.snap_progress": "Capturing screenshots {start}–{end} / {total}…",
    "inv.snap_done": "Done — {n} snapshots captured",
    "page.btn_dl_failed": "Download URLs needing manual capture (CSV)",
    "url.select": "Select URL",
    "inv.chain": "Redirect Chain",
    "inv.not_scanned": "Not scanned yet. Go to the Scan tab.",
    "inv.chain_caption": "Final URL: `{final_url}` · {hops} hops · {status}",
    "inv.whois_header": "Domain & hosting (WHOIS / ASN)",
    "inv.scan_first": "Complete a scan first.",
    "page.case_locale": "🌍 Browser locale: **{locale}** ({tz})",
    "domain.btn_intel": "Query WHOIS / ASN",
    "domain.btn_intel_help": "Look up domain registration and hosting info.",
    "domain.spinner": "WHOIS / ASN…",
    "domain.error": "Domain intel failed: {e}",
    "page.btn_recapture": "Re-capture",
    "page.btn_capture": "Capture snapshot",
    "page.spinner": "Capturing screenshot + WHOIS / ASN…",
    "page.error": "Snapshot failed: {e}",
    "domain.final_domain": "**Final Domain:** {v}",
    "domain.ip_address": "**IP Address:** {v}",
    "domain.asn_hosting": "**ASN / Hosting:** {v}",
    "domain.registrar": "**Registrar:** {v}",
    "domain.domain_created": "**Domain Created:** {v}",
    "domain.intel_updated": "Domain intel updated: `{ts}`",
    "domain.risk_flags": "**Risk Flags:** {v}",
    "net.tls_header": "TLS Certificate",
    "net.tls_issuer": "**Issuer:** {v}",
    "net.tls_subject": "**Subject:** {v}",
    "net.tls_valid": "**Valid:** {start} → {end}",
    "net.tls_serial": "**Serial:** {v}",
    "net.tls_san": "**SAN:** {v}",
    "net.headers_header": "Response Headers ({n})",
    "corr.header": "🔗 Third-party Corroboration",
    "corr.urlscan": "**urlscan.io:** [{url}]({url}) (submitted {at})",
    "corr.urlscan_skip": "urlscan.io: skipped (no API key configured)",
    "corr.wayback": "**Wayback Machine:** [{url}]({url}) (saved {at})",
    "corr.timestamp": "**RFC 3161 Timestamp:** TSA `{tsa}` (requested {at})",
    "corr.timestamp_digest": "Digest (SHA-256): `{digest}`",
    "corr.at": "Corroborated at: {at}",
    "corr.none": "No third-party corroboration yet.",
    "corr.run": "🔗 Corroborate now",
    "corr.retry": "🔄 Re-corroborate",
    "corr.spinner": "Contacting third-party services…",
    "inv.snapshot_header": "Snapshot (screenshot & page)",
    "inv.scan_first_snap": "Complete a scan first.",
    "page.no_snapshot": "No snapshot yet. Use **Capture snapshot** above for Playwright evidence, or fetch **domain intel** without a screenshot.",
    "page.capture_status": "Capture status: `{status}`",
    "page.capture_status_detail": "Capture status: `{status}` — {detail}",
    "page.missing_screenshot": "Screenshot file missing.",
    "page.request_domains": "Request Domains ({n})",
    "page.request_domains_caption": "All domains the browser contacted during page load — includes third-party scripts, ad networks, trackers, and CDNs. A high count indicates the landing page embeds many external services.",
    "page.btn_dl_html": "Download HTML",
    "page.btn_dl_har": "Download HAR (network log)",
    "page.manual_caption": "Upload a screenshot/HTML captured manually in your browser (e.g. when automation is blocked).",
    "page.upload_png": "Replace screenshot (PNG)",
    "page.upload_html": "Replace HTML (optional)",
    "page.btn_save_manual": "Save manual evidence",
    "page.warn_choose_png": "Choose a PNG file first.",

    # ── Clusters ────────────────────────────────────────────────────────────
    "clusters.insights": "Case Insights (rule-based summary)",
    "clusters.data_gaps": "Data gaps",
    "clusters.legend": "Risk flag legend",
    "clusters.legend_table": _LEGEND_EN,
    "clusters.destinations": "Scanned Destinations",
    "clusters.info_unresolved": "**{n} URL(s) excluded from destination analysis:** the scan stopped at the shortlink service itself ({names}) and did not reach the real destination. Re-scan those URLs or check them manually.",
    "clusters.no_data": "No data yet. Scan URLs in the Scan tab first.",
    "clusters.drill_dest": "Drill into destination",
    "clusters.shortlinks_here": "**Shortlinks that resolved here ({total} total, {flagged} flagged):**",
    "clusters.btn_less": "Show less",
    "clusters.btn_all": "Show all {n}",
    "clusters.found_in_posts": "**Found in posts:**",
    "clusters.preview_posts": "Showing {preview} of {total} posts — click 'Show all' above to expand.",
    "clusters.params": "Shared URL Parameters",
    "clusters.params_caption": "Query parameter key+value pairs that appear in 2 or more distinct posts (checked in both the original shortlink and the final URL). Requires identical key=value across posts — a single post with multiple matching URLs does not qualify. Values longer than 100 characters are compared by SHA-256 prefix (shown as `[hash:abc12345…]`) so opaque tokens still cluster.",
    "clusters.no_params": "No shared parameters found across posts.",
    "clusters.infra": "Hosting Infrastructure",
    "clusters.infra_caption": "Abuse landing domains grouped by ASN (hosting provider). Populated after querying WHOIS/ASN in the **Domain** tab.",
    "clusters.no_asn": "No ASN data yet. Query WHOIS/ASN in the **Domain** tab first.",
    "clusters.drill_asn": "Drill into ASN",
    "clusters.domains_asn": "**Domains hosted on AS{asn} ({n} total):**",
    "clusters.shortlinks_asn": "**Shortlinks pointing to this infrastructure ({total} total, {flagged} flagged):**",
    "clusters.tls": "Shared TLS Certificates",
    "clusters.tls_caption": "Landing domains that share a TLS certificate, or whose certificates were issued within a 24-hour window. Same-cert is the strongest cross-domain link (one server / one operator). Same-window suggests batch provisioning.",
    "clusters.no_tls": "No shared TLS evidence found across landing domains.",
    "clusters.tls_by_cert": "Same certificate covers multiple landing domains in this case",
    "clusters.tls_by_window": "Distinct certs issued within 24 hours of each other",

    # ── Providers ───────────────────────────────────────────────────────────
    "prov.shortlinks": "Shortlink Providers",
    "prov.shortlinks_caption": "Services whose customers are distributing abusive shortlinks.",
    "prov.drill": "Drill into provider",
    "prov.urls_provider": "**URLs using this provider ({total} total, {flagged} flagged):**",
    "prov.no_providers": "No known shortlink providers identified yet. Add URLs containing services like bit.ly, t.co, tinyurl.com etc.",
    "prov.registrars": "Domain Registrars",
    "prov.registrars_caption": "Registrars whose customers registered the abuse destination domains.",
    "prov.no_registrars": "No registrar data yet. Query WHOIS in the **Domain** tab to populate.",

    # ── Export ──────────────────────────────────────────────────────────────
    "export.title": "Evidence Pack Export",
    "export.caption": "Download a ZIP containing all evidence for this case — messages, URLs, redirect chains, snapshots, WHOIS data, and a SHA-256 manifest.",
    "export.posts": "Source Posts",
    "export.urls": "URLs",
    "export.scans": "Scans",
    "export.snapshots": "Snapshots",
    "export.btn_export": "Export Evidence Pack",
    "export.spinner": "Building ZIP...",
    "export.success": "Export complete: `{name}`",
    "export.btn_download": "Download ZIP",
    "export.previous": "Previous Exports",
    "export.no_exports": "No exports yet.",
    "export.dl_previous": "Download  {label}",
    "export.file_not_found": "{label}  _(file not found)_",

    # ── Scan / Investigate labels ───────────────────────────────────────────
    "scan.status_unscanned": "unscanned",
    "inv.status_not_scanned": "not scanned",

    # ── Insights (used in insights.py) ──────────────────────────────────────
    "insights.headline_none": "No URLs in this case yet. Add content in the Input tab.",
    "insights.headline_counts": "**{url_count}** URLs total, **{scanned}** with completed redirect scans.",
    "insights.headline_dest": "**{n_dest}** distinct landing domains identified",
    "insights.headline_dest_unresolved": "; **{n_un}** still stopped at the shortlink service (not penetrated).",
    "insights.headline_params": "**{n}** cross-post repeated URL parameters detected (likely tracking or campaign IDs).",
    "insights.headline_asn": "**{n}** hosting / ASN clusters across landing domains.",
    "insights.bullet_landing": "**Landing concentration:** top destinations by post coverage: {bits}.",
    "insights.bullet_landing_item": "`{domain}` ({posts} posts, {urls} URLs)",
    "insights.bullet_risk": "**Risk flags:** {flagged} URLs carry risk flags — {parts}.",
    "insights.bullet_risk_item": "`{tag}` ({label}) x{cnt}",
    "insights.bullet_unresolved": "**Shortlinks not penetrated:** {n} landing domains are still known shortlink services — real destination unknown. Re-scan or open manually.",
    "insights.bullet_param": "**Cross-post parameters:** Most repeated is `{key}={value}`{owner} (found in {posts} distinct posts).",
    "insights.bullet_param_owner": ", attributed to {owner}",
    "insights.bullet_param2": "Followed by `{key}={value}`{owner} ({posts} posts).",
    "insights.bullet_tls_cert": "**Shared TLS cert:** {n_certs} certificate(s) cover 2+ landing domains in this case (top: 1 cert → {domains} domains, issued by {issuer}). Strongest cross-domain link — same server / same operator.",
    "insights.bullet_tls_window": "**Same-window cert issuance:** {n_windows} cluster(s) of certs issued within 24h (top: {certs} certs → {domains} domains). Suggests batch provisioning.",
    "insights.bullet_infra": "**Infrastructure:** By URL volume, **AS{asn}** ({org}) covers the most landing domains and shortlinks ({domains} domains, {urls} URLs).",
    "insights.bullet_no_scans": "No scanned URLs yet — run scans in the **Scan** tab to generate pattern summaries here.",
    "insights.gap_intel": "**{n}** scanned URLs still lack domain intel (WHOIS/ASN) — go to the **Domain** tab to query.",
    "insights.gap_snap": "**{n}** URLs have no page evidence — go to the **Page** tab to capture screenshots.",
    "insights.gap_tls": "**{n}** HTTPS URLs have no TLS certificate recorded — re-scan to capture.",
    "insights.gap_corr": "**{n}** URLs have no third-party corroboration — use the Corroboration tab to archive them.",
    "insights.gap_unscanned": "**{n}** URLs not yet scanned or latest scan not marked done.",

    # ── Risk tag labels ─────────────────────────────────────────────────────
    "risk.multi_hop": "multiple redirects",
    "risk.no_https": "no HTTPS",
    "risk.new_domain": "newly registered domain",
    "risk.suspicious_download": "suspicious download",
    "risk.high_tracker_count": "high third-party tracker count",
    "risk.url_shortener_chain": "shortener chain (destination unknown)",
    "risk.capture_error": "screenshot failed",

    # ── Param attribution ───────────────────────────────────────────────────
    "param.traffic_source": "traffic source",
    "param.traffic_medium": "traffic medium",
    "param.campaign_name": "campaign name",
    "param.paid_keyword": "paid keyword / tracking code",
    "param.ad_creative": "ad creative variant",
    "param.campaign_id": "campaign ID",
    "param.click_id": "click ID",
    "param.click_source_type": "click source type",
    "param.app_attribution_ios": "app attribution (iOS)",
    "param.web_to_app": "web-to-app attribution",
    "param.doubleclick_click_id": "DoubleClick click ID",
    "param.action_id": "action ID",
    "param.ad_group_id": "ad group ID",
    "param.ad_network": "ad network",
    "param.recipient_id": "recipient ID",
    "param.referral_affiliate": "referral / affiliate code",
    "param.affiliate_code": "affiliate code",
    "param.affiliate_id": "affiliate ID",
    "param.user_tracking_id": "user / affiliate tracking ID",
    "param.session_id": "session ID",
    "param.click_tracking_id": "click tracking ID",
    "param.tracking_id": "tracking ID",
    "param.utm_tracking": "UTM tracking parameter",
    "param.hubspot_ad": "HubSpot ad parameter",
    "param.mailchimp_tracking": "Mailchimp tracking parameter",
    "param.facebook_tracking": "Facebook tracking parameter",
    "param.ga_tracking": "GA tracking parameter",
    "param.unrecognized_platform": "unrecognized platform",
    "param.unidentified": "unidentified",
}

_ZH: dict[str, str] = {
    # ── Tabs ────────────────────────────────────────────────────────────────
    "tab.input": "輸入",
    "tab.collected": "已收集",
    "tab.analysis": "分析",
    "tab.providers": "服務提供商",
    "tab.export": "匯出",
    "tab.scan": "掃描",
    "tab.network": "網路路徑",
    "tab.domain": "網域情報",
    "tab.page": "頁面證據",
    "tab.corroboration": "第三方佐證",
    "tab.insights": "分析洞察",
    "tab.investigate": "調查",
    "tab.clusters": "聚合分析",

    "scan.help": "追蹤每條 URL 的 redirect chain，找到真實落地頁。",
    "net.help": "掃描時擷取的網路路徑：redirect 跳轉、TLS 憑證、HTTP 回應標頭。",
    "domain.help": "落地網域的 WHOIS 註冊、IP 位址、ASN 託管資訊。",
    "page.help": "落地頁的瀏覽器截圖、HTML 原始碼、HAR 網路流量紀錄。",
    "corr.help": "獨立第三方紀錄，證明該 URL 的內容在特定時間確實存在。",
    "insights_tab.help": "根據本案所有已掃描 URL 產生的規則式模式與聚合分析。",

    "net.scanned": "已掃描",
    "net.with_tls": "含 TLS",
    "net.pending": "待處理",
    "net.scan_first": "請先在「掃描」分頁掃描 URL。",
    "net.not_scanned": "此 URL 尚未掃描。",
    "net.chain": "Redirect Chain",
    "net.chain_caption": "最終：`{final}`（{hops} 跳）",
    "net.tls": "TLS 憑證",
    "net.no_tls": "無 TLS 資料（HTTP 站或握手失敗）。",
    "net.headers": "回應標頭",
    "net.headers_count": "落地頁回應的 {n} 個標頭。",
    "net.no_headers": "未記錄回應標頭。",

    "domain.help_label": "網域情報",
    "domain.enriched": "已查詢",
    "domain.pending": "待查詢",
    "domain.not_scanned": "未掃描",
    "domain.scan_first": "請先掃描 URL。",
    "domain.btn_batch": "批次查詢 WHOIS/ASN（{n} 筆待處理）",
    "domain.spinner_batch": "正在查詢 WHOIS 與 ASN…",

    "page.captured": "已截圖",
    "page.pending": "待截圖",
    "page.not_scanned": "未掃描",
    "page.scan_first": "請先掃描 URL。",
    "page.btn_batch": "批次截圖（{n} 筆待處理）",
    "page.warn_time": "截圖 {n} 條 URL 預計需要 {lo}–{hi} 分鐘。",

    "corr.done": "已佐證",
    "corr.pending": "待佐證",
    "corr.not_scanned": "未掃描",
    "corr.scan_first": "請先掃描 URL。",

    # ── Sidebar ─────────────────────────────────────────────────────────────
    "sidebar.title": "kwara",
    "sidebar.btn_guide": "使用說明",
    "sidebar.new_case": "+ 新增案件",
    "sidebar.label_title": "標題",
    "sidebar.label_desc": "描述",
    "sidebar.btn_create": "建立",
    "sidebar.victim_locale": "🌍 受害者所在地",
    "sidebar.victim_locale_help": "截圖時瀏覽器使用的語系與時區——影響送給目標站的 Accept-Language。設定為受害者所在地區，讓截到的證據反映其實際看到的頁面。",
    "sidebar.custom_locale": "語系 (BCP 47)",
    "sidebar.custom_tz": "時區 (IANA)",
    "sidebar.success_created": "案件已建立：{title}",
    "sidebar.warn_title": "標題為必填。",
    "sidebar.active_case": "目前案件",
    "sidebar.info_no_cases": "尚無案件，請在上方新增。",
    "sidebar.delete_case": "🗑 刪除案件",
    "sidebar.delete_warn": "此操作將永久刪除此案件的所有資料，包括截圖、掃描結果及匯出紀錄，且無法復原。",
    "sidebar.delete_confirm": "輸入 DELETE 以確認",
    "sidebar.delete_btn": "刪除案件",
    "sidebar.delete_done": "案件已刪除。",
    "sidebar.delete_type_confirm": "請輸入 DELETE 以確認刪除。",
    "sidebar.settings": "⚙ 設定",
    "settings.scanner_timeout": "掃描逾時",
    "settings.max_hops": "最大跳轉數",
    "settings.new_domain_days": "新網域門檻",
    "settings.tracker_threshold": "追蹤器數量門檻",
    "settings.default_locale": "預設瀏覽器語系",
    "settings.default_timezone": "預設瀏覽器時區",

    # ── Page header / guard ─────────────────────────────────────────────────
    "page.header": "#### kwara — 數位證據蒐集與佐證工具",
    "page.warn_select": "請先在側欄建立並選取案件。",

    # ── Guide ───────────────────────────────────────────────────────────────
    "guide.dialog_title": "kwara 使用說明",
    "guide.content": _GUIDE_ZH,

    # ── Input ───────────────────────────────────────────────────────────────
    "input.single_post": "單篇貼文",
    "input.csv_batch": "CSV 批次",
    "input.platform": "平台",
    "input.platform_ph": "例：Twitter、Telegram",
    "input.permalink": "貼文連結",
    "input.actor": "發文者標籤",
    "input.actor_ph": "例：@username、頻道名稱",
    "input.posted_at": "發文時間",
    "input.posted_at_ph": "例：2024-01-15 08:30",
    "input.message": "貼文內容 — 貼上包含 URL 的文字",
    "input.screenshot": "截圖（選填）",
    "input.btn_submit": "送出",
    "input.warn_message": "貼文內容為必填。",
    "input.success_saved": "已儲存 — 擷取到 {n} 個 URL。",
    "input.csv_caption": "欄位：`platform`、`permalink`、`actor_label`、`posted_at`、`message_text`（僅 `message_text` 為必填）",
    "input.csv_upload": "上傳 .csv",
    "input.csv_preview": "**預覽（前 5 列）：**",
    "input.csv_error": "無法解析 CSV：{e}",
    "input.btn_import": "匯入",
    "input.csv_success": "已匯入 {posts} 則貼文、{urls} 個 URL。",
    "input.csv_fail": "匯入失敗：{e}",

    # ── Evidence ────────────────────────────────────────────────────────────
    "evidence.posts": "來源貼文",
    "evidence.no_posts": "尚無來源貼文。請在「輸入」分頁新增內容。",
    "evidence.urls": "擷取的 URL",
    "evidence.no_urls": "尚無擷取的 URL。",

    # ── Scan ────────────────────────────────────────────────────────────────
    "scan.no_urls": "找不到 URL。請先在「輸入」分頁新增內容。",
    "scan.total": "總計",
    "scan.unscanned": "未掃描",
    "scan.done": "已完成",
    "scan.failed": "失敗",
    "scan.stuck": "卡住",
    "scan.warn_stuck": "{n} 筆掃描卡在 'running' 狀態 — 可能中斷。重置後可重新掃描。",
    "scan.btn_reset": "重置卡住的掃描（{n}）",
    "scan.btn_all": "掃描全部未掃描（{n}）",
    "scan.progress_start": "啟動中…",
    "scan.progress_url": "{done}/{total} — {url}",
    "scan.progress_done": "完成 — 已掃描 {total} 個 URL",
    "scan.expander_individual": "逐一掃描 URL（共 {n} 個）",
    "scan.btn_scan": "掃描",
    "scan.btn_rescan": "重新掃描",
    "scan.spinner": "掃描中…",

    # ── Investigate ─────────────────────────────────────────────────────────
    "inv.intel_queue": "網域情資佇列（{n} 筆待處理）",
    "inv.intel_caption": "已掃描但尚無 WHOIS/ASN 的 URL。此操作不需瀏覽器，速度很快。可在截圖前先填充分析頁的「主機基礎設施」與「網域註冊商」。",
    "inv.btn_intel_all": "只查 WHOIS/ASN — 全部待處理（{n}）",
    "inv.spinner_intel": "查詢 WHOIS 與 ASN 中…",
    "inv.snap_queue": "快照優先佇列（{n} 筆待處理）",
    "inv.snap_caption": "已掃描但尚未截圖 — 依掃描時風險訊號排序。旗標越多 = 優先調查。",
    "inv.warn_snap_time": "**全部截圖 + WHOIS** 會依序以無頭瀏覽器開啟每個待處理 URL。速度較慢（每個 10–30 秒）且需較多 CPU。預估 {n} 個 URL 需 {lo}–{hi} 分鐘。",
    "inv.btn_snap_all": "全部截圖 + WHOIS（{n} 筆待處理）",
    "inv.snap_progress_start": "啟動中…",
    "inv.snap_progress": "截圖中 {start}–{end} / {total}…",
    "inv.snap_done": "完成 — 已截圖 {n} 張",
    "page.btn_dl_failed": "下載需手動截圖的 URL 清單（CSV）",
    "url.select": "選擇 URL",
    "inv.chain": "重導向鏈",
    "inv.not_scanned": "尚未掃描。請前往「掃描」分頁。",
    "inv.chain_caption": "最終 URL：`{final_url}` · {hops} 跳 · {status}",
    "inv.whois_header": "網域與主機（WHOIS / ASN）",
    "inv.scan_first": "請先完成掃描。",
    "page.case_locale": "🌍 瀏覽器語系：**{locale}**（{tz}）",
    "domain.btn_intel": "查詢 WHOIS / ASN",
    "domain.btn_intel_help": "查詢網域註冊與託管資訊。",
    "domain.spinner": "WHOIS / ASN…",
    "domain.error": "網域情資查詢失敗：{e}",
    "page.btn_recapture": "重新截圖",
    "page.btn_capture": "截圖",
    "page.spinner": "截圖 + WHOIS / ASN 中…",
    "page.error": "截圖失敗：{e}",
    "domain.final_domain": "**最終網域：** {v}",
    "domain.ip_address": "**IP 位址：** {v}",
    "domain.asn_hosting": "**ASN / 主機：** {v}",
    "domain.registrar": "**註冊商：** {v}",
    "domain.domain_created": "**網域建立日：** {v}",
    "domain.intel_updated": "網域情資更新於：`{ts}`",
    "domain.risk_flags": "**風險旗標：** {v}",
    "net.tls_header": "TLS 憑證",
    "net.tls_issuer": "**簽發者：** {v}",
    "net.tls_subject": "**主體：** {v}",
    "net.tls_valid": "**有效期：** {start} → {end}",
    "net.tls_serial": "**序號：** {v}",
    "net.tls_san": "**SAN：** {v}",
    "net.headers_header": "回應標頭（{n}）",
    "corr.header": "🔗 第三方佐證",
    "corr.urlscan": "**urlscan.io：** [{url}]({url})（提交於 {at}）",
    "corr.urlscan_skip": "urlscan.io：已跳過（未設定 API 金鑰）",
    "corr.wayback": "**Wayback Machine：** [{url}]({url})（存檔於 {at}）",
    "corr.timestamp": "**RFC 3161 時間戳：** TSA `{tsa}`（請求於 {at}）",
    "corr.timestamp_digest": "摘要 (SHA-256)：`{digest}`",
    "corr.at": "佐證時間：{at}",
    "corr.none": "尚無第三方佐證。",
    "corr.run": "🔗 立即取得佐證",
    "corr.retry": "🔄 重新取得佐證",
    "corr.spinner": "正在聯繫第三方服務…",
    "inv.snapshot_header": "快照（截圖與頁面）",
    "inv.scan_first_snap": "請先完成掃描。",
    "page.no_snapshot": "尚無快照。使用上方 **截圖** 取得 Playwright 證據，或使用 **查詢網域情資** 取得 WHOIS 資料。",
    "page.capture_status": "截圖狀態：`{status}`",
    "page.capture_status_detail": "截圖狀態：`{status}` — {detail}",
    "page.missing_screenshot": "截圖檔案遺失。",
    "page.request_domains": "Request Domains（{n}）",
    "page.request_domains_caption": "頁面載入時瀏覽器接觸的所有外部網域 — 包含第三方腳本、廣告網路、追蹤器與 CDN。數量偏高表示落地頁嵌入了多個外部服務。",
    "page.btn_dl_html": "下載 HTML",
    "page.btn_dl_har": "下載 HAR（網路流量紀錄）",
    "page.manual_caption": "上傳在瀏覽器中手動截取的截圖／HTML（例如自動化被阻擋時使用）。",
    "page.upload_png": "替換截圖（PNG）",
    "page.upload_html": "替換 HTML（選填）",
    "page.btn_save_manual": "儲存手動證據",
    "page.warn_choose_png": "請先選擇 PNG 檔案。",

    # ── Clusters ────────────────────────────────────────────────────────────
    "clusters.insights": "案件洞察（規則式摘要）",
    "clusters.data_gaps": "資料缺口",
    "clusters.legend": "風險旗標說明",
    "clusters.legend_table": _LEGEND_ZH,
    "clusters.destinations": "已掃描目的地",
    "clusters.info_unresolved": "**{n} 個 URL 已從目的地分析中排除：** 掃描停在短連結服務本身（{names}），未到達真實目的地。建議重新掃描或手動開啟連結確認。",
    "clusters.no_data": "尚無資料。請先在「掃描」分頁執行掃描。",
    "clusters.drill_dest": "展開目的地",
    "clusters.shortlinks_here": "**解析到此處的短連結（共 {total} 條，{flagged} 條有旗標）：**",
    "clusters.btn_less": "收起",
    "clusters.btn_all": "展開全部 {n}",
    "clusters.found_in_posts": "**出現在以下貼文：**",
    "clusters.preview_posts": "顯示 {preview} / {total} 則貼文 — 點擊上方「展開全部」查看完整。",
    "clusters.params": "共用 URL 參數",
    "clusters.params_caption": "出現在 2 篇以上貼文的 query 參數 key=value（同時檢查原始短連結與最終 URL）。相同 key=value 在同一篇貼文的多個 URL 中重複出現不計入。長度超過 100 字元的 value 改以 SHA-256 雜湊比對（顯示為 `[hash:abc12345…]`），讓不透明的長 token 也能群集。",
    "clusters.no_params": "未發現跨貼文的共用參數。",
    "clusters.infra": "主機基礎設施",
    "clusters.infra_caption": "依 ASN（主機供應商）分組的濫用落地網域。需先在「網域情報」分頁查詢 WHOIS/ASN。",
    "clusters.no_asn": "尚無 ASN 資料。請先到「網域情報」分頁查詢。",
    "clusters.drill_asn": "展開 ASN",
    "clusters.domains_asn": "**託管於 AS{asn} 的網域（共 {n} 個）：**",
    "clusters.shortlinks_asn": "**指向此基礎設施的短連結（共 {total} 條，{flagged} 條有旗標）：**",
    "clusters.tls": "共用 TLS 憑證",
    "clusters.tls_caption": "共用 TLS 憑證、或憑證於 24 小時內陸續簽發的落地網域。共用同一張憑證是跨網域關聯最強的訊號（同一台伺服器／同一操作者）；同窗口簽發則提示批量上線。",
    "clusters.no_tls": "未發現跨網域的 TLS 憑證關聯。",
    "clusters.tls_by_cert": "同一張憑證涵蓋多個本案的落地網域",
    "clusters.tls_by_window": "不同憑證於 24 小時內陸續簽發",

    # ── Providers ───────────────────────────────────────────────────────────
    "prov.shortlinks": "短連結服務商",
    "prov.shortlinks_caption": "其用戶正在散布濫用短連結的服務商。",
    "prov.drill": "展開服務商",
    "prov.urls_provider": "**使用此服務商的 URL（共 {total} 條，{flagged} 條有旗標）：**",
    "prov.no_providers": "尚未識別到已知的短連結服務商。請新增包含 bit.ly、t.co、tinyurl.com 等服務的 URL。",
    "prov.registrars": "網域註冊商",
    "prov.registrars_caption": "註冊了濫用落地網域的註冊商。",
    "prov.no_registrars": "尚無註冊商資料。請先到「網域情報」分頁查詢 WHOIS。",

    # ── Export ──────────────────────────────────────────────────────────────
    "export.title": "證據封包匯出",
    "export.caption": "下載包含本案件所有證據的 ZIP 檔 — 貼文、URL、重導向鏈、快照、WHOIS 資料及 SHA-256 manifest。",
    "export.posts": "來源貼文",
    "export.urls": "URL",
    "export.scans": "掃描",
    "export.snapshots": "快照",
    "export.btn_export": "匯出證據封包",
    "export.spinner": "建置 ZIP 中…",
    "export.success": "匯出完成：`{name}`",
    "export.btn_download": "下載 ZIP",
    "export.previous": "歷史匯出",
    "export.no_exports": "尚無匯出紀錄。",
    "export.dl_previous": "下載  {label}",
    "export.file_not_found": "{label}  _（檔案不存在）_",

    # ── Scan / Investigate labels ───────────────────────────────────────────
    "scan.status_unscanned": "未掃描",
    "inv.status_not_scanned": "未掃描",

    # ── Insights ────────────────────────────────────────────────────────────
    "insights.headline_none": "此案件尚無 URL，請先在「輸入」分頁匯入內容。",
    "insights.headline_counts": "共 **{url_count}** 個短連結／URL，其中 **{scanned}** 筆已完成掃描（redirect 解析）。",
    "insights.headline_dest": "可辨識的落地網域 **{n_dest}** 個",
    "insights.headline_dest_unresolved": "；另有 **{n_un}** 個目的地仍停在短連結服務本身（未穿透）。",
    "insights.headline_params": "偵測到 **{n}** 組跨貼文重複的 URL 參數（可能與追蹤或投放有關）。",
    "insights.headline_asn": "託管／ASN 叢集 **{n}** 組（來自已解析 ASN 的落地網域）。",
    "insights.bullet_landing": "**落地集中度：** 貼文覆蓋最高的目的地為 {bits}。",
    "insights.bullet_landing_item": "`{domain}`（{posts} 則貼文、{urls} 條 URL）",
    "insights.bullet_risk": "**風險標記：** 共 {flagged} 條 URL 帶有風險標記。各標記統計：{parts}。",
    "insights.bullet_risk_item": "`{tag}`（{label}）×{cnt}",
    "insights.bullet_unresolved": "**短連結未穿透：** {n} 個落地網域仍為已知短連結服務，真實目的地未知——建議重新掃描或手動開啟連結確認。",
    "insights.bullet_param": "**跨貼文參數：** 最常重複的是 `{key}={value}`{owner}（出現在 {posts} 則不同貼文）。",
    "insights.bullet_param_owner": "，歸屬 {owner}",
    "insights.bullet_param2": "其次為 `{key}={value}`{owner}（{posts} 則貼文）。",
    "insights.bullet_tls_cert": "**共用 TLS 憑證：** 偵測到 {n_certs} 張憑證涵蓋 2 個以上落地網域（最多者：1 張憑證 → {domains} 個網域，由 {issuer} 簽發）。跨網域關聯最強訊號——同一台伺服器／同一操作者。",
    "insights.bullet_tls_window": "**同窗口簽發憑證：** {n_windows} 組憑證於 24 小時內陸續簽發（最多者：{certs} 張憑證 → {domains} 個網域），提示批量上線。",
    "insights.bullet_infra": "**基礎設施：** 以流量／URL 量來看，**AS{asn}**（{org}）涵蓋最多落地網域與短連結（{domains} 網域、{urls} 條 URL）。",
    "insights.bullet_no_scans": "尚無完成掃描的 URL——請到 **掃描** 分頁執行掃描後，此處會出現模式摘要。",
    "insights.gap_intel": "**{n}** 筆已完成掃描但尚未執行網域情資（WHOIS／ASN）——請到「網域情報」分頁查詢。",
    "insights.gap_snap": "**{n}** 筆 URL 尚無頁面證據——請到「頁面證據」分頁截圖。",
    "insights.gap_tls": "**{n}** 筆 HTTPS URL 尚無 TLS 憑證紀錄——重新掃描即可擷取。",
    "insights.gap_corr": "**{n}** 筆 URL 尚無第三方佐證——請到「第三方佐證」分頁進行存檔。",
    "insights.gap_unscanned": "**{n}** 條 URL 尚未完成掃描或最新一次掃描未標記為 done。",

    # ── Risk tag labels ─────────────────────────────────────────────────────
    "risk.multi_hop": "多次跳轉",
    "risk.no_https": "未使用 HTTPS",
    "risk.new_domain": "新註冊網域",
    "risk.suspicious_download": "可疑下載行為",
    "risk.high_tracker_count": "第三方追蹤器數量偏高",
    "risk.url_shortener_chain": "短連結串接（目的地未知）",
    "risk.capture_error": "截圖失敗",

    # ── Param attribution ───────────────────────────────────────────────────
    "param.traffic_source": "流量來源",
    "param.traffic_medium": "流量媒介",
    "param.campaign_name": "活動名稱",
    "param.paid_keyword": "付費關鍵字 / 追蹤碼",
    "param.ad_creative": "廣告素材區分",
    "param.campaign_id": "活動 ID",
    "param.click_id": "點擊 ID",
    "param.click_source_type": "點擊來源類型",
    "param.app_attribution_ios": "App 歸因（iOS）",
    "param.web_to_app": "Web-to-app 歸因",
    "param.doubleclick_click_id": "DoubleClick 點擊 ID",
    "param.action_id": "動作 ID",
    "param.ad_group_id": "廣告群組 ID",
    "param.ad_network": "廣告網路",
    "param.recipient_id": "收件人 ID",
    "param.referral_affiliate": "推薦來源 / 聯盟代碼",
    "param.affiliate_code": "聯盟代碼",
    "param.affiliate_id": "聯盟 ID",
    "param.user_tracking_id": "使用者 / 聯盟追蹤 ID",
    "param.session_id": "Session ID",
    "param.click_tracking_id": "點擊追蹤 ID",
    "param.tracking_id": "追蹤 ID",
    "param.utm_tracking": "UTM 追蹤參數",
    "param.hubspot_ad": "HubSpot 廣告參數",
    "param.mailchimp_tracking": "Mailchimp 追蹤參數",
    "param.facebook_tracking": "Facebook 追蹤參數",
    "param.ga_tracking": "GA 追蹤參數",
    "param.unrecognized_platform": "非屬已知追蹤平台",
    "param.unidentified": "未識別",
}

_TRANSLATIONS: dict[str, dict[str, str]] = {
    "en": _EN,
    "zh-TW": _ZH,
}
