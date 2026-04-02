"""
Lightweight i18n for kwara Streamlit UI.

Usage:
    from i18n import t, set_lang, get_lang, LANGUAGES
    set_lang("zh-TW")
    st.write(t("sidebar.title"))
    st.write(t("scan.progress_text", done=5, total=10))
"""
from __future__ import annotations

import streamlit as st

LANGUAGES = {"en": "English", "zh-TW": "正體中文"}
_DEFAULT = "en"


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
- **Case Insights** — rule-based summary (no LLM): headline, key findings (landing concentration, risk flags, cross-post parameters with platform attribution, infrastructure), and data gaps.
- **Scanned Destinations** — all final domains reached. The table shows total URLs, how many are flagged, post count, and per-flag counts (e.g. `🔴 multi_hop ×2`). Drill in to see individual shortlinks sorted by flag severity. URLs where the scan stopped at the shortlink service itself (did not penetrate to the real destination) are listed separately.
- **Shared URL Parameters** — query parameter key=value pairs that appear in 2+ distinct posts, with automatic attribution for known tracking platforms (e.g. Google Analytics UTM, Facebook fbclid).
- **Hosting Infrastructure** — landing domains grouped by ASN (hosting provider). Identifies shared infrastructure across different abuse domains.

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

`snapshots/snapshots.csv` lists all snapshot attempts. The `screenshot_file` and `html_file` columns show the ZIP-relative path to binary files, or are blank if capture failed — so you always know exactly what is and isn't present.\
"""

_GUIDE_ZH = """\
**kwara** 協助您收集、掃描並記錄 URL 短連結與網域濫用的數位證據。

---

#### 1. 輸入（Input）
從單篇貼文或批次 CSV 新增證據。
- **單篇貼文** — 貼上包含 URL 的文字，填寫平台／發文者等欄位，並可附加截圖。
- **CSV 批次** — 上傳含有以下欄位的試算表：`platform`、`permalink`、`actor_label`、`posted_at`、`message_text`。

系統會自動擷取並去重所有 URL。除 Message Text 外，其餘欄位均為選填。

---

#### 2. 已收集（Collected）
檢視目前案件已匯入的所有內容。
- **來源貼文** — 原始訊息與相關詮釋資料。
- **擷取的 URL** — 所有被找到的 URL，含網域、掃描狀態及最終目的地。

---

#### 3. 分析（Analysis）

**掃描（Scan）** — 逐跳追蹤每個 URL 的重導向鏈。
- 一鍵批次掃描所有未掃描的 URL（8 執行緒平行）。
- 透過展開選單逐一掃描個別 URL。
- 若掃描中斷，該筆會顯示為 **Stuck**；使用 Reset 按鈕將其標為失敗以重新掃描。

**調查（Investigate）** — 深入分析任一已掃描 URL。
- **優先佇列** — 已掃描但尚未截圖的 URL，依掃描時風險訊號排序。旗標越多 = 優先調查。
- **URL 選擇器** — 依風險旗標數量排序；標籤一覽掃描狀態、截圖狀態與旗標。
- **全部截圖 + WHOIS** — 依序以無頭瀏覽器截圖並查詢 WHOIS，每個 URL 約需 10–30 秒，確認前會顯示預估時間。
- 單一 URL 詳情：完整重導向鏈、落地頁截圖、WHOIS（註冊商、網域建立日期）、風險旗標、頁面載入時接觸的外部網域。

**聚合分析（Clusters）** — 跨貼文的事實性分組：
- **案件洞察** — 規則式摘要（非 LLM）：總覽、重點發現（落地集中度、風險標記、跨貼文參數歸屬、基礎設施），以及資料缺口。
- **已掃描目的地** — 所有落地網域，顯示 URL 數、旗標數、貼文數及各旗標統計。展開可查看依旗標嚴重度排序的個別短連結。
- **共用 URL 參數** — 出現在 2 篇以上貼文的 key=value 參數，自動辨識已知追蹤平台歸屬（如 Google Analytics UTM、Facebook fbclid）。
- **主機基礎設施** — 依 ASN（主機商）分組的落地網域，識別跨不同濫用網域的共用基礎設施。

---

#### 4. 服務提供商（Providers）
列出與濫用相關的 **服務提供商**：
- **短連結服務商** — 本案件中使用的已知短連結服務（如 bit.ly、t.co）。展開可查看該服務的所有 URL。
- **網域註冊商** — 濫用落地網域的註冊商（執行截圖或情資查詢後填入）。

用途：識別應向誰發出濫用投訴。

---

#### 5. 匯出（Export）
下載 ZIP 證據封包。根目錄的 **README.txt** 以純文字說明每個檔案與欄位，含跨 CSV 的對照鍵值。

內含：來源貼文、擷取的 URL、重導向鏈、快照詮釋資料（WHOIS、風險旗標、request domains）、落地頁截圖與 HTML（截圖成功時）、操作紀錄、SHA-256 manifest。

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
    "tab.investigate": "Investigate",
    "tab.clusters": "Clusters",

    # ── Sidebar ─────────────────────────────────────────────────────────────
    "sidebar.title": "kwara",
    "sidebar.btn_guide": "How to Use",
    "sidebar.new_case": "+ New Case",
    "sidebar.label_title": "Title",
    "sidebar.label_desc": "Description",
    "sidebar.btn_create": "Create",
    "sidebar.success_created": "Case created: {title}",
    "sidebar.warn_title": "Title is required.",
    "sidebar.active_case": "Active Case",
    "sidebar.info_no_cases": "No cases yet. Create one above.",

    # ── Page header / guard ─────────────────────────────────────────────────
    "page.header": "#### kwara — URL Shortener and Domain Abuse Evidence Kit",
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
    "inv.btn_dl_failed": "Download URLs needing manual capture (CSV)",
    "inv.select_url": "Select URL",
    "inv.chain": "Redirect Chain",
    "inv.not_scanned": "Not scanned yet. Go to the Scan tab.",
    "inv.chain_caption": "Final URL: `{final_url}` · {hops} hops · {status}",
    "inv.whois_header": "Domain & hosting (WHOIS / ASN)",
    "inv.scan_first": "Complete a scan first.",
    "inv.btn_intel_only": "Domain intel only (no screenshot)",
    "inv.btn_intel_help": "WHOIS / ASN only; no browser.",
    "inv.spinner_whois": "WHOIS / ASN…",
    "inv.error_intel": "Domain intel failed: {e}",
    "inv.btn_recapture": "Re-capture",
    "inv.btn_capture": "Capture snapshot",
    "inv.spinner_snapshot": "Capturing screenshot + WHOIS / ASN…",
    "inv.error_snapshot": "Snapshot failed: {e}",
    "inv.final_domain": "**Final Domain:** {v}",
    "inv.ip_address": "**IP Address:** {v}",
    "inv.asn_hosting": "**ASN / Hosting:** {v}",
    "inv.registrar": "**Registrar:** {v}",
    "inv.domain_created": "**Domain Created:** {v}",
    "inv.intel_updated": "Domain intel updated: `{ts}`",
    "inv.risk_flags": "**Risk Flags:** {v}",
    "inv.snapshot_header": "Snapshot (screenshot & page)",
    "inv.scan_first_snap": "Complete a scan first.",
    "inv.no_snapshot": "No snapshot yet. Use **Capture snapshot** above for Playwright evidence, or fetch **domain intel** without a screenshot.",
    "inv.capture_status": "Capture status: `{status}`",
    "inv.capture_status_detail": "Capture status: `{status}` — {detail}",
    "inv.missing_screenshot": "Screenshot file missing.",
    "inv.request_domains": "Request Domains ({n})",
    "inv.request_domains_caption": "All domains the browser contacted during page load — includes third-party scripts, ad networks, trackers, and CDNs. A high count indicates the landing page embeds many external services.",
    "inv.btn_dl_html": "Download HTML",
    "inv.manual_caption": "Upload a screenshot/HTML captured manually in your browser (e.g. when automation is blocked).",
    "inv.upload_png": "Replace screenshot (PNG)",
    "inv.upload_html": "Replace HTML (optional)",
    "inv.btn_save_manual": "Save manual evidence",
    "inv.warn_choose_png": "Choose a PNG file first.",

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
    "clusters.params_caption": "Query parameter key+value pairs that appear in 2 or more distinct posts (checked in both the original shortlink and the final URL). Requires identical key=value across posts — a single post with multiple matching URLs does not qualify.",
    "clusters.no_params": "No shared parameters found across posts.",
    "clusters.infra": "Hosting Infrastructure",
    "clusters.infra_caption": "Abuse landing domains grouped by ASN (hosting provider). Populated after WHOIS/ASN lookup (Investigate: domain intel or snapshot).",
    "clusters.no_asn": "No ASN data yet. Run **Domain intel only** or capture a snapshot in the Investigate tab.",
    "clusters.drill_asn": "Drill into ASN",
    "clusters.domains_asn": "**Domains hosted on AS{asn} ({n} total):**",
    "clusters.shortlinks_asn": "**Shortlinks pointing to this infrastructure ({total} total, {flagged} flagged):**",

    # ── Providers ───────────────────────────────────────────────────────────
    "prov.shortlinks": "Shortlink Providers",
    "prov.shortlinks_caption": "Services whose customers are distributing abusive shortlinks.",
    "prov.drill": "Drill into provider",
    "prov.urls_provider": "**URLs using this provider ({total} total, {flagged} flagged):**",
    "prov.no_providers": "No known shortlink providers identified yet. Add URLs containing services like bit.ly, t.co, tinyurl.com etc.",
    "prov.registrars": "Domain Registrars",
    "prov.registrars_caption": "Registrars whose customers registered the abuse destination domains.",
    "prov.no_registrars": "No registrar data yet. Run **Domain intel only** or capture snapshots in Investigate to populate WHOIS.",

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

    # ── Insights (used in insights.py) ──────────────────────────────────────
    "insights.headline_none": "No URLs in this case yet. Add content in the Input tab.",
    "insights.headline_counts": "**{url_count}** shortlink(s) / URL(s) total, **{scanned}** scanned (redirect resolved).",
    "insights.headline_dest": "**{n_dest}** identifiable landing domain(s)",
    "insights.headline_dest_unresolved": "; **{n_un}** destination(s) still stopped at the shortlink service itself (not penetrated).",
    "insights.headline_params": "**{n}** cross-post repeated URL parameter(s) detected (potentially tracking or campaign related).",
    "insights.headline_asn": "**{n}** hosting / ASN cluster(s) (from resolved landing domains).",
    "insights.bullet_landing": "**Landing concentration:** Top destinations by post coverage: {bits}.",
    "insights.bullet_landing_item": "`{domain}` ({posts} posts, {urls} URLs)",
    "insights.bullet_risk": "**Risk flags:** {flagged} URL(s) carry risk flags. Breakdown: {parts}.",
    "insights.bullet_risk_item": "`{tag}` ({label}) x{cnt}",
    "insights.bullet_unresolved": "**Shortlink not penetrated:** {n} landing domain(s) are known shortlink services — real destination unknown. Consider re-scanning or opening the link manually.",
    "insights.bullet_param": "**Cross-post parameters:** Most repeated is `{key}={value}`{owner} (found in {posts} distinct posts).",
    "insights.bullet_param_owner": ", attributed to {owner}",
    "insights.bullet_param2": "Followed by `{key}={value}`{owner} ({posts} posts).",
    "insights.bullet_infra": "**Infrastructure:** By URL volume, **AS{asn}** ({org}) covers the most landing domains and shortlinks ({domains} domains, {urls} URLs).",
    "insights.bullet_no_scans": "No scanned URLs yet — run scans in the **Scan** tab to generate pattern summaries here.",
    "insights.gap_intel": "**{n}** scanned URL(s) have no domain intel (WHOIS/ASN) yet — use **Domain intel only** in the Investigate tab (no browser needed).",
    "insights.gap_snap": "**{n}** URL(s) have no snapshot record (no screenshot or intel-only). Capture screenshots or upload manual evidence if page-level proof is needed.",
    "insights.gap_unscanned": "**{n}** URL(s) not yet scanned or latest scan not marked as done.",

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
    "tab.investigate": "調查",
    "tab.clusters": "聚合分析",

    # ── Sidebar ─────────────────────────────────────────────────────────────
    "sidebar.title": "kwara",
    "sidebar.btn_guide": "使用說明",
    "sidebar.new_case": "+ 新增案件",
    "sidebar.label_title": "標題",
    "sidebar.label_desc": "描述",
    "sidebar.btn_create": "建立",
    "sidebar.success_created": "案件已建立：{title}",
    "sidebar.warn_title": "標題為必填。",
    "sidebar.active_case": "目前案件",
    "sidebar.info_no_cases": "尚無案件，請在上方新增。",

    # ── Page header / guard ─────────────────────────────────────────────────
    "page.header": "#### kwara — URL 短連結與網域濫用證據套件",
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
    "inv.btn_dl_failed": "下載需手動截圖的 URL 清單（CSV）",
    "inv.select_url": "選擇 URL",
    "inv.chain": "重導向鏈",
    "inv.not_scanned": "尚未掃描。請前往「掃描」分頁。",
    "inv.chain_caption": "最終 URL：`{final_url}` · {hops} 跳 · {status}",
    "inv.whois_header": "網域與主機（WHOIS / ASN）",
    "inv.scan_first": "請先完成掃描。",
    "inv.btn_intel_only": "查詢網域情資（不需截圖）",
    "inv.btn_intel_help": "僅查 WHOIS/ASN，不啟動瀏覽器。",
    "inv.spinner_whois": "WHOIS / ASN…",
    "inv.error_intel": "網域情資查詢失敗：{e}",
    "inv.btn_recapture": "重新截圖",
    "inv.btn_capture": "截圖",
    "inv.spinner_snapshot": "截圖 + WHOIS / ASN 中…",
    "inv.error_snapshot": "截圖失敗：{e}",
    "inv.final_domain": "**最終網域：** {v}",
    "inv.ip_address": "**IP 位址：** {v}",
    "inv.asn_hosting": "**ASN / 主機：** {v}",
    "inv.registrar": "**註冊商：** {v}",
    "inv.domain_created": "**網域建立日：** {v}",
    "inv.intel_updated": "網域情資更新於：`{ts}`",
    "inv.risk_flags": "**風險旗標：** {v}",
    "inv.snapshot_header": "快照（截圖與頁面）",
    "inv.scan_first_snap": "請先完成掃描。",
    "inv.no_snapshot": "尚無快照。使用上方 **截圖** 取得 Playwright 證據，或使用 **查詢網域情資** 取得 WHOIS 資料。",
    "inv.capture_status": "截圖狀態：`{status}`",
    "inv.capture_status_detail": "截圖狀態：`{status}` — {detail}",
    "inv.missing_screenshot": "截圖檔案遺失。",
    "inv.request_domains": "Request Domains（{n}）",
    "inv.request_domains_caption": "頁面載入時瀏覽器接觸的所有外部網域 — 包含第三方腳本、廣告網路、追蹤器與 CDN。數量偏高表示落地頁嵌入了多個外部服務。",
    "inv.btn_dl_html": "下載 HTML",
    "inv.manual_caption": "上傳在瀏覽器中手動截取的截圖／HTML（例如自動化被阻擋時使用）。",
    "inv.upload_png": "替換截圖（PNG）",
    "inv.upload_html": "替換 HTML（選填）",
    "inv.btn_save_manual": "儲存手動證據",
    "inv.warn_choose_png": "請先選擇 PNG 檔案。",

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
    "clusters.params_caption": "出現在 2 篇以上貼文的 query 參數 key=value（同時檢查原始短連結與最終 URL）。相同 key=value 在同一篇貼文的多個 URL 中重複出現不計入。",
    "clusters.no_params": "未發現跨貼文的共用參數。",
    "clusters.infra": "主機基礎設施",
    "clusters.infra_caption": "依 ASN（主機供應商）分組的濫用落地網域。需先執行 WHOIS/ASN 查詢（調查分頁的網域情資或截圖）。",
    "clusters.no_asn": "尚無 ASN 資料。請在「調查」分頁執行 **查詢網域情資** 或截圖。",
    "clusters.drill_asn": "展開 ASN",
    "clusters.domains_asn": "**託管於 AS{asn} 的網域（共 {n} 個）：**",
    "clusters.shortlinks_asn": "**指向此基礎設施的短連結（共 {total} 條，{flagged} 條有旗標）：**",

    # ── Providers ───────────────────────────────────────────────────────────
    "prov.shortlinks": "短連結服務商",
    "prov.shortlinks_caption": "其用戶正在散布濫用短連結的服務商。",
    "prov.drill": "展開服務商",
    "prov.urls_provider": "**使用此服務商的 URL（共 {total} 條，{flagged} 條有旗標）：**",
    "prov.no_providers": "尚未識別到已知的短連結服務商。請新增包含 bit.ly、t.co、tinyurl.com 等服務的 URL。",
    "prov.registrars": "網域註冊商",
    "prov.registrars_caption": "註冊了濫用落地網域的註冊商。",
    "prov.no_registrars": "尚無註冊商資料。請在「調查」分頁執行 **查詢網域情資** 或截圖以填入 WHOIS 資料。",

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
    "insights.bullet_infra": "**基礎設施：** 以流量／URL 量來看，**AS{asn}**（{org}）涵蓋最多落地網域與短連結（{domains} 網域、{urls} 條 URL）。",
    "insights.bullet_no_scans": "尚無完成掃描的 URL——請到 **掃描** 分頁執行掃描後，此處會出現模式摘要。",
    "insights.gap_intel": "**{n}** 筆已完成掃描但尚未執行網域情資（WHOIS／ASN）——可在「調查」分頁使用「只查 WHOIS/ASN」不必截圖。",
    "insights.gap_snap": "**{n}** 筆尚無 snapshot 列（可能未截圖或僅有情資）；若需頁面證據請補截圖或手動上傳。",
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
