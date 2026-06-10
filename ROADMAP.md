# kwara 開發 Roadmap

> 最後更新：2026-06-10
> 目前狀態：Phase 1 + 2 + 3 + 4 + 5.1 完成、過 5 輪 codex review、277/277 測試綠燈、QSH 100 筆端到端驗證通過。
> 下一批：Phase 5.2（header 衍生訊號入索引）/ Phase 6（對外報告）/ Phase 7（watchlist + feed，依賴 5.1）。

---

## 目前已交付（不是 roadmap，是基線）

| Phase | 範圍 | 主要模組 |
|---|---|---|
| Phase 1 | URL 參數聚合、TLS 憑證、Account Patterns、Providers、UI 三段式重塑、模組解耦（i18n / clustering god-module split / pipeline 副作用拆分） | `param_attribution.py`、`clustering_url.py`、`clustering_infra.py`、`views/tab_*.py` |
| Phase 2 | HTML 內嵌 Pixel/GA/GTM/Ads/TikTok 指紋抽取、跨網域 ID 聚合、Providers 整合 URL+HTML 雙訊號 | `fingerprints.py`、`clustering_infra.py` |
| Phase 3 | Wrapper-domain 偵測、輕量 HTML-only fetch、HAR 第三方 endpoint 聚合、第二批指紋（Clarity/Hotjar/LINE Tag/X Pixel） | `clustering_url.wrapper_relationships`、`lightweight_fetch.py`、`fingerprints.py`（擴充） |
| **Phase 4 OPSEC Forensics（已交付）** | **4.1 Cloaking 偵測、4.2 Response header 鑑識（4 函式）、4.3 OPSEC profile、4.4 chunk failure auto-abort；第三批指紋（AdSense / FB Page）；Phase 4 訊號回灌 Insights 摘要；Phase 4 thresholds 移入 config** | **`cloaking.py`、`header_analysis.py`、`opsec.py`、`views/_sub_cloaking.py`、`_sub_headers.py`、`_sub_opsec.py`、`insights.py`** |
| 證據完整性（5 輪 codex review） | per-capture artifact dirs、manifest.sha256、HMAC 簽章、案件刪除 realpath 限制、manual upload 不再 mutate 既有 row、export→restore 路徑對齊 | `snapshots._per_capture_dir`、`exporter.py`、`restore_from_export.py`、`app.py`、`views/_sub_page.py` |

> Phase 4 各子項（4.1–4.4）的設計細節仍保留在下方「Phase 4」章節作為設計紀錄；它們**已全部 shipped**，列在上表基線。

---

## Phase 4 — OPSEC Forensics（從 QSH 100 筆 E2E 驗證浮出來的盲點）

本階段的全部項目都源自 2026-04-28 的真實案件驗證。詳見 `QSH_E2E_TEST_REPORT_2026-04-28.md` 第 4.11 節與後續對話發現。

### 4.1 Cloaking Detection（最高優先）

**問題**：crawlerlanding.{net,org} 看到 `?uid=` 才 302 跳轉、無 `uid` 則正常吐 25KB 內容。kwara 一律帶 tracking param 掃 → 永遠看不到 crawlerlanding 服務 SEO 爬蟲那一面、誤判它為「pure wrapper」。

**做法**：對每個帶 tracking param 的 URL，**順便抓「去 param」版本**比對：

| 比對欄位 | 差異閾值 | 訊號 |
|---|---|---|
| `status_code` | 不同 | cloaking suspect |
| `final_domain` | 不同 | conditional redirect |
| body sha256 | 不同 | 內容差異化（可能 SEO/user 區別） |
| body size | > 30% 差異 | 同上 |

**對應模組**：
- `scanner.py` — 加 `scan_url_pair()` 抓兩個版本
- `db.py` — 新欄位 `scan_runs.cloaking_signal_json`
- `views/_sub_cloaking.py`（新）— 在 `tab_analyze` 下加 sub-tab

**開發效果**：自動標記「主動防偵測」訊號；證據力 **≥ GA4 共用**（後者是無意識指紋、cloaking 是有意識規避）。對 crawlerlanding 這類 cloaker 不再會被騙。

**預估**：0.5 天

---

### 4.2 Response Header 保留（epic）

**問題**：本次手動 `curl -D` 撈 crawlerlanding 302 時，發現 3 個關鍵 OPSEC 漏洞**全部在 response headers 裡**，但 kwara 今天 `redirect_hops` 只存 `(hop_order, url, status_code, location, resolved_url, fetched_at)`，其他 30+ header 現場讀現場丟。

**做法**：
- `redirect_hops` 加 `response_headers_json` 欄位
- `scanner.py` 抓每跳時順便存
- 開 4 個分析 view（依序）

**4 類解鎖分析**：

| 分析 | 訊號類型 | QSH 命中 |
|---|---|---|
| **per-domain header constants** | 持續性 server fingerprint | `x-server-hosted: Malaysia Cloud Pte Ltd` 揭露 Cloudflare 後面的真實 origin |
| **cross-domain header diff** | 多域名共用 server template = 同操作者 | （待跑全資料才知）若 hubsite + satellitesite + visitorlanding 都帶相同假 `x-powered-by`，cluster 證據力 = GA4 共用級別 |
| **anomaly detection（版本字串）** | operator 主動造假指紋的故意性 | `Apache/2.5.1`、`OpenSSL/1.1.2e` 都不存在 |
| **Set-Cookie domain leak** | cookie domain 洩 origin、flag 一致性是指紋 | （待驗證） |

**對應模組**：
- `db.py` — `redirect_hops.response_headers_json`
- `scanner.py` — 抓 + 存
- `clustering_infra.py` — 4 個新 function（`header_constants_per_domain`、`header_diff_across_domains`、`detect_fake_versions`、`cookie_origin_signals`）
- `views/_sub_headers.py`（新）— 在 `tab_analyze` 下

**開發效果**：解鎖 origin host 識別（繞過 Cloudflare proxy）、operator 同 server template 聚合（**比肩 GA4 共用的證據力**）、主動造假 anomaly 偵測。

**預估**：0.5 天 schema + scanner 改動，4 個 view 各 1-2 小時 = **1.5 天總計**

---

### 4.3 OPSEC Profile View

**問題**：本次報告 4.11 表格（每域名的 lightweight vs Playwright 成功率）是手算的——工具沒有 cross-domain 的對比視圖。但這個對比**獨立於 GA4 訊號**指向同樣的兩個操作者切割，是高訊噪比的輔助。

**做法**：在 `tab_analyze` 加 `_sub_opsec.py`，呈現：

```
                lightweight 成功    Playwright 成功    OPSEC 等級
 visitorlanding.example      23 / 23 (100%)     23 / 23 (100%)    弱（不擋 UA）
 hubsite.example     12 / 73 ( 16%)     73 / 73 (100%)    中（擋 UA、放 Chromium）
 satellitesite.example    0 /  4 (  0%)      4 /  4 (100%)    強（嚴格擋 UA）
```

差異 > 50% 的域名標紅、列為「同操作者潛在分組訊號」。

**對應模組**：
- 無 schema 改動（用既有 `snapshots.capture_method` + `capture_status`）
- `views/_sub_opsec.py`（新）— 在 `tab_analyze` 下

**開發效果**：人工可視化「擋 UA 但放 Chromium」WAF 部署模式；輔助 GA4 cluster 推論。

**預估**：半天

---

### 4.4 Chunk Failure-Rate Auto-Abort（操作面改善）

**問題**：本次 E2E 第一次 Playwright 跑 99/100 失敗（`net::ERR_INTERNET_DISCONNECTED`、暫時性網路異常），但批次跑了 16 分鐘才結束才發現。

**做法**：`run_snapshot_batch` 加參數 `failure_rate_threshold=0.5`、`min_chunk_size=5`；連續 N 個 chunk 失敗率超過閾值 → raise `ENV_ABORTED`、提示分析師排查環境。

**對應模組**：
- `pipeline.py:226` `run_snapshot_batch`

**開發效果**：避免 16+ 分鐘空跑；環境異常立即可見。

**預估**：1 小時

---

## Phase 5 — Cross-Case Longitudinal（既定優先）

### 5.1 跨案件查詢 ✅（已交付 2026-06-10）

**問題**：今天每個案件是獨立 SQLite DB，無法回答「`G-T5N9K2Q7W3` 出現在過去哪些案件」、「Malaysia Cloud Pte Ltd 過去半年我們追過幾次」。但這正是 single-user local tool 的**核心增值點**——分析師累積的歷史比任何 SaaS 都深。

**已交付**：
- 集中索引 DB（`~/.kwara/index.db`，可由 `KWARA_INDEX_DB_PATH` 覆寫）儲存 5 類強訊號：tracking_id、TLS cert serial、registrar、ASN、final_domain，每筆帶 provenance（source_db、case_id、case_title、scan_run_id、observed_at）。**含 singleton**（A 案單筆配 B 案單筆才是重點）。
- 手動觸發 upsert（跨案件分頁的「加入索引」按鈕）；full-refresh per (source_db, case_id)，re-index 冪等。
- 查詢介面：`lookup(value)` 查單值所有命中；`recurring_signals(min_cases=2)` 列出跨 2+ 案件再現的訊號。**涵蓋跨不同 DB 檔**（使用者 2026-06-10 拍板的範圍）。

**對應模組**：
- `index_db.py`（新）— schema、抽訊號、index_case、lookup、recurring_signals
- `views/tab_crosscase.py`（新）— 跨案件分頁（第 6 個頂層分頁，介於 分析 與 匯出 之間）
- `sql.py`（新，第一步）— 共用 latest-done-scan / latest-usable-snapshot 子查詢；index_db 直接重用

**尚未做（Phase 5.2 候選）**：x-server-hosted（origin host）、cookie domain、假版本字串等 header 衍生訊號的索引；自動觸發（目前僅手動）。

**開發效果**：kwara 從 per-case → 縱向追蹤；同一個操作者跨案件再現會自動浮出，是 single-user tool 對 SaaS 的最大優勢。也是 Phase 7 watchlist 的存放體。

**預估**：~1 天

---

## Phase 6 — Outreach & Reporting（既定優先）

### 6.1 PDF Executive Summary（中英）

**問題**：今天分析師要對外溝通（給長官、給 trust&safety 平台、給註冊商）只能口頭描述或截圖。

**做法**：
- 一頁 PDF（中英對照）— Operator cluster 圖、關鍵 ID 表、TLS/ASN/cert 證據、redirect chain 樹
- 用 `reportlab` 或 `weasyprint`（純 Python、無外部 binary 依賴）

**對應模組**：
- `insights.py` — **必須先解耦 i18n**（移除 `t()` 呼叫，改成接受 locale 參數的 pure data function）
- `reports/pdf_executive.py`（新）
- `views/tab_report.py`（新）

**開發效果**：對外溝通不再只有截圖；證據呈現格式統一。

**預估**：1.5 天（含 insights.py 解耦）

### 6.2 Abuse 表單 Pre-Fill

**問題**：對 Cloudflare / Google Trust Services / Meta / 各註冊商提 abuse 報告，每家表格欄位不同、手填極耗時。

**做法**：對每個常見對象（Cloudflare abuse / GTS revoke / Meta T&S / NameSilo / PDR / Cloudflare registrar）建欄位映射 → 從案件 DB 抽資料 → 匯出 CSV/JSON 或直接生成預填表格 URL。

**對應模組**：
- `reports/abuse_forms.py`（新）— 各家欄位映射 + 抽資料邏輯
- `views/tab_report.py`（同 6.1）

**開發效果**：對外檢舉時間從 30 分鐘 → 5 分鐘；欄位一致性提高。

**預估**：1 天

### 6.3 urlscan / Wayback 自動提交

**問題**：分析師慣常會手動提交 urlscan / Wayback Machine 留存證據快照，但常忘記。

**做法**：scan 完成後（或手動觸發）批次提交 final_url 到 urlscan.io / web.archive.org/save，把回傳的 url 存進 `scan_runs.corroboration_json`（既有欄位）。

**對應模組**：
- `corroboration.py`（既有，擴充）
- `pipeline.py:_try_corroborate`（既有）

**開發效果**：第三方留存證據自動化；不依賴分析師記性。

**預估**：0.5 天

---

## Phase 7 — Watchlist + Forward Capture（新增候選，依賴 Phase 5）

**問題**：kwara 目前是 query-on-demand，每次都「事後」對已知 URL 做歸因。無法在 operator 一架新站、新 cert 簽出來那一刻就抓到。

**做法**（建立在 Phase 5.1 跨案件 index 之上）：
- 每次案件結束把強訊號（GA4/Pixel ID、cert serial、`x-server-hosted`、假 `x-powered-by` 字串、HAR 直連 IP）抽到 watchlist。
- 對 watchlist 訂閱外部 feed：**PublicWWW**（HTML 反查）、**certstream**（CT log firehose）、**WhoisDS**（每日 newly-registered）、**Shodan/Censys**（HTTP banner）。
- 命中新域 → 自動丟回 kwara 案件管線（調查→保全→分析全套）。

**開發效果**：把「預測下一波」從 at-launch capture 的角度落地——operator 的新資產一上線就進案件。

**前置依賴**：Phase 5.1 跨案件 index（watchlist 的存放體）；解決 single-user local tool 怎麼跑長駐 cron（launchd / lazy run / 極小 daemon）。

**預估**：~2 天（不含 feed API 額度評估）。與 Backlog「威脅情資 feed 整合」「定期 re-check」為同一架構塊，三者一起想。

---

## Backlog（中等信心，需先驗證命中率再投資）

| 候選 | 不確定性 | 觸發條件 |
|---|---|---|
| **威脅情資 feed 整合**（urlscan tags、abuse.ch、OpenPhish） | 大部分 feed 偏 phishing kit、對 FIMI / clickbait 命中率未知 | 先在 QSH 100 筆上 dry-run 看命中率 |
| **網路圖視覺化**（操作者基礎設施 graph） | 視覺化好看但「分析師需要 vs 想要」未驗證 | 先請 2-3 位分析師人工試做、看用不用 |
| **定期 re-check / 變化偵測**（詐騙站還活著嗎、基礎設施換了沒） | 價值高、但增加 cron / storage 維運成本、與 single-user 設計理念有張力 | 先想清楚 single-user 模式怎麼跑 cron（launchd？open kwara 時 lazy run？） |
| **CMS 指紋** | kwara 主要用例是自架 PHP clickbait，CMS 訊號可能稀薄 | **先評估真實命中率再決定是否做** |

---

## 不會做（跟設計理念衝突）

- **多人 / SaaS 化** — kwara 是 single-user local SQLite by design；分析師主權 + 隱私 + 速度都比共享優先
- **AI 自動下協同行為判定** — Account Patterns 已拍板「不自動 flag、避免過擬合」；分析師看矩陣自己判斷
- **任意爬蟲式廣面收集** — kwara 是 evidence-grade、不是 scraper；只跑分析師明確匯入的 URL

---

## 必須保留的契約（任何新功能不能回退這些）

| # | 契約 | 出處 |
|---|---|---|
| 1 | Canonical `platform_id`（symbol equality）作為 dedup key | `param_attribution.PLATFORM_*` |
| 2 | Owner-kind enum：clustering 結果 row 帶 `owner_kind` + `platform_id` | `clustering_*` |
| 3 | `signal_source` 4-state enum：`both` / `mixed_nonoverlap` / `html_embedded` / `url_param`；`both` 必須要求**同 ua_id 或 domain 上的 URL+HTML 交集** | `clustering_infra` |
| 4 | Fingerprint 必須有 invocation context（vendor URL host / 函式呼叫 / dataLayer 字面量） | `fingerprints.py` |
| 5 | `_looks_like_placeholder` 只對字母生效（不擋全相同數字 ID） | `fingerprints.py` |
| 6 | Latest-usable snapshot：`capture_status='ok' AND tracking_ids_json IS NOT NULL ORDER BY id DESC LIMIT 1` | `clustering_infra` |
| 7 | Per-capture artifact dirs：`data/snapshots/{scan_run_id}/{timestamp}_{rand4}/`；ZIP archive 用 `snapshots/{snapshot_id}/...` | `snapshots._per_capture_dir`、`exporter.py` |
| 8 | Manifest 自保護：export 必出 `manifest.sha256`；無 `KWARA_HMAC_KEY` 時 `manifest.json` 必含 `integrity_warning` | `exporter.py` |
| 9 | Lightweight fetch `allow_redirects=False`：信任 scan 已解的 final_url；3xx 變 `error` snapshot | `lightweight_fetch.py` |
| 10 | Case 刪除限制在 `data/snapshots/` 之下（realpath 驗證） | `app.py` |

---

## 優先順序總覽

```
立即（本月）
  ├─ 4.4 chunk auto-abort（1 小時，操作面）
  ├─ 4.1 cloaking detection（0.5 天，最高證據力增益）
  └─ 4.2 response header 保留（1.5 天，4 類分析解鎖）

短期（1-2 週內）
  ├─ 4.3 OPSEC profile view（半天）
  └─ 5.1 跨案件查詢（~1 天）

中期（1 個月內）
  ├─ 6.1 PDF executive summary（1.5 天）
  ├─ 6.2 abuse 表單 pre-fill（1 天）
  └─ 6.3 urlscan / Wayback 自動提交（0.5 天）

Backlog 觸發後
  ├─ 威脅情資 feed（先 dry-run）
  ├─ 網路圖視覺化（先人工試做）
  ├─ 定期 re-check
  └─ CMS 指紋
```

合計 Phase 4-6 預估 **~7-8 天工程時間**，可分散到 2-3 個 session 完成。
