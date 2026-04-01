# kwara — URL 短連結與網域濫用證據套件

kwara 是一套本地端工具，協助調查人員收集、掃描、分析並封存 URL 短連結濫用的數位證據。工具完全離線運行，所有資料儲存於本機 SQLite 資料庫。

---

## 啟動方式

首次使用請在 `kwara/` 內建立虛擬環境、`pip install -r requirements.txt`，並執行一次 `python -m playwright install chromium`（快照／截圖功能需要 Chromium；未安裝時其餘功能多數仍可用）。

之後可執行專案根目錄的 `start_kwara.bat`，或在 `kwara/` 子目錄下執行：

```
streamlit run app.py
```

---

## 資料模型概觀

```
cases（案件）
  └─ message_evidence（來源貼文）
        └─ url_artifacts（擷取的 URL）
              └─ scan_runs（掃描執行紀錄；含 final_url、hop_count）
                    ├─ redirect_hops（每一跳的 redirect）
                    ├─ （選填）網域情資：WHOIS／IP／ASN／intel_risk_tags／domain_enriched_at
                    └─ snapshots（落地頁截圖／HTML／request domains／與頁面相關 risk_tags）
```

掃描完成後即可寫入 **網域情資**（不必先有快照）。執行 Playwright 快照時，系統會再次合併 WHOIS 與頁面衍生旗標，並同步更新 `scan_runs` 與 `snapshots`。

每個案件相互獨立。側邊欄可切換或新增案件。

---

## 頁面說明

### 1. Input（輸入）

新增來源貼文的入口，支援兩種模式：

**Single Post（單篇）**

手動填寫欄位後送出：

| 欄位 | 說明 |
|------|------|
| Platform | 來源平台，例如 YouTube、Telegram |
| Actor Label | 發文者識別標籤，例如帳號名稱、頻道名稱 |
| Posted At | 貼文發布時間，例如 `2024-01-15 08:30` |
| Permalink | 貼文的直達連結 |
| Message Text | 貼文內文，必填；系統自動從中擷取所有 http/https URL |
| Screenshot | 貼文截圖（選填），納入匯出封包 |

**CSV Batch（批次匯入）**

上傳 CSV 檔案，必要欄位：`platform`、`permalink`、`actor_label`、`posted_at`、`message_text`。

匯入時系統自動：
- 為每一列建立一筆 `message_evidence` 記錄
- 從 `message_text` 擷取所有 URL，寫入 `url_artifacts`
- 對相同 URL（同一訊息內重複出現）自動去重

---

### 2. Collected（已收集）

**Source Posts（來源貼文）**

以表格呈現所有已匯入的貼文，欄位包含平台、發文者、時間、內文預覽。

**Extracted URLs（擷取的 URL）**

所有從貼文中擷取的 URL，含：
- `domain`：原始 URL 的主網域（eTLD+1，例如 `bit.ly`）
- `scan_status`：最新掃描狀態
- `final_url`：掃描追蹤到的最終落地網址

---

### 3. Analysis（分析）

分為三個子頁籤：

---

#### 3-1. Scan（掃描）

對每個 URL 執行 HTTP redirect chain 追蹤，逐跳記錄。

**運作邏輯：**
1. 對原始 URL 發出 GET 請求（`allow_redirects=False`）
2. 若回應為 3xx，解析 `Location` header，計算下一跳的絕對 URL，繼續追蹤
3. 收到非 3xx 回應（例如 200）則停止，記錄為 `final_url`
4. 上限 20 跳；每跳結果寫入 `redirect_hops`

**掃描狀態說明：**

| 狀態 | 含義 |
|------|------|
| `done` | 正常到達非 3xx 回應 |
| `max_hops` | 超過 20 跳上限 |
| `loop_detected` | 偵測到 URL 重複出現（迴圈） |
| `timeout` | 請求超時（預設 10 秒） |
| `ssl_error` | SSL 憑證驗證失敗 |
| `error` | 其他網路或解析錯誤 |

**批次掃描：**
- 點「Scan all unscanned」可同時掃描所有未掃描的 URL
- 採 8 執行緒平行掃描，每個 worker 有 0–2 秒的隨機延遲以降低請求集中度
- 進度條即時顯示掃描進度

**Stuck 偵測：**
若掃描在進行中被中斷（例如強制關閉應用），對應的 scan_run 會停留在 `running` 狀態。系統偵測到這類記錄後會顯示 Reset 按鈕，將其標記為 `error` 以便重新掃描。

---

#### 3-2. Investigate（調查）

對已掃描的 URL 進行深度分析：**網域情資（WHOIS／ASN）** 與 **落地頁快照** 可分開執行。

**Domain intel queue（網域情資佇列）**

列出「已掃描、但尚未寫入網域情資（`domain_enriched_at` 為空）」的 URL。提供 **WHOIS / ASN only — all pending** 一鍵：只查註冊商、建立日、解析 IP 與 ASN，**不使用瀏覽器**，速度遠快於全頁快照。

**Snapshot Priority Queue（快照優先佇列）**

列出所有「已掃描、尚未快照」的 URL，依掃描時期的風險訊號排序，供使用者決定優先處理哪些目標。欄位含：

- `final_domain`：掃描到達的網域
- `hops`：redirect 跳數
- `scan_flags`：掃描階段即可判斷的風險標記（詳見下方說明）

提供「Snapshot & WHOIS All」一鍵按鈕，對所有待快照 URL 依序執行；因使用無頭瀏覽器，每個 URL 需 10–30 秒，按鈕旁會顯示預估時間。

**URL 選擇器**

所有 URL 依風險旗標數量由高至低排序，標籤格式為：

```
[ua_id] https://bit.ly/xxx  [done · snap ✓ · multi_hop, no_https]
```

快照完成後系統會自動回到同一個 URL，不會因頁面刷新而跳回第一筆。

**左欄：Redirect Chain**

以表格顯示每一跳的詳細資料：

| 欄位 | 說明 |
|------|------|
| hop_order | 跳序（從 0 開始） |
| url | 該跳請求的 URL |
| status_code | HTTP 回應碼 |
| location | 3xx 回應的 Location header 值 |

**右欄（上）：Domain & hosting（WHOIS / ASN）**

- **查詢網域情資（不需截圖）**：僅執行 WHOIS 與 IP／ASN 查詢，將結果寫入 `scan_runs`（若已存在 snapshot 列則一併更新該列）。
- 顯示 Final Domain、IP、ASN／Hosting、Registrar、Domain Created；並合併 **Risk Flags**（見下方）。

**右欄（下）：Snapshot（screenshot & page）**

點擊「Capture snapshot」或「Re-capture」後，系統執行：
1. 使用 Playwright 以無頭 Chromium 開啟 `final_url`
2. 截取全頁截圖（`screenshot.png`）
3. 擷取頁面 HTML（`page.html`）
4. 記錄頁面載入過程中所有 request domains（第三方外部資源）
5. 再次執行網域情資（與上方邏輯一致），並合併頁面衍生旗標

有快照時另顯示：
- 截圖預覽（若成功）
- **Request Domains**：頁面載入時瀏覽器所接觸的所有外部 domain，可用於識別追蹤器、廣告網路、CDN

---

**風險旗標（Risk Flags）說明**

旗標由兩個時間點產生，互相補充：

*掃描時可判斷（scan-time flags，不需快照即可顯示）：*

| 旗標 | 觸發條件 |
|------|----------|
| `multi_hop` | redirect chain >= 3 跳 |
| `no_https` | final URL 為 `http://`（未加密） |
| `suspicious_download` | final URL 副檔名為 .exe / .zip / .apk / .dmg 等可執行或壓縮格式 |
| `url_shortener_chain` | final domain 本身是已知短連結服務（掃描未穿透至真實目的地） |

*網域情資產生（WHOIS 路徑，不需 Playwright）：*

| 旗標 | 觸發條件 |
|------|----------|
| `new_domain` | 網域創建日期距貼文發布日期不足 180 天（寫入 `intel_risk_tags` 並合併至展示用旗標） |

*快照時額外產生（需 Playwright 執行頁面載入）：*

| 旗標 | 觸發條件 |
|------|----------|
| `high_tracker_count` | 頁面載入過程中接觸的已知第三方追蹤器 >= 3 個 |
| `capture_error` | Playwright 截圖失敗（WHOIS 和 IP/ASN 仍可能已成功） |

旗標說明：
- `url_shortener_chain` 不代表惡意；它代表掃描工具在該短連結服務的 URL 前停住了，**真實的落地頁未知**，需手動確認或以瀏覽器開啟
- `new_domain` 以貼文的 `posted_at` 為基準日計算；若 `posted_at` 無法解析，以執行情資／快照當天為基準
- `high_tracker_count` 的門檻為 3 個，涵蓋 Google Analytics、Facebook Pixel、Hotjar 等常見追蹤服務

---

#### 3-3. Clusters（聚合分析）

對掃描結果進行跨貼文的事實性聚合，不做意圖推斷。

**案件洞察（規則式摘要）**

頁面上方以可摺疊區塊呈現 **規則式、可稽核** 的摘要（非 LLM）：一句話總覽、數條重點（例如落地集中度、跨貼文參數、ASN 集中），以及資料缺口（尚無情資／尚無快照的筆數提示）。

**Scanned Destinations（已掃描目的地）**

將所有掃描完成的 URL 依 `final_url` 的 hostname 分組。表格顯示：

| 欄位 | 說明 |
|------|------|
| final_domain | 落地頁的 hostname |
| urls | 指向此 domain 的短連結數量 |
| flagged_urls | 其中有風險旗標的 URL 數量 |
| posts | 涉及此 domain 的貼文數量 |
| risk_flags | 各旗標及觸發次數，例如 `multi_hop ×2` |

注意：`risk_flags` 會合併 **snapshot 上的旗標** 與 **scan 層級的 `intel_risk_tags`**（例如僅執行 WHOIS 時得到的 `new_domain`），並附上各旗標的觸發次數。`flagged_urls` 欄位讓使用者清楚知道「210 個連結中只有 3 個有問題」，避免誤解整批連結皆有風險。

Drill-down 展開後，URL 清單依旗標數量由多至少排序，每筆附上個別的旗標標示。

若某個掃描的 `final_domain` 本身是短連結服務（`url_shortener_chain`），該筆資料會從 Scanned Destinations 移除，另外以 info box 呈現，說明「這些連結未穿透短連結，真實目的地未知」。

**Hosting Infrastructure（主機基礎設施）**

將已有 **ASN 資料** 的落地 domain 依 ASN 分組（資料可來自 **網域情資** 或 **快照** 列，兩者擇一即可），識別共用同一個 hosting provider 的多個 domain。

表格顯示：ASN 編號、機構名稱（as_org）、國家、domain 數量、URL 數量、flagged URL 數量、貼文數量、風險旗標分布。

Drill-down 展開後顯示：
- 該 ASN 下的所有 domain 及其 IP 位址
- 指向這些 domain 的原始短連結，依風險旗標排序

用途：若多個不同 domain 落在同一個 ASN，可能代表同一批人佈署的基礎設施（例如同一個 VPS 供應商帳號下的多個釣魚站）。

**Shared URL Parameters（共用 URL 參數）**

跨貼文比對 URL 的查詢參數（query string key=value），找出同一組 key=value 出現在 2 篇以上貼文的情況。

- 同時檢查原始短連結 URL 和 final URL
- 過濾規則：key 長度 <= 1 的忽略；value 超過 100 字元的忽略
- 相同 key=value 在同一篇貼文的多個 URL 中重複出現，不計入跨貼文次數

常見的 UTM 追蹤參數（`utm_source`、`utm_campaign`）或自訂的 ref 參數若大量重複出現，可能代表協調性的推廣行動。

---

### 4. Providers（服務提供商）

**Shortlink Providers（短連結服務商）**

列出本案件中使用的已知短連結服務（`bit.ly`、`t.co`、`tinyurl.com` 等），顯示各服務被使用的 URL 數量。Drill-down 展開後列出該服務的所有 URL，依風險旗標排序。

此頁籤的用途：識別哪些短連結服務商是濫用管道，作為發出濫用投訴的對象清單。

**Domain Registrars（網域註冊商）**

在已取得 WHOIS 的前提下（**只查網域情資** 或 **快照流程** 皆可），顯示落地網域的 registrar 與創建日期。

此頁籤的用途：識別落地頁網域的管理方，作為發出 takedown 請求的對象清單。

---

### 5. Export（匯出）

將案件所有證據打包為 ZIP 檔案，可下載並長期保存。

**ZIP 結構：**

```
case_{id}_{timestamp}.zip
├── README.txt               ← 說明所有檔案和欄位的純文字說明文件
├── manifest.json            ← 每個檔案的 SHA-256 雜湊，用於驗證完整性
├── audit.csv                ← 完整操作紀錄（匯入、掃描、快照、匯出）
├── messages/
│   ├── messages.csv         ← 來源貼文（含 has_screenshot 欄位）
│   └── screenshots/         ← 匯入時上傳的貼文截圖（若有）
├── urls/
│   ├── urls.csv             ← 所有 URL（含 scan_run_id；並含 scan 層 whois／asn／domain_enriched_at 等欄位）
│   └── chains/
│       └── url_{id}_hops.csv ← 各 URL 的 redirect chain 逐跳資料
└── snapshots/
    ├── snapshots.csv        ← 快照元資料（WHOIS、風險旗標、request domains）
    │                          含 screenshot_file、html_file 欄位指示附件是否存在
    └── {scan_run_id}/
        ├── screenshot.png   ← 落地頁截圖（僅快照成功時存在）
        └── page.html        ← 落地頁 HTML（僅快照成功時存在）
```

**跨檔對照鍵值：**

```
messages.csv  id
  └─ urls.csv  message_id
        └─ urls/chains/url_{id}_hops.csv
        └─ snapshots.csv  scan_run_id
              └─ snapshots/{scan_run_id}/
```

**關於截圖是否存在：**

`snapshots.csv` 的 `screenshot_file` 欄位若為空白，代表該次快照的截圖未成功（`capture_error`）。WHOIS 資料和風險旗標仍可能存在於 CSV 中。大型平台（如 YouTube）因具備 bot 偵測機制，截圖成功率較低。

---

## 分析流程建議

```
Input（匯入資料）
  ↓
Scan（批次掃描所有 URL，等待完成）
  ↓
Clusters > Scanned Destinations（確認落地網域分布）
Clusters > Shared URL Parameters（確認跨貼文參數重複情況）
  ↓
Investigate > Priority Queue（依風險旗標優先快照高風險 URL）
  ↓
Providers（整理投訴對象：短連結服務商 + 網域註冊商）
  ↓
Export（下載證據封包）
```

---

## 技術架構

| 元件 | 說明 |
|------|------|
| `app.py` | Streamlit UI 主程式 |
| `db.py` | SQLite 連線與 schema 初始化（WAL 模式） |
| `ingestion.py` | 貼文與 URL 匯入邏輯 |
| `scanner.py` | HTTP redirect chain 追蹤 |
| `pipeline.py` | 調度 scanner → snapshots → whois |
| `snapshots.py` | Playwright 截圖、request domain 收集、風險旗標計算 |
| `whois_lookup.py` | WHOIS 查詢與日期正規化 |
| `clustering.py` | Scanned Destinations 與 Shared Parameters 聚合邏輯 |
| `exporter.py` | ZIP 封包建置與 SHA-256 manifest |
| `audit.py` | 操作紀錄寫入 |
| `utils/domain.py` | eTLD+1 網域擷取（支援 tldextract） |

資料庫位置：`kwara/data/kwara.db`
