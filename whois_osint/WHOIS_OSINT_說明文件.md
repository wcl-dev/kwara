**[English](whois_osint_guide.md)**

# WHOIS OSINT 自動化查詢工具 — 技術說明文件

## 一、概述

本腳本（`whois_domain_lookup.py`）是一套 **OSINT（開源情報）自動化工作流程**，用途是：

> **輸入任意 URL 或網域，自動查出該網域的「註冊商（Registrar）」與「註冊時間（Creation Date）」。**

適用於資安調查、網站背景查核、假網站辨識等場景，全程使用免費開源工具，不依賴任何付費 API。

---

## 二、能解決什麼問題？

| 使用情境 | 說明 |
|----------|------|
| **網站背景查核** | 收到一個陌生網址，想知道這個網站是什麼時候註冊的、由哪家註冊商管理 |
| **假網站/釣魚網站辨識** | 新註冊的網域（例如幾天或幾週前才建立）通常是高風險指標 |
| **OSINT 偵察** | 批次查詢多個目標網域的基本資訊，建立調查時間軸 |
| **品牌監控** | 定期追蹤特定網域的註冊狀態變化 |
| **資料歸檔** | 查詢結果以 Excel 累積保存，每日一個分頁，方便回溯 |

---

## 三、資料來源

```
使用者輸入 URL
       │
       ▼
  ┌──────────┐
  │ WHOIS    │  ← 全球網域註冊資料庫（公開資料）
  │ 伺服器    │     每個 TLD（如 .com, .org, .tw）都有對應的 WHOIS 伺服器
  └──────────┘
       │
       ▼
  python-whois 函式庫解析回傳資料
```

- **WHOIS 協定**：一種公開的網路查詢協定（RFC 3912），任何人都可以向 WHOIS 伺服器查詢網域的註冊資訊。
- **python-whois**：Python 開源函式庫，直接連線各 TLD 的 WHOIS 伺服器取得原始資料並解析。
- **tldextract**：輔助函式庫，精確辨識網址中的「主網域」（例如從 `www.google.com` 取出 `google.com`）。
- **完全免費**：不使用 WhoisXMLAPI 等付費服務，僅走標準 WHOIS 協定。

### 資料限制

| 情況 | 腳本行為 |
|------|---------|
| 網域啟用隱私保護（Privacy Protection） | 欄位填入 `Unknown/Private`，**絕不虛構** |
| WHOIS 伺服器拒絕連線 | 標註 `Connection Refused` |
| 查詢頻率過高被限制 | 標註 `Rate Limited` |
| 網域不存在或查無資料 | 標註具體錯誤訊息 |

---

## 四、運作邏輯（流程圖）

```
輸入 URL / 網域清單
        │
        ▼
┌─────────────────────┐
│ Step 1: 網域提取     │  從 URL 中解析出主網域
│                     │  例：https://www.google.com/search?q=test
│                     │       → google.com
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 2: 查緩存       │  同一網域是否已查過？
│                     │  是 → 直接用緩存結果（不重複查詢）
│                     │  否 → 進入 Step 3
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 3: WHOIS 查詢   │  透過 python-whois 連線 WHOIS 伺服器
│                     │  取得原始回傳資料
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 4: 正則解析     │  從回傳資料中提取：
│                     │  - Registrar（註冊商）
│                     │  - Creation Date（註冊時間）
│                     │  日期統一格式化為 YYYY-MM-DD
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 5: 寫入 Excel   │  結果追加到 whois_results.xlsx
│                     │  每天一個 Sheet（如 2026-02-06）
│                     │  同一天多次執行 → 累積在同一 Sheet
│                     │  不同天 → 自動開新 Sheet
└─────────────────────┘
```

---

## 五、輸出格式

輸出檔案：**`whois_results.xlsx`**（Excel 格式）

| 欄位 | 型別 | 說明 |
|------|------|------|
| `Domain` | 文字 | 主網域（如 `google.com`） |
| `Registrar` | 文字 | 註冊商名稱（如 `MarkMonitor, Inc.`），無法取得時為 `Unknown/Private` |
| `Creation_Date` | 日期 | 網域註冊日期，統一為 `YYYY-MM-DD` 格式，無法取得時為 `Unknown/Private` |
| `Last_Checked_Timestamp` | 時間戳 | 本次查詢的 UTC 時間（如 `2026-02-06 03:24:39 UTC`） |
| `Error_Reason` | 文字 | 若查詢失敗，記錄原因（`Connection Refused`、`Rate Limited` 等）；成功時為空 |

### Excel 分頁規則

```
whois_results.xlsx
├── Sheet: 2026-02-05   ← 2/5 查的資料
│   ├── Row 1: 標題列
│   ├── Row 2: example.com ...
│   └── Row 3: test.org ...
├── Sheet: 2026-02-06   ← 2/6 查的資料（今天）
│   ├── Row 1: 標題列
│   ├── Row 2: google.com ...（第一次執行）
│   ├── Row 3: twreporter.org ...（第二次執行，累積）
│   ├── Row 4: github.com ...
│   └── Row 5: facebook.com ...
└── Sheet: 2026-02-07   ← 明天會自動建立
```

---

## 六、使用方式

### 前置條件

- Python 3.10+
- 虛擬環境已建立且已安裝依賴（`pip install -r requirements.txt`）

### 指令格式

```bash
python whois_domain_lookup.py [URL或網域 ...] [選項]
```

### 範例

```bash
# 查單一 URL
python whois_domain_lookup.py "https://www.twreporter.org/a/some-article"

# 查多筆
python whois_domain_lookup.py "https://www.facebook.com" "github.com" "https://tw.yahoo.com"

# 從檔案批次查（urls.txt 每行一筆）
python whois_domain_lookup.py -f urls.txt

# 指定輸出路徑
python whois_domain_lookup.py "google.com" -o my_results.xlsx

# 停用緩存（強制重新查詢）
python whois_domain_lookup.py "google.com" --no-cache
```

### 在 Cursor IDE 中執行

1. 按 `Ctrl+Shift+D` → 上方下拉選單選 **WHOIS 查詢（輸入 URL）** → 按綠色 ▶
2. 在彈出的輸入框貼上 URL → Enter
3. 結果顯示在終端機，同時寫入 `whois_results.xlsx`

---

## 七、技術細節

### 使用的函式庫

| 函式庫 | 用途 | 授權 |
|--------|------|------|
| `python-whois` | WHOIS 查詢與初步解析 | MIT |
| `tldextract` | 精確提取主網域（eTLD+1） | BSD |
| `openpyxl` | 讀寫 Excel `.xlsx` 檔案 | MIT |

### 日期正規化

WHOIS 伺服器回傳的日期格式因 TLD 而異，腳本支援自動轉換以下格式：

| 原始格式 | 轉換後 |
|----------|--------|
| `2023-01-15` | `2023-01-15` |
| `15-Jan-2023` | `2023-01-15` |
| `Jan 15, 2023` | `2023-01-15` |
| `15/01/2023` | `2023-01-15` |
| `2023.01.15` | `2023-01-15` |
| Python `datetime` 物件 | `2023-01-15` |

### 緩存機制

- 緩存檔：`whois_cache.csv`（CSV 格式，純文字可讀）
- 同一網域在同一次程式執行期間只查一次 WHOIS
- 下次執行時，若緩存中已有該網域，直接取用（可用 `--no-cache` 強制重查）

### 錯誤處理

| 錯誤類型 | Error_Reason 欄位值 | 說明 |
|----------|---------------------|------|
| WHOIS 伺服器拒絕連線 | `Connection Refused` | 可能是防火牆或伺服器維護 |
| 查詢頻率過高 | `Rate Limited` | 短時間內查太多次，被伺服器限流 |
| 隱私保護 | 欄位值為 `Unknown/Private` | 網域註冊者啟用了隱私保護服務 |
| 網域不存在 | `Error: ...` | 附帶原始錯誤訊息 |
| 無法從 URL 提取網域 | `Could not extract domain from input` | 輸入格式不正確 |

---

## 八、檔案結構

```
whois_osint/
├── whois_domain_lookup.py    ← 主腳本
├── requirements.txt          ← Python 依賴清單
├── whois_results.xlsx        ← 查詢結果（Excel，每日累積）
├── whois_cache.csv           ← 緩存檔（加速重複查詢）
├── WHOIS_OSINT_說明文件.md    ← 本文件
├── README.md                 ← 快速上手指南
└── .vscode/                  ← Cursor IDE 設定
    ├── launch.json           ← 偵錯/執行設定
    ├── settings.json         ← Python 環境設定
    └── tasks.json            ← 自動化任務
```

---

## 九、限制與注意事項

1. **WHOIS 資料為公開但非即時**：註冊商可能延遲更新，資料可能有數小時到數天的時差。
2. **部分 ccTLD 資料有限**：某些國家級網域（如 `.cn`、`.ru`）的 WHOIS 資訊可能受限。
3. **頻率限制**：短時間大量查詢同一 TLD 的 WHOIS 伺服器可能被暫時封鎖，建議批次查詢時控制速率。
4. **隱私保護普及**：自 GDPR 實施後，許多歐洲網域的 WHOIS 資料被隱藏，這是正常現象。
5. **不可虛構**：任何無法取得的欄位一律標示 `Unknown/Private`，絕不自行猜測或填入假資料。
