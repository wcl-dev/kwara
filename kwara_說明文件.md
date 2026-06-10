**[English](kwara_guide.md)**

# kwara — 數位證據蒐集與佐證工具

kwara 是一套本地端工具，協助調查人員蒐集、掃描並佐證 URL 短連結濫用、網域詐騙及線上詐騙的數位證據。所有資料儲存於本機 SQLite 資料庫。

---

## 啟動方式

```bash
cd kwara
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

> 未安裝 Playwright/Chromium 時，掃描和 WHOIS 仍可用——僅截圖功能需要瀏覽器。

---

## 資料模型

```
cases（案件）
  └─ message_evidence（來源貼文）
        └─ url_artifacts（擷取的 URL）
              └─ scan_runs（redirect chain、TLS、headers、WHOIS/ASN、佐證）
                    ├─ redirect_hops（每一跳的 redirect）
                    └─ snapshots（截圖、HTML、HAR、風險旗標）
```

每個案件相互獨立。從側邊欄切換或新增案件。

---

## 分頁說明

頂層共六個分頁，依工作流順序排列。其中**調查 → 保全 → 分析**是「三段式工作流」，六個證據步驟分布其中：

```
輸入 → 已收集 → 〔調查 → 保全 → 分析〕→ 匯出
                  掃描     頁面     洞察 / 帳號樣態 / 服務商
                  網路路徑 佐證     Cloaking / Headers / OPSEC
                  網域情報
```

### 1. 輸入（Input）

新增包含可疑 URL 的來源貼文。

- **單篇貼文** — 貼上訊息文字，填寫平台/發文者/時間，可附加截圖。
- **CSV 批次** — 上傳含 `platform`、`permalink`、`actor_label`、`posted_at`、`message_text` 欄位的 CSV。

系統自動擷取並去重 URL。

### 2. 已收集（Collected）

以表格形式檢視所有已匯入的貼文與擷取的 URL。

### 3. 調查（Investigate）

三個子分頁，蒐集每條 URL 的網路層證據：

- **掃描（Scan）** — 追蹤 redirect chain 至真實落地頁。可批次掃描（多執行緒平行）或逐一掃描。中斷的掃描可重設。
- **網路路徑（Network）** — 檢視掃描時自動擷取的 Redirect Chain、TLS 憑證、HTTP 回應標頭（含每跳完整 header 集合）。
- **網域情報（Domain）** — 落地網域的 WHOIS 註冊、IP 位址、ASN 託管資訊。可批次或逐一查詢。

### 4. 保全（Preserve）

兩個子分頁，保全頁面證據並取得第三方佐證：

- **頁面證據（Page）** — 瀏覽器截圖、HTML 原始碼、HAR 網路流量紀錄。可批次或逐一截圖、支援手動上傳；亦提供輕量 HTML-only 抓取模式（不啟動瀏覽器、快上 10 倍）。
- **第三方佐證（Corroboration）** — 將落地頁提交至 Internet Archive、urlscan.io，並取得 RFC 3161 受信任時間戳。掃描後自動觸發，可手動重試。

### 5. 分析（Analyze）

六個子分頁，跨 URL 聚合已蒐集的證據：

- **分析洞察（Insights）** — 規則式案件摘要：落地集中度、風險旗標、跨貼文參數歸屬、TLS/ASN 聚合、追蹤碼吻合、**Phase 4 主動防偵測訊號（cloaking / 偽造版本 / server 模板 / 強 UA 阻擋）**，以及資料缺口提示。先看這頁。
- **帳號樣態（Account Patterns）** — 帳號 × 內容矩陣（不自動下協同判定，攤給分析師判讀）。
- **服務提供商（Providers）** — 問責視角：涉案短連結服務商、網域註冊商、託管、CA、廣告/追蹤平台。
- **Cloaking** — conditional cloaker 偵測（帶參數 vs 不帶參數的內容差異）。逐 URL verdict + case-wide 統計。
- **Headers** — 每跳 response header 鑑識：per-domain 常數、跨域 server 模板、偽造版本字串、Set-Cookie origin 洩漏。
- **OPSEC** — 每個落地網域的 lightweight vs Playwright 成功率對比，揭露「擋 UA 但放 Chromium」的 WAF 部署。

> **Phase 4 三個子分頁（Cloaking / Headers / OPSEC）是證據力最強的訊號層**，其判定也會回灌到 Insights 摘要的最上方。詳見 [kwara_分析原理.md](kwara_分析原理.md)。

### 6. 匯出（Export）

下載 ZIP 證據封包（CSV、截圖、HTML、HAR、稽核紀錄、SHA-256 manifest、可選 HMAC 簽章、中英雙語 README）。

---

## 風險旗標

| 旗標 | 意義 |
|---|---|
| `multi_hop` | Redirect chain ≥ 3 跳 |
| `no_https` | 落地頁使用 HTTP |
| `new_domain` | 網域建立未滿 180 天 |
| `suspicious_download` | 落地 URL 結尾為 .exe、.apk、.zip 等 |
| `high_tracker_count` | 頁面接觸 ≥ 3 個已知追蹤服務 |
| `url_shortener_chain` | 最終 URL 仍是已知短連結服務 |
| `capture_error` | 截圖擷取失敗 |

---

## 環境變數

完整清單請見 [README.zh-TW.md](README.zh-TW.md)。
