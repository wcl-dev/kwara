**[English](kwara_guide.md)**

# kwara — 操作者歸因與數位證據工具

kwara 是一套本地端工具，做操作者歸因與數位證據蒐集，特化於數位廣告生態：從可疑 URL（短連結濫用、網域詐騙、線上詐騙）蒐集、掃描並佐證證據，再沿變現與測量訊號把背後的網站聚合成操作者群組。所有資料儲存於本機 SQLite 資料庫。

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

這份文件說明的是 **Streamlit 介面**。同樣的事情不開瀏覽器也做得到——CLI 與 MCP
用法見 [docs/agent-interface.md](docs/agent-interface.md)。

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

## 介面說明

左欄導覽分三個區塊。**進案先看「總覽」**——它給出判定結論與群組拆解，再決定往哪裡深掘。

```
案件 Case        總覽 Overview → 群組卷宗 Dossier → 蒐證 Collection
分析 Analysis    分析 Analysis → 關聯圖 Graph
全域 Global      跨案件 Cross-case → 匯出 Export
```

### 案件 Case

**總覽（Overview）** — 判定結論、操作者群組拆解、證據完整度與資料缺口。落地頁面。

**群組卷宗（Dossier）** — 單一操作者群組的完整卷宗：成員網域、把它們串起來的共用訊號、各自的證據狀態。

**蒐證（Collection）** — 六個步驟，用上方切換：

| 步驟 | 做什麼 |
|---|---|
| 進件 | 貼上貼文／匯入 CSV → 抽出連結並**自動歸因（免截圖）**，群組與關聯圖隨即浮現 |
| 頁面擷取 | 對重點 URL 用瀏覽器擷取截圖／HTML／HAR——補上 JS 注入的追蹤碼，並作為保全證據 |
| 掃描 | （進階／手動）重新追蹤跳轉鏈、記錄 TLS 憑證與 HTTP 標頭 |
| 佐證 | 存檔到 Wayback、提交 urlscan.io、取得 RFC 3161 受信時間戳 |
| 網路詳情 | 檢視掃描結果：憑證、跳轉路徑、回應標頭、ads.txt |
| 網域情報 | WHOIS 註冊資訊、IP 與 ASN 託管 |

> 「進件」之後**不必**急著截圖。自動歸因已足以讓群組浮現；截圖是為了補 JS 注入的追蹤碼與保全證據，成本高得多。

### 分析 Analysis

**分析（Analysis）** — 依分析問題分組，而非依技術模組：

- **歸因與基礎設施** — 分析洞察（Insights，規則式案件摘要）＋ 服務提供商（Providers，問責視角：註冊商、託管、CA、廣告帳號）
- **行為觀察** — Cloaking（帶參數 vs 不帶參數的內容差異）＋ OPSEC（lightweight vs Playwright 成功率對比，揭露「擋爬蟲、放瀏覽器」的 WAF 部署）
- **伺服器標頭鑑識** — 每跳 response header：per-domain 常數、跨域 server 模板、偽造版本字串、Set-Cookie origin 洩漏

> **Cloaking / OPSEC / Headers 是證據力最強的訊號層**，其判定會回灌到 Insights 摘要的最上方。詳見 [docs/analysis-design.md](docs/analysis-design.md)。

**關聯圖（Graph）** — 網域與共用識別資產的關聯圖，按操作者群組配色。無介面用法可輸出成 SVG/PNG 檔。

### 全域 Global

**跨案件（Cross-case）** — 某個追蹤碼／憑證序號／註冊商／ASN／網域，過去出現在哪些案件；以及跨多案件再現的訊號。

**匯出（Export）** — ZIP 證據封包（CSV、截圖、HTML、HAR、稽核紀錄、SHA-256 manifest、可選 HMAC 簽章、中英雙語 README）。

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
