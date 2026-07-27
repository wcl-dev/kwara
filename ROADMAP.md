# kwara Roadmap

kwara 是一套**單機、離線**的操作者歸因與數位證據工具，特化於數位廣告生態鑑識。它的定位是**跨案件的操作者基礎設施歸因引擎**——把可 pivot 的硬訊號（追蹤碼、TLS 憑證、HTTP header 指紋、cloaking 行為、ads.txt 變現帳號）累積成跨案件索引，讓同一操作者在不同案件之間再現時自動浮現。

本文是功能藍圖；安裝與使用見 [README](README.md)，分析原理與標的對照見 [`docs/`](docs/)。

---

## 已交付的能力

### 證據鏈（六步驟）
追蹤 redirect chain 至真實落地頁 → 記錄 TLS 憑證與完整 HTTP 回應 header → WHOIS / IP / ASN 查詢 → 瀏覽器截圖 + HTML 原始碼 + HAR 網路紀錄 → 第三方佐證（Wayback Machine / urlscan.io / RFC 3161 受信任時間戳）→ 規則式案件摘要與風險旗標。

### 操作者層訊號聚合
- **URL 參數歸屬**：自動辨識 50+ 追蹤參數，並區分「同活動」（同值）與「同後台」（同 key、值各異）兩種跨網域聚合
- **HTML 內嵌追蹤碼指紋**：涵蓋 11 個平台（Meta Pixel、GA4、GTM、Google Ads、TikTok、Microsoft Clarity、Hotjar、LINE Tag、X Pixel、AdSense、Facebook Page），跨網域 ID 聚類
- **Wrapper-domain 偵測**與 **HAR 第三方 endpoint 聚合**
- **TLS 憑證聚類**：同一憑證、與短時間批次簽發兩種視角

### 主動防偵測鑑識
- **Cloaking 偵測**：比對「帶追蹤參數」與「去參數」兩版本的行為差異（狀態碼、落地網域、內容雜湊、大小）
- **HTTP header 鑑識**：origin 洩漏、偽造版本字串、跨網域共用 server 模板、cookie origin 洩漏
- **OPSEC 路徑差異**：輕量抓取 vs 瀏覽器抓取的成功率落差，揭露「擋爬蟲、放瀏覽器」的 WAF 部署模式

### 變現歸因
- 抓取並解析各網域的 `ads.txt`（DIRECT / RESELLER、OWNERDOMAIN / MANAGERDOMAIN），對跨網域共用的變現帳號與逐字節相同的模板做聚類；**以頻率加權**區分「共用變現代管商」（弱訊號）與「同操作者聚類」（強訊號）

### 跨案件縱向追蹤
- 集中索引資料庫，橫跨不同案件 DB 檔，回答「某個追蹤碼 / 憑證序號 / 註冊商 / ASN / 網域，過去出現在哪些案件」，並列出跨多個案件再現的訊號——這是單機本地工具相對 SaaS 的核心優勢：分析師累積的歷史最深

### 證據完整性與匯出
- 每次擷取獨立 artifact 目錄、SHA-256 manifest、可選 HMAC 簽章；可匯出為 ZIP 證據封包並還原，讓第三方無需信任工具即可重現所見

### 無介面操作（CLI + MCP）
- **CLI** 是自動化的唯一真相來源：案件、進件、蒐證、分析、跨案件索引、匯出全部可在無瀏覽器環境執行；stdout 只輸出 JSON，可直接串接管線與排程
- **MCP server** 薄薄包一層 CLI 的函式供 agent 呼叫，本身不含分析邏輯，兩介面因此不會各自漂移。刪除案件與無上限擷取刻意不對 agent 開放
- Streamlit 介面保留作為人工檢視證據的視角（截圖、HAR、關聯圖），但新能力一律長在 CLI/MCP 側

---

## 規劃中的方向

### 對外報告
- 一頁式 PDF 執行摘要（中英對照）：操作者叢集圖、關鍵 ID 表、TLS / ASN / 憑證證據、redirect chain
- 對常見對象（CDN / CA / 平台 / 註冊商）的濫用檢舉表單預填
- urlscan / Wayback 自動提交，第三方留存不依賴分析師記性

### Watchlist 與前瞻捕捉
建立在跨案件索引之上：把案件累積的強訊號抽成 watchlist，訂閱外部 feed（HTML 反查、Certificate Transparency log、新註冊網域、HTTP banner）；命中新資產即自動進入案件管線，把歸因從「事後」推向「上線即捕捉」。

---

## Backlog（需先驗證命中率再投資）
- 威脅情資 feed 整合
- 事件時間軸視覺化（操作者基礎設施關聯圖已交付）
- 定期 re-check / 變化偵測（詐騙站是否仍存活、基礎設施是否更換）
- CMS 指紋

---

## 不會做（與設計理念衝突）
- **多人 / SaaS 化** — kwara 是單機本地工具；分析師主權、隱私與速度優先於共享
- **AI 自動下協同行為判定** — 自動 flag 容易過擬合單一資料集；訊號交由分析師判讀
- **任意廣面爬蟲** — kwara 是 evidence-grade 工具，只處理分析師明確匯入的 URL
