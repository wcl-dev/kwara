**[English](README.md)**

# kwara

操作者歸因與數位證據工具，特化於數位廣告生態鑑識——沿著變現與測量訊號（追蹤碼、ads.txt／sellers.json 帳號、TLS 憑證、HTTP 指紋），把可疑連結（短連結濫用、網域詐騙、線上詐騙）背後的網站聚合成操作者群組，並打包成可重現的證據封包。

## kwara 能做什麼

kwara 接收社群貼文中的可疑 URL，引導你走過六步驟的證據鏈：

1. **掃描** — 追蹤 redirect chain 至真實落地頁
2. **網路路徑** — 記錄 TLS 憑證、HTTP 回應標頭、完整跳轉路徑
3. **網域情報** — 查詢 WHOIS 註冊資訊、IP、ASN 託管
4. **頁面證據** — 擷取瀏覽器截圖、HTML 原始碼、HAR 網路流量紀錄
5. **第三方佐證** — 在 Internet Archive 存檔、提交至 urlscan.io、取得 RFC 3161 受信任時間戳
6. **分析洞察** — 產生規則式案件摘要，含風險旗標、參數歸屬、基礎設施聚合、追蹤碼吻合，以及**主動防偵測訊號**（cloaking、偽造 server 版本、跨域 server 模板、強 UA 阻擋）

所有證據存於本機 SQLite，可匯出為 ZIP 證據封包（含 SHA-256 manifest 與可選 HMAC 簽章）。

## 主要特色

- **兩套介面、同一核心** — Streamlit 介面供人工檢視證據，無介面 CLI + MCP server 供自動化與 agent 操作；兩者呼叫同一份分析程式碼
- **群組導向工作流** — 以「總覽判定頁 → 操作者群組卷宗 → 關聯圖」為核心，蒐證／分析／跨案件／匯出以左側導覽列組織
- **操作者層訊號聚合** — 跨網域比對 HTML 追蹤碼（11 平台）、TLS 憑證、URL 參數、wrapper 跳轉
- **主動防偵測對抗** — cloaking 偵測、HTTP header 鑑識（origin 洩漏 / 偽造版本 / server 模板）、OPSEC 路徑差異
- **變現歸因鑑識** — 抓取每個網域的 `ads.txt`，聚類共用的 DIRECT 廣告帳號與逐字節相同的模板；以頻率加權區分共用變現代管商（弱）與操作者聚類訊號（強）
- **第三方佐證** — Wayback Machine、urlscan.io、RFC 3161 時間戳提供獨立紀錄
- **Per-case 語系設定** — 依受害者所在地設定截圖瀏覽器語系，突破地理封鎖
- **URL 參數歸屬** — 自動辨識 50+ 已知追蹤參數（UTM、fbclid、gclid 等）
- **雙語** — 英文與正體中文，側欄即時切換或以 `--lang` 指定
- **證據封包匯出** — ZIP 含 CSV、截圖、HTML、HAR、稽核紀錄、SHA-256 manifest、中英雙語 README
- **完全可離線運作** — 所有資料存於本機 SQLite；第三方服務為選用

## 與既有工具的分野

kwara 不取代下列任何一個。它補位的是「**把調查者口袋裡的零散證據，組裝成一份對方不必信任你就能驗證的封包**」這一段。

| 對比對象 | 他們做什麼 | kwara 做什麼 |
|---|---|---|
| Cofacts、台灣事實查核中心 | **內容**查核——這個訊息真假 | **基礎設施**蒐證——這個 URL 背後是誰、跟哪些網域同源 |
| IORG、台灣民主實驗室 | **敘事**與**協同行為**研究——故事怎麼擴散 | **可重現的證據管線**——把基礎設施訊號攤平給其他人核對 |
| 一般 WHOIS／ASN 查詢工具 | 單域單次查詢，隱私代理一遮就斷 | **跨域聚合**——多域的 pixel／憑證／參數／header 是否 cross-link |
| Maltego、SpiderFoot 等通用 OSINT | 廣度大、需要熟手調教、無案件治理 | **單一案件治理＋證據封包匯出＋RFC 3161 時間戳**——可以直接交付 |

## 環境需求

- **Python 3.10+**
- **網路** — 安裝 pip 套件、下載 Playwright 瀏覽器、掃描、WHOIS 查詢時需要

## 快速開始

所有指令都在 repo 根目錄執行：

```bash
git clone https://github.com/wcl-dev/kwara && cd kwara
python -m venv .venv
source .venv/bin/activate           # macOS / Linux
# .venv\Scripts\activate            # Windows
python -m pip install -r kwara/requirements.txt
python -m playwright install chromium
streamlit run kwara/app.py
```

Windows 已安裝依賴的情況下，從專案根目錄雙擊 `start_kwara.bat` 即可。

> 未執行 `playwright install chromium` 時，截圖功能不可用，但掃描、WHOIS 和分析仍正常運作。


## 無介面操作：CLI 與 MCP

UI 能對案件做的事，不開瀏覽器也全部做得到。CLI 是自動化的唯一真相來源，MCP
server 只是薄薄包一層、呼叫同一批函式，兩者不會各自漂移。

```bash
python -m kwara.cli case new --title "夜鶯專案" --locale-preset tw
python -m kwara.cli ingest url --case 1 https://suspicious.example/x
python -m kwara.cli run attribute --case 1          # 輕量歸因，免瀏覽器
python -m kwara.cli analyze clusters --case 1
python -m kwara.cli analyze graph --case 1 --out graph.svg
python -m kwara.cli export case --case 1
```

stdout 只會有 JSON——進度與錯誤都走 stderr，所以接 `jq` 永遠安全。要人讀的格式
加 `--text`。

要讓 agent 直接操作 kwara：

```bash
python -m pip install -r kwara/requirements-agent.txt
claude mcp add kwara -- /abs/path/to/.venv/bin/python -m kwara.mcp_server
```

刪除案件僅限 CLI、無上限的截圖擷取不對 MCP 開放——完整指令參考、工具清單與設計
理由見 [docs/agent-interface.md](docs/agent-interface.md)。


## 可選環境變數

| 變數 | 預設值 | 用途 |
|---|---|---|
| `KWARA_LANG` | `en` | 預設介面語言（`en` 或 `zh`） |
| `KWARA_BROWSER_LOCALE` | `zh-TW` | Playwright 截圖瀏覽器語系 |
| `KWARA_BROWSER_TIMEZONE` | `Asia/Taipei` | Playwright 截圖瀏覽器時區 |
| `KWARA_HMAC_KEY` | *（未設定）* | 證據封包 manifest HMAC 簽章密鑰 |
| `KWARA_URLSCAN_API_KEY` | *（未設定）* | urlscan.io API key（免費 community tier） |
| `KWARA_HTTP_TIMEOUT` | `10` | 掃描逾時秒數 |
| `KWARA_MAX_HOPS` | `20` | Redirect chain 跳轉上限 |
| `KWARA_NEW_DOMAIN_DAYS` | `180` | 「新網域」風險旗標門檻天數 |
| `KWARA_INDEX_DB_PATH` | `~/.kwara/index.db` | 跨案件訊號中央索引（橫跨多個 DB 檔） |

## 專案結構

| 目錄 | 說明 |
|---|---|
| `kwara/` | 主應用程式（核心分析、SQLite、掃描、匯出） |
| `kwara/cli.py` | 無介面 CLI——自動化的唯一真相來源 |
| `kwara/mcp_server.py` | MCP server；薄薄包一層 CLI 的函式 |
| `kwara/views/` | Streamlit UI tab 模組（每個 tab 一個檔案） |
| `kwara/config.py` | 集中配置與環境變數預設值 |
| `kwara/corroboration.py` | 第三方證據服務（Wayback、urlscan、RFC 3161） |
| `docs/agent-interface.md` | 完整 CLI 指令參考與 MCP 工具清單 |
| `docs/analysis-design.md` | 分析層原理與設計——演算法、門檻、必須保留的契約 |
| `docs/` | 圖解對照誌：鑑識標的 ↔ 數位廣告生態（HTML） |
| `restore_from_export.py` | 從匯出的 ZIP 證據封包還原資料庫 |

> **不要**提交 `.venv`、`kwara/data/`、快照目錄——`.gitignore` 已涵蓋。

## 延伸閱讀

- **操作說明** — [`kwara_說明文件.md`](kwara_說明文件.md)
- **分析層設計** — [`docs/analysis-design.md`](docs/analysis-design.md) 說明每個聚類函式怎麼運作、為什麼這樣切：兩種「共用參數」的差異、憑證批次簽發窗口、fingerprint regex 為何必須錨定 invocation context，以及重構時不能破壞的契約。
- **廣告生態對照誌** — 圖解 kwara 各鑑識標的如何對應數位廣告產業（SSP／DSP／DMP、IAB `ads.txt`／`sellers.json`、追蹤 pixel）。線上閱讀：[wcl-dev.github.io/kwara/kwara_adtech_crosswalk.html](https://wcl-dev.github.io/kwara/kwara_adtech_crosswalk.html)（[English](https://wcl-dev.github.io/kwara/kwara_adtech_crosswalk.en.html)），或 clone 後用瀏覽器開啟 `docs/kwara_adtech_crosswalk.html`。
