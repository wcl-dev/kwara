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

- **無介面設計** — CLI 是自動化的唯一真相來源，MCP server 只是薄薄包一層，兩者不會漂移
- **主動發現** — 以 ads.txt 篩選候選母體，找出與已知目標同源的網站，再決定要不要花昂貴的完整管線
- **操作者層訊號聚合** — 跨網域比對 HTML 追蹤碼（11 平台）、TLS 憑證、URL 參數、wrapper 跳轉
- **主動防偵測對抗** — cloaking 偵測、HTTP header 鑑識（origin 洩漏 / 偽造版本 / server 模板）、OPSEC 路徑差異
- **變現歸因鑑識** — 抓取每個網域的 `ads.txt`，聚類共用的 DIRECT 廣告帳號與逐字節相同的模板；以頻率加權區分共用變現代管商（弱）與操作者聚類訊號（強）
- **第三方佐證** — Wayback Machine、urlscan.io、RFC 3161 時間戳提供獨立紀錄
- **Per-case 語系設定** — 依受害者所在地設定截圖瀏覽器語系，突破地理封鎖
- **URL 參數歸屬** — 自動辨識 50+ 已知追蹤參數（UTM、fbclid、gclid 等）
- **雙語** — 英文與正體中文，以 `--lang` 或 `KWARA_LANG` 指定
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
python -m pip install -e .          # 或：-r requirements.txt
python -m playwright install chromium
kwara case new --title "夜鶯專案"
```

> Playwright 是選用的。掃描、WHOIS、ads.txt 與歸因分析都不需要瀏覽器，只有截圖需要。


## CLI 與 MCP

CLI 是自動化的唯一真相來源，MCP server 只是薄薄包一層、呼叫同一批函式，兩者不會
各自漂移。除此之外沒有別的介面。

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
python -m pip install -e '.[agent]'   # 或：-r requirements-agent.txt
claude mcp add kwara -- /abs/path/to/.venv/bin/python -m kwara.mcp_server
```

刪除案件僅限 CLI、無上限的截圖擷取不對 MCP 開放——完整指令參考、工具清單與設計
理由見 [docs/agent-interface.md](docs/agent-interface.md)。


## 可選環境變數

| 變數 | 預設值 | 用途 |
|---|---|---|
| `KWARA_LANG` | `en` | 分析摘要與敘事的語言（`en` 或 `zh`） |
| `KWARA_BROWSER_LOCALE` | `zh-TW` | Playwright 截圖瀏覽器語系 |
| `KWARA_BROWSER_TIMEZONE` | `Asia/Taipei` | Playwright 截圖瀏覽器時區 |
| `KWARA_SCREENSHOT_TIMEOUT` | `45` | 單張截圖秒數上限，逾時改截可視區 |
| `KWARA_HMAC_KEY` | *（未設定）* | 證據封包 manifest HMAC 簽章密鑰 |
| `KWARA_URLSCAN_API_KEY` | *（未設定）* | urlscan.io API key（免費 community tier） |
| `KWARA_HTTP_TIMEOUT` | `10` | 掃描逾時秒數 |
| `KWARA_MAX_HOPS` | `20` | Redirect chain 跳轉上限 |
| `KWARA_NEW_DOMAIN_DAYS` | `180` | 「新網域」風險旗標門檻天數 |
| `KWARA_DATA_DIR` | *（套件目錄旁）* | 案件資料庫、擷取庫、匯出封包。一個旋鈕移動三者——`pip install` 之後套件目錄常是 root 所有、升級時會被清掉 |
| `KWARA_INDEX_DB_PATH` | `~/.kwara/index.db` | 跨案件訊號中央索引（橫跨多個 DB 檔） |

以上是最常設定的幾個。kwara 實際讀取 48 個環境變數，其餘是分析門檻——它們決定的
是像「共用的廣告帳號要判成同一操作者還是同一代管商」這種事。完整清單、預設值與
判定理由見 [`docs/configuration.md`](docs/configuration.md)。

## 專案結構

| 目錄 | 說明 |
|---|---|
| `kwara/` | 套件本體——核心分析、SQLite、掃描、匯出 |
| `pyproject.toml` | 套件描述；`pip install -e .` 會把 `kwara` 指令裝到 PATH |
| `kwara/cli.py` | 無介面 CLI——自動化的唯一真相來源 |
| `kwara/mcp_server.py` | MCP server；薄薄包一層 CLI 的函式 |
| `kwara/config.py` | 集中配置與環境變數預設值 |
| `kwara/corroboration.py` | 第三方證據服務（Wayback、urlscan、RFC 3161） |
| `kwara/reconcile.py` | 磁碟↔資料庫對帳：找出資料庫已遺忘的擷取 |
| `kwara/acquisition.py` | ads.txt 結論所依據的回應位元組：保存、雙雜湊、驗證 |
| `corpus_manifest.py` | 對 gitignore 的發現語料做雜湊，使其完整性可驗證 |
| `docs/agent-interface.md` | 完整 CLI 指令參考與 MCP 工具清單 |
| `docs/analysis-design.md` | 分析層原理與設計——演算法、門檻、必須保留的契約 |
| `docs/configuration.md` | 全部環境變數：預設值，以及每個門檻決定什麼 |
| `docs/guide.md` · `docs/guide.zh-TW.md` | 操作說明，中英各一 |
| `docs/kwara_adtech_crosswalk*.html` | 圖解對照誌：鑑識標的 ↔ 數位廣告生態 |
| `requirements.txt` · `requirements-agent.txt` · `requirements-dev.txt` | 基本安裝、MCP 額外依賴、測試工具 |
| `restore_from_export.py` | 從匯出的 ZIP 證據封包還原資料庫 |

> **不要**提交 `.venv`、`kwara/data/`、快照目錄——`.gitignore` 已涵蓋。

## 延伸閱讀

- **操作說明** — [`docs/guide.zh-TW.md`](docs/guide.zh-TW.md)
- **分析層設計** — [`docs/analysis-design.md`](docs/analysis-design.md) 說明每個聚類函式怎麼運作、為什麼這樣切：兩種「共用參數」的差異、憑證批次簽發窗口、fingerprint regex 為何必須錨定 invocation context，以及重構時不能破壞的契約。
- **廣告生態對照誌** — 圖解 kwara 各鑑識標的如何對應數位廣告產業（SSP／DSP／DMP、IAB `ads.txt`／`sellers.json`、追蹤 pixel）。線上閱讀：[wcl-dev.github.io/kwara/kwara_adtech_crosswalk.html](https://wcl-dev.github.io/kwara/kwara_adtech_crosswalk.html)（[English](https://wcl-dev.github.io/kwara/kwara_adtech_crosswalk.en.html)），或 clone 後用瀏覽器開啟 `docs/kwara_adtech_crosswalk.html`。
