**[English](README.md)**

# kwara

數位證據蒐集與佐證工具，用於調查 URL 短連結濫用、網域詐騙與線上詐騙。

**Repository：** [github.com/wcl-dev/kwara](https://github.com/wcl-dev/kwara)

## kwara 能做什麼

kwara 接收社群貼文中的可疑 URL，引導你走過六步驟的證據鏈：

1. **掃描** — 追蹤 redirect chain 至真實落地頁
2. **網路路徑** — 記錄 TLS 憑證、HTTP 回應標頭、完整跳轉路徑
3. **網域情報** — 查詢 WHOIS 註冊資訊、IP、ASN 託管
4. **頁面證據** — 擷取瀏覽器截圖、HTML 原始碼、HAR 網路流量紀錄
5. **第三方佐證** — 在 Internet Archive 存檔、提交至 urlscan.io、取得 RFC 3161 受信任時間戳
6. **分析洞察** — 產生規則式案件摘要，含風險旗標、參數歸屬、基礎設施聚合、追蹤碼吻合，以及 **Phase 4 主動防偵測訊號**（cloaking、偽造 server 版本、跨域 server 模板、強 UA 阻擋）

所有證據存於本機 SQLite，可匯出為 ZIP 證據封包（含 SHA-256 manifest 與可選 HMAC 簽章）。

## 主要特色

- **三段式工作流** — 調查 → 保全 → 分析，六個證據步驟分布其中
- **操作者層訊號聚合** — 跨網域比對 HTML 追蹤碼（11 平台）、TLS 憑證、URL 參數、wrapper 跳轉
- **主動防偵測對抗（Phase 4）** — cloaking 偵測、HTTP header 鑑識（origin 洩漏 / 偽造版本 / server 模板）、OPSEC 路徑差異
- **變現歸因鑑識（Phase 8）** — 抓取每個網域的 `ads.txt`，聚類共用的 DIRECT 廣告帳號與逐字節相同的模板；以頻率加權區分共用變現代管商（弱）與操作者聚類訊號（強）
- **第三方佐證** — Wayback Machine、urlscan.io、RFC 3161 時間戳提供獨立紀錄
- **Per-case 語系設定** — 依受害者所在地設定截圖瀏覽器語系，突破地理封鎖
- **URL 參數歸屬** — 自動辨識 50+ 已知追蹤參數（UTM、fbclid、gclid 等）
- **雙語介面** — 英文與正體中文，側欄即時切換
- **證據封包匯出** — ZIP 含 CSV、截圖、HTML、HAR、稽核紀錄、SHA-256 manifest、中英雙語 README
- **完全可離線運作** — 所有資料存於本機 SQLite；第三方服務為選用

## 環境需求

- **Python 3.10+**
- **網路** — 安裝 pip 套件、下載 Playwright 瀏覽器、掃描、WHOIS 查詢時需要

## 快速開始

```bash
cd kwara
python -m venv .venv
.venv/Scripts/activate    # Windows
python -m pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

Windows 已安裝依賴的情況下，從專案根目錄雙擊 `start_kwara.bat` 即可。

> 未執行 `playwright install chromium` 時，截圖功能不可用，但掃描、WHOIS 和分析仍正常運作。

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
| `kwara/` | 主應用程式（Streamlit UI、SQLite、掃描、匯出） |
| `kwara/views/` | UI tab 模組（每個 tab 一個檔案，方便編輯） |
| `kwara/config.py` | 集中配置與環境變數預設值 |
| `kwara/corroboration.py` | 第三方證據服務（Wayback、urlscan、RFC 3161） |
| `restore_from_export.py` | 從匯出的 ZIP 證據封包還原資料庫 |

## Clone 後

1. 建立 venv → `pip install -r kwara/requirements.txt` → `python -m playwright install chromium`
2. 在 `kwara/` 內執行 `streamlit run app.py`
3. **不要**提交 `.venv`、`kwara/data/`、快照目錄（`.gitignore` 已涵蓋）

詳細操作說明請見 [`kwara_說明文件.md`](kwara_說明文件.md)。
