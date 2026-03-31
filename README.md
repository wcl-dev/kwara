# kwara 工作區

本資料夾為 **kwara** 相關專案根目錄（短連結／網域濫用證據調查工具與輔助腳本）。

## 環境需求

- **Python**：建議 **3.10+**（與依賴套件相容即可）。
- **網路**：首次安裝後，`pip` 與 Playwright 下載瀏覽器需要連外；主程式使用時若需掃描／WHOIS 亦需網路。

## 快速開始

### 主程式 `kwara/`（Streamlit）

在專案根目錄或 `kwara/` 內建立虛擬環境並安裝依賴：

```powershell
cd kwara
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

接著啟動：

```powershell
streamlit run app.py
```

或於 Windows 在**已安裝依賴**的前提下，從專案根目錄雙擊 `start_kwara.bat`（會進入 `kwara/` 並執行 `streamlit run app.py`）。

> **重要**：未執行 `playwright install chromium` 時，介面中「快照／截圖」相關功能可能失敗；其餘 SQLite、掃描多數仍可運作。

### 子專案 `whois_osint/`

見 [whois_osint/README.md](whois_osint/README.md)。

### 執行自動測試（可選）

於專案根目錄（建議使用**同一個**或**另建**虛擬環境，並已安裝 `kwara` 依賴）：

```powershell
python -m pip install -r kwara/requirements.txt -r requirements-dev.txt
python -m pytest -v
```

（測試涵蓋：SQLite 初始化、網域解析、Streamlit／Playwright 可匯入、`whois_domain_lookup.py -h`、以及 `kwara/` 與 `whois_osint/` 原始碼編譯檢查。）

## 子目錄

| 目錄 | 說明 |
|------|------|
| `kwara/` | 主應用程式（SQLite、掃描、匯出等） |
| `whois_osint/` | 獨立的 WHOIS 批次查詢腳本；可單獨以 VS Code／Cursor 開啟此子資料夾使用。說明見 [whois_osint/README.md](whois_osint/README.md)。 |

## 從 GitHub fork / clone 後

- **不要**提交本機 `.venv`、`kwara/data/*.db`、快照目錄等；根目錄 `.gitignore` 已涵蓋常見產物。
- 依序完成：**建立 venv** → **`pip install -r kwara/requirements.txt`** → **`python -m playwright install chromium`** → 執行 `streamlit run app.py`（路徑見上）。
- **WHOIS 子專案**：於 `whois_osint/` 另建 venv 並 `pip install -r requirements.txt`（與主程式可完全獨立）。

## 其他

- 範例／測試資料：`test_data_youtube_shortlinks.csv`
- MVP 設計評估紀錄：`shortlink_abuse_evidence_kit_mvp_8290f6f4.plan.md`
