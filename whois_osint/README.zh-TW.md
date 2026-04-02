**[English](README.md)**

# WHOIS OSINT 自動化（Cursor Python 擴充使用方式）

## 從 Git 取得專案後（fork / clone）

本目錄的 `.venv` **不會**在版本庫中；請在本機建立一次：

```powershell
cd whois_osint
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

（若僅用 **cmd**：`.\.venv\Scripts\activate.bat`）完成後在 Cursor 選擇解譯器為 `.venv` 即可，與下方「用 Cursor 的 Python 擴充跑起來」相同。

## 用 Cursor 的 Python 擴充跑起來

1. **在 Cursor 開啟此資料夾**  
   檔案 → 開啟資料夾 → 選 `whois_osint`（不要只開上層）。

2. **建立虛擬環境（必做，只做一次）**  
   - 按 `Ctrl+Shift+P` → **Python: Select Interpreter**，先選一個系統上的 Python（否則下面任務找不到 python）。  
   - 再按 `Ctrl+Shift+P` → **Tasks: Run Task** → 選 **建立虛擬環境 (.venv)**，等它跑完。  
   - 再按 **Python: Select Interpreter**，清單裡會出現 **`.venv` (Python 3.x)**，選它。之後 Cursor 就會用這個虛擬環境。

3. **安裝依賴（只用做一次）**  
   - `Ctrl+Shift+P` → **Tasks: Run Task** → 選 **whois_osint: 安裝依賴 (pip install)**（會直接用 .venv 的 python，不需啟用腳本）。  
   若要在終端機手動啟用 .venv 卻出現「無法載入 Activate.ps1」：在 PowerShell 執行一次  
   `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

4. **執行腳本（三選一）**  
   - **方式 A**：在 `whois_domain_lookup.py` 編輯器右上角按 **▶ 執行**（無參數時會自動用範例 URL）。  
   - **方式 B**：左側「執行與偵錯」→ 選 **WHOIS 範例（google.com）** → 按綠色 ▶。  
   - **方式 C**：`Ctrl+Shift+P` → **Tasks: Run Task** → **執行 WHOIS 範例**。

執行後會在同目錄產生 `whois_results.csv`。

## 指令列用法（在 Cursor 終端機）

```bash
# 啟用虛擬環境後（若已設 python.terminal.activateEnvironment 會自動啟用）
python whois_domain_lookup.py "https://www.google.com/search?q=google.com"
python whois_domain_lookup.py -o out.csv example.com https://github.com
python whois_domain_lookup.py -f urls.txt
```

## 輸出欄位

| 欄位 | 說明 |
|------|------|
| Domain | 主網域 |
| Registrar | 註冊商（無法取得時為 Unknown/Private） |
| Creation_Date | 註冊日 YYYY-MM-DD |
| Last_Checked_Timestamp | 查詢時間 |
| Error_Reason | 錯誤原因（連線被拒、Rate Limited 等） |
