**[正體中文](README.zh-TW.md)**

# WHOIS OSINT Automation (Cursor Python Extension Usage)

## After Cloning the Project (fork / clone)

The `.venv` directory in this folder is **not** tracked by version control; create it locally once:

```powershell
cd whois_osint
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

(If using **cmd** only: `.\.venv\Scripts\activate.bat`) Once done, select the `.venv` interpreter in Cursor — same as the "Run with Cursor's Python Extension" section below.

## Run with Cursor's Python Extension

1. **Open this folder in Cursor**  
   File → Open Folder → select `whois_osint` (do not open the parent directory).

2. **Create a virtual environment (required, one-time setup)**  
   - Press `Ctrl+Shift+P` → **Python: Select Interpreter**, first pick a system Python (otherwise the task below cannot find python).  
   - Press `Ctrl+Shift+P` → **Tasks: Run Task** → select **建立虛擬環境 (.venv)**, wait for it to finish.  
   - Press **Python: Select Interpreter** again — you should see **`.venv` (Python 3.x)** in the list; select it. Cursor will use this virtual environment from now on.

3. **Install dependencies (one-time)**  
   - `Ctrl+Shift+P` → **Tasks: Run Task** → select **whois_osint: 安裝依賴 (pip install)** (it uses .venv's python directly, no activation script needed).  
   If manually activating .venv in the terminal causes "cannot load Activate.ps1": run once in PowerShell  
   `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

4. **Run the script (pick one)**  
   - **Option A**: Click the **▶ Run** button in the top-right corner of the `whois_domain_lookup.py` editor (runs with sample URL when no arguments are given).  
   - **Option B**: Go to "Run and Debug" in the sidebar → select **WHOIS 範例（google.com）** → click the green ▶.  
   - **Option C**: `Ctrl+Shift+P` → **Tasks: Run Task** → **執行 WHOIS 範例**.

Results are saved to `whois_results.csv` in the same directory.

## Command-Line Usage (in Cursor Terminal)

```bash
# After activating the virtual environment (auto-activated if python.terminal.activateEnvironment is set)
python whois_domain_lookup.py "https://www.google.com/search?q=google.com"
python whois_domain_lookup.py -o out.csv example.com https://github.com
python whois_domain_lookup.py -f urls.txt
```

## Output Fields

| Field | Description |
|-------|-------------|
| Domain | Primary domain |
| Registrar | Domain registrar (shown as Unknown/Private when unavailable) |
| Creation_Date | Registration date in YYYY-MM-DD format |
| Last_Checked_Timestamp | Query timestamp |
| Error_Reason | Error details (Connection Refused, Rate Limited, etc.) |
