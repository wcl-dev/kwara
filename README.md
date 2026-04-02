**[正體中文](README.zh-TW.md)**

# kwara

kwara is a short-link / domain abuse evidence investigation tool.

**Repository:** [github.com/wcl-dev/kwara](https://github.com/wcl-dev/kwara)

## Feature Overview

- **Scan**: Trace HTTP redirect chains and record the landing `final_url`.
- **Domain Intelligence**: After scanning, run **WHOIS / ASN** lookups independently (no screenshot required), writing results into `scan_runs`; screenshots are still captured via Playwright for page evidence.
- **Analysis**: Rule-based **case insights** (summary sentences and key bullet points, including risk tag statistics and parameter attribution — no LLM dependency), destination clustering, shared URL parameters (auto-identifies known tracking platform attribution such as UTM / fbclid), and hosting profile by ASN.
- **Export**: Evidence pack ZIP (`urls.csv` includes scan-level intelligence fields).
- **Cross-device Transfer**: `restore_from_export.py` restores the database and snapshots from an exported evidence pack, making it easy to continue work on another machine.
- **Internationalization (i18n)**: UI supports English and Traditional Chinese, switchable instantly from the sidebar.

See [`kwara_guide.md`](kwara_guide.md) for details.

## Requirements

- **Python**: **3.10+** recommended (any version compatible with the dependencies).
- **Network**: After initial installation, `pip` and Playwright browser downloads require internet access; scanning and WHOIS lookups also need network connectivity.

## Quick Start

### Main App `kwara/` (Streamlit)

Create a virtual environment and install dependencies in the project root or inside `kwara/`:

```powershell
cd kwara
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m playwright install chromium
```

Then start the app:

```powershell
streamlit run app.py
```

Alternatively, on Windows with dependencies already installed, double-click `start_kwara.bat` from the project root (it enters `kwara/` and runs `streamlit run app.py`).

> **Important**: If `playwright install chromium` has not been run, snapshot / screenshot features may fail; scanning, WHOIS / ASN intelligence, and SQLite will still work.

> **Database Migration**: Each app launch runs `migrate_db` on the current connection; if you encounter column errors after upgrading from an older version, refresh or restart Streamlit.

### Subproject `whois_osint/`

See [whois_osint/README.md](whois_osint/README.md).

### Running Tests (Optional)

From the project root (use the **same** or a **separate** virtual environment with `kwara` dependencies installed):

```powershell
python -m pip install -r kwara/requirements.txt -r requirements-dev.txt
python -m pytest -v
```

(Tests cover: SQLite initialization, domain parsing, Streamlit / Playwright importability, `whois_domain_lookup.py -h`, and source compilation checks for `kwara/` and `whois_osint/`.)

## Subdirectories

| Directory | Description |
|-----------|-------------|
| `kwara/` | Main application (SQLite, scanning, export, etc.) |
| `whois_osint/` | Standalone WHOIS batch query script; can be opened independently in VS Code / Cursor as its own workspace. See [whois_osint/README.md](whois_osint/README.md). |

## After Forking / Cloning from GitHub

- **Do not** commit local `.venv`, `kwara/data/*.db`, snapshot directories, etc.; the root `.gitignore` already covers common artifacts.
- Complete in order: **create venv** → **`pip install -r kwara/requirements.txt`** → **`python -m playwright install chromium`** → run `streamlit run app.py` (see paths above).
- **WHOIS Subproject**: Create a separate venv inside `whois_osint/` and run `pip install -r requirements.txt` (fully independent from the main app).

## Miscellaneous

- Sample / test data: `test_data_youtube_shortlinks.csv`
- MVP design evaluation notes: `shortlink_abuse_evidence_kit_mvp_8290f6f4.plan.md`
