**[正體中文](README.zh-TW.md)**

# kwara

Digital evidence collection and corroboration toolkit for investigating URL shortlink abuse, domain fraud, and online scams.

**Repository:** [github.com/wcl-dev/kwara](https://github.com/wcl-dev/kwara)

## What kwara does

kwara takes suspicious URLs from social media posts and walks them through a six-step evidence chain:

1. **Scan** — follow redirect chains to the real landing page
2. **Network** — record TLS certificates, HTTP headers, and the full redirect path
3. **Domain** — look up WHOIS registration, IP, and ASN hosting
4. **Page** — capture browser screenshots, HTML source, and HAR network logs
5. **Corroboration** — archive the landing page on Internet Archive, submit to urlscan.io, and obtain an RFC 3161 trusted timestamp
6. **Insights** — generate rule-based case summaries with risk flags, parameter attribution, infrastructure clustering, and Phase 4 active-evasion signals (cloaking, fabricated server versions, shared server templates, strong UA-gating)

All evidence is stored locally in SQLite and can be exported as a ZIP evidence pack with SHA-256 manifest and optional HMAC signature.

## Key features

- **Three-stage workflow** — Investigate → Preserve → Analyze, with the six evidence steps distributed across them
- **Operator-level signal clustering** — cross-domain matching of HTML tracking IDs (11 platforms), TLS certificates, URL parameters, and wrapper redirects
- **Active-evasion forensics (Phase 4)** — cloaking detection, HTTP header forensics (origin leak / fabricated versions / server templates), and OPSEC path differential
- **Third-party proof** — Wayback Machine, urlscan.io, and RFC 3161 timestamps provide independent records
- **Per-case locale** — set victim's region so screenshots reflect what they actually saw (defeats geo-cloaking)
- **URL parameter attribution** — auto-identifies 50+ tracking parameters (UTM, fbclid, gclid, etc.)
- **Bilingual UI** — English and Traditional Chinese, switchable from the sidebar
- **Evidence pack export** — ZIP with CSVs, screenshots, HTML, HAR, audit log, SHA-256 manifest, and bilingual README
- **Fully offline-capable** — all data stored in local SQLite; third-party services are optional

## Requirements

- **Python 3.10+**
- **Network** — needed for pip install, Playwright browser download, scanning, and WHOIS lookups

## Quick Start

```bash
cd kwara
python -m venv .venv
.venv/Scripts/activate    # Windows
python -m pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

On Windows with dependencies already installed, double-click `start_kwara.bat` from the project root.

> If `playwright install chromium` has not been run, screenshot features won't work but scanning, WHOIS, and analysis still function.

## Optional environment variables

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_LANG` | `en` | Default UI language (`en` or `zh`) |
| `KWARA_BROWSER_LOCALE` | `zh-TW` | Playwright browser locale for screenshots |
| `KWARA_BROWSER_TIMEZONE` | `Asia/Taipei` | Playwright browser timezone |
| `KWARA_HMAC_KEY` | *(unset)* | HMAC key for signing evidence pack manifest |
| `KWARA_URLSCAN_API_KEY` | *(unset)* | urlscan.io API key (free community tier) |
| `KWARA_HTTP_TIMEOUT` | `10` | Scanner per-request timeout (seconds) |
| `KWARA_MAX_HOPS` | `20` | Redirect chain hop limit |
| `KWARA_NEW_DOMAIN_DAYS` | `180` | "New domain" risk flag threshold (days) |

## Project structure

| Directory | Description |
|---|---|
| `kwara/` | Main application (Streamlit UI, SQLite, scanning, export) |
| `kwara/views/` | UI tab modules (one file per tab for easy editing) |
| `kwara/config.py` | Centralized configuration and environment variable defaults |
| `kwara/corroboration.py` | Third-party evidence services (Wayback, urlscan, RFC 3161) |
| `whois_osint/` | Standalone WHOIS batch query script ([README](whois_osint/README.md)) |
| `restore_from_export.py` | Restore database from an exported evidence pack ZIP |

## After cloning

1. Create venv → `pip install -r kwara/requirements.txt` → `python -m playwright install chromium`
2. Run `streamlit run app.py` inside `kwara/`
3. Do **not** commit `.venv`, `kwara/data/`, or snapshot directories (covered by `.gitignore`)

See [`kwara_guide.md`](kwara_guide.md) for detailed usage instructions.
