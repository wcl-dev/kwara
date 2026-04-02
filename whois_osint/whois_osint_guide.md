**[正體中文](WHOIS_OSINT_說明文件.md)**

# WHOIS OSINT Automated Query Tool — Technical Guide

## 1. Overview

This script (`whois_domain_lookup.py`) is an **OSINT (Open Source Intelligence) automation workflow** designed to:

> **Accept any URL or domain as input and automatically retrieve its Registrar and Creation Date.**

It is suitable for cybersecurity investigations, website background checks, phishing site identification, and similar scenarios. It relies entirely on free, open-source tools with no paid API dependencies.

---

## 2. Use Cases

| Scenario | Description |
|----------|-------------|
| **Website background check** | Received an unfamiliar URL and want to know when the site was registered and which registrar manages it |
| **Phishing site identification** | Newly registered domains (e.g., created days or weeks ago) are typically high-risk indicators |
| **OSINT reconnaissance** | Batch-query basic information for multiple target domains to build an investigation timeline |
| **Brand monitoring** | Periodically track registration status changes for specific domains |
| **Data archiving** | Query results are accumulated in Excel with one sheet per day for easy historical review |

---

## 3. Data Source

```
User input URL
       │
       ▼
  ┌──────────┐
  │ WHOIS    │  ← Global domain registration database (public data)
  │ Server   │    Each TLD (e.g., .com, .org, .tw) has a corresponding WHOIS server
  └──────────┘
       │
       ▼
  python-whois library parses the response
```

- **WHOIS Protocol**: A public network query protocol (RFC 3912) that allows anyone to query domain registration information from WHOIS servers.
- **python-whois**: An open-source Python library that connects directly to each TLD's WHOIS server to retrieve and parse raw data.
- **tldextract**: A helper library for accurately identifying the registered domain from a URL (e.g., extracting `google.com` from `www.google.com`).
- **Completely free**: No paid services such as WhoisXMLAPI are used; only the standard WHOIS protocol is used.

### Data Limitations

| Situation | Script Behavior |
|-----------|-----------------|
| Domain has privacy protection enabled | Fields are set to `Unknown/Private` — **never fabricated** |
| WHOIS server refuses connection | Marked as `Connection Refused` |
| Query rate exceeded | Marked as `Rate Limited` |
| Domain does not exist or no data found | Marked with the specific error message |

---

## 4. Processing Logic (Flowchart)

```
Input URL / domain list
        │
        ▼
┌─────────────────────┐
│ Step 1: Extract      │  Parse the registered domain from the URL
│         Domain       │  e.g., https://www.google.com/search?q=test
│                     │       → google.com
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 2: Check Cache  │  Has this domain been queried before?
│                     │  Yes → Use cached result (no duplicate query)
│                     │  No  → Proceed to Step 3
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 3: WHOIS Query  │  Connect to WHOIS server via python-whois
│                     │  Retrieve raw response data
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 4: Regex Parse  │  Extract from response:
│                     │  - Registrar
│                     │  - Creation Date
│                     │  Dates are normalized to YYYY-MM-DD
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│ Step 5: Write to     │  Results appended to whois_results.xlsx
│         Excel        │  One sheet per day (e.g., 2026-02-06)
│                     │  Same day, multiple runs → accumulate in same sheet
│                     │  Different day → new sheet created automatically
└─────────────────────┘
```

---

## 5. Output Format

Output file: **`whois_results.xlsx`** (Excel format)

| Field | Type | Description |
|-------|------|-------------|
| `Domain` | Text | Registered domain (e.g., `google.com`) |
| `Registrar` | Text | Registrar name (e.g., `MarkMonitor, Inc.`); `Unknown/Private` when unavailable |
| `Creation_Date` | Date | Domain registration date in `YYYY-MM-DD` format; `Unknown/Private` when unavailable |
| `Last_Checked_Timestamp` | Timestamp | UTC time of the query (e.g., `2026-02-06 03:24:39 UTC`) |
| `Error_Reason` | Text | Reason for failure (`Connection Refused`, `Rate Limited`, etc.); empty on success |

### Excel Sheet Rules

```
whois_results.xlsx
├── Sheet: 2026-02-05   ← Data queried on 2/5
│   ├── Row 1: Header row
│   ├── Row 2: example.com ...
│   └── Row 3: test.org ...
├── Sheet: 2026-02-06   ← Data queried on 2/6 (today)
│   ├── Row 1: Header row
│   ├── Row 2: google.com ... (first run)
│   ├── Row 3: twreporter.org ... (second run, accumulated)
│   ├── Row 4: github.com ...
│   └── Row 5: facebook.com ...
└── Sheet: 2026-02-07   ← Will be created automatically tomorrow
```

---

## 6. Usage

### Prerequisites

- Python 3.10+
- Virtual environment created with dependencies installed (`pip install -r requirements.txt`)

### Command Format

```bash
python whois_domain_lookup.py [URL or domain ...] [options]
```

### Examples

```bash
# Query a single URL
python whois_domain_lookup.py "https://www.twreporter.org/a/some-article"

# Query multiple targets
python whois_domain_lookup.py "https://www.facebook.com" "github.com" "https://tw.yahoo.com"

# Batch query from a file (one URL per line in urls.txt)
python whois_domain_lookup.py -f urls.txt

# Specify output path
python whois_domain_lookup.py "google.com" -o my_results.xlsx

# Disable cache (force re-query)
python whois_domain_lookup.py "google.com" --no-cache
```

### Running in Cursor IDE

1. Press `Ctrl+Shift+D` → select **WHOIS 查詢（輸入 URL）** from the dropdown → click the green ▶
2. Paste the URL in the prompt that appears → press Enter
3. Results are displayed in the terminal and written to `whois_results.xlsx`

---

## 7. Technical Details

### Libraries Used

| Library | Purpose | License |
|---------|---------|---------|
| `python-whois` | WHOIS query and initial parsing | MIT |
| `tldextract` | Accurate registered domain extraction (eTLD+1) | BSD |
| `openpyxl` | Read/write Excel `.xlsx` files | MIT |

### Date Normalization

WHOIS servers return dates in varying formats depending on the TLD. The script automatically converts the following formats:

| Original Format | Converted |
|-----------------|-----------|
| `2023-01-15` | `2023-01-15` |
| `15-Jan-2023` | `2023-01-15` |
| `Jan 15, 2023` | `2023-01-15` |
| `15/01/2023` | `2023-01-15` |
| `2023.01.15` | `2023-01-15` |
| Python `datetime` object | `2023-01-15` |

### Caching Mechanism

- Cache file: `whois_cache.csv` (CSV format, human-readable plain text)
- Each domain is queried only once per script execution
- On subsequent runs, if the domain exists in cache, the cached result is used (use `--no-cache` to force a fresh query)

### Error Handling

| Error Type | Error_Reason Field Value | Description |
|------------|--------------------------|-------------|
| WHOIS server refuses connection | `Connection Refused` | May be caused by firewall or server maintenance |
| Query rate exceeded | `Rate Limited` | Too many queries in a short period; throttled by the server |
| Privacy protection | Field value is `Unknown/Private` | Domain registrant has enabled privacy protection |
| Domain does not exist | `Error: ...` | Includes the original error message |
| Cannot extract domain from URL | `Could not extract domain from input` | Input format is incorrect |

---

## 8. File Structure

```
whois_osint/
├── whois_domain_lookup.py    ← Main script
├── requirements.txt          ← Python dependency list
├── whois_results.xlsx        ← Query results (Excel, daily accumulation)
├── whois_cache.csv           ← Cache file (speeds up repeated queries)
├── WHOIS_OSINT_說明文件.md    ← Technical guide (Chinese)
├── whois_osint_guide.md      ← Technical guide (English, this file)
├── README.md                 ← Quick start guide (English)
├── README.zh-TW.md           ← Quick start guide (Chinese)
└── .vscode/                  ← Cursor IDE configuration
    ├── launch.json           ← Debug/run configuration
    ├── settings.json         ← Python environment settings
    └── tasks.json            ← Automated tasks
```

---

## 9. Limitations and Notes

1. **WHOIS data is public but not real-time**: Registrars may delay updates; data can lag by hours to days.
2. **Some ccTLDs have limited data**: Certain country-code domains (e.g., `.cn`, `.ru`) may have restricted WHOIS information.
3. **Rate limiting**: Querying the same TLD's WHOIS server in large volumes within a short period may result in temporary blocks; control query rates during batch operations.
4. **Privacy protection is widespread**: Since GDPR took effect, many European domain WHOIS records are hidden — this is expected behavior.
5. **No fabrication**: Any field that cannot be retrieved is marked `Unknown/Private`; the tool never guesses or fills in false data.
