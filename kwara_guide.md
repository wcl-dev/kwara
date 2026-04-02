**[正體中文](kwara_說明文件.md)**

# kwara — URL Shortlink & Domain Abuse Evidence Toolkit

kwara is a local toolkit that helps investigators collect, scan, analyze, and archive digital evidence of URL shortlink abuse. The tool runs entirely offline, with all data stored in a local SQLite database.

---

## Getting Started

For first-time use, create a virtual environment inside `kwara/`, run `pip install -r requirements.txt`, and execute `python -m playwright install chromium` once (Chromium is required for snapshot/screenshot features; most other features still work without it).

After setup, run `start_kwara.bat` from the project root, or inside the `kwara/` subdirectory run:

```
streamlit run app.py
```

---

## Data Model Overview

```
cases
  └─ message_evidence (source posts)
        └─ url_artifacts (extracted URLs)
              └─ scan_runs (scan execution records; includes final_url, hop_count)
                    ├─ redirect_hops (each redirect hop)
                    ├─ (optional) domain intel: WHOIS / IP / ASN / intel_risk_tags / domain_enriched_at
                    └─ snapshots (landing page screenshots / HTML / request domains / page-related risk_tags)
```

Domain intel can be written as soon as scanning is complete (snapshots are not required first). When a Playwright snapshot is taken, the system re-merges WHOIS and page-derived flags, updating both `scan_runs` and `snapshots` accordingly.

Each case is independent. Use the sidebar to switch between or create new cases.

---

## Page Descriptions

### 1. Input

Entry point for adding source posts, supporting two modes:

**Single Post**

Manually fill in the fields and submit:

| Field | Description |
|-------|-------------|
| Platform | Source platform, e.g., YouTube, Telegram |
| Actor Label | Identifier for the poster, e.g., account name, channel name |
| Posted At | Post publication time, e.g., `2024-01-15 08:30` |
| Permalink | Direct link to the post |
| Message Text | Post content, required; the system automatically extracts all http/https URLs from it |
| Screenshot | Post screenshot (optional), included in the export package |

**CSV Batch**

Upload a CSV file with required columns: `platform`, `permalink`, `actor_label`, `posted_at`, `message_text`.

During import, the system automatically:
- Creates a `message_evidence` record for each row
- Extracts all URLs from `message_text` and writes them to `url_artifacts`
- Deduplicates identical URLs within the same message

---

### 2. Collected

**Source Posts**

Displays all imported posts in a table, with columns for platform, poster, timestamp, and content preview.

**Extracted URLs**

All URLs extracted from posts, including:
- `domain`: The original URL's primary domain (eTLD+1, e.g., `bit.ly`)
- `scan_status`: Latest scan status
- `final_url`: The final landing URL traced by the scan

---

### 3. Analysis

Divided into three sub-tabs:

---

#### 3-1. Scan

Performs HTTP redirect chain tracing for each URL, recording each hop.

**How it works:**
1. Sends a GET request to the original URL (`allow_redirects=False`)
2. If the response is 3xx, parses the `Location` header, computes the next hop's absolute URL, and continues tracing
3. Stops upon receiving a non-3xx response (e.g., 200) and records it as `final_url`
4. Maximum of 20 hops; each hop result is written to `redirect_hops`

**Scan status descriptions:**

| Status | Meaning |
|--------|---------|
| `done` | Successfully reached a non-3xx response |
| `max_hops` | Exceeded the 20-hop limit |
| `loop_detected` | Detected a repeated URL (loop) |
| `timeout` | Request timed out (default 10 seconds) |
| `ssl_error` | SSL certificate verification failed |
| `error` | Other network or parsing errors |

**Batch scanning:**
- Click "Scan all unscanned" to scan all unscanned URLs simultaneously
- Uses 8 parallel threads, each worker with a random 0–2 second delay to reduce request concentration
- A progress bar shows real-time scanning progress

**Stuck detection:**
If a scan is interrupted while in progress (e.g., force-closing the application), the corresponding scan_run remains in `running` status. When the system detects such records, it displays a Reset button to mark them as `error` so they can be rescanned.

---

#### 3-2. Investigate

Performs in-depth analysis on scanned URLs: **Domain intel (WHOIS/ASN)** and **Landing page snapshots** can be executed independently.

**Domain intel queue**

Lists URLs that have been scanned but lack domain intel (`domain_enriched_at` is empty). Provides a **WHOIS / ASN only — all pending** one-click button: queries only registrar, creation date, resolved IP, and ASN, **without using a browser**, much faster than full-page snapshots.

**Snapshot Priority Queue**

Lists all scanned URLs that lack snapshots, sorted by risk signals from the scan phase, helping users decide which targets to prioritize. Columns include:

- `final_domain`: The domain reached by the scan
- `hops`: Number of redirect hops
- `scan_flags`: Risk flags determinable at the scan phase (see details below)

Provides a "Snapshot & WHOIS All" one-click button to process all pending URLs sequentially; since a headless browser is used, each URL takes 10–30 seconds, with estimated time shown next to the button.

**URL Selector**

All URLs are sorted by number of risk flags in descending order, with labels formatted as:

```
[ua_id] https://bit.ly/xxx  [done · snap ✓ · multi_hop, no_https]
```

After a snapshot completes, the system automatically returns to the same URL without jumping back to the first entry due to page refresh.

**Left column: Redirect Chain**

Displays each hop's details in a table:

| Field | Description |
|-------|-------------|
| hop_order | Hop sequence (starting from 0) |
| url | The URL requested at this hop |
| status_code | HTTP response code |
| location | Location header value for 3xx responses |

**Right column (top): Domain & hosting (WHOIS / ASN)**

- **Query domain intel (no screenshot required)**: Executes only WHOIS and IP/ASN queries, writing results to `scan_runs` (if a snapshot row already exists, it is also updated).
- Displays Final Domain, IP, ASN/Hosting, Registrar, Domain Created; with merged **Risk Flags** (see below).

**Right column (bottom): Snapshot (screenshot & page)**

After clicking "Capture snapshot" or "Re-capture", the system:
1. Opens `final_url` using Playwright with headless Chromium
2. Takes a full-page screenshot (`screenshot.png`)
3. Captures the page HTML (`page.html`)
4. Records all request domains during page load (third-party external resources)
5. Re-executes domain intel (same logic as above) and merges page-derived flags

When a snapshot exists, the following are also displayed:
- Screenshot preview (if successful)
- **Request Domains**: All external domains contacted by the browser during page load, useful for identifying trackers, ad networks, and CDNs

---

**Risk Flags Reference**

Flags are generated at two points in time and complement each other:

*Scan-time flags (displayed without requiring a snapshot):*

| Flag | Trigger condition |
|------|-------------------|
| `multi_hop` | Redirect chain >= 3 hops |
| `no_https` | Final URL uses `http://` (unencrypted) |
| `suspicious_download` | Final URL file extension is .exe / .zip / .apk / .dmg or other executable/archive formats |
| `url_shortener_chain` | Final domain is itself a known shortlink service (scan did not penetrate to the real destination) |

*Domain intel flags (WHOIS path, no Playwright required):*

| Flag | Trigger condition |
|------|-------------------|
| `new_domain` | Domain creation date is less than 180 days before the post publication date (written to `intel_risk_tags` and merged into display flags) |

*Snapshot-time flags (require Playwright page load):*

| Flag | Trigger condition |
|------|-------------------|
| `high_tracker_count` | >= 3 known third-party trackers contacted during page load |
| `capture_error` | Playwright screenshot failed (WHOIS and IP/ASN may still have succeeded) |

Flag notes:
- `url_shortener_chain` does not indicate malicious intent; it means the scanning tool stopped at a shortlink service URL, **the real landing page is unknown**, and requires manual verification or opening in a browser
- `new_domain` is calculated relative to the post's `posted_at` date; if `posted_at` cannot be parsed, the date of intel/snapshot execution is used as the baseline
- `high_tracker_count` threshold is 3, covering common tracking services such as Google Analytics, Facebook Pixel, Hotjar, etc.

---

#### 3-3. Clusters

Performs cross-post factual aggregation on scan results without inferring intent.

**Case Insights (rule-based summary)**

Displayed at the top of the page in a collapsible section, presenting **rule-based, auditable** summaries (not LLM-generated): a one-line overview, key points, and data gaps. Key points cover:

- **Landing concentration**: Destination domains with the highest post coverage
- **Risk flag statistics**: Aggregated risk tag occurrence counts across all destinations with descriptions (e.g., `high_tracker_count` (high third-party tracker count) ×100)
- **Cross-post parameters**: Most frequently repeated URL parameters, with platform attribution labels (e.g., "attributed to Google Analytics"; see "URL Parameter Attribution" below)
- **Infrastructure**: Largest ASN clusters by URL count
- **Data gaps**: Count of entries without intel / without snapshots

**Scanned Destinations**

Groups all scanned URLs by `final_url` hostname. The table displays:

| Field | Description |
|-------|-------------|
| final_domain | Landing page hostname |
| urls | Number of shortlinks pointing to this domain |
| flagged_urls | Number of URLs with risk flags among them |
| posts | Number of posts involving this domain |
| risk_flags | Each flag and its trigger count, e.g., `multi_hop ×2` |

Note: `risk_flags` merges **snapshot-level flags** with **scan-level `intel_risk_tags`** (e.g., `new_domain` obtained from WHOIS-only execution), showing trigger counts for each. The `flagged_urls` field helps users understand that "only 3 out of 210 links have issues," preventing the misconception that the entire batch is risky.

The drill-down expansion sorts the URL list by number of flags in descending order, with individual flag labels on each entry.

If a scan's `final_domain` is itself a shortlink service (`url_shortener_chain`), that entry is removed from Scanned Destinations and displayed separately in an info box stating "these links did not penetrate the shortlink; the real destination is unknown."

**Hosting Infrastructure**

Groups landing domains that have **ASN data** by ASN (data can come from **domain intel** or **snapshot** rows, either suffices), identifying multiple domains sharing the same hosting provider.

The table displays: ASN number, organization name (as_org), country, domain count, URL count, flagged URL count, post count, and risk flag distribution.

The drill-down expansion shows:
- All domains under that ASN with their IP addresses
- Original shortlinks pointing to these domains, sorted by risk flags

Purpose: If multiple different domains fall under the same ASN, it may indicate infrastructure deployed by the same group (e.g., multiple phishing sites under the same VPS provider account).

**Shared URL Parameters**

Compares URL query parameters (query string key=value) across posts, finding cases where the same key=value pair appears in 2 or more posts.

- Checks both original shortlink URLs and final URLs
- Filtering rules: keys with length <= 1 are ignored; values exceeding 100 characters are ignored
- The same key=value appearing in multiple URLs within the same post does not count toward cross-post frequency

Table columns include `param_key`, `param_value`, `owner` (attributed platform), `purpose`, `domains` (which domains it appears on), `post_count`, `url_count`.

**URL Parameter Attribution**

The system includes a built-in lookup table for known tracking platforms, automatically labeling parameter attribution and purpose:

| Parameter example | Attribution | Purpose |
|-------------------|-------------|---------|
| `utm_source`, `utm_term`, etc. | Google Analytics | Traffic source, paid keywords, etc. |
| `fbclid` | Meta / Facebook | Click ID |
| `gclid` | Google Ads | Click ID |
| `msclkid` | Microsoft Ads | Click ID |
| `ttclid` | TikTok Ads | Click ID |

Parameters not in the lookup table (e.g., site-specific `uid`, `ref`, etc.) show "Not a known tracking platform" for `owner` and "Unidentified" for `purpose`; users can determine the source from the `domains` field. This mechanism is data-driven and not hard-coded for any specific case.

---

### 4. Providers

**Shortlink Providers**

Lists known shortlink services used in this case (`bit.ly`, `t.co`, `tinyurl.com`, etc.), showing the URL count for each service. The drill-down expansion lists all URLs for that service, sorted by risk flags.

Purpose of this tab: Identify which shortlink providers are abuse channels, serving as a target list for filing abuse complaints.

**Domain Registrars**

When WHOIS data is available (from either **domain intel only** or **snapshot workflow**), displays landing domain registrars and creation dates.

Purpose of this tab: Identify the managing parties of landing page domains, serving as a target list for filing takedown requests.

---

### 5. Export

Packages all case evidence into a ZIP file for download and long-term preservation.

**ZIP structure:**

```
case_{id}_{timestamp}.zip
├── README.txt               ← Plain text documentation explaining all files and fields
├── manifest.json            ← SHA-256 hash for each file, for integrity verification
├── audit.csv                ← Complete operation log (import, scan, snapshot, export)
├── messages/
│   ├── messages.csv         ← Source posts (includes has_screenshot field)
│   └── screenshots/         ← Post screenshots uploaded during import (if any)
├── urls/
│   ├── urls.csv             ← All URLs (includes scan_run_id; also includes scan-level whois/asn/domain_enriched_at fields)
│   └── chains/
│       └── url_{id}_hops.csv ← Redirect chain hop-by-hop data for each URL
└── snapshots/
    ├── snapshots.csv        ← Snapshot metadata (WHOIS, risk flags, request domains)
    │                          Includes screenshot_file and html_file fields indicating whether attachments exist
    └── {scan_run_id}/
        ├── screenshot.png   ← Landing page screenshot (exists only when snapshot succeeded)
        └── page.html        ← Landing page HTML (exists only when snapshot succeeded)
```

**Cross-file reference keys:**

```
messages.csv  id
  └─ urls.csv  message_id
        └─ urls/chains/url_{id}_hops.csv
        └─ snapshots.csv  scan_run_id
              └─ snapshots/{scan_run_id}/
```

**Regarding screenshot availability:**

If the `screenshot_file` field in `snapshots.csv` is empty, it means the screenshot for that snapshot was unsuccessful (`capture_error`). WHOIS data and risk flags may still be present in the CSV. Large platforms (e.g., YouTube) have lower screenshot success rates due to bot detection mechanisms.

---

## Suggested Analysis Workflow

```
Input (import data)
  ↓
Scan (batch scan all URLs, wait for completion)
  ↓
Clusters > Scanned Destinations (review landing domain distribution)
Clusters > Shared URL Parameters (review cross-post parameter overlap)
  ↓
Investigate > Priority Queue (prioritize snapshots for high-risk URLs by risk flags)
  ↓
Providers (compile complaint targets: shortlink providers + domain registrars)
  ↓
Export (download evidence package)
```

---

## Technical Architecture

| Component | Description |
|-----------|-------------|
| `app.py` | Streamlit UI main application |
| `db.py` | SQLite connection and schema initialization (WAL mode) |
| `ingestion.py` | Post and URL import logic |
| `scanner.py` | HTTP redirect chain tracing |
| `pipeline.py` | Orchestration: scanner → snapshots → whois |
| `snapshots.py` | Playwright screenshots, request domain collection, risk flag computation |
| `whois_lookup.py` | WHOIS queries and date normalization |
| `clustering.py` | Scanned Destinations, Shared Parameters aggregation logic, URL parameter attribution |
| `insights.py` | Rule-based case insights (headline, bullets, gaps), including risk flag statistics and parameter attribution summaries |
| `exporter.py` | ZIP package building and SHA-256 manifest |
| `audit.py` | Operation log writing |
| `i18n.py` | Multi-language support (English / Traditional Chinese), provides `t()` translation function and language switching |
| `ip_lookup.py` | DNS resolution and ASN queries |
| `wayback_fallback.py` | Internet Archive fallback when Playwright screenshots fail |
| `utils/domain.py` | eTLD+1 domain extraction (supports tldextract) |

Root directory tools:

| Component | Description |
|-----------|-------------|
| `restore_from_export.py` | Restore SQLite database and snapshot files from an exported evidence pack (for cross-device transfer) |
| `start_kwara.bat` | Windows quick start (enters `kwara/` and runs `streamlit run app.py`) |

Database location: `kwara/data/kwara.db`
