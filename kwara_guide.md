**[正體中文](kwara_說明文件.md)**

# kwara — Digital Evidence Collection & Corroboration Toolkit

kwara is a local toolkit that helps investigators collect, scan, and corroborate digital evidence of URL shortlink abuse, domain fraud, and online scams. All data is stored in a local SQLite database.

---

## Getting Started

```bash
cd kwara
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

> Without Playwright/Chromium, scanning and WHOIS still work — only screenshots require a browser.

---

## Data Model

```
cases
  └─ message_evidence (source posts)
        └─ url_artifacts (extracted URLs)
              └─ scan_runs (redirect chain, TLS, headers, WHOIS/ASN, corroboration)
                    ├─ redirect_hops (each hop in the chain)
                    └─ snapshots (screenshot, HTML, HAR, risk tags)
```

Each case is independent. Switch or create cases from the sidebar.

---

## Tab Guide

### 1. Input

Add source posts containing suspicious URLs.

- **Single Post** — paste message text, fill in platform/actor/time, optionally attach a screenshot.
- **CSV Batch** — upload a CSV with columns: `platform`, `permalink`, `actor_label`, `posted_at`, `message_text`.

URLs are extracted and deduplicated automatically.

### 2. Collected

Review all ingested posts and extracted URLs in table format.

### 3. Analysis — Evidence Chain

Six sub-tabs guide you through the evidence collection workflow. Work left to right:

#### Scan

Follow each URL's redirect chain to find the real landing page. Batch-scan all unscanned URLs (8 parallel workers) or scan individually. Stuck scans can be reset.

**What you get**: `final_url`, `hop_count`, `status`, and each hop's `url`, `status_code`, `location`.

#### Network

View evidence collected during the scan — no extra action needed:

- **Redirect Chain** — every hop with status code and location header
- **TLS Certificate** — issuer, subject, validity period, serial number, SAN list (HTTPS only)
- **Response Headers** — full HTTP headers from the landing page (including Set-Cookie, Server, etc.)

#### Domain

WHOIS registration and hosting intelligence for the landing domain:

- **Domain info** — final domain, IP address, ASN, AS organization, country
- **WHOIS** — registrar, domain creation date
- **Risk flags** — `new_domain` (created within 180 days of the post)

Batch-query all pending URLs or query individually.

#### Page

Browser-rendered evidence of the landing page:

- **Screenshot** — full-page PNG captured by Playwright
- **HTML** — raw page source at time of capture
- **HAR** — complete HTTP Archive of all requests during page load
- **Request Domains** — all third-party hosts the page contacted
- **Manual Upload** — upload your own screenshot/HTML if automated capture failed

Batch-capture all pending or capture individually. The browser locale follows the case's Victim Locale setting.

#### Corroboration

Submit the landing page to independent third-party services:

- **Internet Archive (Wayback Machine)** — creates a permanent archived copy at archive.org
- **urlscan.io** — independent URL scan with its own permalink (requires API key)
- **RFC 3161 Timestamp** — trusted timestamp from FreeTSA.org proving when the evidence was collected

Corroboration runs automatically after scanning. Use the button to retry or re-corroborate.

#### Insights

Rule-based case summary (no LLM):

- **Headline** — total URLs, scanned count, landing domains, parameter clusters
- **Key findings** — landing concentration, risk flag breakdown, cross-post parameter attribution (50+ known trackers), ASN infrastructure clusters
- **Data gaps** — alerts for missing WHOIS, snapshots, TLS certificates, and corroboration

Also includes: Scanned Destinations drill-down, Shared URL Parameters table, and Hosting Infrastructure (ASN) grouping.

### 4. Providers

Shortlink services and domain registrars involved in the case. Use this to identify abuse report recipients.

### 5. Export

Download a ZIP evidence pack containing:

- `messages/` — source posts and screenshots
- `urls/` — all URLs, scan results, redirect chains
- `snapshots/` — screenshots, HTML, metadata (WHOIS, risk flags, request domains)
- `audit.csv` — full action log
- `manifest.json` — SHA-256 hash of every file
- `manifest.sig` — HMAC signature (if `KWARA_HMAC_KEY` is set)
- `README.txt` — bilingual (English + Chinese) file/column guide

---

## Risk Flags

| Flag | Meaning |
|---|---|
| `multi_hop` | Redirect chain ≥ 3 hops |
| `no_https` | Landing page uses HTTP (not HTTPS) |
| `new_domain` | Domain created within 180 days of the post |
| `suspicious_download` | Landing URL ends in .exe, .apk, .zip, etc. |
| `high_tracker_count` | Page contacts ≥ 3 known tracking services |
| `url_shortener_chain` | Final URL is still a known shortlink service |
| `capture_error` | Screenshot capture failed |

---

## Evidence Strength

| Capability | Status |
|---|---|
| Redirect chain tracing | ✅ Up to 20 hops with loop/SSL/timeout detection |
| WHOIS + ASN + IP geolocation | ✅ RDAP + port-43 fallback |
| TLS certificate extraction | ✅ Issuer, SAN, validity, serial |
| Browser screenshot + HTML + HAR | ✅ Playwright with Cloudflare bypass |
| Third-party archiving (Wayback) | ✅ Automatic after scan |
| Third-party scanning (urlscan.io) | ✅ With API key |
| Trusted timestamps (RFC 3161) | ✅ FreeTSA.org |
| Evidence pack HMAC signing | ✅ With HMAC key |
| Per-case browser locale | ✅ Defeats geo-cloaking |

---

## Environment Variables

See [README.md](README.md#optional-environment-variables) for the full list.
