**[正體中文](kwara_說明文件.md)**

# kwara — Operator Attribution & Digital Evidence Toolkit

kwara is a local toolkit for operator attribution and digital evidence, specialised in the digital-advertising ecosystem: it collects, scans and corroborates evidence from suspicious URLs (shortlink abuse, domain fraud, online scams), then clusters the sites behind them into operator groups via monetisation and measurement signals. All data is stored in a local SQLite database.

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

This guide covers the **Streamlit interface**. Everything here can also be done
without a browser — see [docs/agent-interface.md](docs/agent-interface.md) for
the CLI and MCP server.

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

## Interface Guide

Left-rail navigation, three sections. **Start at Overview** — it gives you the
verdict and the group breakdown, which tells you where to dig.

```
Case       Overview → Group Dossier → Collection
Analysis   Analysis → Graph
Global     Cross-case → Export
```

### Case → Overview

The landing page: verdict, operator-group breakdown, evidence completeness, and data gaps.

### Case → Group Dossier

One operator group in full — member domains, the shared signals linking them, and each domain's evidence status.

### Case → Collection

Six steps, switched from the control at the top of the page.

#### Ingest

Add source posts containing suspicious URLs.

- **Single Post** — paste message text, fill in platform/actor/time, optionally attach a screenshot.
- **CSV Batch** — upload a CSV with columns: `platform`, `permalink`, `actor_label`, `posted_at`, `message_text`.

URLs are extracted and deduplicated automatically, then **attributed without
screenshots** — groups and the relationship graph appear immediately. You do
*not* need to capture pages before seeing whether the sites are linked.

#### Scan

Follow each URL's redirect chain to find the real landing page. Batch-scan all unscanned URLs (parallel workers) or scan individually. Stuck scans can be reset.

**What you get**: `final_url`, `hop_count`, `status`, and each hop's `url`, `status_code`, `location`, plus the full per-hop response header set.

#### Network

View evidence collected during the scan — no extra action needed:

- **Redirect Chain** — every hop with status code and location header
- **TLS Certificate** — issuer, subject, validity period, serial number, SAN list (HTTPS only)
- **Response Headers** — full HTTP headers from each hop (including Set-Cookie, Server, etc.)

#### Domain

WHOIS registration and hosting intelligence for the landing domain:

- **Domain info** — final domain, IP address, ASN, AS organization, country
- **WHOIS** — registrar, domain creation date
- **Risk flags** — `new_domain` (created within 180 days of the post)

Batch-query all pending URLs or query individually.

#### Page Capture

Browser-rendered evidence of the landing page:

- **Screenshot** — full-page PNG captured by Playwright
- **HTML** — raw page source at time of capture
- **HAR** — complete HTTP Archive of all requests during page load
- **Request Domains** — all third-party hosts the page contacted
- **Lightweight HTML-only fetch** — skip the browser for ~10× faster captures (no screenshot; still extracts tracking IDs)
- **Manual Upload** — upload your own screenshot/HTML if automated capture failed

Batch-capture all pending or capture individually. The browser locale follows the case's Victim Locale setting.

#### Corroboration

Submit the landing page to independent third-party services:

- **Internet Archive (Wayback Machine)** — creates a permanent archived copy at archive.org
- **urlscan.io** — independent URL scan with its own permalink (requires API key)
- **RFC 3161 Timestamp** — trusted timestamp from FreeTSA.org proving when the evidence was collected

Corroboration runs automatically after scanning. Use the button to retry or re-corroborate.

### Analysis → Analysis

Panels are grouped by the question you are asking, not by the module that answers it.

**Attribution & infrastructure** — Insights + Providers
**Behavioural observation** — Cloaking + OPSEC
**Server-header forensics** — Headers

#### Insights

Rule-based case summary (no LLM). Read this first:

- **Headline** — total URLs, scanned count, landing domains, parameter clusters
- **Key findings** — landing concentration, risk flags, cross-post parameter attribution (50+ trackers), tracking-ID matches, TLS/ASN clustering, and **Phase 4 active-evasion signals (cloaking suspects, fabricated server versions, shared server templates, strong UA-gating)**
- **Data gaps** — alerts for missing WHOIS, snapshots, TLS certificates, and corroboration

#### Providers

Accountability lens: shortlink services, domain registrars, hosting, CAs, and ad/tracking platforms involved in the case. Use this to identify abuse-report recipients.

#### Cloaking

Conditional-cloaker detection — compares the page served *with* tracking params vs *without*. Per-URL verdict plus case-wide counts. Catches operators (e.g. crawlerlanding) that vary behaviour by visitor type — the strongest active-evasion signal.

#### Headers

Per-hop response-header forensics: per-domain constant headers (origin leak), cross-domain shared templates (same-operator signal), fabricated version strings, and Set-Cookie origin leaks.

#### OPSEC

Per-domain success-rate comparison between the lightweight fetch and Playwright paths — exposes "blocks User-Agent but renders in Chromium" WAF deployments, a same-operator signal independent of GA4/TLS.

### Analysis → Graph

Domains and the shared identity assets connecting them, coloured by operator
group. Headless callers can write it out as SVG/PNG/PDF.

### Global → Cross-case

Which past cases a given tracking ID, certificate serial, registrar, ASN, or
domain appeared in — plus signals recurring across multiple investigations.

### Global → Export

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
| TLS certificate extraction + cross-domain clustering | ✅ Issuer, SAN, validity, serial; `by_cert` + 24h `by_issuance` |
| HTML tracking-ID extraction (11 platforms) | ✅ Context-anchored regex; cross-domain ID clustering |
| HAR third-party endpoint aggregation | ✅ Cross-domain shared endpoints, direct-IP flagging |
| Cloaking detection (Phase 4) | ✅ With-param vs without-param differential |
| HTTP header forensics (Phase 4) | ✅ Origin leak / fabricated versions / shared templates / cookie origin |
| OPSEC path differential (Phase 4) | ✅ Lightweight vs Playwright success-rate per domain |
| Browser screenshot + HTML + HAR | ✅ Playwright with Cloudflare bypass |
| Third-party archiving (Wayback) | ✅ Automatic after scan |
| Third-party scanning (urlscan.io) | ✅ With API key |
| Trusted timestamps (RFC 3161) | ✅ FreeTSA.org |
| Evidence pack HMAC signing | ✅ With HMAC key |
| Per-case browser locale | ✅ Defeats geo-cloaking |

---

## Environment Variables

See [README.md](README.md#optional-environment-variables) for the full list.
