**[正體中文](README.zh-TW.md)**

# kwara

Operator-attribution and digital-evidence toolkit specialised in the digital-advertising ecosystem — it clusters the sites behind suspicious URLs (shortlink abuse, domain fraud, online scams) into operator groups via monetisation and measurement signals (tracking IDs, ads.txt / sellers.json accounts, TLS certificates, HTTP fingerprints), and packages the result as reproducible evidence.

## What kwara does

kwara takes suspicious URLs from social media posts and walks them through a six-step evidence chain:

1. **Scan** — follow redirect chains to the real landing page
2. **Network** — record TLS certificates, HTTP headers, and the full redirect path
3. **Domain** — look up WHOIS registration, IP, and ASN hosting
4. **Page** — capture browser screenshots, HTML source, and HAR network logs
5. **Corroboration** — archive the landing page on Internet Archive, submit to urlscan.io, and obtain an RFC 3161 trusted timestamp
6. **Insights** — generate rule-based case summaries with risk flags, parameter attribution, infrastructure clustering, and active-evasion signals (cloaking, fabricated server versions, shared server templates, strong UA-gating)

All evidence is stored locally in SQLite and can be exported as a ZIP evidence pack with SHA-256 manifest and optional HMAC signature.

## Key features

- **Headless by design** — a CLI that is the source of truth for automation, and an MCP server that is a thin wrapper over it, so the two cannot drift
- **Candidate discovery** — screens a candidate population by ads.txt to find sites sharing a deployment with known targets, before spending the expensive pipeline on them
- **Operator-level signal clustering** — cross-domain matching of HTML tracking IDs (11 platforms), TLS certificates, URL parameters, and wrapper redirects
- **Active-evasion forensics** — cloaking detection, HTTP header forensics (origin leak / fabricated versions / server templates), and OPSEC path differential
- **Monetisation forensics** — fetches each domain's `ads.txt` and clusters shared DIRECT ad accounts + byte-identical templates, frequency-weighted to separate shared monetisation managers (weak) from operator-cluster signals (strong)
- **Third-party proof** — Wayback Machine, urlscan.io, and RFC 3161 timestamps provide independent records
- **Per-case locale** — set victim's region so screenshots reflect what they actually saw (defeats geo-cloaking)
- **URL parameter attribution** — auto-identifies 50+ tracking parameters (UTM, fbclid, gclid, etc.)
- **Bilingual** — English and Traditional Chinese, via `--lang` or `KWARA_LANG`
- **Evidence pack export** — ZIP with CSVs, screenshots, HTML, HAR, audit log, SHA-256 manifest, and bilingual README
- **Fully offline-capable** — all data stored in local SQLite; third-party services are optional

## Where kwara fits

kwara replaces none of the tools below. It fills the gap between them: turning an investigator's scattered findings into a package the recipient can verify without trusting the investigator.

| Compared with | What they do | What kwara does |
|---|---|---|
| Fact-checking orgs (Cofacts, Taiwan FactCheck Center) | **Content** verification — is this claim true? | **Infrastructure** evidence — who is behind this URL, and which domains share an operator |
| Influence-operations research (IORG, Doublethink Lab) | **Narrative** and **coordinated behaviour** research — how a story spreads | A **reproducible evidence pipeline** — infrastructure signals laid out flat for others to check |
| WHOIS / ASN lookup tools | One domain, one query — a privacy proxy ends the trail | **Cross-domain clustering** — whether pixels, certificates, parameters, and headers link the domains |
| General OSINT suites (Maltego, SpiderFoot) | Broad reach, needs a skilled operator, no case governance | **Per-case governance + evidence-pack export + RFC 3161 timestamps** — deliverable as-is |

## Requirements

- **Python 3.10+**
- **Network** — needed for pip install, Playwright browser download, scanning, and WHOIS lookups

## Quick Start

All commands run from the repository root:

```bash
git clone https://github.com/wcl-dev/kwara && cd kwara
python -m venv .venv
source .venv/bin/activate           # macOS / Linux
# .venv\Scripts\activate            # Windows
python -m pip install -e .          # or: -r requirements.txt
python -m playwright install chromium
kwara case new --title "Op Nightingale"
```

> Playwright is optional. Scanning, WHOIS, ads.txt and the attribution analysis need no browser; only screenshots do.


## CLI and MCP

The CLI is the source of truth for automation; the MCP server is a thin wrapper
over the same functions, so the two cannot drift apart. There is no other
surface.

```bash
python -m kwara.cli case new --title "Op Nightingale" --locale-preset tw
python -m kwara.cli ingest url --case 1 https://suspicious.example/x
python -m kwara.cli run attribute --case 1          # cheap pass, no browser
python -m kwara.cli analyze clusters --case 1
python -m kwara.cli analyze graph --case 1 --out graph.svg
python -m kwara.cli export case --case 1
```

stdout is JSON and nothing else — progress and errors go to stderr, so piping
into `jq` is always safe. Add `--text` for human-readable output.

To drive kwara from an agent:

```bash
python -m pip install -e '.[agent]'   # or: -r requirements-agent.txt
claude mcp add kwara -- /abs/path/to/.venv/bin/python -m kwara.mcp_server
```

Deleting a case is CLI-only and unbounded snapshot capture is not exposed over
MCP — see [docs/agent-interface.md](docs/agent-interface.md) for the full
command reference, the tool list, and the reasoning.


## Optional environment variables

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_LANG` | `en` | Language for insights and narrative (`en` or `zh`) |
| `KWARA_BROWSER_LOCALE` | `zh-TW` | Playwright browser locale for screenshots |
| `KWARA_BROWSER_TIMEZONE` | `Asia/Taipei` | Playwright browser timezone |
| `KWARA_HMAC_KEY` | *(unset)* | HMAC key for signing evidence pack manifest |
| `KWARA_URLSCAN_API_KEY` | *(unset)* | urlscan.io API key (free community tier) |
| `KWARA_PUBLICWWW_API_KEY` | *(unset)* | PublicWWW source-code search key; enables `discover publicwww`. Read from the env only, never written to disk — see [docs/agent-interface.md](docs/agent-interface.md) |
| `KWARA_HTTP_TIMEOUT` | `10` | Scanner per-request timeout (seconds) |
| `KWARA_MAX_HOPS` | `20` | Redirect chain hop limit |
| `KWARA_NEW_DOMAIN_DAYS` | `180` | "New domain" risk flag threshold (days) |
| `KWARA_DATA_DIR` | *(beside the package)* | Case database, capture store and export packs. Move all three together — after `pip install` the package directory is often root-owned and wiped on upgrade |
| `KWARA_INDEX_DB_PATH` | `~/.kwara/index.db` | Central cross-case signal index (spans multiple DB files) |

Those are the ones most people set. kwara reads 48 variables in all — the
rest are analysis thresholds, and they decide things like whether a shared
ad account reads as *same operator* or *same reseller*. Complete list with
defaults and reasoning: [`docs/configuration.md`](docs/configuration.md).

## Project structure

| Directory | Description |
|---|---|
| `kwara/` | The package — core analysis, SQLite, scanning, export |
| `pyproject.toml` | Package metadata; `pip install -e .` puts a `kwara` command on PATH |
| `kwara/cli.py` | Headless CLI — the source of truth for automation |
| `kwara/mcp_server.py` | MCP server; a thin wrapper over the CLI's functions |
| `kwara/config.py` | Centralized configuration and environment variable defaults |
| `kwara/corroboration.py` | Third-party evidence services (Wayback, urlscan, RFC 3161) |
| `kwara/reconcile.py` | Disk → database reconciliation: captures the database has forgotten |
| `kwara/acquisition.py` | Response bytes an ads.txt finding rests on: retention, two hashes, verification |
| `corpus_manifest.py` | Hashes the gitignored discovery corpus so its integrity is checkable |
| `docs/agent-interface.md` | Full CLI command reference and MCP tool list |
| `docs/analysis-design.md` | How the analysis layer works and why — algorithms, thresholds, invariants |
| `docs/configuration.md` | Every environment variable: defaults, and what each threshold decides |
| `docs/guide.md` · `docs/guide.zh-TW.md` | Usage guide, English and Traditional Chinese |
| `docs/kwara_adtech_crosswalk*.html` | Illustrated crosswalk: forensic targets ↔ the digital-advertising ecosystem |
| `requirements.txt` · `requirements-agent.txt` · `requirements-dev.txt` | Base install, MCP extras, test tooling |
| `restore_from_export.py` | Restore database from an exported evidence pack ZIP |

> Do **not** commit `.venv`, `kwara/data/`, or snapshot directories — `.gitignore` already covers them.

## Learn more

- **Usage guide** — [`docs/guide.md`](docs/guide.md)
- **Analysis design** — [`docs/analysis-design.md`](docs/analysis-design.md) explains how each clustering function works and why it is cut that way: the two kinds of "shared parameter", certificate batch-issuance windows, why fingerprint regexes must be invocation-anchored, and the invariants a refactor must not break. Written in Traditional Chinese.
- **Ad-tech crosswalk** — a visual, encyclopedia-style explainer mapping kwara's forensic targets to the digital-advertising ecosystem (SSP/DSP/DMP, IAB `ads.txt`/`sellers.json`, tracking pixels). Read it online at [wcl-dev.github.io/kwara/kwara_adtech_crosswalk.en.html](https://wcl-dev.github.io/kwara/kwara_adtech_crosswalk.en.html) ([中文版](https://wcl-dev.github.io/kwara/kwara_adtech_crosswalk.html)), or open `docs/kwara_adtech_crosswalk.en.html` in a browser after cloning.
