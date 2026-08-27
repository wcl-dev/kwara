# kwara configuration — every environment variable

kwara reads all configuration from the environment. Nothing here is required:
every variable has a default, and an unset key means the integration is simply
unavailable — the analysis never fails for a missing one.

The variables most people touch are in [README.md](../README.md). This file is
the complete list, including the analysis thresholds. Those thresholds are
worth reading before you argue with a verdict: they decide whether a shared ad
account reads as *the same operator* or as *the same reseller*, and the
defaults are calibrated against measured sweeps, not picked for roundness.

Defaults are as of the code in `kwara/config.py`; that module is the authority
if the two ever disagree.

---

## Paths and language

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_DATA_DIR` | *(beside the package)* | Case database, capture store and export packs. Move all three together — after `pip install` the package directory is often root-owned and wiped on upgrade |
| `KWARA_DB_PATH` | `$KWARA_DATA_DIR/kwara.db` | Case database |
| `KWARA_INDEX_DB_PATH` | `~/.kwara/index.db` | Central cross-case signal index; spans cases held in several `KWARA_DB_PATH` files |
| `KWARA_LANG` | `en` | The **operator's** language for insights and narrative (`en` or `zh`). Independent of `KWARA_BROWSER_LOCALE`, which is the victim's browser |

## Scanning and network

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_HTTP_TIMEOUT` | `10` | Scanner per-request timeout (seconds) |
| `KWARA_MAX_HOPS` | `20` | Redirect chain cutoff |
| `KWARA_SCANNER_UA` | *(a browser-like UA)* | Scanner User-Agent. Set it to an honest identifier if you prefer to be announced |
| `HTTP_PROXY` / `HTTPS_PROXY` | *(unset)* | Standard proxy variables, honoured by the scanner |
| `KWARA_PLAYWRIGHT_PROXY` | *(falls back to `HTTPS_PROXY`)* | Proxy for the Playwright browser specifically |

## Browser capture (what the victim would have seen)

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_BROWSER_LOCALE` | `zh-TW` | Playwright context locale |
| `KWARA_BROWSER_TIMEZONE` | `Asia/Taipei` | Playwright context timezone |
| `KWARA_BROWSER_LANGUAGES` | *(derived from the locale)* | Comma-separated `navigator.languages` override; wins over the derived value |
| `KWARA_SCREENSHOT_TIMEOUT` | `45` | Seconds one screenshot may take. On overrun the capture falls back to a viewport-only image and records why in `capture_detail`, rather than waiting on a page that never finishes rendering |
| `KWARA_SNAPSHOT_CHUNK` | `5` | URLs per capture subprocess. Each chunk's rows are committed before the next starts, so an interrupted run loses at most one chunk instead of the whole batch |

Per-case locale presets (`case new --locale-preset tw`) set these for one case;
the variables are the process-wide fallback.

**On a page that will not finish.** Playwright's own timeouts are not the last
line of defence here. Against a page whose main thread is jammed, `page.goto`
returns, `page.content()` never does — it takes no timeout at all — and even
`page.screenshot(timeout=…)` was measured still blocked at four times its
stated budget. So the worker carries a watchdog thread outside the browser
greenlet: a URL that overruns its phase budget is recorded as a stalled
capture, the worker takes itself down, and the parent resumes at the next URL.
One hostile domain costs one domain, not the batch.

## Risk flags

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_NEW_DOMAIN_DAYS` | `180` | Age below which a domain earns the `new_domain` risk flag |

## URL parameter clustering

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_PARAM_VALUE_HASH_THRESHOLD` | `100` | Parameter values longer than this many characters are compared by SHA-256 instead of literally, so base64 / JWT-style tracking tokens are not discarded as noise |
| `KWARA_PARAM_KEY_MIN_POSTS` | `3` | Minimum posts a parameter key must appear in before it counts as same-backend coordination |
| `KWARA_PARAM_KEY_MIN_VALUES` | `2` | Minimum distinct values for that key (a sophisticated operator gives each victim a unique id) |
| `KWARA_PARAM_KEY_MAX_DOMAINS` | `5` | Above this many domains the key is treated as generic, not operator-specific |

Tighter thresholds mean less noise and more missed signals; loosen them on
small samples.

## Evasion forensics

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_CLOAKING_BODY_SIZE_DIFF` | `0.30` | With-params and without-params responses count as the same content while their size differs by less than this fraction — room for ad-script variability without firing on template noise |
| `KWARA_OPSEC_PW_MIN` | `0.70` | Playwright's own success rate must reach this before an OPSEC level is assigned at all |
| `KWARA_OPSEC_LW_HIGH` | `0.70` | Lightweight-fetch success at or above this → OPSEC `low` (no UA gate) |
| `KWARA_OPSEC_LW_LOW` | `0.20` | Below this → OPSEC `strong` (near-total UA gate); in between → `medium` |

## ads.txt monetisation forensics

These decide the tier of a shared ad account, which is the most contested call
kwara makes. `docs/analysis-design.md` §11 explains the reasoning in full.

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_ADS_TXT_TIMEOUT` | `10` | Per-request timeout when fetching `/ads.txt` (seconds) |
| `KWARA_ADS_TXT_MAX_BYTES` | `262144` | Size cap on a fetched ads.txt (256 KB; MFA sites run to 700+ lines) |
| `KWARA_ADS_TXT_MANAGER_BREADTH` | `0.8` | A DIRECT account on at least this fraction of the case's ads.txt-bearing domains is read as a shared monetisation manager (weak), not a same-operator signal (strong) |
| `KWARA_ADS_TXT_TEMPLATE_OVERLAP` | `0.4` | Two domains whose DIRECT account sets overlap by at least this fraction of the smaller file are running the same monetisation template, so their shared accounts are demoted regardless of breadth |
| `KWARA_ADS_TXT_TEMPLATE_MIN_SHARED` | `8` | Minimum shared accounts before that demotion applies — guards a genuinely rare account two domains happen to share |
| `KWARA_ADS_TXT_TEMPLATE_PAIR_RATIO` | `0.6` | Fraction of carrier pairs that must be linked for the template demotion. Unanimity used to be required, and one thin ads.txt defeated the whole test |
| `KWARA_ADS_TXT_OPERATOR_MAX_APEXES` | `4` | An account carried by more registrable domains than this, counted across **every** case in the DB, cannot be operator-tier. Absolute counts, deliberately: a ratio would need a population of normal sites, and an investigation corpus is all suspects |
| `KWARA_ADS_TXT_MANAGER_MIN_APEXES` | `10` | At or above this DB-wide apex count the account is manager-tier |
| `KWARA_ADS_TXT_INDEX_MAX_CARRIER_ACCOUNTS` | `500` | A domain declaring more DIRECT accounts than this is running a full programmatic stack, so its account signals are kept out of the cross-case index. The ads.txt template hash is still indexed for every domain |
| `KWARA_ADS_TXT_PLATFORM_ACCOUNTS` | `300` | A byte-identical ads.txt cluster whose files carry at least this many accounts is flagged `platform` (a monetisation provider emitting one file for its clients) rather than `portfolio` (one operator's own estate) |
| `KWARA_ADS_TXT_PREVALENCE_PATH` | `discovery/data/reference_prevalence.json` | Reference prevalence table built by `discover prevalence`. **Optional** — when absent, tier falls back to the thresholds above rather than treating every account as rare |
| `KWARA_ADS_TXT_COMMODITY_PREVALENCE` | `0.005` | An account carried by at least this fraction of ordinary publishers in that table cannot distinguish an operator. Calibrated on a 5,232-site sweep where the one genuine operator account measured 0.00% and surviving commodity accounts ran 1.7%–45% |

## Weak-signal weighting

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_WEAK_GENERIC_BREADTH` | `0.8` | A header value on at least this fraction of the case's landing domains is ubiquitous infrastructure (`server: cloudflare`), not attribution |
| `KWARA_HEADER_VALUE_MIN_LENGTH` | `8` | Minimum length for an indexed header value. Filters shape, not uniqueness — it drops values carrying nothing at all (`MISS`, `0`) where only the header name was informative |
| `KWARA_COVERAGE_CLASS_CAP` | `3` | Maximum instances any one evidence class contributes to the coverage figure, so the weakest class cannot saturate it |

## Candidate discovery

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_DISCOVERY_WORKERS` | `8` | Concurrency for the ads.txt screening sweep. Bounded on purpose — a run contacts thousands of unrelated third-party sites. Raise only with a reason |
| `KWARA_DISCOVERY_MAX_REDIRECTS` | `3` | Hop limit while screening. A legitimate `/ads.txt` is at most a couple of hops away; longer is a redirect chain, not a canonical host |
| `KWARA_PUBLICWWW_API_KEY` | *(unset)* | Enables `discover publicwww`. Read from the environment only and never written to disk — see [agent-interface.md](agent-interface.md) |
| `KWARA_PUBLICWWW_API_URL` | `https://publicwww.com/websites/` | PublicWWW export endpoint |
| `KWARA_PUBLICWWW_TIMEOUT` | `30` | PublicWWW request timeout (seconds) |
| `KWARA_PUBLICWWW_MAX_RESULTS` | `2000` | Cap on domains a single pivot pulls, so the candidate list stays reviewable. Override per run with `discover publicwww --limit` |

## Third-party corroboration and evidence integrity

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_URLSCAN_API_KEY` | *(unset)* | urlscan.io key (free community tier, 100 scans/day) |
| `KWARA_TSA_URL` | `https://freetsa.org/tsr` | RFC 3161 Time Stamp Authority. FreeTSA is free and needs no key |
| `KWARA_HMAC_KEY` | *(unset)* | Signs an evidence pack's `manifest.json`. Unset exports carry a note saying the manifest is unsigned |

## Batch snapshot runner (`kwara/_run_pending.py`)

A helper script for large capture backlogs, not part of the CLI surface.

| Variable | Default | Purpose |
|---|---|---|
| `KWARA_MAX_SNAPSHOT_BATCHES` | `999999` | Stop after this many batches — set to `1` for a smoke test |
| `KWARA_FAILURE_THRESHOLD` | `0.5` | Per-batch failure-rate ceiling |
| `KWARA_FAILURE_CHUNKS` | `2` | Consecutive bad chunks before aborting the run |
| `KWARA_MIN_CHUNK_SIZE` | `5` | A batch must hold at least this many URLs to count toward the failure test |
