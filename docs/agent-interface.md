# kwara agent interface — CLI and MCP

kwara has two surfaces, and no others:

- **`kwara/cli.py`** — the CLI. This is the source of truth for automation.
- **`kwara/mcp_server.py`** — an MCP server that wraps the CLI's command
  functions so an agent can call them as tools.

The MCP server contains no analysis logic of its own; every tool builds an
argument namespace and calls the same `cmd_*` function the CLI calls. The two
surfaces cannot drift apart.

There was a Streamlit UI; it was removed on 2026-08-07. It had been frozen
since the CLI landed, and freezing turned out to mean it showed *less* than
the CLI did — no reasoning behind a tier verdict, no explanation for an empty
OPSEC result. A surface that quietly claims more confidence than another is
worse than no surface. Browsing evidence is now `evidence browse`.

---

## CLI

### Install and invoke

```bash
source .venv/bin/activate
python -m kwara.cli --help
```

Nothing beyond `requirements.txt` is needed.

### Output contract

- **stdout is JSON** and nothing else. Errors, progress, and warnings go to
  stderr, so `python -m kwara.cli ... | jq` is always safe.
- `--text` switches to human-readable output; `--compact` gives single-line JSON.
- Exit codes: `0` success, `1` handled error, `2` bad usage, `130` interrupted.

### Global flags

Accepted **before or after** the subcommand.

| Flag | Meaning |
|---|---|
| `--db PATH` | Case database (default `$KWARA_DB_PATH`) |
| `--index-db PATH` | Cross-case index DB (default `$KWARA_INDEX_DB_PATH`) |
| `--lang en\|zh-TW` | Language for insight text (default `$KWARA_LANG`) |
| `--text` | Human-readable instead of JSON |
| `--compact` | Single-line JSON |
| `--quiet` | Suppress progress on stderr |

### Commands

**Cases**

```bash
python -m kwara.cli case list
python -m kwara.cli case new --title "Op Nightingale" --locale-preset tw
python -m kwara.cli case show --case 1
python -m kwara.cli case locale --case 1 --locale en-GB --timezone Europe/London
python -m kwara.cli case delete --case 1 --confirm DELETE     # irreversible
```

`--locale-preset` accepts `tw us uk jp kr de`, and sets the browser locale and
timezone used for screenshots. Set it to the **victim's** region: geo-cloaked
pages serve different content per region, so capturing with the analyst's own
locale can produce evidence of a page the victim never saw.

**Ingest**

```bash
python -m kwara.cli ingest url --case 1 https://a.example/x https://b.example/y
python -m kwara.cli ingest url --case 1 --message "$(cat post.txt)" \
    --platform facebook --permalink https://fb.com/posts/123
python -m kwara.cli ingest csv --case 1 --file posts.csv
```

CSV columns: `platform, permalink, actor_label, posted_at, message_text`.
UTF-8, with or without a BOM. Only `message_text` is required.

`posted_at` accepts ISO-8601 (`2025-05-18T17:29:25Z`, `...+08:00` — normalised
to UTC) or `YYYY-MM-DD[ HH:MM[:SS]]`, `YYYY/MM/DD`, `DD-MM-YYYY`, `MM/DD/YYYY`.
It is stored verbatim and parsed later, when domain intel dates a domain
against the post that carried it; an unparseable value is reported on stderr
at that point and the domain age is measured from now instead.

**Collection**

```bash
python -m kwara.cli run attribute --case 1          # start here
python -m kwara.cli run scan --case 1
python -m kwara.cli run scan --case 1 --artifact 42   # re-observe one URL
python -m kwara.cli run intel --case 1
python -m kwara.cli run snapshot --case 1 --limit 5 # slow: Playwright
python -m kwara.cli run corroborate --scan-run 12
python -m kwara.cli run cloaking --scan-run 12 --force
python -m kwara.cli run adstxt --scan-run 12 --force
```

`run scan` and `run attribute` fetch each distinct URL in the case once, not
once per post that carried it — N accounts pushing one link is the finding,
not a reason to send N requests at the target. The artifacts that were not
fetched still carry their posts through every attribution query, and the
response reports `skipped_duplicate_urls` so the saving is visible. Pass
explicit `--artifact` ids to re-observe a URL the case has already scanned.

`run attribute` is the cheap first pass — redirect scan, static HTML tracking
IDs, ads.txt, and WHOIS/ASN, with no browser. It populates the clustering
signals in seconds per URL.

> **Caveat worth repeating to whoever reads the output:** `run attribute` only
> sees tracking IDs embedded statically in the HTML. IDs injected by
> JavaScript (GA4 loaded through GTM, for instance) require `run snapshot`.
> Few or zero groups after an attribution pass does **not** prove the domains
> are unrelated.

`run snapshot` drives Playwright against live sites and takes roughly a minute
per URL. Use `--limit`, and run it in the background for large batches:

```bash
nohup python -m kwara.cli run snapshot --case 1 --limit 50 > snap.log 2>&1 &
python -m kwara.cli case show --case 1     # poll pending_snapshots
```

**Analysis** (read-only)

```bash
python -m kwara.cli analyze insights --case 1 --lang en
python -m kwara.cli analyze clusters --case 1
python -m kwara.cli analyze narrative --case 1
python -m kwara.cli analyze graph --case 1 --out graph.svg
python -m kwara.cli analyze graph --case 1 --group 2 --out g2.dot
```

`analyze graph` writes `.dot` with no extra dependency. `.svg` / `.png` /
`.pdf` need the graphviz `dot` binary (`brew install graphviz`); without it
the command fails with a message naming the missing piece rather than writing
a broken file.

An empty graph is a **result**, not a failure. The `note` field distinguishes
"scanned, but these sites share no hard signals — they appear independent"
from "nothing scanned yet".

`analyze narrative` currently emits Traditional Chinese regardless of
`--lang`; its strings are not routed through i18n.

**Cross-case index**

```bash
python -m kwara.cli index build --case 1
python -m kwara.cli index lookup "G-ABC123" --type tracking_id
python -m kwara.cli index recurring --min-cases 2
```

The index spans multiple case databases, so the same operator resurfacing in
a separate investigation is visible.

**Evidence and export**

```bash
python -m kwara.cli evidence list --case 1
python -m kwara.cli export case --case 1
```

`evidence list` checks each referenced file on disk and reports
`missing_screenshot_files` — a database row pointing at a file that is gone is
a chain-of-custody gap, not a cosmetic issue.

**Reconciling the store against the database**

```bash
python -m kwara.cli evidence reconcile
python -m kwara.cli evidence reconcile --attach                # dry run
python -m kwara.cli evidence reconcile --attach --apply        # writes rows
```

`evidence list` runs database → disk. `evidence reconcile` runs the other
direction, which nothing else does: it walks the capture store and finds
directories **no database claims**. That matters because a row can lose its
paths — a batch timeout, a re-capture that repointed the row at a fresh
directory, a database replaced between investigations — and the files then
stay on disk with nothing pointing at them. On one live store that was 12,873
directories holding 1.2 GB of real screenshots, page bodies and HARs from
open cases, and no command in the tool could have surfaced any of it.

Read `safe` first:

| Field | Meaning |
|---|---|
| `safe` | false when a database that might own these captures could not be read. Every "orphan" is then provisional — **do not act on the list** |
| `databases` | every database consulted, and where that path came from |
| `by_kind` | `empty` / `manifest_only` / `partial` / `capture`, with byte totals, size bands and a `single_byte_fill` count |
| `loose_legacy_files` | artifacts written directly into a scan_run bucket, before per-capture directories existed. Invisible to any depth-2 sweep |

"Orphan" is a claim about a **set** of databases, not about a directory. The
set is assembled from the cross-case index's `source_db` registry — the only
record of which databases have seen this store — plus any `--also-db` you
name. Judged against one database alone, another investigation's captures
read as debris.

`--attach` reconstructs the missing rows, re-deriving tracking IDs and request
domains so the recovered evidence actually counts in analysis. It is a dry run
unless `--apply` is given, and it refuses far more than it accepts:

- the domain recovered from the **artifacts** must be one the scan_run has
  been observed reaching. capture.json is written at directory *allocation*
  time, so it records intent, not result, and cannot corroborate itself
- the capture must **postdate** the scan. scan_run ids are not stable across
  databases, so a bucket number alone proves nothing about which scan wrote it
- `--include-partial` also considers page-body-only directories; without it
  they are left alone, because those are real evidence when the browser-free
  pass wrote them and test debris when a test did

Nothing here deletes. The module contains no deletion primitive at all, and a
test asserts that against the parsed source.

`acquisitions` in the report covers the other half of "evidence nothing points
at": rows whose scan_run has been deleted (the foreign key is SET NULL rather
than CASCADE precisely so the record survives a case deletion, which means
these accumulate by design), rows whose retained body is missing, and rows
whose body no longer matches its recorded hash. Reported only.

**Retained response bytes**

Every ads.txt fetch — 200, 403, redirect — writes its body to an immutable
artifact and records the acquisition beside it: requested and final URL,
status, headers with duplicates preserved, user agent, tool version, byte
count, and TWO hashes. `captured_sha256` covers what was written;
`complete_sha256` covers the whole response and is NULL when the read hit the
size ceiling. Only `complete_sha256` may be compared for byte-identity — a
prefix hash matched as identity would bind two files that differ after the
first 256 KB.

The table is append-only: a forced re-fetch inserts, and no code path updates
or deletes a row or a body.

`analyze clusters` therefore reports a `verification` on every template
cluster, and a `verification_by_domain` naming the weakest member:

| Verdict | Means |
|---|---|
| `verified` | Bytes present and still hashing to the claim. Only these bind a group |
| `legacy_unverifiable` | Fetched before retention existed |
| `body_missing` / `body_mismatch` | The artifact is gone or has changed |
| `hash_disagrees` | Intact bytes that are not the ones claimed |
| `wrong_scan_run` / `wrong_kind` | The acquisition cited belongs to something else |
| `truncated` | A prefix cannot establish identity |

Clusters that are not `verified` appear under `unverified_templates` with the
claimed hash, the reason, and the re-fetch that would settle it. They are
never rendered as a group at a softer tier — that would keep the same
inference under a gentler label.

**Shared GTM containers**

`weak_links` carries `type: "gtm_container"` entries at tier `相關未證實`
("related, unproven" — tier values are emitted as literal strings),
with `container_id`, `domains`, per-domain `members` giving each domain's
`group_id` (null when it belongs to no confirmed group), `spans_groups`, and
both `readings`. A container never contributes a union edge. In the cross-case
index it has its own `gtm_container` signal type rather than `tracking_id`,
whose recurrence wording reads as "the same operator resurfaced" — a sentence
a shared container does not support.

### Where the evidence actually lives

Captured files are ordinary files, independent of any UI:

```
kwara/data/snapshots/{scan_run_id}/{timestamp}_{rand4}/
    screenshot.png            full-page screenshot
    page.html                 browser-rendered HTML
    page_http_only.html       plain HTTP fetch (cloaking comparison)
    page_cloaking_alt.html    alternate UA / path fetch
    traffic.har               full network recording
```

SQLite stores the paths. `export case` bundles all of it into a ZIP with CSVs,
an audit log, a SHA-256 manifest, and a bilingual README.

---

## `discover` — the candidate screening funnel

**This group makes outbound connections** and visits candidate sites directly.
The full reasoning is in [analysis-design.md](analysis-design.md) §11 (written
in Traditional Chinese).

```bash
# 1. Pull candidate publisher domains out of an SSP's sellers.json
python -m kwara.cli discover candidates ssp1.json ssp2.json \
    --out candidates.txt --exclude-scanned

# 2. Fetch each candidate's /ads.txt and compare against known templates.
#    --bank is the point: it stores the observations, and those are both the
#    reference population and the input to self-clustering
python -m kwara.cli discover screen --domains candidates.txt \
    --bank observations.jsonl

# 3. Let the candidates cluster against each other (requires no prior
#    knowledge of any domain)
python -m kwara.cli discover cluster --observations observations.jsonl \
    --portfolio-only

# 4. Build the reference population from the observations — tier reads it
python -m kwara.cli discover prevalence --observations observations.jsonl \
    --out discovery/data/reference_prevalence.json
```

Pick obscure SSPs. A large exchange also serves mainstream publishers, so the
pool is diluted (9,501 candidates, 1 hit), while a small regional SSP's list
is far denser (666 candidates, 2 hits).

`screen` can only promote a candidate, never exonerate one — a miss reports
`no_match`, which is not the same as "clean".

### `discover publicwww` — pivot from a tracking id to candidate domains

`sellers.json` answers "which publishers does this SSP serve". PublicWWW
answers the other direction — **which domains embed this tracking id in their
source**. ads.txt screening cannot make that pivot, because ads.txt is a fixed
path, not page source.

```bash
# Needs KWARA_PUBLICWWW_API_KEY; output matches discover candidates, so it
# feeds screen directly
python -m kwara.cli discover publicwww 'G-ABC1234' 'AW-9988776' \
    --out cand.txt --exclude-scanned
python -m kwara.cli discover screen --domains cand.txt --bank obs.jsonl
```

One operator will embed the same tracking id across a pile of subdomains, so
the default **collapses to the apex and deduplicates** (`--no-apex` keeps full
hostnames). `--limit` overrides `KWARA_PUBLICWWW_MAX_RESULTS`.

Two deliberate boundaries:

- **The key never lands on disk.** PublicWWW's export API carries the key in
  the query string, and kwara is a tool that retains everything (acquisition
  stores the requested URL, the screen bank stores observation URLs, export
  bundles both). So this source keeps the HTTP transaction **transient**: the
  key travels in request params, the URL is never logged, no acquisition is
  written, no body is banked — only the domains survive.
  `tests/test_publicwww_source.py` pins that against the source.
- **CLI-only, not exposed over MCP.** Looking up a tracking id tells a third
  party which operator you are following — the same class of disclosure
  decision as `run corroborate`. `mcp_server._WITHHELD` lists
  `cmd_discover_publicwww`, and the command says so on stderr before it runs.

**Limitation: it only finds ids in the static homepage source.** PublicWWW
indexes statically fetched HTML and by default covers the homepage only, so
three kinds of id are invisible to it — and the pivot cannot reach them:

- **Ids injected through GTM or JS.** When GA4 loads via GTM, the `G-…` sits
  inside the GTM container JSON, not in page source. kwara sees it because it
  renders the page in a browser; PublicWWW's static crawler does not.
- **Ids that appear only on inner pages.** Large sites often carry AdSense on
  article pages alone, with nothing in the homepage source (the internal-pages
  search the site offers is a separate, paid path).
- **Sites below the crawl threshold.** A small regional farm may simply not be
  in PublicWWW's index at all.

That is precisely the shape of a GTM/cloaker-type operator, so **PublicWWW is
least useful against the most technically capable targets.** Measured on the
free tier against three real operator ids on 2026-08-19: the farm that
hard-codes `data-ad-client=` statically returned 10 (and the local corpus
already held more, so it added nothing), while another AdSense account and a
GTM-delivered GA4 both returned **0**. **Treat it as a supporting source for
low-sophistication, static-template farms, not as the primary way to track a
capable operator. A null result does not mean a small footprint — it may mean
only that this source cannot see it.**

### `discover normalize` — any list → apexes, one entry point

`candidates` (sellers.json) and `publicwww` (tracking ids) each produce
candidates their own way; blocklists, meanwhile, arrive scattered across
`hosts` format (`0.0.0.0 bad.example`) and adblock format (`||bad.example^`).
`normalize` folds those, along with plain lists and CSVs, into apexes that feed
`screen` directly. Purely local, no network:

```bash
python -m kwara.cli discover normalize --file blocklist.txt --out cand.txt
python -m kwara.cli discover screen --domains cand.txt --bank obs.jsonl
```

Non-domain rules — element hiding, regex, exceptions (`@@`) — are dropped;
they are not clean domains. `--no-apex` keeps full hostnames. The MCP tool is
`normalize_domains` (local transformation, exposed).

## MCP server

### Install

```bash
python -m pip install -r requirements-agent.txt
```

### Register with Claude Code

```bash
claude mcp add kwara -- /absolute/path/to/kwara/.venv/bin/python -m kwara.mcp_server
```

Set `KWARA_DB_PATH` in the environment, or pass `db` per tool call.

### Tools

| Tool | Purpose |
|---|---|
| `list_cases` | Every case with URL and scan counts |
| `create_case` | Open a case (with victim locale) |
| `case_status` | Detail plus progress counts |
| `ingest_urls` | Add URLs or a whole post body |
| `run_attribution` | Cheap attribution pass, no browser |
| `capture_snapshots` | Playwright capture, bounded by `limit` |
| `insights` | Rule-based summary, risk flags, evidence gaps |
| `clusters` | Operator groups and linking signals |
| `narrative` | Prose verdict with reasoning |
| `relationship_graph` | Write the graph to a file, return the path |
| `index_case` | Add case signals to the cross-case index |
| `lookup_signal` | Every case a signal value appears in |
| `recurring_signals` | Signals spanning multiple investigations |
| `list_evidence` | Evidence files with on-disk existence checks |
| `reconcile_evidence` | Captures on disk no database knows about (dry run only) |
| `describe_evidence` | Write a capture.json caption into each directory |
| `browse_evidence` | Domain-keyed symlink tree over the store |
| `ingest_csv` | Ingest a CSV of messages/URLs |
| `set_case_locale` | Set the locale and timezone captures render under |
| `export_case` | ZIP evidence pack |

### Deliberately not exposed

The list below is enforced, not documented: `mcp_server._WITHHELD` names each
withheld command with its reason, and a test fails if any `cmd_*` in cli.py is
neither wrapped nor listed there. It became enforced on 2026-08-11, when the
prose claimed three exclusions while eleven commands were quietly missing.

- **Deleting a case.** It irreversibly destroys evidence files. An agent
  should never be one tool call away from that — use `cli case delete`.
- **Unbounded capture.** `capture_snapshots` requires a limit (default 5,
  capped at 25) so one tool call cannot become an hour-long crawl of live
  scam infrastructure.
- **Writing recovered captures.** `reconcile_evidence` reports and dry-runs;
  `--apply` is CLI-only. Attaching binds a directory to a scan_run on
  circumstantial grounds, and a person signs for that.
- **The passes inside `run attribute`.** scan, ads.txt, cloaking and intel are
  steps of one pass that is exposed whole; driving them separately produces
  half-attributed scan_runs that read as complete.
- **Third-party corroboration.** `run corroborate` sends the URL under
  investigation to Wayback and urlscan, publishing the fact that it is being
  investigated. That is a disclosure decision, not a tool call.

### A reasonable agent workflow

1. `create_case` with the victim's region.
2. `ingest_urls`.
3. `run_attribution` — cheap, gets groups on the board.
4. `clusters` / `insights` — read the picture; decide what deserves capture.
5. `capture_snapshots` in small batches for the URLs that matter.
6. `index_case`, then `recurring_signals` to connect to prior investigations.
7. `export_case` when the evidence pack is needed.

---

## Design notes

**Why the CLI is the source of truth.** MCP tool schemas are convenient but
awkward to test and impossible to use from a shell script or a cron job. By
putting the logic in `cli.py` and having `mcp_server.py` synthesise argument
namespaces, both surfaces are exercised by the same tests and neither can
quietly diverge.

**What moved to make this possible.**

- `kwara/cases.py` — case lifecycle, previously inline SQL in the Streamlit
  sidebar. The snapshot-directory confinement guard moved with it and now has
  regression tests.
- `kwara/graph.py` — the DOT builder, previously inside `views/page_graph.py`.
  The graph was the one analytic output that only existed as a client-side
  render; it can now be written to a file.
- `kwara/i18n.py` — language is a process-wide setting. It used to defer to
  `st.session_state` so two browser tabs could differ; with one process there
  is one language, from `KWARA_LANG` or `--lang`.
- `kwara/palette.py` — was `ui_tokens.py`. The colours outlived the UI: the
  relationship graph and the operator-group labelling both use them.


### The discovery tools over MCP

| Tool | Outbound? | What it does |
|---|---|---|
| `extract_candidates` | No | Pull candidate publisher domains out of a sellers.json you already hold |
| `normalize_domains` | No | Fold any list format (plain / hosts / adblock / CSV) into apexes; local, no network |
| `screen_candidates` | **Yes** | Fetch candidates' /ads.txt and compare against known fingerprints. **Cap 500 per call, default 100** |
| `cluster_observations` | No | Cluster stored observations against each other, with no prior knowledge of any domain |
| `build_prevalence_table` | No | Build the reference population table that tier decisions read |

`screen_candidates` is capped for the same reason as `capture_snapshots`: it
visits every candidate directly, and screening lists routinely run to five
figures. An agent should not be able to start a sweep of tens of thousands of
sites in a single call. Larger batches go through the CLI, where a person is
present.

### `index crosslinks` — when a third-party endpoint is itself an investigated landing domain

```bash
python -m kwara.cli index crosslinks
```

Most of the endpoint index is ad tech a page happened to load, and "rarity"
cannot separate that from an operator's own infrastructure — an investigation
corpus is all suspects, so a DSP called by exactly one page looks just as rare
as a private asset host. This query asks a yes/no question instead: **is this
third-party host itself a domain we have investigated?** If it is, the two are
wired together, whatever their respective ads.txt files say.

No threshold needed. The MCP tool is `operator_cross_links`.

Real output (2026-08-06): QSH's `hub-site.example`, `satellite-site.example`
and `satellite2-site.example` all load static assets from
`statics.private-cdn.example` and `s1.private-cdn2.example` — the private CDN
of the 01-family cluster. That link had been sitting in the HAR for three
months, and it overturned an earlier "the two cases are unrelated" conclusion
that had been drawn from ads.txt accounts.

### `evidence list` — where the evidence is

The capture store is addressed by `scan_run_id`:

```
kwara/data/snapshots/7/20260505T081730971984_9fd1/screenshot.png
                     ↑ scan_run_id
```

**6.6 GB of evidence, every directory named in digits.** The filesystem itself
cannot say which directory belongs to which domain. Translating that back was
the one thing the Streamlit UI did that nothing else replaced.

```bash
# Where is this domain's evidence (across all cases)
python -m kwara.cli evidence list --domain visitor-landing.example

# What evidence does this case have
python -m kwara.cli evidence list --case 3
```

At least one of `--case` and `--domain` is required — with neither, the answer
is the entire store, and that is not an answer.

The `by_domain` summary gives each domain's capture count, the methods used,
and a sample path; `items` gives per-record detail. Every file gets an
**on-disk existence check**: files the database claims but that have since
vanished are counted in `missing_screenshot_files` — precisely the
chain-of-custody gap worth reporting.

The MCP tool is `list_evidence(case=..., domain=...)`.

### The evidence area: `evidence describe` and `evidence browse`

The capture store's layout is built for **write safety** — one directory per
scan_run, one subdirectory per capture, never overwritten. That is the right
shape for chain of custody and the wrong shape for a person. These two
commands supply the human side, and neither moves a single byte.

**`evidence describe`** drops a `capture.json` into each capture directory
(domain, URL, capture time, method, case):

```bash
python -m kwara.cli evidence describe            # backfill everything
python -m kwara.cli evidence describe --dry-run  # see how many would change
```

The point: when the folder is handed to someone else, or when the database
breaks, **the directory can still say what it is**. That is what the "a third
party should not have to trust us" design claim requires. `captured_at` is
when the evidence was captured, `described_at` when the description was
written — a backfill does not stamp today's date on May's evidence.

**`evidence browse`** projects a second view that uses domains as directory
names:

```bash
python -m kwara.cli evidence browse --out ~/evidence-area --case 3
```

```
~/evidence-area/visitor-landing.example/2026-05-05T0817_playwright -> the real capture directory
```

Symlinks, so the evidence is neither copied nor forked, and the view can be
rebuilt at any time — the store is the truth. **It refuses to write into a
directory it did not create**: it empties the tree before rebuilding, so a
mistyped path would otherwise destroy someone else's files.
