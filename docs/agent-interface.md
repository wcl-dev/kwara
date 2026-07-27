# kwara agent interface — CLI and MCP

kwara has two headless surfaces beside the Streamlit UI:

- **`kwara/cli.py`** — the CLI. This is the source of truth for automation.
- **`kwara/mcp_server.py`** — an MCP server that wraps the CLI's command
  functions so an agent can call them as tools.

The MCP server contains no analysis logic of its own; every tool builds an
argument namespace and calls the same `cmd_*` function the CLI calls. The two
surfaces cannot drift apart.

The Streamlit UI still works and shares the same core modules. It is frozen —
new capability lands on the CLI/MCP side.

---

## CLI

### Install and invoke

```bash
source .venv/bin/activate
python -m kwara.cli --help
```

Nothing beyond `kwara/requirements.txt` is needed.

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

**Collection**

```bash
python -m kwara.cli run attribute --case 1          # start here
python -m kwara.cli run scan --case 1
python -m kwara.cli run intel --case 1
python -m kwara.cli run snapshot --case 1 --limit 5 # slow: Playwright
python -m kwara.cli run corroborate --scan-run 12
python -m kwara.cli run cloaking --scan-run 12 --force
python -m kwara.cli run adstxt --scan-run 12 --force
```

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

## MCP server

### Install

```bash
python -m pip install -r kwara/requirements-agent.txt
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
| `export_case` | ZIP evidence pack |

### Deliberately not exposed

- **Deleting a case.** It irreversibly destroys evidence files. An agent
  should never be one tool call away from that — use `cli case delete`.
- **Unbounded capture.** `capture_snapshots` requires a limit (default 5,
  capped at 25) so one tool call cannot become an hour-long crawl of live
  scam infrastructure.

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
  render; it can now be written to a file. The UI imports it from here.
- `kwara/i18n.py` — Streamlit is now imported lazily and optionally, so a
  headless process neither pulls in the UI framework nor emits
  "missing ScriptRunContext" warnings.
