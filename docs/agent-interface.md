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

## `discover` — 候選篩選漏斗

**這一組會對外連線**，直接造訪候選網站。完整原理見 [analysis-design.md](analysis-design.md) §十一。

```bash
# 1. 從 SSP 的 sellers.json 取出候選發布商網域
python -m kwara.cli discover candidates ssp1.json ssp2.json \
    --out candidates.txt --exclude-scanned

# 2. 抓每個候選的 /ads.txt，比對索引裡的已知模板
#    --bank 是重點：把觀測存下來，它同時是參照母體與自我分群的輸入
python -m kwara.cli discover screen --domains candidates.txt \
    --bank observations.jsonl

# 3. 讓候選彼此分群（不需要事先認識任何網域）
python -m kwara.cli discover cluster --observations observations.jsonl \
    --portfolio-only

# 4. 用觀測建參照母體——tier 判定會讀它
python -m kwara.cli discover prevalence --observations observations.jsonl \
    --out discovery/data/reference_prevalence.json
```

挑 SSP 要挑冷門的：大型交易所同時服務主流發布商，池子會被稀釋（9,501 個候選命中 1 個），小型區域 SSP 的名單密度高得多（666 個候選命中 2 個）。

`screen` 只能把候選升級，不能替它開脫——未命中回報 `no_match`，不是「乾淨」。

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


### MCP 的 discovery 工具

| 工具 | 對外？ | 說明 |
|---|---|---|
| `extract_candidates` | 否 | 從手上的 sellers.json 取出候選發布商網域 |
| `screen_candidates` | **是** | 抓候選的 /ads.txt 比對已知指紋。**每次上限 500、預設 100** |
| `cluster_observations` | 否 | 讓已存的觀測彼此分群，不需事先認識任何網域 |
| `build_prevalence_table` | 否 | 建參照母體表，tier 判定會讀它 |

`screen_candidates` 設上限的理由與 `capture_snapshots` 相同：它直接造訪每一個候選，而掃描清單動輒五位數。agent 不該一次呼叫就啟動上萬網站的掃描；更大的批次走 CLI，那裡有人在場。

### `index crosslinks` — 第三方 endpoint 同時也是被調查的落地網域

```bash
python -m kwara.cli index crosslinks
```

endpoint 索引裡多數是網頁碰巧載入的廣告科技，而「稀有」分不出它與操作者自架設施——調查語料全是嫌疑者，只有一個頁面呼叫過的 DSP 看起來跟私有資產主機一樣罕見。這個查詢改問是非題：**這個第三方主機，本身是不是我們調查過的網域？** 是的話，兩邊就是接在一起的，不管各自的 ads.txt 怎麼說。

不需要任何門檻。MCP 對應工具 `operator_cross_links`。

實際產出（2026-08-06）：QSH 的 `hubsite.example`／`satellitesite.example`／`satellite2site.example` 都從 `statics.privatecdn.example` 與 `s1.privatecdn2.example` 載入靜態資源——那是 01 家族叢集的私有 CDN。這條連結在 HAR 裡躺了三個月，而且推翻了先前依 ads.txt 帳號得出的「兩案無關聯」判斷。

### `evidence list` — 證據在哪

擷取庫是用 `scan_run_id` 當門牌：

```
kwara/data/snapshots/7/20260505T081730971984_9fd1/screenshot.png
                     ↑ scan_run_id
```

**6.6 GB 的證據，目錄名全是數字**，檔案系統本身看不出哪個目錄屬於哪個網域。把它翻譯回來是 Streamlit UI 唯一不可替代的功能。

```bash
# 這個網域的證據在哪（跨所有案件）
python -m kwara.cli evidence list --domain visitorlanding.example

# 這個案件有哪些證據
python -m kwara.cli evidence list --case 3
```

`--case` 與 `--domain` 至少要給一個——都不給的話答案是整個庫，那不算答案。

輸出的 `by_domain` 摘要給每個網域的擷取次數、用過哪些方式、範例路徑；`items` 給逐筆細節。每個檔案都做**磁碟實存檢查**：資料庫聲稱存在但檔案已消失的，計入 `missing_screenshot_files`——那正是值得舉報的保管鏈缺口。

MCP 對應工具 `list_evidence(case=..., domain=...)`。

### 證據區：`evidence describe` 與 `evidence browse`

擷取庫的佈局是為了**寫入安全**設計的——每個 scan_run 一個目錄、每次擷取一個子目錄、永不覆蓋。那對保管鏈是對的形狀，對人是錯的形狀。兩個指令補上人這一側，都不搬動任何位元組。

**`evidence describe`** 在每個擷取目錄放一個 `capture.json`（網域、URL、擷取時間、方式、案件）：

```bash
python -m kwara.cli evidence describe            # 全部回填
python -m kwara.cli evidence describe --dry-run  # 先看會動幾個
```

意義在於：把資料夾交給別人、或資料庫壞掉時，**目錄本身仍然說得出自己是什麼**。這才符合「第三方不需要信任我們」那個設計主張。`captured_at` 是證據擷取時間、`described_at` 是說明寫入時間——回填不會把今天的日期蓋在五月的證據上。

**`evidence browse`** 用網域當目錄名，投影出第二個檢視：

```bash
python -m kwara.cli evidence browse --out ~/evidence-area --case 3
```

```
~/evidence-area/visitorlanding.example/2026-05-05T0817_playwright -> 真正的擷取目錄
```

符號連結，證據不複製也不會分岔；隨時可重建，庫才是真相。**它會拒絕寫入不是自己建立的目錄**——重建前會清空樹，指錯路徑會毀掉別人的東西。
