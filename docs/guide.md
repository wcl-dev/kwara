**[正體中文](guide.zh-TW.md)**

# kwara — working a case

kwara is a local operator-attribution and digital-evidence tool specialised in
the digital-advertising ecosystem: it collects, scans and corroborates evidence
from suspicious URLs, then clusters the sites behind them into operator groups
along monetisation and measurement signals. Everything lives in a local SQLite
database.

This document is about **how to work a case** — the order of operations and the
judgement calls. The per-command reference is [agent-interface.md](agent-interface.md);
the algorithms and why they are cut that way are in [analysis-design.md](analysis-design.md).

kwara has no graphical interface. Everything runs through the CLI or MCP.

---

## Install

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e .          # or: -r requirements.txt
python -m playwright install chromium
```

`pip install -e .` puts a `kwara` command on PATH; without it, every command
below also works as `python -m kwara.cli ...` from the repository root.

Playwright is optional. Scanning, WHOIS, ads.txt and the attribution analysis
need no browser; only screenshots do.

---

## Data model

```
cases
  └─ message_evidence          (the source post)
        └─ url_artifacts       (URLs pulled out of it)
              └─ scan_runs     (redirect chain, TLS, headers, WHOIS/ASN,
                    │           ads.txt, corroboration)
                    ├─ redirect_hops  (every hop, with full response headers)
                    └─ snapshots      (screenshot, HTML, HAR, risk flags)
```

Cases are independent of one another. The one thing that spans them is the
**cross-case index** (`~/.kwara/index.db`), which remembers where a signal has
been seen before — across separate database files, not just separate cases.

---

## The order of a case

```bash
kwara case new --title "Op Nightingale" --locale-preset tw
kwara ingest url --case 1 https://suspicious.example/x
kwara run attribute --case 1
kwara analyze clusters --case 1
```

`run attribute` is the **browser-free pass**: follow redirects, record TLS and
headers, fetch ads.txt, look up WHOIS, extract tracking IDs from static HTML.

> **Do not rush to screenshots after ingesting.** The cheap pass is usually
> enough for operator groups to surface. Captures cost far more, and what they
> add is **tracking IDs injected by JavaScript** (GA4 loaded through GTM, for
> instance) plus page evidence for preservation.

When you want those:

```bash
kwara run snapshot --case 1          # Playwright: screenshot + HTML + HAR
kwara run corroborate --case 1       # Wayback, urlscan, RFC 3161 timestamp
```

**Run both capture paths or the OPSEC verdict cannot exist.** It compares
success rates between the browser-free fetch and Playwright, which is what
exposes a WAF configured to block scrapers and admit browsers. Run only one and
every domain reports `indeterminate` — `analyze insights` names the missing
path in its gaps.

---

## Reading the results

```bash
kwara analyze insights --case 1      # rule-based summary: verdict, findings, gaps
kwara analyze clusters --case 1      # operator groups and the signals linking them
kwara analyze narrative --case 1     # plain-prose verdict
kwara analyze graph --case 1 --out graph.svg
```

**Read the gaps in `insights` first.** They list what has not been collected —
no third-party corroboration, no TLS recorded, an OPSEC path missing. An empty
analysis usually means uncollected, not absent.

The signals are not equal. The full tiering is in `analysis-design.md`; in
practice the order is:

1. **Byte-identical ads.txt, shared tracking IDs, the same certificate** — strong
   enough to bind an operator group
2. **Cloaking, fabricated versions, cross-domain server templates** — observed
   evasion behaviour
3. **Shared ad accounts** — nearly always commodity; do not claim shared
   operation from these

---

## Cross-case memory

```bash
kwara index build --case 1                    # file this case's signals
kwara index lookup G-B2C3D4E5F6               # every case a value appears in
kwara index recurring                         # signals spanning several cases
kwara index crosslinks                        # endpoints that are themselves investigated domains
```

Read `domain_count` on `recurring` results: a "cross-case recurrence" covering
one domain is usually the same site filed under two cases, not something that
resurfaced elsewhere.

---

## Where the evidence is

The capture store is keyed by `scan_run_id`, so the filesystem alone cannot say
which domain a directory holds.

```bash
kwara evidence list --domain visitorlanding.example       # every capture for a site, across cases
kwara evidence describe                       # write a capture.json caption into each directory
kwara evidence browse --out ~/evidence-area --case 1
```

`browse` builds a symlink tree keyed by domain, so a file manager can walk it
and open the screenshots. Nothing is copied and the tree can be rebuilt at will.

---

## Delivery

```bash
kwara export case --case 1
```

A ZIP with CSVs, screenshots, HTML, HAR, the audit log, a SHA-256 manifest and
a bilingual README. Signing needs `KWARA_HMAC_KEY`; without it the manifest
**says so itself** (`integrity_warning`) rather than implying it was signed.

`restore_from_export.py` rebuilds a database from a pack, so a recipient can
reconstruct what you saw instead of taking your word for it.

---

## Risk flags

| Flag | Meaning |
|---|---|
| `multi_hop` | Redirect chain of 3 or more hops |
| `no_https` | Landing page served over HTTP |
| `new_domain` | Domain registered less than 180 days ago |
| `suspicious_download` | Final URL ends in .exe, .apk, .zip, … |
| `high_tracker_count` | Page contacts 3 or more known trackers |
| `url_shortener_chain` | Final URL is still a known shortener |
| `capture_error` | Screenshot capture failed |

---

## Going looking

The screening funnel finds candidates sharing a deployment with targets you
already know. That is a **separate workflow** — see the `discover` section of
[agent-interface.md](agent-interface.md).

The full list of environment variables is in [README.md](../README.md).
