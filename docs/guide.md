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
kwara evidence list --domain visitor-landing.example       # every capture for a site, across cases
kwara evidence describe                       # write a capture.json caption into each directory
kwara evidence browse --out ~/evidence-area --case 1
```

`browse` builds a symlink tree keyed by domain, so a file manager can walk it
and open the screenshots. Nothing is copied and the tree can be rebuilt at will.

Those three all start from a database row and ask whether its file survived.
The reverse question needs its own command:

```bash
kwara evidence reconcile                       # what is on disk that no DB knows
kwara evidence reconcile --attach              # dry run: what could be recovered
kwara evidence reconcile --attach --apply      # write the recovered rows
```

A row can lose its paths — a batch timeout, a re-capture that repointed the
row at a fresh directory, a database replaced between investigations — and the
files then sit on disk with nothing pointing at them. Nothing else in kwara
can see that.

**Read `safe` before anything else.** It is false when a database that might
own these captures could not be read, and every "orphan" is then provisional.
"Orphan" is a claim about a *set* of databases: the set comes from the
cross-case index plus any `--also-db` you name, and judged against one
database alone another investigation's captures look like debris.

`--attach` refuses far more than it accepts, and the refusals are the useful
part. A capture is only reattached when the domain recovered from its
**artifacts** is one that scan_run has been observed reaching, and when it
postdates the scan — scan_run ids are not stable across databases, so a bucket
number alone proves nothing. Evidence that fails those tests is still real;
it is just no longer connected to anything the current database records, and
the tool will not invent the connection for you.

`reconcile` never deletes.

## What a finding can prove

Two domains serving a byte-identical ads.txt is the strongest binding this
tool makes. Until 2026-08-12 it was also a claim a recipient had to take on
trust: kwara hashed the response, parsed it and discarded the bytes, and the
export pack carried no ads.txt at all.

Now every response is retained — 200s, 403 challenge pages, redirects alike —
and travels in the pack, so a recipient re-hashes rather than believes.

Read the `verification` on a template cluster before quoting it:

| Verdict | Means |
|---|---|
| `verified` | Every member's bytes are on disk and still hash to what the record claims. This one you can stand behind |
| `legacy_unverifiable` | Fetched before retention existed. Real history, but nobody can now show the files were identical |
| `body_missing` / `body_mismatch` | The retained file is gone or has changed since capture |
| `hash_disagrees` | The bytes are intact and are not the ones the derived record claims |
| `truncated` | The read hit the size ceiling; a prefix hash cannot establish identity |

**Only `verified` clusters bind an operator group.** Anything else appears
under `unverified_templates` with the domains, the claimed hash, why it cannot
be verified, and the re-fetch that would settle it — visible, but not merging
anything. Re-fetching restores it where the site still serves the same bytes;
where the site has started refusing requests, that binding is simply gone, and
saying so is more useful than implying otherwise.

Two limits worth stating to whoever reads your report. Retention makes a hash
recomputable; it does not establish WHEN the fetch happened, because
`fetched_at` is this machine's clock. And two identical files prove identical
captured bytes, not a common operator — platform-generated ads.txt templates
are common.

## Shared GTM containers

A GA4 property, an AdSense publisher id or a Meta Page identifies an ACCOUNT
someone holds. A Google Tag Manager container identifies a tag deployment,
which an agency or a CMS vendor can legitimately run across unrelated clients.

So a shared container never binds an operator group. It appears in
`weak_links` at tier `相關未證實` with the container id, every domain, which
group each domain sits in, and both competing readings — one operator running
two monetisation lines, or two operators sharing a managed container. Which
one applies is not answerable from the data alone: there is no reference
population for tracking IDs, so nobody can say how rare a shared container is.

GA4, AdSense, Meta and the rest are unaffected and still bind.

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

The variables you are most likely to set are in [README.md](../README.md).
The complete list — including every analysis threshold — is in
[configuration.md](configuration.md).
