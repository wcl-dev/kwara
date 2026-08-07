"""kwara MCP server — the agent-facing surface.

A deliberately thin wrapper: every tool builds an argparse-style namespace and
calls the matching `cmd_*` function in cli.py. There is no analysis logic
here, so the MCP tools and the CLI cannot drift apart — fix a bug once and
both surfaces get it.

Run it:
    python -m kwara.mcp_server

Register it with Claude Code:
    claude mcp add kwara -- /path/to/.venv/bin/python -m kwara.mcp_server

Two things are intentionally NOT exposed:

  • **Deleting a case.** It destroys evidence files irreversibly. An agent
    should never be one tool call away from that; use the CLI.
  • **Unbounded snapshot capture.** Playwright captures take minutes and can
    hit dozens of live scam sites. `capture_snapshots` requires an explicit
    limit so a single tool call can't turn into an hour-long crawl.
  • **Unbounded candidate screening.** `screen_candidates` contacts every
    candidate directly, and a sweep list runs to five figures. Same reasoning
    as snapshots: it is capped per call so an agent cannot start a ten-thousand
    site sweep unattended. Larger runs belong in the CLI, with a human there.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cli  # noqa: E402  — needs the sys.path line above

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - dependency guidance
    raise SystemExit(
        "The MCP SDK is not installed. Run:\n"
        "    python -m pip install -r kwara/requirements-agent.txt"
    )

mcp = FastMCP("kwara")


def _call(fn, **kwargs):
    """Invoke a cli.cmd_* function with a synthesised argument namespace."""
    ns = argparse.Namespace(**{**cli._GLOBAL_DEFAULTS, **kwargs})
    return fn(ns)


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@mcp.tool()
def list_cases(db: str | None = None) -> list[dict]:
    """List every investigation case with its URL and scan counts."""
    return _call(cli.cmd_case_list, db=db)


@mcp.tool()
def create_case(
    title: str,
    description: str = "",
    locale_preset: str | None = None,
    db: str | None = None,
) -> dict:
    """Open a new case.

    `locale_preset` (tw/us/uk/jp/kr/de) sets the browser locale and timezone
    used for screenshots, so captures show what a victim in that region
    actually saw rather than what the analyst's machine renders. Set it when
    the victim's region is known — geo-cloaked pages serve different content
    per region and getting this wrong makes the evidence misleading.
    """
    return _call(cli.cmd_case_new, title=title, description=description,
                 locale_preset=locale_preset, locale=None, timezone=None, db=db)


@mcp.tool()
def case_status(case: int, db: str | None = None) -> dict:
    """Case detail plus progress counts: URLs, scanned, unscanned, pending snapshots."""
    return _call(cli.cmd_case_show, case=case, db=db)


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

@mcp.tool()
def ingest_urls(
    case: int,
    urls: list[str],
    platform: str = "",
    permalink: str = "",
    actor: str = "",
    posted_at: str = "",
    message: str | None = None,
    db: str | None = None,
) -> dict:
    """Add suspicious URLs to a case.

    Pass `message` instead of `urls` to ingest a whole post body — URLs are
    extracted from it, and the original text is retained as provenance.
    """
    return _call(cli.cmd_ingest_url, case=case, urls=urls, message=message,
                 platform=platform, permalink=permalink, actor=actor,
                 posted_at=posted_at, db=db)


@mcp.tool()
def run_attribution(case: int, force: bool = False, db: str | None = None) -> dict:
    """Cheap attribution pass over every un-scanned URL in the case.

    Follows redirect chains, fetches static HTML for embedded tracking IDs,
    pulls ads.txt, and enriches WHOIS/ASN — no browser, so it takes seconds
    per URL rather than minutes. This is the right first step: it populates
    the operator-clustering signals so groups and the relationship graph
    appear without the heavy capture step.

    Caveat worth passing on to the user: only STATIC, HTML-embedded tracking
    IDs are visible here. IDs injected by JavaScript (e.g. GA4 loaded through
    GTM) need capture_snapshots. Finding few or zero groups after this does
    NOT prove the domains are unrelated.
    """
    return _call(cli.cmd_run_attribute, case=case, force=force, db=db, quiet=True)


@mcp.tool()
def capture_snapshots(case: int, limit: int = 5, db: str | None = None) -> dict:
    """Capture full evidence for pending URLs: screenshot, HTML, and HAR.

    Slow (Playwright, roughly a minute per URL) and it visits live sites, so
    `limit` is required and defaults to 5. Call it repeatedly to work through
    a backlog rather than asking for a large batch in one go. Uses the case's
    victim locale automatically.
    """
    limit = max(1, min(int(limit), 25))
    return _call(cli.cmd_run_snapshot, case=case, scan_run=None,
                 limit=limit, db=db, quiet=True)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@mcp.tool()
def insights(case: int, lang: str = "en", db: str | None = None) -> dict:
    """Rule-based case summary: headline, findings, risk flags, and evidence gaps."""
    _set_lang(lang)
    return _call(cli.cmd_analyze_insights, case=case, db=db)


@mcp.tool()
def clusters(case: int, db: str | None = None) -> dict:
    """Operator groups and the shared signals linking domains together.

    Groups are formed from hard signals — the same tracking ID, TLS
    certificate, or ads.txt account across domains. Weak links are reported
    separately and should not be presented as proof of common control.
    """
    return _call(cli.cmd_analyze_clusters, case=case, db=db)


@mcp.tool()
def narrative(case: int, db: str | None = None) -> dict:
    """Plain-prose verdict with the reasoning behind it. Output is Traditional Chinese."""
    return _call(cli.cmd_analyze_narrative, case=case, db=db)


@mcp.tool()
def relationship_graph(
    case: int,
    out: str,
    group: int | None = None,
    fmt: str = "svg",
    db: str | None = None,
) -> dict:
    """Write the operator relationship graph to a file and return its path.

    `fmt` svg/png/pdf needs the graphviz `dot` binary installed; `dot` writes
    the raw DOT source and always works. An empty graph is a real finding
    ("these sites share nothing"), not an error — check the `note` field.
    """
    return _call(cli.cmd_analyze_graph, case=case, group=group, out=out,
                 format=fmt, include_dot=False, db=db)


# ---------------------------------------------------------------------------
# Cross-case index
# ---------------------------------------------------------------------------

@mcp.tool()
def index_case(case: int, db: str | None = None, index_db: str | None = None) -> dict:
    """Add this case's signals to the central cross-case index."""
    return _call(cli.cmd_index_build, case=case, db=db, index_db=index_db)


@mcp.tool()
def lookup_signal(
    value: str,
    signal_type: str | None = None,
    index_db: str | None = None,
) -> dict:
    """Find every indexed case a signal value appears in — a tracking ID, cert serial, ASN, ads.txt account."""
    return _call(cli.cmd_index_lookup, value=value, type=signal_type, index_db=index_db)


@mcp.tool()
def operator_cross_links(index_db: str | None = None) -> dict:
    """Third-party endpoints that are THEMSELVES investigated landing domains.

    The sharpest read on endpoint data and the only one needing no threshold.
    Most endpoints are ad-tech a page happened to load, and rarity cannot
    separate that from operator infrastructure — in an all-suspect corpus a DSP
    one page called looks as rare as a private asset host. This asks a
    yes/no question instead: does this host also appear as a domain under
    investigation? If a landing page fetches resources from one that does, the
    two are wired together whatever their ads.txt says.
    """
    return _call(cli.cmd_index_crosslinks, index_db=index_db)


@mcp.tool()
def recurring_signals(min_cases: int = 2, index_db: str | None = None) -> dict:
    """Signals that resurface across separate investigations — the same operator showing up again."""
    return _call(cli.cmd_index_recurring, min_cases=min_cases, index_db=index_db)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@mcp.tool()
def list_evidence(case: int | None = None, domain: str | None = None,
                  db: str | None = None) -> dict:
    """Where a domain's captured evidence sits on disk, with existence checks.

    The capture store is keyed by scan_run_id — `data/snapshots/7/2026…_9fd1/`
    — so the filesystem alone cannot say which domain a directory holds. Pass
    `domain` to find every capture for a site across all cases, or `case` for
    one investigation; at least one is required, because without a filter the
    answer is the whole store.

    `missing_screenshot_files` counts rows whose file the database references
    but which are no longer on disk — a chain-of-custody gap worth raising.
    """
    return _call(cli.cmd_evidence_list, case=case, domain=domain, db=db)


@mcp.tool()
def export_case(case: int, db: str | None = None) -> dict:
    """Export the case as a ZIP evidence pack: CSVs, screenshots, HTML, HAR, audit log, SHA-256 manifest."""
    return _call(cli.cmd_export_case, case=case, db=db)



# ---------------------------------------------------------------------------
# Discovery — finding candidates rather than working a known case
# ---------------------------------------------------------------------------

@mcp.tool()
def extract_candidates(
    sellers_json: list[str],
    out: str | None = None,
    exclude_scanned: bool = False,
    db: str | None = None,
) -> dict:
    """Publisher domains listed in SSPs' sellers.json files — a sweep's candidates.

    sellers.json is the mirror of ads.txt: it sits on the ad exchange and names
    the publishers it works with, so one public file yields thousands of
    candidates without crawling. Offline — it only reads files you already have.

    Pick the SSPs deliberately. Large exchanges serve mainstream publishers
    alongside the targets and dilute the pool; a small regional SSP is far
    denser. `exclude_scanned` drops domains this case DB has already seen.
    """
    return _call(cli.cmd_discover_candidates, sellers_json=sellers_json,
                 out=out, exclude_scanned=exclude_scanned, db=db)


@mcp.tool()
def screen_candidates(
    domains: str,
    limit: int = 100,
    bank: str | None = None,
    db: str | None = None,
    index_db: str | None = None,
) -> dict:
    """Fetch each candidate's /ads.txt and match it against known templates.

    OUTBOUND: contacts every candidate directly, one small request each. Capped
    per call (default 100, max 500) — run it repeatedly to work through a list
    rather than asking for a whole sweep in one go.

    A byte-identical ads.txt means the same deployer, which is the one ads.txt
    signal strong enough to bind an operator group. A miss is reported as
    `no_match`, never as clean: this stage can promote a candidate, never
    exonerate one.

    Pass `bank` to keep the parsed observations — they are the input to
    `cluster_observations` and `build_prevalence_table`, and re-fetching them
    later means hitting every site again.
    """
    limit = max(1, min(int(limit), 500))
    return _call(cli.cmd_discover_screen, domains=domains, limit=limit,
                 bank=bank, workers=None, db=db, index_db=index_db, quiet=True)


@mcp.tool()
def cluster_observations(observations: str, portfolio_only: bool = False) -> dict:
    """Group banked observations that serve a byte-identical ads.txt as each other.

    Offline. Unlike screening, this needs no prior knowledge of any domain — it
    asks which candidates share a file with one another, so it finds operators
    the index has never seen. `portfolio_only` drops templates carrying
    hundreds of accounts, which are a monetisation platform emitting one file
    for its clients rather than one operator's own estate.

    Clusters found here are leads, not evidence. Ingest them into a case and
    run attribution: tracking IDs cross template clusters and templates do not,
    so ads.txt alone understates how far an operator reaches.
    """
    return _call(cli.cmd_discover_cluster, observations=observations,
                 portfolio_only=portfolio_only)


@mcp.tool()
def build_prevalence_table(
    observations: str,
    out: str,
    source: str | None = None,
) -> dict:
    """Build the reference table that tells common ad accounts from rare ones.

    Offline. Every domain in an investigation is a suspect, so rarity measured
    inside a case measures nothing — accounts that read as strong evidence turn
    out to sit on a third of all ordinary publishers. This counts how many
    sites in an OUTSIDE population carry each account, and the tier logic reads
    it to demote the commodity ones.

    Feed it a sweep of ordinary publishers, not your own case domains: doing
    the latter rebuilds the exact bias the table exists to remove. Record what
    was swept in `source`.
    """
    return _call(cli.cmd_discover_prevalence, observations=observations,
                 out=out, source=source)


def _set_lang(lang: str) -> None:
    from i18n import set_lang
    if lang in ("en", "zh-TW"):
        set_lang(lang)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
