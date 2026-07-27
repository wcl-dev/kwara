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
def recurring_signals(min_cases: int = 2, index_db: str | None = None) -> dict:
    """Signals that resurface across separate investigations — the same operator showing up again."""
    return _call(cli.cmd_index_recurring, min_cases=min_cases, index_db=index_db)


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@mcp.tool()
def list_evidence(case: int, db: str | None = None) -> dict:
    """Captured evidence files for a case, with an on-disk existence check per file.

    `missing_screenshot_files` counts rows whose file the database references
    but which are no longer on disk — a chain-of-custody gap worth raising.
    """
    return _call(cli.cmd_evidence_list, case=case, db=db)


@mcp.tool()
def export_case(case: int, db: str | None = None) -> dict:
    """Export the case as a ZIP evidence pack: CSVs, screenshots, HTML, HAR, audit log, SHA-256 manifest."""
    return _call(cli.cmd_export_case, case=case, db=db)


def _set_lang(lang: str) -> None:
    from i18n import set_lang
    if lang in ("en", "zh-TW"):
        set_lang(lang)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
