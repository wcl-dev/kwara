"""kwara CLI — the headless surface the agent tooling is built on.

Everything the Streamlit UI can do to a case, minus the pixels. This is the
single source of truth for automation: mcp_server.py is a thin wrapper that
calls the same functions, so the CLI and the MCP tools can never drift.

Output is JSON on stdout by default (agents parse it; `--text` is there for
humans). Progress and warnings go to stderr so piping stdout into `jq` stays
clean. Exit code is 0 on success, 1 on a handled error, 2 on bad usage.

    python -m kwara.cli case new --title "QSH shortlinks"
    python -m kwara.cli ingest url --case 1 https://example.com/a
    python -m kwara.cli run attribute --case 1
    python -m kwara.cli analyze insights --case 1
    python -m kwara.cli analyze graph --case 1 --out graph.svg

Long jobs (`run snapshot`, `run pending`) drive Playwright and can take
minutes; run them in the background and poll `case show`.
"""
import argparse
import json
import os
import sqlite3
import stat
import sys



def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _emit(data, args) -> None:
    """Write the result to stdout in the requested shape."""
    if getattr(args, "text", False):
        _emit_text(data)
        return
    indent = None if getattr(args, "compact", False) else 2
    print(json.dumps(data, ensure_ascii=False, indent=indent, default=str))


def _emit_text(data, depth: int = 0) -> None:
    pad = "  " * depth
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                print(f"{pad}{k}:")
                _emit_text(v, depth + 1)
            else:
                print(f"{pad}{k}: {v}")
    elif isinstance(data, list):
        if not data:
            print(f"{pad}(none)")
        for item in data:
            if isinstance(item, (dict, list)):
                _emit_text(item, depth)
                print()
            else:
                print(f"{pad}- {item}")
    else:
        print(f"{pad}{data}")


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

def _open_db(args) -> sqlite3.Connection:
    from .db import get_conn, init_db, migrate_db
    from . import config

    db_path = args.db or config.DB_PATH
    parent = os.path.dirname(os.path.abspath(db_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = get_conn(db_path)
    init_db(conn)
    migrate_db(conn)
    return conn


def _open_index(args) -> sqlite3.Connection:
    from .index_db import get_index_conn
    from . import config

    return get_index_conn(args.index_db or config.INDEX_DB_PATH)


def _case_env(conn, case_id: int) -> dict[str, str] | None:
    """Browser env overrides derived from the case's victim locale.

    Screenshots must render what the victim saw, not what the analyst's
    machine defaults to — otherwise geo-cloaked pages quietly show the wrong
    content and the evidence is misleading. The UI does this on every
    capture; the CLI has to as well.
    """
    from .cases import get_case

    case = get_case(conn, case_id) or {}
    env: dict[str, str] = {}
    if case.get("browser_locale"):
        env["KWARA_BROWSER_LOCALE"] = case["browser_locale"]
    if case.get("browser_timezone"):
        env["KWARA_BROWSER_TIMEZONE"] = case["browser_timezone"]
    return env or None


# ---------------------------------------------------------------------------
# case
# ---------------------------------------------------------------------------

def cmd_case_list(args):
    from . import cases
    conn = _open_db(args)
    return cases.list_cases(conn)


def cmd_case_new(args):
    from . import cases
    conn = _open_db(args)
    locale, tz = cases.resolve_locale(args.locale_preset, args.locale, args.timezone)
    case_id = cases.create_case(
        conn, title=args.title, description=args.description or "",
        browser_locale=locale, browser_timezone=tz,
    )
    return {"case_id": case_id, "title": args.title.strip(),
            "browser_locale": locale, "browser_timezone": tz}


def cmd_case_show(args):
    from . import cases
    from .clusters import case_counts
    conn = _open_db(args)
    case = cases.require_case(conn, args.case)
    n_urls, scanned = case_counts(conn, args.case)
    pending_snapshots = conn.execute(
        """SELECT COUNT(*) AS n FROM scan_runs sr
             JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
             LEFT JOIN snapshots s ON s.scan_run_id = sr.id
            WHERE ua.case_id = ? AND s.id IS NULL""",
        (args.case,),
    ).fetchone()["n"]
    return {
        **case,
        "url_count": n_urls,
        "scanned": scanned,
        "unscanned": max(0, n_urls - scanned),
        "pending_snapshots": pending_snapshots,
    }


def cmd_case_locale(args):
    from . import cases
    conn = _open_db(args)
    locale, tz = cases.resolve_locale(args.locale_preset, args.locale, args.timezone)
    cases.set_case_locale(conn, args.case, locale, tz)
    return {"case_id": args.case, "browser_locale": locale, "browser_timezone": tz}


def cmd_case_delete(args):
    from . import cases
    conn = _open_db(args)
    return cases.delete_case(conn, args.case, confirm=args.confirm)


# ---------------------------------------------------------------------------
# ingest
# ---------------------------------------------------------------------------

def cmd_ingest_url(args):
    from .cases import require_case
    from .ingestion import ingest_message
    conn = _open_db(args)
    require_case(conn, args.case)

    # ingest_message extracts URLs out of the message body, so a bare list of
    # URLs is just a message whose text is those URLs. Keeping one code path
    # means CLI-ingested URLs carry the same provenance row as UI-ingested
    # ones.
    text = args.message or "\n".join(args.urls)
    message_id, urls = ingest_message(
        conn, args.case, message_text=text,
        platform=args.platform or "", permalink=args.permalink or "",
        actor_label=args.actor or "", posted_at=args.posted_at or "",
    )
    return {"case_id": args.case, "message_id": message_id,
            "urls": urls, "url_count": len(urls)}


def cmd_ingest_csv(args):
    from .cases import require_case
    from .ingestion import ingest_csv
    conn = _open_db(args)
    require_case(conn, args.case)
    if not os.path.isfile(args.file):
        raise ValueError(f"no such file: {args.file}")
    rows = ingest_csv(conn, args.case, args.file)
    return {"case_id": args.case, "messages": len(rows),
            "url_count": sum(r["url_count"] for r in rows), "rows": rows}


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def cmd_run_attribute(args):
    from . import pipeline
    from .cases import require_case
    conn = _open_db(args)
    require_case(conn, args.case)
    return pipeline.run_fast_attribution(
        conn, args.case, force=args.force,
        progress=None if args.quiet else _err,
    )


def cmd_run_scan(args):
    from . import pipeline
    from .cases import require_case
    conn = _open_db(args)
    require_case(conn, args.case)

    artifact_ids = args.artifact or pipeline._artifacts_needing_scan(conn, args.case)
    scanned, errors = [], []
    for aid in artifact_ids:
        try:
            scanned.append(pipeline.run_scan_only(conn, aid))
        except Exception as e:  # noqa: BLE001 — best-effort batch, report per item
            errors.append(f"artifact {aid}: {e}")
    return {"case_id": args.case, "scanned": len(scanned),
            "scan_run_ids": scanned, "errors": errors}


def cmd_run_intel(args):
    from . import pipeline
    from .cases import require_case
    conn = _open_db(args)
    require_case(conn, args.case)
    targets = args.scan_run or pipeline._scan_runs_needing(
        conn, args.case, force=args.force)["intel"]
    pipeline.run_domain_intel_batch(conn, targets)
    return {"case_id": args.case, "enriched": len(targets), "scan_run_ids": targets}


def cmd_run_snapshot(args):
    from . import pipeline
    from .cases import require_case
    conn = _open_db(args)
    require_case(conn, args.case)

    if args.scan_run:
        targets = args.scan_run
    else:
        # Pending means "has no BROWSER capture", not "has no snapshot".
        # `run attribute` writes an http_only snapshot for every URL, so the
        # older any-snapshot test made `run snapshot` a silent no-op after the
        # cheap pass — which is the exact order the guide recommends. A manual
        # upload or a Wayback substitute counts as satisfied; those are the
        # analyst deliberately supplying the page another way.
        targets = [
            r["id"] for r in conn.execute(
                """SELECT sr.id FROM scan_runs sr
                     JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
                    WHERE ua.case_id = ?
                      AND NOT EXISTS (
                          SELECT 1 FROM snapshots s
                           WHERE s.scan_run_id = sr.id
                             AND (
                                 (s.capture_method = 'playwright'
                                  AND s.capture_status IN ('ok', 'manual', 'wayback'))
                                 OR s.capture_status IN ('manual', 'wayback')
                             )
                      )
                    ORDER BY sr.id""",
                (args.case,),
            ).fetchall()
        ]
    if args.limit:
        targets = targets[: args.limit]
    if not targets:
        return {"case_id": args.case, "snapshots": 0, "scan_run_ids": [],
                "note": "nothing pending"}

    env = _case_env(conn, args.case)
    if not args.quiet:
        _err(f"capturing {len(targets)} snapshot(s), env={env or 'default'}")
    snapshot_ids = pipeline.run_snapshot_batch(conn, targets, env_override=env)
    return {"case_id": args.case, "snapshots": len(snapshot_ids),
            "snapshot_ids": snapshot_ids, "scan_run_ids": targets}


def cmd_run_corroborate(args):
    from . import pipeline
    conn = _open_db(args)
    results = {sid: pipeline.run_corroborate(conn, sid) for sid in args.scan_run}
    return {"corroborated": results}


def cmd_run_cloaking(args):
    from . import pipeline
    conn = _open_db(args)
    return {"cloaking": {sid: pipeline.run_cloaking(conn, sid, force=args.force)
                         for sid in args.scan_run}}


def cmd_run_adstxt(args):
    from . import pipeline
    conn = _open_db(args)
    return {"ads_txt": {sid: pipeline.run_ads_txt(conn, sid, force=args.force)
                        for sid in args.scan_run}}


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def cmd_analyze_insights(args):
    from .cases import require_case
    from .insights import case_insights
    conn = _open_db(args)
    require_case(conn, args.case)
    return case_insights(conn, args.case)


def cmd_analyze_clusters(args):
    from .cases import require_case
    from .clusters import case_clusters
    conn = _open_db(args)
    require_case(conn, args.case)
    return case_clusters(conn, args.case)


def cmd_analyze_narrative(args):
    from .cases import require_case
    from .narrative import case_narrative
    conn = _open_db(args)
    require_case(conn, args.case)
    return case_narrative(conn, args.case)


def cmd_analyze_graph(args):
    from .cases import require_case
    from . import graph as graph_mod
    conn = _open_db(args)
    require_case(conn, args.case)

    result = graph_mod.case_dot(conn, args.case, gid=args.group)
    if result["dot"] is None:
        # An empty graph is a real finding ("these sites share nothing"), not
        # a failure — say which of the two it is instead of printing nothing.
        result["note"] = (
            "no shared hard signals between domains — the sites appear "
            "independent" if result["scanned"] > 0
            else "nothing scanned yet; run `run attribute` first"
        )
        return result

    if args.out:
        fmt = args.format or (os.path.splitext(args.out)[1].lstrip(".") or "dot")
        result["output_path"] = graph_mod.render_dot(result["dot"], args.out, fmt)
        result["format"] = fmt
        result.pop("dot")
    elif not args.include_dot:
        result.pop("dot")
    return result


# ---------------------------------------------------------------------------
# index (cross-case)
# ---------------------------------------------------------------------------

def cmd_index_build(args):
    from . import config
    from .cases import require_case
    from .index_db import index_case
    conn = _open_db(args)
    case = require_case(conn, args.case)
    index_conn = _open_index(args)
    written = index_case(
        index_conn, conn,
        source_db=os.path.abspath(args.db or config.DB_PATH),
        case_id=args.case, case_title=case["title"],
    )
    return {"case_id": args.case, "signals_indexed": written}


def cmd_index_crosslinks(args):
    from .index_db import get_index_conn, operator_cross_links
    return {"cross_links": operator_cross_links(get_index_conn(_index_path(args)))}


def cmd_index_lookup(args):
    from .index_db import lookup
    hits = lookup(_open_index(args), args.value, signal_type=args.type)
    return {"value": args.value, "type": args.type, "hits": len(hits), "rows": hits}


def cmd_index_recurring(args):
    from .index_db import recurring_signals
    rows = recurring_signals(_open_index(args), min_cases=args.min_cases)
    return {"min_cases": args.min_cases, "count": len(rows), "signals": rows}


# ---------------------------------------------------------------------------
# evidence / export
# ---------------------------------------------------------------------------

BROWSE_MARKER = ".kwara-evidence-browse"


def cli_module_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def cmd_evidence_browse(args):
    """Build a browsable evidence area keyed by domain, without moving anything.

    The store is laid out for write safety — one directory per scan_run, one
    subdirectory per capture, nothing ever overwritten. That is the right shape
    for chain of custody and the wrong shape for a person: 6.6 GB of integer
    folders you cannot walk. This projects a second view over the same bytes,
    named the way an analyst thinks:

        <out>/visitorlanding.example/20260505T081730_playwright -> the real capture dir

    Symlinks, so the evidence is never copied and never diverges. Regenerate
    whenever; the tree is disposable and the store is the truth.

    Refuses to write into a directory it did not create — this walks a user
    -supplied path and clearing the wrong one would destroy work.
    """
    conn = _open_db(args)
    out_dir = os.path.realpath(os.path.expanduser(args.out))
    store = os.path.realpath(
        os.path.join(os.path.dirname(os.path.abspath(cli_module_dir())),
                     "kwara", "data", "snapshots"))
    if out_dir == store or out_dir.startswith(store + os.sep):
        raise SystemExit(
            "evidence browse: --out must not be inside the capture store "
            f"({store}) — that mixes generated links into the evidence and "
            "creates symlink cycles for anything walking it.")
    marker = os.path.join(out_dir, BROWSE_MARKER)
    if os.path.exists(out_dir):
        # lstat, not isfile: isfile() follows a symlink, so a marker planted as
        # a link to page.html would be accepted here and then TRUNCATED by the
        # open() below. The guard that exists to protect evidence would be the
        # thing that destroyed it.
        marker_ok = False
        try:
            marker_ok = stat.S_ISREG(os.lstat(marker).st_mode)
        except OSError:
            marker_ok = False
        if os.path.islink(out_dir) or not os.path.isdir(out_dir) or not marker_ok:
            raise SystemExit(
                f"evidence browse: {out_dir} exists and was not created by "
                f"this command — refusing to touch it. Pass a fresh path.")
        for name in os.listdir(out_dir):
            if name == BROWSE_MARKER:
                continue
            target = os.path.join(out_dir, name)
            if os.path.islink(target):
                os.unlink(target)
            elif os.path.isdir(target):
                for link in os.listdir(target):
                    lp = os.path.join(target, link)
                    if os.path.islink(lp):
                        os.unlink(lp)
                if not os.listdir(target):
                    os.rmdir(target)
    else:
        os.makedirs(out_dir)
    # O_NOFOLLOW so a marker swapped for a symlink between the check above and
    # this write cannot redirect the truncation onto an artifact.
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("Generated by `kwara evidence browse`. Symlinks into the "
                 "capture store; safe to delete and regenerate.\n")

    where, params = [], []
    if args.case:
        where.append("ua.case_id = ?")
        params.append(args.case)
    if args.domain:
        where.append("LOWER(COALESCE(s.final_domain, sr.final_url)) LIKE ?")
        params.append(f"%{args.domain.strip().lower()}%")
    rows = conn.execute(
        f"""SELECT s.final_domain, s.captured_at, s.capture_method,
                   s.screenshot_path, s.html_path, s.har_path
              FROM snapshots s
              JOIN scan_runs sr ON sr.id = s.scan_run_id
              JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
             {'WHERE ' + ' AND '.join(where) if where else ''}
             ORDER BY s.final_domain, s.captured_at""",
        params,
    ).fetchall()

    linked, skipped, domains = 0, 0, set()
    for r in rows:
        capture_dir = next((os.path.dirname(r[c]) for c in
                            ("screenshot_path", "html_path", "har_path")
                            if r[c]), None)
        if not capture_dir or not os.path.isdir(capture_dir):
            skipped += 1
            continue
        domain = (r["final_domain"] or "unknown").strip() or "unknown"
        # A domain is used as a path segment here; keep it to a safe leaf.
        domain = domain.replace("/", "_").replace("..", "_").lstrip(".")
        ddir = os.path.join(out_dir, domain)
        os.makedirs(ddir, exist_ok=True)
        stamp = (r["captured_at"] or "").replace(":", "").replace(" ", "T")[:15]
        name = f"{stamp}_{r['capture_method'] or 'unknown'}"
        link = os.path.join(ddir, name)
        n = 2
        while os.path.lexists(link):
            link = os.path.join(ddir, f"{name}_{n}")
            n += 1
        os.symlink(capture_dir, link)
        linked += 1
        domains.add(domain)
    return {"out": out_dir, "domains": len(domains), "captures_linked": linked,
            "skipped_missing_on_disk": skipped}


def cmd_evidence_describe(args):
    """Backfill the capture.json sidecar for directories written before it existed.

    703 capture directories predate the sidecar. Without it the store is 6.6 GB
    of integer-named folders whose meaning lives only in the DB beside them —
    the opposite of evidence a third party can read without trusting us.
    """
    from .snapshots import CAPTURE_MANIFEST, _write_capture_manifest
    conn = _open_db(args)
    where, params = [], []
    if args.case:
        where.append("ua.case_id = ?")
        params.append(args.case)
    rows = conn.execute(
        f"""SELECT s.scan_run_id, ua.case_id, s.final_url, s.final_domain,
                   s.capture_method, s.captured_at,
                   s.screenshot_path, s.html_path, s.har_path
              FROM snapshots s
              JOIN scan_runs sr ON sr.id = s.scan_run_id
              JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
             {'WHERE ' + ' AND '.join(where) if where else ''}""",
        params,
    ).fetchall()

    seen, written, already, orphaned = set(), 0, 0, 0
    for r in rows:
        for col in ("screenshot_path", "html_path", "har_path"):
            path = r[col]
            if not path:
                continue
            d = os.path.dirname(path)
            if d in seen:
                continue
            seen.add(d)
            if not os.path.isdir(d):
                orphaned += 1          # DB references a directory disk lacks
                continue
            if os.path.isfile(os.path.join(d, CAPTURE_MANIFEST)):
                already += 1
                continue
            if not args.dry_run:
                _write_capture_manifest(
                    d, scan_run_id=r["scan_run_id"], case_id=r["case_id"],
                    final_url=r["final_url"], final_domain=r["final_domain"],
                    capture_method=r["capture_method"],
                    captured_at=r["captured_at"], backfilled_from_db=True)
            written += 1
    return {"case_id": args.case, "dry_run": bool(args.dry_run),
            "directories": len(seen), "described": written,
            "already_described": already, "missing_on_disk": orphaned}


def cmd_evidence_list(args):
    """Where the evidence for a domain actually sits on disk.

    The capture store is keyed by scan_run_id — `data/snapshots/7/2026…_9fd1/`
    — so the filesystem alone cannot say which domain a 6.6 GB tree belongs to.
    Translating that back is what the Streamlit UI was uniquely doing, and it
    is why removing the UI without this leaves an analyst unable to find a
    screenshot they know exists.

    Either `--case` or `--domain` is required; without one the answer is the
    whole store, which is not an answer.
    """
    from .cases import require_case
    conn = _open_db(args)
    where, params = [], []
    if args.case:
        require_case(conn, args.case)
        where.append("ua.case_id = ?")
        params.append(args.case)
    if args.domain:
        # Substring so a bare apex finds its subdomains and www. variants.
        where.append("LOWER(COALESCE(s.final_domain, sr.final_url)) LIKE ?")
        params.append(f"%{args.domain.strip().lower()}%")
    if not where:
        raise SystemExit("evidence list: pass --case and/or --domain")

    rows = conn.execute(
        f"""SELECT s.id AS snapshot_id, s.scan_run_id, ua.case_id,
                   COALESCE(s.final_domain, '') AS final_domain,
                   sr.final_url, s.captured_at, s.capture_method,
                   s.capture_status, s.screenshot_path, s.html_path, s.har_path
              FROM snapshots s
              JOIN scan_runs sr ON sr.id = s.scan_run_id
              JOIN url_artifacts ua ON ua.id = sr.url_artifact_id
             WHERE {' AND '.join(where)}
             ORDER BY final_domain, s.captured_at, s.id""",
        params,
    ).fetchall()

    out, by_domain = [], {}
    for r in rows:
        item = dict(r)
        # On-disk truth, not what the DB claims. A row pointing at a deleted
        # file is exactly the chain-of-custody gap worth surfacing.
        for col in ("screenshot_path", "html_path", "har_path"):
            item[col.replace("_path", "_exists")] = bool(
                item[col] and os.path.isfile(item[col]))
        domain = item["final_domain"] or "(unknown)"
        d = by_domain.setdefault(domain, {
            "domain": domain, "captures": 0, "screenshots": 0,
            "missing_files": 0, "methods": set(), "capture_dirs": set()})
        d["captures"] += 1
        d["screenshots"] += int(item["screenshot_exists"])
        d["missing_files"] += sum(
            1 for c in ("screenshot_path", "html_path", "har_path")
            if item[c] and not item[c.replace("_path", "_exists")])
        if item["capture_method"]:
            d["methods"].add(item["capture_method"])
        for c in ("screenshot_path", "html_path", "har_path"):
            if item[c]:
                d["capture_dirs"].add(os.path.dirname(item[c]))
        out.append(item)

    # The summary answers "where do I look", so it carries a few example
    # paths and a count — not 276 directories, which is the store again.
    summary = sorted(
        ({k: v for k, v in d.items() if k != "capture_dirs"}
         | {"methods": sorted(d["methods"]),
            "capture_dir_count": len(d["capture_dirs"]),
            "capture_dirs_sample": sorted(d["capture_dirs"])[:3]}
         for d in by_domain.values()),
        key=lambda x: x["domain"])
    return {
        "case_id": args.case,
        "domain_filter": args.domain,
        "snapshots": len(out),
        "missing_screenshot_files": sum(
            1 for i in out if i["screenshot_path"] and not i["screenshot_exists"]),
        "by_domain": summary,
        "items": out,
    }


def cmd_export_case(args):
    from .cases import require_case
    from .exporter import export_case
    conn = _open_db(args)
    require_case(conn, args.case)
    path = export_case(conn, args.case)
    return {"case_id": args.case, "export_path": path,
            "size_bytes": os.path.getsize(path) if os.path.exists(path) else None}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _add_locale_flags(p):
    p.add_argument("--locale-preset", choices=["tw", "us", "uk", "jp", "kr", "de"],
                   help="victim region preset (sets browser locale + timezone)")
    p.add_argument("--locale", help="explicit browser locale, e.g. en-GB")
    p.add_argument("--timezone", help="explicit browser timezone, e.g. Europe/London")


# Global flags are attached to every leaf subparser as well as the root, so
# `kwara case list --compact` works as naturally as `kwara --compact case list`.
# Defaults are SUPPRESS so a flag given at the root isn't clobbered by the
# subparser re-parsing into the same namespace; main() fills the gaps.
_GLOBAL_DEFAULTS = {"db": None, "index_db": None, "lang": None,
                    "text": False, "compact": False, "quiet": False}


def _global_parser() -> argparse.ArgumentParser:
    g = argparse.ArgumentParser(add_help=False)
    g.add_argument("--db", default=argparse.SUPPRESS,
                   help="case DB path (default: $KWARA_DB_PATH)")
    g.add_argument("--lang", choices=["en", "zh-TW"], default=argparse.SUPPRESS,
                   help="language for insights/narrative text (default: $KWARA_LANG)")
    g.add_argument("--index-db", default=argparse.SUPPRESS,
                   help="cross-case index DB path (default: $KWARA_INDEX_DB_PATH)")
    g.add_argument("--text", action="store_true", default=argparse.SUPPRESS,
                   help="human-readable output instead of JSON")
    g.add_argument("--compact", action="store_true", default=argparse.SUPPRESS,
                   help="single-line JSON")
    g.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS,
                   help="suppress progress on stderr")
    return g


_G = _global_parser()



# ── discover ───────────────────────────────────────────────────────────────
# The screening funnel. Outbound work here contacts candidate sites directly,
# so every command that does says so on stderr before it starts.

def cmd_discover_candidates(args):
    from . import discovery
    doms = discovery.candidates_from_sellers_json(args.sellers_json)
    if args.exclude_scanned:
        from urllib.parse import urlparse
        from .utils.domain import extract_domain_from_url
        conn = _open_db(args)
        seen = {extract_domain_from_url(r[0] or "") for r in conn.execute(
            "SELECT final_url FROM scan_runs WHERE final_url IS NOT NULL")}
        doms = [d for d in doms if d not in seen]
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(doms) + "\n")
    return {"candidates": len(doms), "out": args.out,
            "domains": None if args.out else doms}


def cmd_discover_screen(args):
    from . import discovery
    from .index_db import get_index_conn
    known = discovery.known_templates(get_index_conn(_index_path(args)))
    with open(args.domains, encoding="utf-8") as fh:
        doms = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if args.limit:
        doms = doms[:args.limit]
    if not args.quiet:
        _err(f"screening {len(doms)} candidates against {len(known)} known "
             f"templates — this contacts each one directly")
    done = [0]

    def progress(_r):
        done[0] += 1
        if not args.quiet and done[0] % 250 == 0:
            _err(f"  {done[0]}/{len(doms)}")

    from .config import DISCOVERY_WORKERS
    obs = discovery.screen_domains(doms, known,
                                   workers=args.workers or DISCOVERY_WORKERS,
                                   on_result=progress)
    # Banking is the default, not a flag to remember: the sweep pays for this
    # data anyway and it is the reference population plus the clustering input.
    if args.bank:
        with open(args.bank, "w", encoding="utf-8") as fh:
            for o in obs:
                fh.write(json.dumps(o, ensure_ascii=False) + "\n")
    from collections import Counter
    hits = [o for o in obs if o["verdict"] == discovery.VERDICT_TEMPLATE_MATCH]
    return {"screened": len(obs), "banked_to": args.bank,
            "verdicts": dict(Counter(o["verdict"] for o in obs)),
            "hits": [{"domain": h["domain"], "matched": h["matched_domains"]}
                     for h in hits]}


def cmd_discover_cluster(args):
    from . import discovery
    obs = _read_observations(args.observations)
    clusters = discovery.cluster_by_template(obs)
    if args.portfolio_only:
        clusters = [c for c in clusters if c["kind"] == "portfolio"]
    return {"observations": len(obs), "clusters": len(clusters),
            "domains_clustered": sum(c["domain_count"] for c in clusters),
            "results": clusters}


def cmd_discover_prevalence(args):
    from . import discovery
    obs = _read_observations(args.observations)
    table = discovery.build_prevalence(obs)
    table["source"] = args.source or f"built from {args.observations}"
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(table, fh, ensure_ascii=False)
    return {"out": args.out, "site_count": table["site_count"],
            "accounts": len(table["accounts"])}


def _read_observations(path: str) -> list:
    """Accept either the JSONL a sweep banks or a JSON array."""
    with open(path, encoding="utf-8") as fh:
        head = fh.read(1)
        fh.seek(0)
        if head == "[":
            return json.load(fh)
        return [json.loads(l) for l in fh if l.strip()]


def _index_path(args) -> str:
    from .config import INDEX_DB_PATH
    return getattr(args, "index_db", None) or INDEX_DB_PATH


def _leaf(group, name: str, **kw) -> argparse.ArgumentParser:
    """A leaf subcommand that also accepts the global flags."""
    return group.add_parser(name, parents=[_G], **kw)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kwara",
        parents=[_G],
        description="kwara — operator attribution and digital evidence, headless.",
    )
    sub = p.add_subparsers(dest="group", required=True)

    # ── case ──────────────────────────────────────────────────────────────
    case = sub.add_parser("case", help="case lifecycle").add_subparsers(
        dest="cmd", required=True)

    _leaf(case, "list", help="list all cases").set_defaults(fn=cmd_case_list)

    c_new = _leaf(case, "new", help="open a new case")
    c_new.add_argument("--title", required=True)
    c_new.add_argument("--description", default="")
    _add_locale_flags(c_new)
    c_new.set_defaults(fn=cmd_case_new)

    c_show = _leaf(case, "show", help="case detail + progress counts")
    c_show.add_argument("--case", type=int, required=True)
    c_show.set_defaults(fn=cmd_case_show)

    c_loc = _leaf(case, "locale", help="set the victim locale used for screenshots")
    c_loc.add_argument("--case", type=int, required=True)
    _add_locale_flags(c_loc)
    c_loc.set_defaults(fn=cmd_case_locale)

    c_del = _leaf(case, "delete", help="IRREVERSIBLY delete a case and its files")
    c_del.add_argument("--case", type=int, required=True)
    c_del.add_argument("--confirm", default="",
                       help='must be the literal string DELETE')
    c_del.set_defaults(fn=cmd_case_delete)

    # ── ingest ────────────────────────────────────────────────────────────
    ing = sub.add_parser("ingest", help="add URLs to a case").add_subparsers(
        dest="cmd", required=True)

    i_url = _leaf(ing, "url", help="ingest one or more URLs")
    i_url.add_argument("urls", nargs="+")
    i_url.add_argument("--case", type=int, required=True)
    i_url.add_argument("--message", default=None,
                       help="full post text (URLs are extracted from it)")
    i_url.add_argument("--platform", default="")
    i_url.add_argument("--permalink", default="")
    i_url.add_argument("--actor", default="")
    i_url.add_argument("--posted-at", default="")
    i_url.set_defaults(fn=cmd_ingest_url)

    i_csv = _leaf(ing, "csv", help="ingest a CSV of posts")
    i_csv.add_argument("--case", type=int, required=True)
    i_csv.add_argument("--file", required=True,
                       help="columns: platform, permalink, actor_label, posted_at, message_text")
    i_csv.set_defaults(fn=cmd_ingest_csv)

    # ── run ───────────────────────────────────────────────────────────────
    run = sub.add_parser("run", help="collection steps").add_subparsers(
        dest="cmd", required=True)

    r_attr = _leaf(run, 
        "attribute",
        help="cheap attribution pass: scan + static HTML + ads.txt + WHOIS (no browser)")
    r_attr.add_argument("--case", type=int, required=True)
    r_attr.add_argument("--force", action="store_true")
    r_attr.set_defaults(fn=cmd_run_attribute)

    r_scan = _leaf(run, "scan", help="follow redirect chains (no third-party calls)")
    r_scan.add_argument("--case", type=int, required=True)
    r_scan.add_argument("--artifact", type=int, action="append",
                        help="specific url_artifact id (repeatable); default = all pending")
    r_scan.set_defaults(fn=cmd_run_scan)

    r_intel = _leaf(run, "intel", help="WHOIS / IP / ASN enrichment")
    r_intel.add_argument("--case", type=int, required=True)
    r_intel.add_argument("--scan-run", type=int, action="append")
    r_intel.add_argument("--force", action="store_true")
    r_intel.set_defaults(fn=cmd_run_intel)

    r_snap = _leaf(run, 
        "snapshot", help="Playwright capture: screenshot + HTML + HAR (slow)")
    r_snap.add_argument("--case", type=int, required=True)
    r_snap.add_argument("--scan-run", type=int, action="append")
    r_snap.add_argument("--limit", type=int, help="cap how many to capture this run")
    r_snap.set_defaults(fn=cmd_run_snapshot)

    r_corr = _leaf(run, "corroborate", help="Wayback + urlscan + RFC 3161 timestamp")
    r_corr.add_argument("--scan-run", type=int, action="append", required=True)
    r_corr.set_defaults(fn=cmd_run_corroborate)

    r_cloak = _leaf(run, "cloaking", help="re-run cloaking detection")
    r_cloak.add_argument("--scan-run", type=int, action="append", required=True)
    r_cloak.add_argument("--force", action="store_true")
    r_cloak.set_defaults(fn=cmd_run_cloaking)

    r_ads = _leaf(run, "adstxt", help="re-fetch ads.txt")
    r_ads.add_argument("--scan-run", type=int, action="append", required=True)
    r_ads.add_argument("--force", action="store_true")
    r_ads.set_defaults(fn=cmd_run_adstxt)

    # ── analyze ───────────────────────────────────────────────────────────
    ana = sub.add_parser("analyze", help="read-only analysis").add_subparsers(
        dest="cmd", required=True)

    for name, fn, helptext in (
        ("insights", cmd_analyze_insights, "rule-based case summary + risk flags"),
        ("clusters", cmd_analyze_clusters, "operator groups and the signals linking them"),
        ("narrative", cmd_analyze_narrative, "verdict + reasoning in prose form"),
    ):
        sp = _leaf(ana, name, help=helptext)
        sp.add_argument("--case", type=int, required=True)
        sp.set_defaults(fn=fn)

    a_graph = _leaf(ana, "graph", help="operator relationship graph")
    a_graph.add_argument("--case", type=int, required=True)
    a_graph.add_argument("--group", type=int, help="restrict to one group id")
    a_graph.add_argument("--out", help="write to this file (.dot/.svg/.png/.pdf)")
    a_graph.add_argument("--format", choices=["dot", "svg", "png", "pdf"],
                         help="override format inferred from --out extension")
    a_graph.add_argument("--include-dot", action="store_true",
                         help="include the DOT source in JSON output")
    a_graph.set_defaults(fn=cmd_analyze_graph)

    # ── discover ──────────────────────────────────────────────────────────
    dis = sub.add_parser(
        "discover",
        help="candidate screening funnel (OUTBOUND: contacts candidate sites)"
    ).add_subparsers(dest="cmd", required=True)

    d_cand = _leaf(dis, "candidates",
                   help="extract publisher domains from SSPs' sellers.json")
    d_cand.add_argument("sellers_json", nargs="+")
    d_cand.add_argument("--out", help="write one domain per line to this file")
    d_cand.add_argument("--exclude-scanned", action="store_true",
                        help="drop domains this case DB has already scanned")
    d_cand.set_defaults(fn=cmd_discover_candidates)

    d_scr = _leaf(dis, "screen",
                  help="fetch each candidate's /ads.txt and match known templates")
    d_scr.add_argument("--domains", required=True, help="one domain per line")
    d_scr.add_argument("--bank", help="write the observations here (JSONL) — "
                                      "the reference population and clustering input")
    d_scr.add_argument("--limit", type=int)
    d_scr.add_argument("--workers", type=int, default=None)
    d_scr.set_defaults(fn=cmd_discover_screen)

    d_clu = _leaf(dis, "cluster",
                  help="group banked observations sharing a byte-identical ads.txt")
    d_clu.add_argument("--observations", required=True)
    d_clu.add_argument("--portfolio-only", action="store_true",
                       help="drop platform-generated templates")
    d_clu.set_defaults(fn=cmd_discover_cluster)

    d_prev = _leaf(dis, "prevalence",
                   help="build the reference prevalence table from observations")
    d_prev.add_argument("--observations", required=True)
    d_prev.add_argument("--out", required=True)
    d_prev.add_argument("--source", help="note describing the population")
    d_prev.set_defaults(fn=cmd_discover_prevalence)

    # ── index ─────────────────────────────────────────────────────────────
    idx = sub.add_parser("index", help="cross-case signal index").add_subparsers(
        dest="cmd", required=True)

    x_build = _leaf(idx, "build", help="index one case into the central index")
    x_build.add_argument("--case", type=int, required=True)
    x_build.set_defaults(fn=cmd_index_build)

    x_look = _leaf(idx, "lookup", help="every case a signal value appears in")
    x_look.add_argument("value")
    from .index_db import ALL_SIGNAL_TYPES
    x_look.add_argument("--type", choices=sorted(ALL_SIGNAL_TYPES),
                        help="constrain to one signal type")
    x_look.set_defaults(fn=cmd_index_lookup)

    x_xl = _leaf(idx, "crosslinks",
                 help="endpoints that are themselves investigated landing domains")
    x_xl.set_defaults(fn=cmd_index_crosslinks)

    x_rec = _leaf(idx, "recurring", help="signals spanning multiple cases")
    x_rec.add_argument("--min-cases", type=int, default=2)
    x_rec.set_defaults(fn=cmd_index_recurring)

    # ── evidence / export ─────────────────────────────────────────────────
    ev = sub.add_parser("evidence", help="captured evidence files").add_subparsers(
        dest="cmd", required=True)
    e_list = _leaf(ev, "list", help="snapshot files on disk, with existence checks")
    e_br = _leaf(ev, "browse",
                 help="build a domain-keyed symlink tree over the capture store")
    e_br.add_argument("--out", required=True, help="directory to build (created)")
    e_br.add_argument("--case", type=int)
    e_br.add_argument("--domain")
    e_br.set_defaults(fn=cmd_evidence_browse)

    e_desc = _leaf(ev, "describe",
                   help="backfill capture.json into capture directories")
    e_desc.add_argument("--case", type=int, help="limit to one case")
    e_desc.add_argument("--dry-run", action="store_true")
    e_desc.set_defaults(fn=cmd_evidence_describe)

    e_list.add_argument("--case", type=int,
                        help="limit to one case (or use --domain)")
    e_list.add_argument("--domain",
                        help="find every capture for a domain, across cases")
    e_list.set_defaults(fn=cmd_evidence_list)

    exp = sub.add_parser("export", help="evidence pack").add_subparsers(
        dest="cmd", required=True)
    x_case = _leaf(exp, "case", help="ZIP with CSVs, files, manifest, README")
    x_case.add_argument("--case", type=int, required=True)
    x_case.set_defaults(fn=cmd_export_case)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Globals use SUPPRESS defaults so position doesn't matter; anything the
    # user never passed is simply absent and gets its default here.
    for key, default in _GLOBAL_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, default)
    if args.lang:
        from .i18n import set_lang
        set_lang(args.lang)
    try:
        _emit(args.fn(args), args)
    except (ValueError, RuntimeError, FileNotFoundError) as e:
        _err(f"error: {e}")
        return 1
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
