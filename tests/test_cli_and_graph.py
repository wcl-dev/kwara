"""The headless surface: cli.py, graph.py, and i18n outside Streamlit.

These pin the contracts the agent tooling depends on — stdout stays parseable
JSON, global flags work in any position, an empty graph is reported as a
finding rather than an error, and importing kwara headlessly does not require
Streamlit.
"""
import json
import os
import tempfile

import pytest

import cli
import graph


@pytest.fixture
def db_path():
    td = tempfile.mkdtemp()
    return os.path.join(td, "kwara.db")


def _run(capsys, *argv) -> tuple[int, str]:
    code = cli.main(list(argv))
    return code, capsys.readouterr().out


def _json(capsys, *argv):
    code, out = _run(capsys, *argv)
    assert code == 0, out
    return json.loads(out)


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def test_case_new_then_show(capsys, db_path):
    created = _json(capsys, "--db", db_path, "case", "new",
                    "--title", "Op Test", "--locale-preset", "tw")
    assert created["browser_locale"] == "zh-TW"

    shown = _json(capsys, "--db", db_path, "case", "show",
                  "--case", str(created["case_id"]))
    assert shown["title"] == "Op Test"
    assert shown["url_count"] == 0


def test_global_flags_accepted_after_subcommand(capsys, db_path):
    """Agents naturally put flags last; both positions must work."""
    _json(capsys, "--db", db_path, "case", "new", "--title", "x")
    trailing = _json(capsys, "case", "list", "--db", db_path)
    leading = _json(capsys, "--db", db_path, "case", "list")
    assert trailing == leading


def test_output_is_parseable_json_by_default(capsys, db_path):
    assert _json(capsys, "--db", db_path, "case", "list") == []


def test_text_mode_is_not_json(capsys, db_path):
    _json(capsys, "--db", db_path, "case", "new", "--title", "readable")
    code, out = _run(capsys, "--db", db_path, "case", "list", "--text")
    assert code == 0
    assert "readable" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_unknown_case_exits_nonzero_without_stdout(capsys, db_path):
    code, out = _run(capsys, "--db", db_path, "case", "show", "--case", "404")
    assert code == 1
    assert out.strip() == "", "errors must not pollute the JSON channel"


def test_ingest_extracts_urls_from_message(capsys, db_path):
    case_id = _json(capsys, "--db", db_path, "case", "new",
                    "--title", "ingest")["case_id"]
    result = _json(capsys, "--db", db_path, "ingest", "url",
                   "--case", str(case_id), "https://ignored.test/",
                   "--message", "look at https://a.test/1 and https://b.test/2")
    assert result["urls"] == ["https://a.test/1", "https://b.test/2"]


def test_ingest_bare_urls(capsys, db_path):
    case_id = _json(capsys, "--db", db_path, "case", "new",
                    "--title", "bare")["case_id"]
    result = _json(capsys, "--db", db_path, "ingest", "url",
                   "--case", str(case_id), "https://a.test/1", "https://b.test/2")
    assert result["url_count"] == 2


def test_delete_requires_confirm_string(capsys, db_path):
    case_id = _json(capsys, "--db", db_path, "case", "new",
                    "--title", "guarded")["case_id"]
    code, _ = _run(capsys, "--db", db_path, "case", "delete", "--case", str(case_id))
    assert code == 1
    assert _json(capsys, "--db", db_path, "case", "show",
                 "--case", str(case_id))["id"] == case_id


def test_evidence_list_on_empty_case(capsys, db_path):
    case_id = _json(capsys, "--db", db_path, "case", "new",
                    "--title", "empty")["case_id"]
    result = _json(capsys, "--db", db_path, "evidence", "list", "--case", str(case_id))
    assert result["snapshots"] == 0
    assert result["missing_screenshot_files"] == 0


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def test_empty_graph_is_a_finding_not_an_error(capsys, db_path):
    case_id = _json(capsys, "--db", db_path, "case", "new",
                    "--title", "no signals")["case_id"]
    result = _json(capsys, "--db", db_path, "analyze", "graph", "--case", str(case_id))
    assert result["group_count"] == 0
    assert "nothing scanned yet" in result["note"]


def test_build_dot_emits_valid_structure():
    groups = [{
        "gid": 1, "label": "Group 1",
        "domains": ["a.test", "b.test"],
        "domain_count": 2, "signal_count": 1,
        "signals": [{"type": "tracking", "label": "GA4",
                     "value": "G-XYZ", "domains": ["a.test", "b.test"]}],
    }]
    dot = graph.build_dot(groups)
    assert dot.startswith("digraph rel {")
    assert dot.rstrip().endswith("}")
    assert "subgraph cluster_1" in dot
    assert "a.test" in dot and "G-XYZ" in dot


def test_build_dot_escapes_quotes():
    """A domain or signal value carrying a quote must not break the DOT."""
    groups = [{
        "gid": 1, "label": "G",
        "domains": ['ev"il.test'], "domain_count": 1, "signal_count": 0,
        "signals": [],
    }]
    assert '\\"' in graph.build_dot(groups)


def test_render_dot_writes_source_without_graphviz(tmp_path):
    out = tmp_path / "nested" / "g.dot"
    path = graph.render_dot("digraph x { a -> b; }", str(out), "dot")
    assert os.path.isfile(path)
    assert "digraph x" in open(path, encoding="utf-8").read()


def test_render_dot_rejects_unknown_format(tmp_path):
    with pytest.raises(ValueError):
        graph.render_dot("digraph x {}", str(tmp_path / "g.xyz"), "xyz")


def test_render_dot_explains_missing_graphviz(tmp_path, monkeypatch):
    monkeypatch.setattr(graph, "graphviz_available", lambda: False)
    with pytest.raises(RuntimeError, match="graphviz"):
        graph.render_dot("digraph x {}", str(tmp_path / "g.svg"), "svg")


def test_ui_page_reuses_core_build_dot():
    """views/page_graph.py must not carry its own copy of the DOT builder."""
    src = open(os.path.join(os.path.dirname(graph.__file__),
                            "views", "page_graph.py"), encoding="utf-8").read()
    assert "def build_dot" not in src
    assert "from graph import build_dot" in src


# ---------------------------------------------------------------------------
# Headless i18n
# ---------------------------------------------------------------------------

def test_i18n_works_without_streamlit_session():
    import i18n
    original = i18n.get_lang()
    try:
        i18n.set_lang("zh-TW")
        assert i18n.get_lang() == "zh-TW"
        assert i18n.t("sidebar.title")  # must not raise or warn
        i18n.set_lang("en")
        assert i18n.get_lang() == "en"
    finally:
        i18n.set_lang(original)


def test_core_modules_import_without_streamlit():
    """Importing the analysis core must not require the UI framework.

    Checked by module graph rather than by unloading streamlit, which pytest
    may already have imported via another test.
    """
    import importlib
    for name in ("cases", "graph", "cli", "insights", "clusters", "narrative"):
        mod = importlib.import_module(name)
        src = open(mod.__file__, encoding="utf-8").read()
        assert "import streamlit" not in src, f"{name} imports streamlit"


def _tmp_db_with_snapshot(rows):
    """rows: [(scan_run_id_seed, final_domain, screenshot_path), ...]"""
    import tempfile, os as _os
    from datetime import datetime, timezone
    from db import get_conn, init_db, migrate_db
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    path = _os.path.join(tempfile.mkdtemp(), "case.db")
    conn = get_conn(path); init_db(conn); migrate_db(conn)
    cid = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) "
        "VALUES ('t','',?,?)", (now, now)).lastrowid
    for _seed, domain, shot in rows:
        pid = conn.execute(
            """INSERT INTO message_evidence (case_id, platform, permalink,
               actor_label, posted_at, message_text, screenshot_path, ingested_at)
               VALUES (?,'','','','','','',?)""", (cid, now)).lastrowid
        ua = conn.execute(
            "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
            "url_order, created_at) VALUES (?,?,?,'',0,?)",
            (pid, cid, f"https://{domain}/", now)).lastrowid
        sr = conn.execute(
            "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
            "status) VALUES (?,?,?,0,'done')",
            (ua, now, f"https://{domain}/")).lastrowid
        conn.execute(
            """INSERT INTO snapshots (scan_run_id, final_url, final_domain,
               captured_at, capture_method, capture_status, screenshot_path)
               VALUES (?,?,?,?,'playwright','ok',?)""",
            (sr, f"https://{domain}/", domain, now, shot))
    conn.commit()
    return conn, path


# ── evidence lookup: translating scan_run_id back to a domain ──────────────

def test_evidence_list_finds_captures_by_domain_across_cases():
    """The capture store is keyed by scan_run_id, so the filesystem cannot say
    which domain `data/snapshots/7/2026…_9fd1/` belongs to. Translating that
    back is what the Streamlit UI was uniquely doing; an analyst who cannot do
    it cannot find a screenshot they know exists."""
    from cli import build_parser
    conn, path = _tmp_db_with_snapshot(
        [(1, "farm.com", "/nonexistent/a.png"),
         (2, "farm.com", "/nonexistent/b.png"),
         (3, "other.com", "/nonexistent/c.png")])
    args = build_parser().parse_args(
        ["evidence", "list", "--domain", "farm.com", "--db", path])
    out = args.fn(args)
    assert out["snapshots"] == 2
    assert [d["domain"] for d in out["by_domain"]] == ["farm.com"]
    assert out["by_domain"][0]["captures"] == 2


def test_evidence_list_requires_a_filter():
    """Without one the answer is the whole store, which is not an answer."""
    from cli import build_parser
    conn, path = _tmp_db_with_snapshot([(1, "farm.com", "/nonexistent/a.png")])
    args = build_parser().parse_args(["evidence", "list", "--db", path])
    with pytest.raises(SystemExit):
        args.fn(args)


def test_evidence_list_reports_files_the_db_claims_but_disk_lacks():
    from cli import build_parser
    conn, path = _tmp_db_with_snapshot([(1, "farm.com", "/nonexistent/gone.png")])
    args = build_parser().parse_args(
        ["evidence", "list", "--domain", "farm.com", "--db", path])
    out = args.fn(args)
    assert out["missing_screenshot_files"] == 1
    assert out["items"][0]["screenshot_exists"] is False
