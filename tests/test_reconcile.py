"""Disk → database reconciliation, and the four things that make it safe.

This module walks an evidence store and decides which directories no database
claims. Every one of its safety properties was learned from the live store on
2026-08-11, and each is here because getting it wrong destroys or fabricates
evidence rather than merely reporting a wrong number:

  1. It never deletes. Asserted by reading the source, not by trusting review.
  2. "Orphan" is relative to a SET of databases. The live store holds 34
     directories owned by a second investigation whose database lives
     elsewhere; judged against the primary alone they read as debris.
  3. A capture is attached only if it corroborates the scan_run whose bucket
     it sits in — the test suite deposited fabricated captures of target.com
     into real scan_run buckets, and a dry run would have attached 1,702 rows
     with those among them.
  4. A capture cannot predate its scan. scan_run ids are not stable across
     databases: the one holding April's rows was replaced in May, so bucket
     `1` on disk was written by a scan_run 1 that no longer exists.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

import pytest

from kwara import reconcile
from kwara.db import get_conn, init_db, migrate_db

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 2048


def _har(*urls) -> str:
    return json.dumps({"log": {"entries": [
        {"request": {"url": u}} for u in urls]}})


@pytest.fixture
def store(tmp_path):
    root = tmp_path / "snapshots"
    root.mkdir()
    return str(root)


def _capture(store, scan_run_id, when="20260601T120000000000_ab12", *,
             png=None, html=None, har=None, manifest=None):
    d = os.path.join(store, str(scan_run_id), when)
    os.makedirs(d, exist_ok=True)
    if png is not None:
        with open(os.path.join(d, "screenshot.png"), "wb") as fh:
            fh.write(png)
    if html is not None:
        name, body = html
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write(body)
    if har is not None:
        with open(os.path.join(d, "traffic.har"), "w", encoding="utf-8") as fh:
            fh.write(har)
    if manifest is not None:
        with open(os.path.join(d, "capture.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)
    return d


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "primary.db")


@pytest.fixture
def db(db_path):
    path = db_path
    conn = get_conn(path)
    init_db(conn)
    migrate_db(conn)
    conn.execute("INSERT INTO cases (title, description, created_at, updated_at) "
                 "VALUES ('t', '', '', '')")
    conn.commit()
    return conn


def _scan_run(conn, url, run_at="2026-05-01 00:00:00 UTC"):
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink,
           actor_label, posted_at, message_text, screenshot_path, ingested_at)
           VALUES (1, '', '', '', '', '', '', '')""")
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, 1, ?, '', 0, '')",
        (cur.lastrowid, url))
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status) VALUES (?, ?, ?, 0, 'done')", (cur.lastrowid, run_at, url))
    conn.commit()
    return cur.lastrowid


# ── 1. it never deletes ───────────────────────────────────────────────────

def _code_only(module) -> str:
    """Module source with comments and docstrings removed.

    Needed because the prose in this module NAMES the primitives it promises
    not to call — a naive substring scan would fail on its own safety notice.
    """
    import ast
    import inspect
    import io
    import tokenize

    src = inspect.getsource(module)
    tree = ast.parse(src)
    doc_lines = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef,
                                 ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        body = getattr(node, "body", None)
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            doc_lines.update(range(body[0].lineno, body[0].end_lineno + 1))

    lines = src.splitlines()
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            row, col = tok.start
            lines[row - 1] = lines[row - 1][:col]
    for n in doc_lines:
        lines[n - 1] = ""
    return "\n".join(lines)


# Anything that can remove or overwrite bytes, by the name it is CALLED by.
# Checked on the call node rather than as text, because the substring version
# of this test was defeated by `from os import remove`, `pathlib.Path.unlink`,
# and `open(p, "w")` — none of which contain the strings it looked for.
# Unambiguous: no harmless builtin or stdlib type has a method by these names.
_DESTRUCTIVE_CALLS = {
    "unlink", "rmdir", "removedirs", "rmtree", "ftruncate", "copyfile",
    "write_text", "write_bytes", "symlink_to", "mkdir", "makedirs", "touch",
}
# Shared with harmless methods — `dt.replace(tzinfo=...)`, `str.replace`,
# `list.remove`, `dict.copy` — so these count only when called on a module
# that can actually touch the filesystem.
_AMBIGUOUS_CALLS = {"remove", "replace", "rename", "renames", "move", "copy",
                    "truncate", "chmod"}
_FS_MODULES = {"os", "shutil", "pathlib", "Path"}
_WRITE_MODES = set("wax+")


def _destructive_calls(module) -> list:
    """Every call in the module that could remove or overwrite bytes."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(module))

    # `from os import remove` strips the prefix the module check relies on, so
    # track what was imported from a filesystem module and treat a bare call
    # to those names as the qualified call it is.
    unqualified = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in _FS_MODULES:
            for alias in node.names:
                unqualified.add(alias.asname or alias.name)

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (func.attr if isinstance(func, ast.Attribute)
                else func.id if isinstance(func, ast.Name) else "")
        prefix = ""
        if isinstance(func, ast.Attribute):
            base = func.value
            prefix = (base.id if isinstance(base, ast.Name)
                      else base.attr if isinstance(base, ast.Attribute) else "")
        if name in _DESTRUCTIVE_CALLS:
            found.append(f"{name}() at line {node.lineno}")
        elif name in _AMBIGUOUS_CALLS and (prefix in _FS_MODULES
                                           or (not prefix and name in unqualified)):
            found.append(f"{prefix or 'imported'}.{name}() at line {node.lineno}")
        if name == "open":
            mode = ""
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if set(mode) & _WRITE_MODES:
                found.append(f"open(mode={mode!r}) at line {node.lineno}")
    return found


def test_the_module_contains_no_destructive_call():
    """The load-bearing safety property, asserted against the parsed source
    rather than trusted. Deciding what to remove from an evidence store is the
    analyst's call; this module exists to inform it, not to make it."""
    assert _destructive_calls(reconcile) == []


def test_the_module_issues_no_destructive_sql():
    """attach() inserts. It must never update or delete: a recovered capture
    is a new observation, never an edit to an existing row."""
    code = _code_only(reconcile)
    for stmt in ("DELETE FROM", "DROP TABLE", "UPDATE ", "REPLACE INTO"):
        assert stmt not in code.upper(), f"reconcile.py must not issue {stmt}"


def test_the_destructive_call_scan_actually_catches_things():
    """A guard that cannot fail is not a guard. Prove the scan fires on each
    evasion that defeated its substring predecessor."""
    import ast
    import types

    def _probe(src):
        mod = types.SimpleNamespace()
        import inspect
        orig = inspect.getsource
        try:
            inspect.getsource = lambda m: src
            return _destructive_calls(mod)
        finally:
            inspect.getsource = orig

    assert _probe("import os\nos.remove(p)\n")
    assert _probe("from os import remove\nremove(p)\n")          # no 'os.remove'
    assert _probe("import pathlib\npathlib.Path(p).unlink()\n")  # no 'os.' at all
    assert _probe("open(p, 'w')\n")                              # truncates
    assert _probe("open(p, mode='a')\n")
    assert _probe("import shutil\nshutil.move(a, b)\n")
    assert _probe("import os\nos.replace(a, b)\n")
    assert _probe("open(p)\n") == []                             # reading is fine
    assert _probe("import os\nos.listdir(p)\n") == []
    # ...and does not fire on same-named methods that touch nothing
    assert _probe("dt.replace(tzinfo=utc)\n") == []
    assert _probe("s.replace('a', 'b')\n") == []
    assert _probe("seen.remove(x)\n") == []


def test_reporting_does_not_touch_the_store(store, db, db_path, tmp_path):
    d = _capture(store, 1, png=PNG)
    before = {p: os.path.getmtime(os.path.join(d, p)) for p in os.listdir(d)}
    reconcile.report(store, db_path)
    assert {p: os.path.getmtime(os.path.join(d, p))
            for p in os.listdir(d)} == before


# ── 2. orphan is relative to every database ───────────────────────────────

def test_a_second_databases_capture_is_not_an_orphan(store, db, db_path, tmp_path):
    """The highest-severity finding on the live store: 34 directories belonged
    to another investigation. A sweep driven by the primary database alone
    would have destroyed another case's evidence."""
    other_path = str(tmp_path / "other.db")
    other = get_conn(other_path)
    init_db(other)
    migrate_db(other)

    other.execute("INSERT INTO cases (title, description, created_at, "
                  "updated_at) VALUES ('other', '', '', '')")
    other_sr = _scan_run(other, "https://other-case.test/")
    d = _capture(store, 7, png=PNG)
    other.execute("INSERT INTO snapshots (scan_run_id, capture_method, "
                  "capture_status, screenshot_path) VALUES (?, 'playwright', "
                  "'ok', ?)", (other_sr, os.path.join(d, "screenshot.png")))
    other.commit()
    other.close()

    alone = reconcile.report(store, db_path)
    assert alone["orphans"] == 1, "sanity: unknown to the primary database"

    together = reconcile.report(store, db_path, extra_dbs=(other_path,))
    assert together["orphans"] == 0
    assert together["referenced"] == 1


def test_the_cross_case_index_supplies_the_database_registry(store, db, db_path, tmp_path):
    """How the second database was found at all — nothing else records which
    databases have seen this store."""
    idx = str(tmp_path / "index.db")
    conn = sqlite3.connect(idx)
    conn.execute("CREATE TABLE signals (source_db TEXT NOT NULL)")
    conn.execute("INSERT INTO signals (source_db) VALUES (?)",
                 (str(tmp_path / "elsewhere.db"),))
    conn.commit()
    conn.close()

    dbs = reconcile.known_databases(db_path, index_db=idx)
    assert any(d["source"] == "cross-case index" for d in dbs)


def test_an_unreadable_registered_database_makes_the_answer_provisional(
        store, db, db_path, tmp_path):
    """If a database that owns captures here cannot be read, every 'orphan'
    might be its. That is unsafe, not merely incomplete."""
    missing = str(tmp_path / "moved-away.db")
    rep = reconcile.report(store, db_path, extra_dbs=(missing,))
    assert rep["safe"] is False
    assert missing in rep["unreadable_databases"]

    out = reconcile.attach(db, rep, dry_run=True)
    assert out["refused"] is True
    assert out["attached"] == 0


def test_force_overrides_the_refusal_and_says_so(store, db, db_path, tmp_path):
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://a.test/"))
    rep = reconcile.report(store, db_path,
                           extra_dbs=(str(tmp_path / "gone.db"),))
    out = reconcile.attach(db, rep, dry_run=True, force=True)
    assert out["refused"] is False


# ── the layout as it really is ────────────────────────────────────────────

def test_legacy_files_written_straight_into_a_bucket_are_reported(store, db, db_path):
    """13 such files exist on the live store, from before per-capture
    directories. Any depth-2 sweep is blind to them, so a cleanup written
    against the current layout would miss them — or, if written by path
    prefix, take them silently."""
    os.makedirs(os.path.join(store, "3"))
    with open(os.path.join(store, "3", "page.html"), "w") as fh:
        fh.write("<html>legacy</html>")

    rep = reconcile.report(store, db_path)
    assert len(rep["loose_legacy_files"]) == 1
    assert rep["loose_legacy_files"][0]["scan_run_id"] == 3


def test_classification_is_structural(store, db, db_path):
    _capture(store, 1, "20260601T120000000000_0001")                    # empty
    _capture(store, 1, "20260601T120000000000_0002",
             manifest={"scan_run_id": 1})                               # sidecar
    _capture(store, 1, "20260601T120000000000_0003",
             png=b"PLAYWRIGHT_PNG")                                     # not a PNG
    _capture(store, 1, "20260601T120000000000_0004", png=PNG,
             har=_har("https://real.test/"))                            # capture

    kinds = {k: v["directories"] for k, v in
             reconcile.report(store, db_path)["by_kind"].items()}
    assert kinds == {"empty": 1, "manifest_only": 1, "partial": 1, "capture": 1}


def test_a_file_of_one_repeated_byte_is_flagged(store, db, db_path):
    """5,242,880 bytes of the letter 'x' — an HTML-truncation fixture that
    accounts for 490 MB in the live store. Detected by shape, never by
    searching content for marker strings: that approach misfiled 27 genuine
    captures, because a real stylesheet contained a run of sixteen 9s."""
    d = _capture(store, 1, html=("page.html", "x" * 200_000))
    desc = reconcile.describe_directory(d)
    assert desc["single_byte_fill"] == ["page.html"]

    real = _capture(store, 2, html=("page.html", "<html>" + "a b " * 50_000))
    assert reconcile.describe_directory(real)["single_byte_fill"] == []


# ── 3. attaching requires corroboration ───────────────────────────────────

def test_a_capture_of_the_wrong_site_is_not_attached(store, db, db_path):
    """The test suite wrote fabricated captures of target.com into real
    scan_run buckets on the live store. Nothing but this check stands between
    them and the evidence database."""
    sr = _scan_run(db, "https://real-case.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://target.com/"))

    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0
    assert out["skipped_reasons"].get("does not corroborate") == 1


def test_a_persona_the_scan_already_saw_does_corroborate(store, db, db_path):
    """Cloaking makes personas land on DIFFERENT domains — on the live store,
    252 scan_runs send a browser to one domain and a crawler to another. The
    crawler-facing capture must still attach, so corroboration checks every
    domain the scan has been observed reaching, not just its final_url."""
    sr = _scan_run(db, "https://visitor.test/")
    db.execute("INSERT INTO snapshots (scan_run_id, capture_method, "
               "capture_status, final_domain) VALUES (?, 'cloaking_alt', 'ok', "
               "'crawler.test')", (sr,))
    db.commit()

    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://crawler.test/x"))
    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 1
    assert out["details"][0]["final_domain"] == "crawler.test"


def test_a_bucket_this_database_never_had_is_skipped(store, db, db_path):
    _capture(store, 999, png=PNG, har=_har("https://x.test/"))
    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0
    assert out["skipped_reasons"].get("not this database's scan_run") == 1


# ── 4. a capture cannot predate its scan ──────────────────────────────────

def test_a_capture_older_than_the_scan_run_is_refused(store, db, db_path):
    """scan_run ids are not stable across databases. The database holding
    April's rows was replaced in May, so bucket 1 on disk was written by a
    scan_run 1 that no longer exists and today's scan_run 1 merely inherited
    the number. On the live store this check refused 43 of 44 candidates that
    had already passed the domain test — attaching them would have bound
    April's evidence to a May scan."""
    sr = _scan_run(db, "https://a.test/", run_at="2026-05-01 00:00:00 UTC")
    _capture(store, sr, "20260428T040649610269_f217", png=PNG,
             har=_har("https://a.test/"))

    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0
    assert out["skipped_reasons"].get("capture predates the scan_run") == 1


def test_a_capture_after_the_scan_run_attaches(store, db, db_path):
    sr = _scan_run(db, "https://a.test/", run_at="2026-05-01 00:00:00 UTC")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://a.test/"))
    assert reconcile.attach(db, reconcile.report(store, db_path),
                            dry_run=True)["attached"] == 1


# ── what attaching actually writes ────────────────────────────────────────

def test_a_dry_run_writes_nothing(store, db, db_path):
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://a.test/"))
    before = db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0] == before


def test_attaching_rederives_the_signals_analysis_reads(store, db, db_path):
    """A row that only points at the files would leave the evidence still
    uncounted: clustering reads tracking_ids_json and request_domains_json, so
    recovery has to re-derive them or 1.2 GB stays invisible while looking
    restored."""
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             html=("page.html",
                   "<script>gtag('config', 'G-B2C3D4E5F6');</script>"),
             har=_har("https://a.test/", "https://tracker.example/px",
                      "https://ads.example/x"))

    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=False)
    assert out["attached"] == 1

    row = db.execute("SELECT * FROM snapshots WHERE capture_detail LIKE "
                     "'%reconcile%'").fetchone()
    assert row is not None
    assert "G-B2C3D4E5F6" in row["tracking_ids_json"]
    assert set(json.loads(row["request_domains_json"])) == {
        "a.test", "tracker.example", "ads.example"}
    assert row["capture_status"] == "ok"
    assert row["captured_at"].startswith("2026-07-01")


def test_attaching_is_written_to_the_audit_log(store, db, db_path):
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://a.test/"))
    reconcile.attach(db, reconcile.report(store, db_path), dry_run=False)
    actions = [r[0] for r in db.execute("SELECT action FROM audit_log")]
    assert "evidence.reconcile.attach" in actions


def test_capture_method_follows_the_filename_the_writer_used(store, db, db_path):
    for name, method in (("page_http_only.html", "http_only"),
                         ("page_cloaking_alt.html", "cloaking_alt"),
                         ("page.html", "playwright")):
        sr = _scan_run(db, "https://a.test/")
        _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
                 html=(name, "<html>x</html>"), har=_har("https://a.test/"))
        out = reconcile.attach(db, reconcile.report(store, db_path),
                               dry_run=True)
        got = {d["capture_method"] for d in out["details"]
               if d["scan_run_id"] == sr}
        assert got == {method}, name


def test_single_byte_fill_is_never_attached(store, db, db_path):
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12",
             html=("page.html", "x" * 200_000))
    out = reconcile.attach(db, reconcile.report(store, db_path),
                           dry_run=True, include_partial=True)
    assert out["attached"] == 0
    assert out["skipped_reasons"].get("one byte repeated") == 1


def test_partial_directories_need_an_explicit_opt_in(store, db, db_path):
    """A page body with no screenshot and no HAR is real evidence when it came
    from the browser-free pass and a fixture when it came from a test. The
    default declines to guess."""
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12",
             html=("page_http_only.html", "<html>" + "content " * 500),
             manifest={"final_url": "https://a.test/", "final_domain": "a.test"})

    rep = reconcile.report(store, db_path)
    assert reconcile.attach(db, rep, dry_run=True)["attached"] == 0
    assert reconcile.attach(db, rep, dry_run=True,
                            include_partial=True)["attached"] == 1


# ── defects found by the adversarial pass, 2026-08-11 ─────────────────────
#
# 43 attacks, 12 confirmed. The pattern in four of them was one mistake:
# every gate abstained when it could not see. `if want and got and ...`
# passes when either side is missing, which is exactly the shape a stray
# directory has. These pin each fix to the attack that found it.

def test_reporting_never_creates_the_database_it_reports_against(
        store, tmp_path, monkeypatch):
    """Confirmed defect, high. `cmd_evidence_reconcile` called `_open_db`,
    which CREATES an absent database — so the primary was always readable,
    always empty, and `safe` could never go false for the one operator error
    it exists to catch. Measured on the live store, a mistyped --db turned all
    13,890 directories into "orphans" with safe=true and no warning, and left
    a decoy database behind in the evidence directory."""
    from kwara import config
    from kwara.cli import build_parser

    typo = str(tmp_path / "typo.db")
    _capture(store, 1, png=PNG)
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", store)
    monkeypatch.setattr(config, "INDEX_DB_PATH", str(tmp_path / "no-index.db"))

    ns = build_parser().parse_args(
        ["evidence", "reconcile", "--db", typo, "--quiet", "--limit", "0"])
    out = ns.fn(ns)

    assert not os.path.exists(typo), "a report created a database"
    assert out["safe"] is False
    assert typo in out["unreadable_databases"]


def test_attaching_into_a_database_that_does_not_exist_is_an_error(
        store, tmp_path, monkeypatch):
    from kwara import config
    from kwara.cli import build_parser

    monkeypatch.setattr(config, "SNAPSHOT_ROOT", store)
    monkeypatch.setattr(config, "INDEX_DB_PATH", str(tmp_path / "no-index.db"))
    ns = build_parser().parse_args(
        ["evidence", "reconcile", "--db", str(tmp_path / "absent.db"),
         "--attach", "--quiet", "--limit", "0"])
    with pytest.raises(ValueError, match="no database at"):
        ns.fn(ns)


def test_a_symlinked_bucket_cannot_drag_the_walk_out_of_the_store(
        store, db, db_path, tmp_path):
    """Confirmed defect, high. Nothing checked that a walked path stayed under
    the root, and os.path.isdir follows links — so a symlinked bucket made
    reconcile describe, report and attach files anywhere on the machine."""
    outside = tmp_path / "outside"
    (outside / "20260701T120000000000_ab12").mkdir(parents=True)
    (outside / "20260701T120000000000_ab12" / "screenshot.png").write_bytes(PNG)
    os.symlink(str(outside), os.path.join(store, "5"))

    rep = reconcile.report(store, db_path)
    assert rep["orphans"] == 0, "the walk followed a symlink out of the store"
    assert any("5" in p for p in rep["unexpected_paths"])


def test_a_capture_directory_that_is_a_symlink_is_refused(
        store, db, db_path, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "screenshot.png").write_bytes(PNG)
    os.makedirs(os.path.join(store, "5"))
    os.symlink(str(outside), os.path.join(store, "5", "20260701T120000000000_ab12"))

    rep = reconcile.report(store, db_path)
    assert rep["orphans"] == 0
    assert rep["unexpected_paths"]


def test_a_database_path_containing_a_question_mark_is_not_reinterpreted(
        tmp_path):
    """Confirmed defect, high. The URI was built by f-string, and SQLite reads
    everything after the first '?' as parameters — so such a path opened a
    DIFFERENT file, in the caller's default read-WRITE mode."""
    weird = tmp_path / "case?mode=rw&x=1.db"
    conn = get_conn(str(weird))
    init_db(conn)
    migrate_db(conn)
    conn.close()

    decoy = tmp_path / "case"
    assert not decoy.exists()
    # Must open the real file, not the prefix, and must not create the decoy.
    got = reconcile.referenced_directories([str(weird)])
    assert got == {}
    assert not decoy.exists()


def test_a_bucket_named_in_another_scripts_digits_is_not_scan_run_7(store, db,
                                                                    db_path):
    """Confirmed defect, medium. `name.isdigit()` is true for '٧', and
    int('٧') is 7 — so such a directory was silently attributed to
    scan_run 7. '²' is also isdigit() but int() rejects it, which crashed
    the whole walk."""
    for name in ("٧", "²"):
        os.makedirs(os.path.join(store, name), exist_ok=True)
    rep = reconcile.report(store, db_path)          # must not raise
    assert 7 not in [e["scan_run_id"] for e in rep["orphan_details"]]
    assert len(rep["unexpected_paths"]) == 2


def test_an_unrecoverable_domain_now_fails_corroboration(store, db, db_path):
    """Confirmed defect, high. `if want and got and got not in want` skipped
    itself whenever the domain could not be read — and a valid screenshot with
    no HAR and no manifest is a common shape, so the check simply did not run
    for it."""
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG)   # no HAR, no manifest

    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0
    assert "no landing domain" in " ".join(out["skipped_reasons"])


def test_a_scan_run_with_no_resolved_url_corroborates_nothing(store, db,
                                                              db_path):
    """Confirmed defect, medium. An empty `want` made the gate accept ANY
    capture into that bucket — and a scan that failed before resolving its URL
    is exactly the bucket a stray directory sits in."""
    cur = db.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink,
           actor_label, posted_at, message_text, screenshot_path, ingested_at)
           VALUES (1, '', '', '', '', '', '', '')""")
    cur = db.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, 1, '', '', 0, '')", (cur.lastrowid,))
    cur = db.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status) VALUES (?, '2026-05-01 00:00:00 UTC', '', 0, 'done')",
        (cur.lastrowid,))
    db.commit()
    sr = cur.lastrowid

    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://anything-at-all.test/"))
    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0


def test_the_manifest_cannot_vouch_for_itself(store, db, db_path):
    """Confirmed defect, high. capture.json is written at directory ALLOCATION
    time, before the capture runs — it records intent, not result. The gate
    read the domain from it in preference to the artifacts, so it validated
    the sidecar and never looked at what was captured."""
    sr = _scan_run(db, "https://a.test/")
    _capture(store, sr, "20260701T120000000000_ab12", png=PNG,
             har=_har("https://somewhere-else.test/"),
             manifest={"final_url": "https://a.test/", "final_domain": "a.test"})

    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0
    assert any("capture.json says" in w for w in out["skipped_reasons"])


def test_a_directory_name_without_a_timestamp_fails_the_temporal_gate(
        store, db, db_path):
    """Confirmed defect, high. `if when and ran` meant any directory whose
    name missed the pattern skipped the check the module calls the one that
    matters most — and the row was then written with captured_at NULL."""
    sr = _scan_run(db, "https://a.test/", run_at="2026-05-01 00:00:00 UTC")
    _capture(store, sr, "some-directory", png=PNG, har=_har("https://a.test/"))

    out = reconcile.attach(db, reconcile.report(store, db_path), dry_run=True)
    assert out["attached"] == 0
    assert any("no capture time" in w for w in out["skipped_reasons"])


def test_uppercase_hex_in_a_directory_name_still_carries_its_timestamp():
    """The pattern demanded lowercase hex, so an uppercase suffix silently
    produced captured_at=None and disabled the temporal gate."""
    assert reconcile._dir_timestamp("20260701T120000000000_AB12") is not None
    assert reconcile._dir_timestamp("20260701T120000000000_ab12") is not None
