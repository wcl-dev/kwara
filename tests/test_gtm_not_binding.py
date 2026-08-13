"""A shared GTM container is a lead, not a binding.

GA4, AdSense and Meta identify an ACCOUNT the operator holds. A Google Tag
Manager container identifies a tag deployment, which an agency or a CMS vendor
can legitimately run across unrelated clients. So sharing one is correlated
with common operation without establishing it.

kwara treated every shared tracking ID as a hard signal, so one container
merged two operator groups. The analyst's own published report
(UNIFIED_CLUSTER_REPORT_2026-05-08 §3.2) had already declined to do that on
GTM-T5N9K2Q, listing both readings; measurement on that case agreed with the
report, not the tool. These tests hold the tool to it.

The rule is about the SIGNAL TYPE. There is no allowlist, nothing special
about PQ3GKRX, and a public search returning nothing cannot upgrade it.
"""
import json
from datetime import datetime, timezone

import pytest

from kwara.clusters import GTM_READINGS, TIER_RELATED, case_clusters
from kwara.db import get_conn, init_db, migrate_db


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@pytest.fixture
def db(tmp_path):
    conn = get_conn(str(tmp_path / "t.db"))
    init_db(conn)
    migrate_db(conn)
    conn.execute("INSERT INTO cases (title, description, created_at, updated_at)"
                 " VALUES ('t','',?,?)", (_now(), _now()))
    conn.commit()
    return conn


def _site(conn, domain, tracking: dict):
    """One scanned domain carrying {platform: [ids]}."""
    now = _now()
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink,
           actor_label, posted_at, message_text, screenshot_path, ingested_at)
           VALUES (1,'','','','','','',?)""", (now,))
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain,"
        " url_order, created_at) VALUES (?,1,?,?,0,?)",
        (cur.lastrowid, f"https://{domain}/", domain, now))
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,"
        " status) VALUES (?,?,?,0,'done')",
        (cur.lastrowid, now, f"https://{domain}/"))
    conn.execute(
        "INSERT INTO snapshots (scan_run_id, final_url, final_domain,"
        " captured_at, capture_status, capture_method, tracking_ids_json)"
        " VALUES (?,?,?,?,'ok','playwright',?)",
        (cur.lastrowid, f"https://{domain}/", domain, now,
         json.dumps(tracking)))
    conn.commit()


def _groups(conn):
    return sorted(tuple(sorted(g["domains"])) for g in case_clusters(conn, 1)["groups"])


def _gtm_links(conn):
    return [w for w in case_clusters(conn, 1)["weak_links"]
            if w["type"] == "gtm_container"]


# ── the rule ──────────────────────────────────────────────────────────────

def test_a_shared_container_alone_makes_no_group(db):
    _site(db, "a.test", {"Google Tag Manager": ["GTM-SAME"]})
    _site(db, "b.test", {"Google Tag Manager": ["GTM-SAME"]})

    assert _groups(db) == []
    links = _gtm_links(db)
    assert len(links) == 1
    assert links[0]["container_id"] == "GTM-SAME"
    assert sorted(links[0]["domains"]) == ["a.test", "b.test"]


def test_a_container_never_joins_two_otherwise_separate_groups(db):
    """The α/γ shape in miniature. Two groups, each bound by its own account,
    sharing only a container: they must stay two."""
    for d in ("a1.test", "a2.test"):
        _site(db, d, {"Google Analytics 4": ["G-ALPHA"],
                      "Google Tag Manager": ["GTM-SHARED"]})
    for d in ("g1.test", "g2.test"):
        _site(db, d, {"Meta Facebook Page": ["111222333"],
                      "Google Tag Manager": ["GTM-SHARED"]})

    assert _groups(db) == [("a1.test", "a2.test"), ("g1.test", "g2.test")]

    link = _gtm_links(db)[0]
    assert link["container_id"] == "GTM-SHARED"
    assert len(link["spans_groups"]) == 2, \
        "the link must name both groups it bridges"
    assert {m["domain"] for m in link["members"]} == {
        "a1.test", "a2.test", "g1.test", "g2.test"}
    assert all(m["group_id"] is not None for m in link["members"])


def test_a_gtm_only_pair_is_visible_even_with_no_groups_at_all(db):
    """Criterion the weak-link structure had to grow into: a relationship
    between two domains that belong to no confirmed group is no less real."""
    _site(db, "x.test", {"Google Tag Manager": ["GTM-LONE"]})
    _site(db, "y.test", {"Google Tag Manager": ["GTM-LONE"]})

    link = _gtm_links(db)[0]
    assert link["spans_groups"] == []
    assert [m["group_id"] for m in link["members"]] == [None, None]
    assert link["tier"] == TIER_RELATED


def test_a_container_is_corroboration_when_something_hard_already_binds(db):
    """It is not suppressed — it just is not what did the binding."""
    for d in ("p.test", "q.test"):
        _site(db, d, {"Google Analytics 4": ["G-REAL"],
                      "Google Tag Manager": ["GTM-ALSO"]})

    assert _groups(db) == [("p.test", "q.test")]
    signals = case_clusters(db, 1)["groups"][0]["signals"]
    assert [s["value"] for s in signals] == ["G-REAL"]
    assert "GTM-ALSO" not in [s["value"] for s in signals]
    assert _gtm_links(db)[0]["container_id"] == "GTM-ALSO"


# ── everything else is untouched ──────────────────────────────────────────

@pytest.mark.parametrize("platform,value", [
    ("Google Analytics 4", "G-B2C3D4E5F6"),
    ("Google AdSense", "REDACTEDID162"),
    ("Meta Facebook Page", "1000000000000001"),
    ("Google Analytics (UA)", "UA-10000001-1"),
])
def test_other_tracking_ids_still_bind(db, platform, value):
    _site(db, "a.test", {platform: [value]})
    _site(db, "b.test", {platform: [value]})
    assert _groups(db) == [("a.test", "b.test")]


# ── the observation carries its ambiguity ─────────────────────────────────

def test_both_readings_travel_with_the_observation(db):
    """There is no reference population for tracking IDs, so "how rare is a
    shared container" is unanswerable. The output says so by carrying both
    interpretations rather than implying one."""
    _site(db, "a.test", {"Google Tag Manager": ["GTM-X"]})
    _site(db, "b.test", {"Google Tag Manager": ["GTM-X"]})

    link = _gtm_links(db)[0]
    assert link["readings"] == list(GTM_READINGS)
    assert len(link["readings"]) == 2
    assert link["platform"] == "Google Tag Manager"
    assert "GTM" in link["channel"]


def test_breadth_never_suppresses_a_container(db):
    """The weak-link breadth filter drops a value carried by most of a case's
    domains as ubiquitous infrastructure. That is right for "server: nginx"
    and backwards here — a container on every domain is the MOST interesting
    one. Breadth is reported, never applied."""
    for d in ("a.test", "b.test", "c.test", "d.test", "e.test"):
        _site(db, d, {"Google Tag Manager": ["GTM-EVERYWHERE"]})

    link = _gtm_links(db)[0]
    assert link["domain_count"] == 5
    assert link["breadth_ratio"] == 1.0, "breadth is reported"
    assert link["container_id"] == "GTM-EVERYWHERE"


def test_the_narrative_does_not_count_a_container_as_a_tracking_signal(db):
    from kwara.narrative import signal_summary

    _site(db, "a.test", {"Google Tag Manager": ["GTM-X"]})
    _site(db, "b.test", {"Google Tag Manager": ["GTM-X"]})

    s = signal_summary(db, 1)
    assert s["tracking"] == 0
    assert s["gtm_containers"] == 1


def _code_only(module) -> str:
    """Module source with comments and docstrings stripped.

    The prose in clusters.py NAMES the container and the domains, because that
    is where the reasoning and the measurement are recorded. A naive scan would
    fail on the very documentation that explains why there is no allowlist —
    the same false positive a "NO CASCADE" comment produced in the migration.
    """
    import ast
    import inspect
    import io
    import tokenize

    src = inspect.getsource(module)
    doc_lines = set()
    for node in ast.walk(ast.parse(src)):
        body = getattr(node, "body", None)
        if (isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef))
                and body and isinstance(body[0], ast.Expr)
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


def test_there_is_no_allowlist():
    """The rule is about the signal type. PQ3GKRX gets no special treatment in
    either direction — it behaves exactly like any other container, and no
    case's domains appear in the logic."""
    from kwara import clusters, index_db, narrative

    for module in (clusters, index_db, narrative):
        code = _code_only(module)
        assert "PQ3GKRX" not in code, module.__name__
        for banned in ("visitorlanding", "crawlerlanding", "operatorhub", "farm1"):
            assert banned not in code.lower(), f"{module.__name__}: {banned}"


def test_the_allowlist_scan_would_actually_catch_one():
    """A guard that cannot fail is not a guard: prove the stripper leaves real
    code behind rather than blanking the file."""
    from kwara import clusters

    code = _code_only(clusters)
    assert "def _is_gtm" in code and "gtm_container" in code


# ── the case this came from ───────────────────────────────────────────────

def test_the_alpha_gamma_case_stays_two_groups(db):
    """Regression for the analyst's own case. α is bound by its Google
    accounts, γ by its Meta Page; the only thing they share is GTM-T5N9K2Q.
    Before this change the tool merged them into one 13-domain group and
    claimed more than the published report was willing to."""
    alpha = ["redacted139.farm1.example", "operatorhub.example", "farm4.example",
             "farm5.example", "farm6.example", "farm7.example",
             "farm8.example", "www.farm2.example", "www.farm3.example",
             "www.farm9.example"]
    gamma = ["visitorlanding.example", "crawlerlanding.example", "crawlerlanding2.example"]

    for d in alpha:
        _site(db, d, {"Google AdSense": ["REDACTEDID162"],
                      "Google Analytics (UA)": ["UA-10000001-1"],
                      "Google Tag Manager": ["GTM-T5N9K2Q"]})
    for d in gamma:
        _site(db, d, {"Meta Facebook Page": ["1000000000000001"],
                      "Google Tag Manager": ["GTM-T5N9K2Q"]})

    groups = _groups(db)
    assert len(groups) == 2, f"expected α and γ to stay separate, got {groups}"
    assert sorted(len(g) for g in groups) == [3, 10]
    assert set(groups[0]) | set(groups[1]) == set(alpha) | set(gamma)
    assert not any(len(g) == 13 for g in groups)

    link = _gtm_links(db)[0]
    assert link["container_id"] == "GTM-T5N9K2Q"
    assert len(link["spans_groups"]) == 2
    assert link["domain_count"] == 13


# ── cross-case memory ─────────────────────────────────────────────────────

def test_a_container_is_indexed_under_its_own_signal_type(db, tmp_path):
    """`tracking_id` recurrence reads as "the same operator resurfaced". A
    container does not support that sentence, so it is indexed as a lead under
    its own type rather than inheriting the wording."""
    from kwara.index_db import (SIGNAL_GTM_CONTAINER, SIGNAL_TRACKING_ID,
                                extract_case_signals)

    _site(db, "a.test", {"Google Tag Manager": ["GTM-X"],
                         "Google Analytics 4": ["G-Y"]})
    signals = extract_case_signals(db, 1, "/tmp/x.db", "t")
    by_type = {}
    for s in signals:
        by_type.setdefault(s["signal_type"], []).append(s["signal_value"])

    assert by_type.get(SIGNAL_GTM_CONTAINER) == ["GTM-X"]
    assert "GTM-X" not in by_type.get(SIGNAL_TRACKING_ID, [])
    assert "G-Y" in by_type.get(SIGNAL_TRACKING_ID, [])


def test_legacy_index_rows_are_retyped_in_place(tmp_path):
    """The analyst's index holds containers filed under tracking_id from
    before this split. Retyped automatically — an index that silently mixes
    the two makes every later lookup ambiguous, and a rebuild someone has to
    remember is a rebuild that does not happen."""
    import sqlite3

    from kwara.index_db import (SIGNAL_GTM_CONTAINER, SIGNAL_TRACKING_ID,
                                get_index_conn)

    path = str(tmp_path / "index.db")
    conn = get_index_conn(path)
    rows = [
        (SIGNAL_TRACKING_ID, "GTM-OLD", "Google Tag Manager"),
        (SIGNAL_TRACKING_ID, "G-KEEP", "Google Analytics 4"),
        (SIGNAL_TRACKING_ID, "ca-pub-KEEP", "Google AdSense"),
    ]
    for st, val, plat in rows:
        conn.execute(
            "INSERT INTO signals (signal_type, signal_value, platform, "
            "source_db, case_id, case_title, scan_run_id, final_domain, "
            "observed_at, indexed_at) VALUES (?,?,?,'/tmp/x.db',1,'t',1,"
            "'a.test','','')", (st, val, plat))
    conn.commit()
    conn.close()

    conn = get_index_conn(path)          # opening runs the retype
    got = {r[0]: r[1] for r in conn.execute(
        "SELECT signal_value, signal_type FROM signals")}
    assert got["GTM-OLD"] == SIGNAL_GTM_CONTAINER
    assert got["G-KEEP"] == SIGNAL_TRACKING_ID, "a GA4 row was moved"
    assert got["ca-pub-KEEP"] == SIGNAL_TRACKING_ID, "an AdSense row was moved"

    # Provenance is untouched: this renames the type and nothing else.
    row = conn.execute("SELECT * FROM signals WHERE signal_value='GTM-OLD'"
                       ).fetchone()
    assert row["platform"] == "Google Tag Manager"
    assert row["final_domain"] == "a.test"
    assert row["case_id"] == 1

    before = conn.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
    get_index_conn(path)                 # idempotent
    assert conn.execute("SELECT COUNT(*) FROM signals").fetchone()[0] == before
    assert conn.execute(
        "SELECT COUNT(*) FROM signals WHERE signal_type = ?",
        (SIGNAL_GTM_CONTAINER,)).fetchone()[0] == 1
