"""Every MCP tool, actually called.

The MCP server's premise is that it is a thin wrapper over the same cmd_*
functions, so the two surfaces cannot drift. That only holds if someone checks:
_call() synthesises an argparse namespace, and a cmd_* function reading an
attribute the tool never set fails at runtime, in the branch, on the agent's
machine — not here. 63% coverage meant most tools had never been invoked.
"""
import inspect
import json
import os

import pytest

from kwara import config, mcp_server
from kwara.cli import build_parser


@pytest.fixture
def case(tmp_path, monkeypatch, site):
    """A small real case, so tools return data rather than empty shells."""
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snapshots"))
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    db = str(tmp_path / "c.db")
    site.route("/", body="<html><head><script>gtag('config','G-MCPTEST001');"
                         "</script></head><body>x</body></html>")
    site.route("/ads.txt", body=b"clickforce.com.tw, pub-MCP, DIRECT\n")

    def run(argv):
        ns = build_parser().parse_args(argv + ["--db", db, "--quiet"])
        return ns.fn(ns)

    cid = run(["case", "new", "--title", "mcp"])["case_id"]
    run(["ingest", "url", "--case", str(cid), site.url + "/"])
    run(["run", "attribute", "--case", str(cid)])
    return {"db": db, "case": cid, "index_db": str(tmp_path / "index.db"),
            "tmp": tmp_path}


def _tools():
    return [n for n, f in vars(mcp_server).items()
            if callable(f) and not n.startswith("_")
            and inspect.getmodule(f) is mcp_server
            and n not in {"main", "cli"}]


def test_every_tool_is_a_thin_wrapper_over_a_cli_command():
    """No analysis logic may live in the MCP layer, or the surfaces drift."""
    src = inspect.getsource(mcp_server)
    for name in _tools():
        fn = getattr(mcp_server, name)
        body = inspect.getsource(fn)
        if name == "_set_lang":
            continue
        assert "_call(cli.cmd_" in body or "cli." in body, (
            f"{name} does not delegate to a cli.cmd_* function")


def test_read_only_tools_all_dispatch(case):
    """Each of these builds a namespace and calls into the CLI. A missing
    attribute only surfaces when the branch runs, so run them."""
    db, cid, idx = case["db"], case["case"], case["index_db"]

    assert isinstance(mcp_server.list_cases(db=db), list)
    assert mcp_server.case_status(case=cid, db=db)["id"] == cid
    assert mcp_server.insights(case=cid, db=db)["headline"]
    assert isinstance(mcp_server.clusters(case=cid, db=db), (dict, list))
    assert mcp_server.narrative(case=cid, db=db)["scope_note"]

    # One landing domain means no edges. An empty graph is a RESULT, not a
    # failure — the tool says so in its own docs — so assert the contract
    # rather than the file.
    dot = str(case["tmp"] / "g.dot")
    g = mcp_server.relationship_graph(case=cid, db=db, out=dot, fmt="dot")
    assert isinstance(g, dict)
    assert g.get("note") or os.path.exists(dot), g

    mcp_server.index_case(case=cid, db=db, index_db=idx)
    assert mcp_server.lookup_signal("G-MCPTEST001", index_db=idx)["hits"] >= 1
    assert isinstance(mcp_server.recurring_signals(index_db=idx), dict)
    assert isinstance(mcp_server.operator_cross_links(index_db=idx)["cross_links"], list)

    ev = mcp_server.list_evidence(case=cid, db=db)
    assert "by_domain" in ev

    exported = mcp_server.export_case(case=cid, db=db)
    assert os.path.isfile(exported["export_path"])


def test_discovery_tools_dispatch(case, tmp_path):
    sellers = tmp_path / "sellers.json"
    sellers.write_text(json.dumps({"sellers": [
        {"seller_id": "1", "domain": "farm.example.com"},
        {"seller_id": "2", "is_confidential": 1},
    ]}))
    cand = mcp_server.extract_candidates(sellers_json=[str(sellers)])
    assert cand["candidates"] == 1

    obs = tmp_path / "obs.jsonl"
    obs.write_text("\n".join(json.dumps(o) for o in [
        {"domain": "a.com", "raw_sha256": "S", "status": "ok",
         "record_count": 2, "accounts": [["x.com", "1"], ["y.net", "2"]]},
        {"domain": "b.net", "raw_sha256": "S", "status": "ok",
         "record_count": 2, "accounts": [["x.com", "1"], ["y.net", "2"]]},
    ]))
    cl = mcp_server.cluster_observations(observations=str(obs))
    assert cl["clusters"] == 1

    out = tmp_path / "prev.json"
    tbl = mcp_server.build_prevalence_table(observations=str(obs), out=str(out),
                                            source="mcp dispatch test")
    assert tbl["site_count"] == 2 and out.is_file()


def test_screening_is_capped_so_an_agent_cannot_start_a_sweep(site, tmp_path):
    """Same reasoning as capture_snapshots: the tool contacts every candidate
    directly and a sweep list runs to five figures. An agent must not be one
    call away from that; larger runs belong in the CLI with a human present."""
    site.route("/ads.txt", body=b"google.com, pub-1, DIRECT\n")
    doms = tmp_path / "d.txt"
    port = site.url.rsplit(":", 1)[1]
    doms.write_text("\n".join([f"127.0.0.1:{port}"] * 3))
    src = inspect.getsource(mcp_server.screen_candidates)
    assert "min(int(limit), 500)" in src

    res = mcp_server.screen_candidates(domains=str(doms), limit=2,
                                       index_db=str(tmp_path / "i.db"))
    assert res["screened"] <= 2


def test_destructive_operations_are_not_exposed():
    """Deleting a case destroys evidence irreversibly. It is CLI-only on
    purpose, and the docstring says so — assert the absence, because an
    absence is easy to undo by accident."""
    names = set(_tools())
    assert "delete_case" not in names
    assert not any("delete" in n for n in names), names
    assert "Deleting a case" in mcp_server.__doc__
