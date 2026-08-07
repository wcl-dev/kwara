"""kwara discover — the screening funnel as a CLI surface.

Everything the funnel does was reachable only through hand-written scripts
after the 2026-08-05 sweeps, which breaks the contract that the CLI is the
single source of truth for automation: an agent could not run a sweep, and
neither could the analyst without writing Python. These cover the three
offline commands; the fourth (`screen`) is outbound and exercised live.
"""
import json
import os
import tempfile

from kwara.cli import build_parser


def _run(argv):
    args = build_parser().parse_args(argv)
    return args.fn(args)


def _tmp(name, content):
    path = os.path.join(tempfile.mkdtemp(), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def test_candidates_extracts_publisher_domains_and_skips_redacted():
    sj = _tmp("sellers.json", json.dumps({"sellers": [
        {"seller_id": "1", "domain": "www.Farm.com", "name": "a"},
        {"seller_id": "2", "domain": "other.net"},
        {"seller_id": "3", "is_confidential": 1},          # no domain to take
    ]}))
    out = _run(["discover", "candidates", sj])
    assert out["candidates"] == 2
    assert out["domains"] == ["farm.com", "other.net"]   # apex, lowercased


def test_candidates_writes_a_file_when_asked():
    sj = _tmp("s.json", json.dumps({"sellers": [{"domain": "x.com"}]}))
    dest = os.path.join(tempfile.mkdtemp(), "cand.txt")
    out = _run(["discover", "candidates", sj, "--out", dest])
    assert out["domains"] is None            # not duplicated into stdout
    assert open(dest).read().split() == ["x.com"]


def _obs(domain, sha, accounts, status="ok"):
    return {"domain": domain, "raw_sha256": sha, "status": status,
            "record_count": len(accounts), "accounts": accounts}


def test_cluster_reads_banked_jsonl_and_can_drop_platform_templates():
    big = [[f"n{i}.com", str(i)] for i in range(400)]
    small = [["a.com", "1"], ["b.net", "2"]]
    banked = _tmp("obs.jsonl", "\n".join(json.dumps(o) for o in [
        _obs("p1.com", "BIG", big), _obs("p2.com", "BIG", big),
        _obs("f1.com", "SML", small), _obs("f2.com", "SML", small)]))

    both = _run(["discover", "cluster", "--observations", banked])
    assert both["clusters"] == 2
    only = _run(["discover", "cluster", "--observations", banked,
                 "--portfolio-only"])
    assert [c["sha256"] for c in only["results"]] == ["SML"]


def test_prevalence_round_trips_into_a_loadable_table():
    """The table the tier reads must be produced by the tool, not by hand —
    it had no producer at all until this command existed."""
    from kwara import prevalence
    banked = _tmp("obs.jsonl", "\n".join(json.dumps(o) for o in [
        _obs("a.com", "S1", [["ads.com", "1"], ["rare.net", "9"]]),
        _obs("b.com", "S2", [["ads.com", "1"]]),
        _obs("c.com", "S3", [], status="non_200"),      # not a reference site
    ]))
    dest = os.path.join(tempfile.mkdtemp(), "prev.json")
    out = _run(["discover", "prevalence", "--observations", banked,
                "--out", dest, "--source", "unit test"])
    assert out["site_count"] == 2 and out["accounts"] == 2

    table = prevalence.load(dest)
    assert table.site_count == 2
    assert table.ratio("ads.com", "1") == 1.0
    assert table.ratio("rare.net", "9") == 0.5
    assert table.ratio("never.org", "0") is None
