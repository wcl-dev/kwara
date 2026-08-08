"""One case, start to finish, against a local origin.

Nothing else in the suite touches more than one stage, which is how three
breakages survived a package refactor on 2026-08-07: restore_from_export.py,
and both saved sweep scripts, were silently broken because no test imports
them. This test walks the chain a user actually walks —

    case new -> ingest -> run attribute -> analyze -> index -> export -> restore

— through the CLI, because the CLI is the surface a user and an agent both
use, and internals that pass while the CLI is broken are worth nothing.
"""
import json
import os
import subprocess
import sys

import pytest

from kwara import config
from kwara.cli import build_parser

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One tracking ID on two different origins. That is the signal the whole tool
# is built around: a shared measurement account is expensive to rotate, so it
# binds sites together more reliably than hosting or registration does.
SHARED_GA4 = "G-E2E0SMOKE1"
PAGE = ("<html><head><script>gtag('config', '%s');</script></head>"
        "<body>landing</body></html>" % SHARED_GA4)
ADS_TXT = (b"OWNERDOMAIN=e2e-owner.example\n"
           b"clickforce.com.tw, pub-E2E, DIRECT\n"
           b"rubiconproject.com, 22588, RESELLER\n")


def _run(argv, db):
    args = build_parser().parse_args(argv + ["--db", db, "--quiet"])
    return args.fn(args)


@pytest.fixture
def two_origins(site):
    """Two hostnames, one server.

    Clustering is per landing DOMAIN, so two TestSites would not do: both bind
    127.0.0.1 and differ only by port, which is one domain as far as the
    analysis is concerned. `localhost` and `127.0.0.1` resolve to the same
    socket but are distinct hosts, which is exactly the shape needed — two
    sites, one shared measurement account.
    """
    site.route("/", status=302, headers={"Location": "/landing"})
    site.route("/landing", body=PAGE,
               headers={"x-powered-by": "Apache/2.5.1 (Win64) OpenSSL/1.1.2e"})
    site.route("/ads.txt", body=ADS_TXT)
    port = site.url.rsplit(":", 1)[1]
    yield f"http://127.0.0.1:{port}", f"http://localhost:{port}", site


def test_full_case_lifecycle(two_origins, tmp_path, monkeypatch):
    first_url, second_url, first = two_origins
    db = str(tmp_path / "case.db")
    index_db = str(tmp_path / "index.db")
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snapshots"))

    # ── open a case and ingest ────────────────────────────────────────────
    case = _run(["case", "new", "--title", "E2E smoke"], db)["case_id"]
    _run(["ingest", "url", "--case", str(case), first_url + "/", second_url + "/"], db)
    assert _run(["case", "show", "--case", str(case)], db)["url_count"] == 2

    # ── the browser-free pass ─────────────────────────────────────────────
    attributed = _run(["run", "attribute", "--case", str(case)], db)
    assert attributed["scanned"] == 2, attributed
    assert attributed["ads"] == 2, attributed

    # The redirect was followed to the real landing page, and the response
    # headers were kept per hop — the header-forensics layer reads those.
    assert any(str(q.path) == "/landing" for q in first.requests)
    assert any(str(q.path) == "/ads.txt" for q in first.requests)

    # ── analysis sees what collection recorded ────────────────────────────
    clusters = _run(["analyze", "clusters", "--case", str(case)], db)
    assert clusters, "no clusters returned"

    from kwara.clustering_infra import shared_ad_accounts, shared_tracking_ids
    from kwara.db import get_conn
    conn = get_conn(db)
    tracking = shared_tracking_ids(conn, case)
    assert any(SHARED_GA4 in str(t.get("tracking_id")) for t in tracking), (
        "the GA4 ID served on both origins did not cluster them: %r" % tracking)
    ads = shared_ad_accounts(conn, case)
    assert ads["by_template"], "identical ads.txt on both origins did not cluster"

    insights = _run(["analyze", "insights", "--case", str(case)], db)
    assert insights["headline"]
    # An empty analysis usually means uncollected, not absent — the gaps must
    # say which.
    assert isinstance(insights["gaps"], list)

    narrative = _run(["analyze", "narrative", "--case", str(case)], db)
    # The prose a reader is handed. It must name the determination rather than
    # leaving them to infer it, and must carry the standing scope note — the
    # claim is bounded to the digital-asset layer, never to intent.
    assert narrative["has_signal"], narrative
    assert "可確定屬同一基礎設施群體" in narrative["group_line"], narrative["group_line"]
    assert narrative["summary"]
    assert narrative["scope_note"]        # the claim is bounded, always
    # NOTE: case_narrative returns the determination only as PROSE
    # (`group_line`). An agent consuming the JSON has to string-match Chinese
    # to recover it, while `verdict()` computes a machine-readable
    # grouping="strong"|"none" one layer down and drops it. Worth surfacing.

    dot = str(tmp_path / "g.dot")
    _run(["analyze", "graph", "--case", str(case), "--out", dot, "--format", "dot"], db)
    assert os.path.getsize(dot) > 0

    # ── cross-case memory ─────────────────────────────────────────────────
    _run(["index", "build", "--case", str(case), "--index-db", index_db], db)
    hits = _run(["index", "lookup", SHARED_GA4, "--index-db", index_db], db)
    assert hits["hits"] >= 2, ("the tracking ID must be indexed for BOTH "
                               "landing domains: %r" % hits)
    recurring = _run(["index", "recurring", "--index-db", index_db], db)
    assert isinstance(recurring, dict)
    crosslinks = _run(["index", "crosslinks", "--index-db", index_db], db)
    assert isinstance(crosslinks["cross_links"], list)

    # ── delivery, and a recipient rebuilding it ───────────────────────────
    exported = _run(["export", "case", "--case", str(case)], db)
    pack = exported["export_path"]
    assert os.path.isfile(pack)

    import zipfile
    with zipfile.ZipFile(pack) as z:
        names = z.namelist()
        assert any(n.endswith("manifest.json") for n in names)
        assert any(n.endswith("manifest.sha256") for n in names)
        manifest = json.loads(z.read([n for n in names
                                      if n.endswith("manifest.json")][0]))
        # No HMAC key in the test environment, so the pack must say so rather
        # than let a recipient assume it was signed.
        assert "integrity_warning" in manifest

    # restore_from_export.py lives at the repo root, OUTSIDE the package. It is
    # the piece a package refactor breaks silently, because nothing imports it.
    restored_dir = tmp_path / "restored"
    unpacked = tmp_path / "unpacked"
    with zipfile.ZipFile(pack) as z:
        z.extractall(unpacked)
    # The pack extracts flat (messages/, urls/, snapshots/, manifest.json), so
    # the export root IS the extraction directory.
    assert (unpacked / "messages").is_dir(), sorted(p.name for p in unpacked.iterdir())
    env = dict(os.environ, KWARA_DATA_DIR=str(restored_dir))
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "restore_from_export.py"), str(unpacked)],
        capture_output=True, text=True, env=env, cwd=REPO, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    restored_db = restored_dir / "kwara.db"
    assert restored_db.is_file(), proc.stdout + proc.stderr
    rconn = get_conn(str(restored_db))
    n = rconn.execute("SELECT COUNT(*) FROM url_artifacts").fetchone()[0]
    assert n == 2, "the recipient's rebuild lost URLs"
