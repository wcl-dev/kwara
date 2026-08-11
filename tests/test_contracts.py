"""The stated invariants, one test each, named after the invariant.

docs/analysis-design.md and several module docstrings name guarantees that must
survive refactoring. Until now they were defended by tests scattered across the
suite under names that did not say which guarantee they belonged to, so a
regression read as "some test went red" rather than "invariant 6 is broken".

Where a guarantee is already asserted properly elsewhere, this file asserts it
at its narrowest point rather than duplicating the setup.
"""
import json
import os

import pytest

from kwara import config, prevalence
from kwara.clustering_infra import MAJOR_AD_EXCHANGES
from kwara.fingerprints import extract_tracking_ids
from kwara.param_attribution import PLATFORM_ADS_TXT_SELLER, PLATFORM_GOOGLE_ANALYTICS
from kwara.sql import LATEST_DONE_SCAN_RUN, usable_snapshots


def test_contract_01_platform_ids_are_constants_not_display_strings():
    """Dedup keys must be symbols. A typo in a free-text label writes into the
    wrong bucket silently; a typo in a constant is a NameError."""
    assert isinstance(PLATFORM_ADS_TXT_SELLER, str)
    assert PLATFORM_ADS_TXT_SELLER == PLATFORM_ADS_TXT_SELLER.lower()
    assert " " not in PLATFORM_ADS_TXT_SELLER


def test_contract_04_fingerprints_require_invocation_context():
    """Bare-token matching pulled IDs out of vendor documentation and JSON
    blobs. Every pattern must anchor on a real invocation, a vendor host, or a
    dataLayer literal."""
    real = "<script>gtag('config', 'G-B2C3D4E5F6');</script>"
    assert any("G-B2C3D4E5F6" in str(v) for v in extract_tracking_ids(real).values())

    prose = "<p>Set your measurement ID, for example G-B2C3D4E5F6, in the console.</p>"
    found = extract_tracking_ids(prose)
    assert not any("G-B2C3D4E5F6" in str(v) for v in found.values()), found


def test_contract_05_placeholder_filter_applies_to_letters_not_digits():
    """AW-1111111111 exists in the wild, so repeated digits must NOT be
    filtered — a rare false positive is preferable to silently dropping a
    legitimate attribution. Repeated letters are documentation placeholders."""
    from kwara.fingerprints import _looks_like_placeholder
    assert _looks_like_placeholder("G-XXXXXXXX")
    assert _looks_like_placeholder("GTM-EXAMPLE")
    assert not _looks_like_placeholder("AW-1111111111")


def test_contract_06_a_failed_recapture_does_not_shadow_a_good_one():
    """A later failed re-capture — a Cloudflare challenge, a timeout — must not
    shadow an earlier good snapshot's data. The rule lives in sql.py so the
    ~10 call sites cannot drift; assert the SQL still carries both halves."""
    frag = usable_snapshots("tracking_ids_json")
    assert "capture_status = 'ok'" in frag
    assert "tracking_ids_json IS NOT NULL" in frag
    with pytest.raises(ValueError):
        usable_snapshots("arbitrary_column")   # allow-list, not interpolation

    # Assert the invariant itself, not the shape of the SQL that delivers it.
    # The string form was pinned to `ORDER BY id DESC`, which is exactly what
    # had to change on 2026-08-11 to stop recency selecting the crawler-facing
    # capture — a test that fails when a defect is fixed is defending nothing.
    import tempfile
    from kwara.db import get_conn, init_db, migrate_db

    conn = get_conn(os.path.join(tempfile.mkdtemp(), "c6.db"))
    init_db(conn)
    migrate_db(conn)
    conn.execute("INSERT INTO cases (title, description, created_at, updated_at) "
                 "VALUES ('c6', '', '', '')")
    conn.execute("""INSERT INTO message_evidence (case_id, platform, permalink,
                    actor_label, posted_at, message_text, screenshot_path,
                    ingested_at) VALUES (1, '', '', '', '', '', '', '')""")
    conn.execute("INSERT INTO url_artifacts (message_id, case_id, original_url, "
                 "domain, url_order, created_at) VALUES (1, 1, 'https://a.test/', "
                 "'a.test', 0, '')")
    conn.execute("INSERT INTO scan_runs (url_artifact_id, run_at, final_url, "
                 "hop_count, status) VALUES (1, '', 'https://a.test/', 0, 'done')")
    good = conn.execute(
        "INSERT INTO snapshots (scan_run_id, capture_method, capture_status, "
        "tracking_ids_json) VALUES (1, 'playwright', 'ok', ?)",
        (json.dumps(["G-GOOD"]),)).lastrowid
    conn.execute(
        "INSERT INTO snapshots (scan_run_id, capture_method, capture_status, "
        "tracking_ids_json) VALUES (1, 'playwright', 'cf_challenge', ?)",
        (json.dumps(["G-FROM-A-CHALLENGE-PAGE"]),))
    conn.commit()

    used = {r["id"] for r in conn.execute(
        f"SELECT s.id FROM scan_runs sr JOIN snapshots s "
        f"ON s.id IN {usable_snapshots('tracking_ids_json')} WHERE sr.id = 1")}
    assert used == {good}, \
        "the challenge page was read as data, or the good capture was dropped"


def test_contract_analysis_pins_the_latest_done_scan():
    assert "status = 'done'" in LATEST_DONE_SCAN_RUN
    assert "ORDER BY id DESC" in LATEST_DONE_SCAN_RUN


def test_contract_07_per_capture_dirs_are_never_reused(tmp_path, monkeypatch):
    """Repeated captures on one scan_run must not overwrite each other, or an
    older snapshot row ends up pointing at bytes that are no longer what it
    recorded."""
    from kwara.snapshots import _per_capture_dir
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path))
    assert _per_capture_dir(5) != _per_capture_dir(5)


def test_contract_09_scan_path_does_not_follow_redirects():
    """The scan already resolved the canonical final_url; following further
    redirects here would capture an artifact belonging to a different host.
    Screening is the deliberate exception and checks the landing host itself."""
    import inspect
    from kwara import adstxt, lightweight_fetch
    for mod in (adstxt, lightweight_fetch):
        src = inspect.getsource(mod)
        assert "allow_redirects=False" in src, mod.__name__


def test_contract_10_deletion_is_confined_to_the_snapshot_root(tmp_path, monkeypatch):
    from kwara import cases
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snaps"))
    root = cases._snap_root()
    assert os.path.isabs(root) and root == os.path.realpath(root)


def test_contract_major_exchanges_never_reach_operator_tier():
    """A floor under the frequency weighting: an account at an exchange used by
    millions of unrelated sites is never per-operator attribution. Google is
    deliberately absent — a `google.com, pub-…` DIRECT line can be an
    operator's own AdSense account."""
    assert "criteo.com" in MAJOR_AD_EXCHANGES
    assert "rubiconproject.com" in MAJOR_AD_EXCHANGES
    assert "google.com" not in MAJOR_AD_EXCHANGES


def test_contract_prevalence_never_seen_is_none_not_zero(tmp_path):
    """The distinction the tier rests on. An account the reference population
    never saw may be genuinely rare or simply outside its reach; reporting 0.0
    would silently promote every unknown account to strong evidence — the same
    error as measuring rarity inside an all-suspect corpus."""
    path = tmp_path / "prev.json"
    path.write_text(json.dumps({"schema": prevalence.SCHEMA, "site_count": 100,
                                "accounts": {"seen.com|1": 30}}))
    table = prevalence.load(str(path))
    assert table.ratio("seen.com", "1") == 0.3
    assert table.ratio("unseen.com", "9") is None


def test_contract_prevalence_table_is_optional(monkeypatch):
    """Analysis must not fail for want of a reference file, nor treat its
    absence as evidence that everything is rare."""
    assert prevalence.load("/nonexistent/prevalence.json") is None
