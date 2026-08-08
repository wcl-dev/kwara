"""Guards against the failure this tool cannot tolerate: fabricated evidence.

On 2026-08-07 a verification pass found 13,785 capture directories on disk
against 983 with a database row. `snapshots/99` alone held 9,807, accumulated
over roughly 98 runs of a 100-iteration loop in the test suite. Their contents
were fixture data — capture.json naming https://target.com/, HTML carrying an
invented Meta Pixel ID — sitting in buckets numbered like real scan_run_ids and
indistinguishable on disk from genuine captures. delete_case only removes
directories the database lists, so nothing ever cleaned them up.

The cause was not careless tests: `_per_capture_dir` derived its root from the
package directory, so there was no way to redirect it, and the same hardcoding
meant a real `pip install` would write evidence into site-packages.
"""
import json
import os
import threading

import pytest

from kwara import cases, config, exporter, snapshots


def _tree(root: str) -> set[str]:
    out: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for f in filenames:
            out.add(os.path.join(dirpath, f))
    return out


@pytest.fixture(scope="session", autouse=True)
def _real_store_untouched():
    """The whole suite must not add a single file to the operator's store.

    Session-scoped and autouse so it holds regardless of which tests run or in
    what order — a guard you have to remember to apply is a guard that will
    eventually be forgotten.

    It reads the root from the environment rather than from config, because
    the per-test fixture has already redirected config by the time any test
    body runs; this needs the real one.
    """
    root = os.path.abspath(os.path.expanduser(os.environ.get(
        "KWARA_DATA_DIR",
        os.path.join(os.path.dirname(os.path.abspath(config.__file__)), "data"))))
    before = _tree(root) if os.path.isdir(root) else set()
    yield
    after = _tree(root) if os.path.isdir(root) else set()
    added = sorted(after - before)
    assert not added, (
        f"the test suite wrote {len(added)} file(s) into the real evidence "
        f"store at {root}; first few: {added[:5]}")


def test_one_knob_moves_the_database_captures_and_exports(monkeypatch):
    """Only DB_PATH was relocatable before, so `--db /elsewhere/case.db` put the
    database in one place and its evidence in another — a case split across two
    locations, with no way to tell from either half."""
    monkeypatch.setenv("KWARA_DATA_DIR", "/tmp/kwara-relocated")
    monkeypatch.delenv("KWARA_DB_PATH", raising=False)
    import importlib
    fresh = importlib.reload(config)
    try:
        assert fresh.DATA_DIR == "/tmp/kwara-relocated"
        assert fresh.SNAPSHOT_ROOT.startswith("/tmp/kwara-relocated")
        assert fresh.EXPORTS_DIR.startswith("/tmp/kwara-relocated")
        assert fresh.DB_PATH.startswith("/tmp/kwara-relocated")
    finally:
        monkeypatch.undo()
        importlib.reload(config)


def test_capture_dirs_are_unique_under_concurrency(tmp_path, monkeypatch):
    """Invariant 7. exist_ok=True used to accept a collision between two
    captures landing in the same microsecond with the same 16-bit suffix; both
    then wrote the same fixed filenames, and an older snapshot row pointed at
    overwritten bytes. snapshot_batch runs captures in parallel, so this is not
    hypothetical."""
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "snapshots"))
    seen: list[str] = []
    lock = threading.Lock()

    def grab():
        d = snapshots._per_capture_dir(7)
        with lock:
            seen.append(d)

    threads = [threading.Thread(target=grab) for _ in range(24)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(seen) == 24
    assert len(set(seen)) == 24, "two captures were handed the same directory"
    assert all(os.path.isdir(d) for d in seen)


def test_capture_dirs_land_under_the_configured_root(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(tmp_path / "elsewhere"))
    d = snapshots._per_capture_dir(3)
    assert d.startswith(str(tmp_path / "elsewhere")), d


def test_deletion_stays_inside_the_relocated_root(tmp_path, monkeypatch):
    """Invariant 10 confines deletion to the capture store. The guard resolves
    the root at call time; a constant frozen at import would have confined
    deletion to a tree the captures were no longer in."""
    root = tmp_path / "snapshots"
    root.mkdir()
    monkeypatch.setattr(config, "SNAPSHOT_ROOT", str(root))
    assert cases._snap_root() == os.path.realpath(str(root))

    outside = tmp_path / "not-evidence"
    outside.mkdir()
    (outside / "precious.txt").write_text("keep me")
    assert not os.path.realpath(str(outside)).startswith(cases._snap_root() + os.sep)


# Manifest self-protection (invariant 8) is already asserted properly in
# test_exporter_integrity.py::test_manifest_includes_integrity_warning_when_no_hmac_key,
# which builds a real pack and reads the manifest. A second, weaker check here
# would only dilute the signal.
