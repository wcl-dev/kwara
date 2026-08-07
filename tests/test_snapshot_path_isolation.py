"""Tests for per-capture artifact directory isolation (codex review #1).

The bug: paths used to be `data/snapshots/{scan_run_id}/<filename>`, so a
re-snapshot, lightweight fetch, or manual upload on the same scan_run
silently overwrote files older snapshot rows still referenced — silent
evidence corruption.

The fix (kwara/snapshots.py::_per_capture_dir) routes each capture into a
fresh timestamped+random subdirectory. These tests pin that.
"""
import os
import re

from snapshots import _per_capture_dir


def test_per_capture_dir_creates_unique_subdir_per_call():
    a = _per_capture_dir(1)
    b = _per_capture_dir(1)
    assert a != b, "two calls for the same scan_run_id must yield different dirs"
    assert os.path.isdir(a) and os.path.isdir(b)


def test_per_capture_dir_format_includes_timestamp_and_random_suffix():
    """Format: data/snapshots/{scan_run_id}/{YYYYMMDDTHHMMSSffffff}_{rand4}/"""
    p = _per_capture_dir(42)
    leaf = os.path.basename(p)
    # 14-digit base (YYYYMMDD + T + HHMMSS) + microseconds(6) + _ + 4 hex
    assert re.fullmatch(r"\d{8}T\d{6}\d{6}_[0-9a-f]{4}", leaf), leaf
    # Parent is the scan_run_id directory
    assert os.path.basename(os.path.dirname(p)) == "42"


def test_per_capture_dir_does_not_collide_under_rapid_calls():
    """Even if many captures fire in tight succession (microsecond
    resolution may overlap on slow filesystems), the random suffix prevents
    collisions."""
    seen = set()
    for _ in range(100):
        d = _per_capture_dir(99)
        assert d not in seen
        seen.add(d)


def test_per_capture_dir_lives_under_kwara_data_snapshots():
    """Sanity: the path is under kwara/data/snapshots (the data root)."""
    p = _per_capture_dir(7)
    assert "/data/snapshots/" in p.replace(os.sep, "/")
    # cleanup
    import shutil; shutil.rmtree(p)


def test_two_scan_runs_have_separate_parent_directories():
    a = _per_capture_dir(1)
    b = _per_capture_dir(2)
    # Different scan_run_id parents
    assert os.path.basename(os.path.dirname(a)) == "1"
    assert os.path.basename(os.path.dirname(b)) == "2"
