"""Shared SQL fragment builders (sql.py).

These fragments are interpolated into analysis queries via f-strings, so the
allow-list guard on latest_usable_snapshot() is the one thing standing
between "hard-coded column name" and "arbitrary string in SQL". Pin it.
"""
from __future__ import annotations

import pytest

from kwara.sql import LATEST_DONE_SCAN_RUN, latest_usable_snapshot


def test_latest_done_scan_run_shape():
    s = LATEST_DONE_SCAN_RUN
    assert "scan_runs" in s
    assert "status = 'done'" in s
    assert "ORDER BY id DESC LIMIT 1" in s
    # References the outer ua alias — enclosing query must provide it.
    assert "url_artifact_id = ua.id" in s


def test_latest_usable_snapshot_known_columns():
    for col in ("tracking_ids_json", "request_domains_json"):
        s = latest_usable_snapshot(col)
        assert "capture_status = 'ok'" in s
        assert f"{col} IS NOT NULL" in s
        assert f"TRIM({col})" in s
        assert "ORDER BY id DESC LIMIT 1" in s


def test_latest_usable_snapshot_rejects_unknown_column():
    # The guard is what keeps the f-string interpolation injection-free.
    with pytest.raises(ValueError):
        latest_usable_snapshot("tracking_ids_json; DROP TABLE snapshots")
    with pytest.raises(ValueError):
        latest_usable_snapshot("arbitrary_column")
