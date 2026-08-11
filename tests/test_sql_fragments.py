"""Shared SQL fragment builders (sql.py).

These fragments are interpolated into analysis queries via f-strings, so the
allow-list guard on usable_snapshots() is the one thing standing
between "hard-coded column name" and "arbitrary string in SQL". Pin it.
"""
from __future__ import annotations

import pytest

from kwara.sql import LATEST_DONE_SCAN_RUN, usable_snapshots


def test_latest_done_scan_run_shape():
    s = LATEST_DONE_SCAN_RUN
    assert "scan_runs" in s
    assert "status = 'done'" in s
    assert "ORDER BY id DESC LIMIT 1" in s
    # References the outer ua alias — enclosing query must provide it.
    assert "url_artifact_id = ua.id" in s


def test_usable_snapshots_known_columns():
    for col in ("tracking_ids_json", "request_domains_json"):
        s = usable_snapshots(col)
        assert "capture_status = 'ok'" in s
        assert f"{col} IS NOT NULL" in s
        assert f"TRIM({col})" in s
        # No LIMIT and no ordering: this returns every usable capture of the
        # scan, because a cloaker serves different personas different pages.
        # Behaviour is asserted against a real database in
        # test_capture_predicate.py.
        assert "LIMIT" not in s, "attribution must not collapse to one persona"


def test_usable_snapshots_rejects_unknown_column():
    # The guard is what keeps the f-string interpolation injection-free.
    with pytest.raises(ValueError):
        usable_snapshots("tracking_ids_json; DROP TABLE snapshots")
    with pytest.raises(ValueError):
        usable_snapshots("arbitrary_column")
