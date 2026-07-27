"""Case lifecycle, extracted from the Streamlit sidebar into cases.py.

The delete path carries a security-relevant guard: snapshot rows are used to
decide which directories to rmtree, so a row pointing outside the snapshot
root must never be acted on. That guard previously lived inline in app.py and
had no test; it does now.
"""
import os
import tempfile

import pytest

import cases


@pytest.fixture
def conn():
    td = tempfile.mkdtemp()
    from db import get_conn, init_db, migrate_db
    c = get_conn(os.path.join(td, "kwara.db"))
    init_db(c)
    migrate_db(c)
    yield c
    c.close()


def _add_snapshot(conn, case_id: int, screenshot_path: str) -> int:
    """Wire up message -> url_artifact -> scan_run -> snapshot for a file path."""
    mid = conn.execute(
        "INSERT INTO message_evidence (case_id, message_text, ingested_at) VALUES (?, '', '')",
        (case_id,),
    ).lastrowid
    aid = conn.execute(
        """INSERT INTO url_artifacts (message_id, case_id, original_url, domain, url_order, created_at)
           VALUES (?, ?, 'https://x.test/', 'x.test', 0, '')""",
        (mid, case_id),
    ).lastrowid
    sr = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at) VALUES (?, '')", (aid,)
    ).lastrowid
    snap = conn.execute(
        "INSERT INTO snapshots (scan_run_id, screenshot_path) VALUES (?, ?)",
        (sr, screenshot_path),
    ).lastrowid
    conn.commit()
    return snap


def test_create_and_get_case(conn):
    cid = cases.create_case(conn, "Op Nightingale", "desc",
                            browser_locale="zh-TW", browser_timezone="Asia/Taipei")
    case = cases.get_case(conn, cid)
    assert case["title"] == "Op Nightingale"
    assert case["browser_locale"] == "zh-TW"
    assert case["browser_timezone"] == "Asia/Taipei"


def test_create_case_rejects_blank_title(conn):
    with pytest.raises(ValueError):
        cases.create_case(conn, "   ")


def test_create_case_writes_audit_row(conn):
    cid = cases.create_case(conn, "audited")
    row = conn.execute(
        "SELECT action FROM audit_log WHERE case_id = ?", (cid,)
    ).fetchone()
    assert row["action"] == "create_case"


def test_list_cases_counts_urls(conn):
    cid = cases.create_case(conn, "counted")
    _add_snapshot(conn, cid, "")
    listed = next(c for c in cases.list_cases(conn) if c["id"] == cid)
    assert listed["url_count"] == 1
    assert listed["scan_count"] == 1


def test_require_case_raises_on_missing(conn):
    with pytest.raises(ValueError):
        cases.require_case(conn, 9999)


def test_set_case_locale(conn):
    cid = cases.create_case(conn, "relocate")
    cases.set_case_locale(conn, cid, "en-GB", "Europe/London")
    assert cases.get_case(conn, cid)["browser_locale"] == "en-GB"


@pytest.mark.parametrize("preset,expected", [
    ("tw", ("zh-TW", "Asia/Taipei")),
    ("uk", ("en-GB", "Europe/London")),
    (None, (None, None)),
])
def test_resolve_locale_presets(preset, expected):
    assert cases.resolve_locale(preset) == expected


def test_resolve_locale_explicit_wins_over_preset():
    assert cases.resolve_locale("tw", timezone_name="UTC") == ("zh-TW", "UTC")


def test_delete_requires_confirmation(conn):
    cid = cases.create_case(conn, "protected")
    with pytest.raises(ValueError):
        cases.delete_case(conn, cid, confirm="yes")
    assert cases.get_case(conn, cid) is not None


def test_delete_removes_case_and_children(conn):
    cid = cases.create_case(conn, "doomed")
    _add_snapshot(conn, cid, "")
    cases.delete_case(conn, cid, confirm="DELETE")
    assert cases.get_case(conn, cid) is None
    assert conn.execute(
        "SELECT COUNT(*) AS n FROM url_artifacts WHERE case_id = ?", (cid,)
    ).fetchone()["n"] == 0


def test_delete_only_touches_paths_under_snapshot_root(conn, tmp_path):
    """A snapshot row pointing outside data/snapshots/ must not be deleted.

    Without the confinement guard a corrupted or crafted DB row could steer
    shutil.rmtree at an arbitrary directory.
    """
    outside = tmp_path / "not_kwara"
    outside.mkdir()
    victim = outside / "important.png"
    victim.write_bytes(b"x")

    cid = cases.create_case(conn, "path traversal")
    _add_snapshot(conn, cid, str(victim))

    result = cases.delete_case(conn, cid, confirm="DELETE")

    assert victim.exists(), "deletion escaped the snapshot root"
    assert result["removed_dirs"] == []


def test_delete_removes_paths_inside_snapshot_root(conn, monkeypatch, tmp_path):
    snap_root = tmp_path / "snapshots"
    target_dir = snap_root / "42" / "20260101T000000_abcd"
    target_dir.mkdir(parents=True)
    shot = target_dir / "screenshot.png"
    shot.write_bytes(b"x")
    monkeypatch.setattr(cases, "_SNAP_ROOT", os.path.realpath(str(snap_root)))

    cid = cases.create_case(conn, "cleanup")
    _add_snapshot(conn, cid, str(shot))
    result = cases.delete_case(conn, cid, confirm="DELETE")

    assert not target_dir.exists()
    assert result["removed_dirs"] == [os.path.realpath(str(target_dir))]
