"""insights.case_insights() must surface Phase 4 OPSEC-forensics verdicts.

Before this, cloaking / header-forensics / opsec — the strongest evidence
layers — were collected and shown in their own sub-tabs but never reached
the Insights headline bullets, so an analyst reading only that screen would
not learn the operator was actively evading. These tests pin the wiring.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

from kwara.db import get_conn, init_db, migrate_db
from kwara.insights import case_insights


def _now():
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fresh_db():
    td = tempfile.mkdtemp()
    conn = get_conn(os.path.join(td, "test.db"))
    init_db(conn)
    migrate_db(conn)
    return conn


def _seed_case(conn) -> int:
    cur = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) VALUES ('t', '', ?, ?)",
        (_now(), _now()),
    )
    return cur.lastrowid


def _seed_scan(conn, case_id, url, *, final_url=None,
               cloaking=None, headers=None) -> int:
    """message → url_artifact → scan_run (+optional cloaking + a hop w/ headers)."""
    final_url = final_url or url
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink, actor_label,
           posted_at, message_text, screenshot_path, ingested_at)
           VALUES (?, '', '', '', '', '', '', ?)""",
        (case_id, _now()),
    )
    pid = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
        "url_order, created_at) VALUES (?, ?, ?, '', 0, ?)",
        (pid, case_id, url, _now()),
    )
    ua_id = cur.lastrowid
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
        "status, cloaking_signal_json) VALUES (?, ?, ?, 1, 'done', ?)",
        (ua_id, _now(), final_url, json.dumps(cloaking) if cloaking else None),
    )
    sr_id = cur.lastrowid
    if headers is not None:
        conn.execute(
            """INSERT INTO redirect_hops (scan_run_id, hop_order, url, status_code,
               response_headers_json, fetched_at)
               VALUES (?, 0, ?, 200, ?, ?)""",
            (sr_id, final_url, json.dumps(headers), _now()),
        )
    conn.commit()
    return sr_id


def test_cloaking_suspect_surfaces_in_bullets():
    conn = _fresh_db()
    cid = _seed_case(conn)
    _seed_scan(conn, cid, "https://crawler-landing.example/a?uid=1",
               final_url="https://visitor-landing.example/a",
               cloaking={"verdict": "cloaking_suspect", "diffs": ["final_domain"]})
    out = case_insights(conn, cid)
    blob = " ".join(out["bullets"])
    assert "cloaking" in blob.lower() or "Cloaking" in blob


def test_no_cloaking_verdict_produces_no_cloaking_bullet():
    conn = _fresh_db()
    cid = _seed_case(conn)
    _seed_scan(conn, cid, "https://clean.example/a?uid=1",
               cloaking={"verdict": "no_cloaking"})
    out = case_insights(conn, cid)
    assert not any("cloaking" in b.lower() for b in out["bullets"])


def test_fake_version_header_surfaces_in_bullets():
    conn = _fresh_db()
    cid = _seed_case(conn)
    # Apache 2.5.1 never shipped — detect_fake_versions should flag it.
    _seed_scan(conn, cid, "https://fake.example/",
               headers=[["x-powered-by", "Apache/2.5.1 OpenSSL/1.1.2e"]])
    out = case_insights(conn, cid)
    assert any("2.5.1" in b for b in out["bullets"])


def test_clean_case_has_no_phase4_bullets():
    conn = _fresh_db()
    cid = _seed_case(conn)
    _seed_scan(conn, cid, "https://plain.example/",
               headers=[["server", "nginx"]])
    out = case_insights(conn, cid)
    blob = " ".join(out["bullets"]).lower()
    assert "cloaking" not in blob
    assert "2.5.1" not in blob
