"""The investigator's own address must not survive into evidence, and a capture
batch that produced no capture must not exit 0.

Both came out of the same live store: 582 files carrying 22 of the analyst's
addresses, all echoed by third-party ad responses; and six `file_missing` rows
reported as `snapshots: 6` because the Playwright browser was not installed.
"""
import json
import os
import sqlite3
import tempfile

import pytest

from kwara import cli, ip_exposure
from kwara.ip_exposure import REDACTION_MARKER

CLIENT4 = "203.0.113.7"     # RFC 5737 documentation address: never a real visitor
CLIENT6 = "2001:db8:10:20:30:40:50:7"   # RFC 3849; full form, as browsers report it
SERVER = "198.51.100.10"


def _har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def _entry(url, headers=None, body=None, server=SERVER):
    return {
        "request": {"url": url, "headers": []},
        "response": {"status": 200, "headers": headers or [],
                     "content": {"text": body or "", "mimeType": "text/plain"}},
        "serverIPAddress": server,
    }


def _write(tmp, name, data):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(data if isinstance(data, str) else json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# discovery: the echo pass
# ---------------------------------------------------------------------------

def test_echo_headers_yield_the_client_not_the_server():
    har = _har([_entry("https://www.temu.com/api/adx/cm/pixel-google?x=1",
                       headers=[{"name": "cip", "value": CLIENT4},
                                {"name": "x-edge-ip", "value": SERVER}])])
    hits = ip_exposure.echo_candidates_in_har(har)
    assert [h["ip"] for h in hits] == [CLIENT4]
    assert hits[0]["header"] == "cip"


def test_x_forwarded_for_takes_the_first_hop_only():
    proxy = "198.51.100.20"
    har = _har([_entry("https://gtrace.mediago.io/ju/cs/google",
                       headers=[{"name": "X-Forwarded-For",
                                 "value": f"{CLIENT4}, {proxy}"}])])
    assert [h["ip"] for h in ip_exposure.echo_candidates_in_har(har)] == [CLIENT4]


def test_query_parameter_and_bare_body_count_as_echoes():
    har = _har([
        _entry(f"https://ad.example/cm?auip={CLIENT4}&c=1"),
        _entry("https://whatismyip.example/", body=f"  {CLIENT6}\n"),
    ])
    hits = ip_exposure.echo_candidates_in_har(har)
    assert {h["where"] for h in hits} == {"request-query", "response-body"}
    assert {h["ip"] for h in hits} == {CLIENT4, CLIENT6}


def test_addresses_that_are_servers_or_hosts_are_not_candidates():
    har = _har([_entry(f"https://{SERVER}/img.gif",
                       headers=[{"name": "cip", "value": SERVER}], server=SERVER)])
    assert ip_exposure.echo_candidates_in_har(har) == []


def test_private_and_version_like_strings_are_ignored():
    har = _har([_entry("https://a.example/?ip=10.0.0.5",
                       headers=[{"name": "cip", "value": "192.168.1.9"}],
                       body="192.0.2.15,0,1.02")])
    assert ip_exposure.echo_candidates_in_har(har) == []


def test_embedded_player_remote_host_is_an_echo_whatever_the_address():
    """An embedded video player writes the viewer's address into its page
    config. Behind a VPN that address belongs to no local ISP, so only the
    label can identify it — a range check let thirteen such files through."""
    config = ('ytcfg.set({"INNERTUBE_CONTEXT":{"client":{"hl":"zh-TW","gl":"TW",'
              f'"remoteHost":"{CLIENT6}","deviceMake":""}}}});')
    har = _har([_entry("https://player.example/embed/abc", body=config)])
    hits = ip_exposure.echo_candidates_in_har(har)
    assert [(h["where"], h["marker"], h["ip"]) for h in hits] == [
        ("response-text", "remoteHost", CLIENT6)]


def test_ip_path_segment_of_a_video_url_is_an_echo():
    har = _har([
        _entry(f"https://rr1.video.example/videoplayback/expire/1/ip/{CLIENT4}/ipbits/0/x"),
        # The CDN may already blank it; the unspecified address is nobody's.
        _entry("https://rr2.video.example/videoplayback/expire/1/ip/0.0.0.0/ipbits/0/x"),
    ])
    hits = ip_exposure.echo_candidates_in_har(har)
    assert [(h["where"], h["ip"]) for h in hits] == [("request-path", CLIENT4)]


def test_ip_orig_key_in_a_response_body_is_an_echo():
    har = _har([_entry("https://geo.example/lookup",
                       body=f'{{"country":"TW","ipOrig":"{CLIENT4}","asn":1}}')])
    assert [h["ip"] for h in ip_exposure.echo_candidates_in_har(har)] == [CLIENT4]


def test_documentation_addresses_are_public_but_private_ones_are_not():
    assert ip_exposure._is_public(CLIENT4) and ip_exposure._is_public(CLIENT6)
    assert not ip_exposure._is_public("10.0.0.1")
    assert not ip_exposure._is_public("0.0.0.0")


def test_html_your_ip_label_is_an_echo_and_flags_the_screenshot(tmp_path):
    html = _write(tmp_path, "page.html",
                  f"<div class='err'>您的IP: <span>{CLIENT4}</span></div>")
    res = ip_exposure.scan_capture(None, html, redact=False)
    assert res["ips"] == [CLIENT4]
    assert res["screenshot_may_show_ip"] is True


def test_configured_addresses_join_the_known_pass(tmp_path, monkeypatch):
    other = "203.0.113.99"
    har = _write(tmp_path, "traffic.har",
                 _har([_entry("https://x.example/", body=f'{{"visitor":"{other}"}}')]))
    monkeypatch.setenv("KWARA_INVESTIGATOR_IPS", other)
    res = ip_exposure.scan_capture(har, None, redact=False)
    assert res["ips"] == [other] and res["occurrences"] == 1


# ---------------------------------------------------------------------------
# redaction: the known pass
# ---------------------------------------------------------------------------

def test_redaction_removes_every_occurrence_and_keeps_har_valid(tmp_path):
    har = _write(tmp_path, "traffic.har", _har([
        _entry("https://www.temu.com/api/adx/cm/pixel?x=1",
               headers=[{"name": "cip", "value": CLIENT4}]),
        _entry("https://other.example/beacon",
               body=f'{{"seen_from":"{CLIENT4}","ok":true}}'),   # outside any echo position
    ]))
    res = ip_exposure.scan_capture(har, None, redact=True)
    assert res["redacted"] is True and res["occurrences"] == 2
    text = open(har, encoding="utf-8").read()
    assert CLIENT4 not in text and text.count(REDACTION_MARKER) == 2
    json.loads(text)
    assert not os.path.exists(os.path.join(tmp_path, "traffic.original-unredacted.har"))


def test_keep_original_preserves_bytes_and_never_overwrites(tmp_path):
    har = _write(tmp_path, "traffic.har",
                 _har([_entry("https://a/", headers=[{"name": "cip", "value": CLIENT4}])]))
    before = open(har, "rb").read()
    ip_exposure.redact_file(har, [CLIENT4], keep_original=True)
    orig = os.path.join(tmp_path, "traffic.original-unredacted.har")
    assert open(orig, "rb").read() == before
    # A second round (a newly discovered address) must not clobber the backup.
    with open(har, "a", encoding="utf-8") as f:
        f.write("")
    ip_exposure.redact_file(har, ["203.0.113.8"], keep_original=True)
    assert open(orig, "rb").read() == before


def test_redaction_is_abandoned_if_the_har_would_break(tmp_path):
    # Replacing the address inside a JSON key would leave valid JSON, so force
    # a break: the address is the whole document.
    p = _write(tmp_path, "traffic.har", CLIENT4)
    with pytest.raises(json.JSONDecodeError):
        ip_exposure.redact_file(p, [CLIENT4])
    assert open(p, encoding="utf-8").read() == CLIENT4


def test_nothing_found_is_a_quiet_result(tmp_path):
    har = _write(tmp_path, "traffic.har", _har([_entry("https://a/")]))
    res = ip_exposure.scan_capture(har, None, redact=True)
    assert res["ips"] == [] and res["redacted"] is False and "redaction" not in res


# ---------------------------------------------------------------------------
# the capture path and the CLI
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path():
    return os.path.join(tempfile.mkdtemp(), "kwara.db")


def _json(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr().out
    return code, json.loads(out)


def _seed_scan_run(db_path, case_id, url="https://farm.example/"):
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO message_evidence (case_id, message_text, ingested_at) "
                 "VALUES (?, '', '2026-01-01')", (case_id,))
    mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO url_artifacts (message_id, case_id, original_url, domain, "
                 "url_order, created_at) VALUES (?, ?, ?, 'farm.example', 0, '2026-01-01')",
                 (mid, case_id, url))
    ua = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count, "
                 "status) VALUES (?, '2026-01-01', ?, 1, 'done')", (ua, url))
    sr = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit(); conn.close()
    return sr


def _fake_batch(status, detail, har_text=None):
    def run_snapshot_batch(conn, scan_run_ids, env_override=None):
        ids = []
        for sr in scan_run_ids:
            har_path = None
            if har_text is not None:
                d = tempfile.mkdtemp(); har_path = os.path.join(d, "traffic.har")
                open(har_path, "w").write(har_text)
            conn.execute(
                "INSERT INTO snapshots (scan_run_id, final_domain, captured_at, "
                "capture_status, capture_detail, capture_method, har_path) "
                "VALUES (?, 'farm.example', '2026-01-01', ?, ?, 'playwright', ?)",
                (sr, status, detail, har_path))
            ids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        conn.commit()
        return ids
    return run_snapshot_batch


def test_snapshot_batch_with_no_capture_exits_nonzero(capsys, db_path, monkeypatch):
    from kwara import pipeline
    _, created = _json(capsys, "--db", db_path, "case", "new", "--title", "t")
    case = created["case_id"]
    _seed_scan_run(db_path, case)
    monkeypatch.setattr(pipeline, "run_snapshot_batch", _fake_batch(
        "file_missing", "no result file; stderr: Please run: playwright install"))
    code = cli.main(["--db", db_path, "run", "snapshot", "--case", str(case)])
    captured = capsys.readouterr()
    out = json.loads(captured.out)
    assert code == 1
    assert out["snapshots"] == 1 and out["captured"] == 0 and out["failed"] == 1
    assert out["by_status"] == {"file_missing": 1}
    assert out["failures"][0]["status"] == "file_missing"
    assert "playwright install chromium" in captured.err


def test_snapshot_batch_with_a_capture_exits_zero(capsys, db_path, monkeypatch):
    from kwara import pipeline
    _, created = _json(capsys, "--db", db_path, "case", "new", "--title", "t")
    case = created["case_id"]
    _seed_scan_run(db_path, case)
    monkeypatch.setattr(pipeline, "run_snapshot_batch", _fake_batch("ok", None))
    code, out = _json(capsys, "--db", db_path, "run", "snapshot", "--case", str(case))
    assert code == 0 and out["captured"] == 1 and "exit_code" not in out


def test_record_capture_redacts_before_the_row_is_written(db_path, tmp_path, monkeypatch):
    """The real recorder: a HAR echoing the client address is rewritten and the
    snapshot row says so, all before anything downstream can bind the bytes."""
    from kwara import snapshots
    from kwara.db import get_conn, init_db, migrate_db
    conn = get_conn(db_path); init_db(conn); migrate_db(conn)
    conn.execute("INSERT INTO cases (title, created_at, updated_at) VALUES ('t','x','x')")
    case = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    sr = _seed_scan_run(db_path, case)
    har = _write(tmp_path, "traffic.har", _har([
        _entry("https://www.temu.com/api/adx/cm/pixel", headers=[{"name": "cip", "value": CLIENT4}])]))
    html = _write(tmp_path, "page.html", "<html><body>hello</body></html>")
    shot = os.path.join(tmp_path, "screenshot.png"); open(shot, "wb").write(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
    meta = {"final_url": "https://farm.example/", "final_domain": "farm.example",
            "hop_count": 1, "case_id": case}
    r = {"screenshot_path": shot, "html_path": html, "har_path": har,
         "request_domains": ["www.temu.com"], "error": None}
    sid = snapshots._record_capture(conn, sr, meta, r)
    row = conn.execute("SELECT investigator_ip_json, har_path FROM snapshots WHERE id = ?",
                       (sid,)).fetchone()
    info = json.loads(row["investigator_ip_json"])
    assert info["ips"] == [CLIENT4] and info["redacted"] is True
    assert CLIENT4 not in open(row["har_path"], encoding="utf-8").read()


def test_evidence_ip_scan_reports_then_redacts_with_backup(capsys, db_path, monkeypatch, tmp_path):
    from kwara import pipeline
    _, created = _json(capsys, "--db", db_path, "case", "new", "--title", "t")
    case = created["case_id"]
    _seed_scan_run(db_path, case)
    har_text = json.dumps(_har([_entry("https://a/", headers=[{"name": "x-client-ip", "value": CLIENT4}])]))
    # Bypass the recorder so the file lands unredacted, as a pre-feature store would have it.
    monkeypatch.setattr(pipeline, "run_snapshot_batch", _fake_batch("ok", None, har_text))
    _json(capsys, "--db", db_path, "run", "snapshot", "--case", str(case))
    code, rep = _json(capsys, "--db", db_path, "evidence", "ip-scan", "--case", str(case))
    assert code == 0 and rep["captures_with_ip"] == 1 and rep["redacted"] is False
    code, rep = _json(capsys, "--db", db_path, "evidence", "ip-scan", "--case", str(case), "--redact")
    item = rep["items"][0]
    assert item["redacted"] is True
    har_path = item["files_affected"][0]
    assert CLIENT4 not in open(har_path, encoding="utf-8").read()
    assert os.path.exists(har_path.replace("traffic.har", "traffic.original-unredacted.har"))
    code, rep = _json(capsys, "--db", db_path, "evidence", "ip-scan", "--case", str(case))
    assert rep["captures_with_ip"] == 0
