"""Acquisition records — keeping the bytes an analysis was derived from.

kwara read an ads.txt response, hashed it, parsed the DIRECT accounts and
discarded the bytes. So its strongest binding signal — two domains serving a
byte-identical ads.txt — was a claim a recipient had to take on trust: they
could not recompute either hash, and where the site had since started refusing
requests they could not re-fetch it. blockedsite.example was recorded on 2026-08-05
serving sha 3bb8f682471e, 278 accounts, identical to siblingsite.example, and returned
HTTP 403 the following day.

Each test here pins one property that makes a recorded fetch re-checkable.
"""
import hashlib
import json
import os
import sqlite3

import pytest

from kwara import acquisition as acq
from kwara import config
from kwara.db import get_conn, init_db, migrate_db


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    conn = get_conn(str(tmp_path / "t.db"))
    init_db(conn)
    migrate_db(conn)
    conn.execute("INSERT INTO cases (title, description, created_at, updated_at)"
                 " VALUES ('t','','','')")
    conn.commit()
    return conn


def _scan_run(conn, url="https://a.test/"):
    cur = conn.execute(
        """INSERT INTO message_evidence (case_id, platform, permalink,
           actor_label, posted_at, message_text, screenshot_path, ingested_at)
           VALUES (1,'','','','','','','')""")
    cur = conn.execute(
        "INSERT INTO url_artifacts (message_id, case_id, original_url, domain,"
        " url_order, created_at) VALUES (?,1,?,'',0,'')", (cur.lastrowid, url))
    cur = conn.execute(
        "INSERT INTO scan_runs (url_artifact_id, run_at, final_url, hop_count,"
        " status) VALUES (?,'',?,0,'done')", (cur.lastrowid, url))
    conn.commit()
    return cur.lastrowid


# ── the bytes come back exactly ───────────────────────────────────────────

def test_the_stored_body_is_byte_for_byte_what_was_fetched(db):
    """CRLF line endings, a BOM and a trailing NUL all survive. ads.txt
    identity is byte identity — normalising anything here would make two
    different files hash the same."""
    body = (b"\xef\xbb\xbfgoogle.com, pub-1, DIRECT\r\n"
            b"appnexus.com, 123, RESELLER\r\n\x00")
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=body)
    row = db.execute("SELECT * FROM acquisitions WHERE id=?", (aid,)).fetchone()

    with open(row["body_path"], "rb") as fh:
        assert fh.read() == body
    assert row["captured_sha256"] == hashlib.sha256(body).hexdigest()
    assert row["complete_sha256"] == row["captured_sha256"]
    assert row["captured_bytes"] == len(body)


def test_an_empty_body_is_still_a_body(db):
    """A 200 with zero bytes is a real observation and not the same as a
    network error. It must be distinguishable from one."""
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"")
    row = db.execute("SELECT * FROM acquisitions WHERE id=?", (aid,)).fetchone()
    assert row["body_path"] and os.path.isfile(row["body_path"])
    assert row["complete_sha256"] == hashlib.sha256(b"").hexdigest()
    assert acq.verify(db, aid) == acq.VERIFIED


# ── the two hashes, and why they are two ──────────────────────────────────

def test_a_truncated_capture_has_no_complete_hash(db):
    """The whole point of the split. A prefix hash offered as `complete`
    would be matched as byte-identity by template clustering, binding two
    domains on the first 256 KB of files that differ after that."""
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"x" * 100,
                           truncated=True)
    row = db.execute("SELECT * FROM acquisitions WHERE id=?", (aid,)).fetchone()

    assert row["captured_sha256"] == hashlib.sha256(b"x" * 100).hexdigest()
    assert row["complete_sha256"] is None
    assert row["truncated"] == 1
    assert acq.verify(db, aid) == acq.TRUNCATED
    assert acq.identity_hash(db, aid) is None, \
        "a truncated capture must never supply an identity hash"


def test_a_network_error_records_metadata_and_no_body(db):
    aid = acq.record_fetch(db, requested_url="https://gone.test/ads.txt",
                           status="error", error="connection refused")
    row = db.execute("SELECT * FROM acquisitions WHERE id=?", (aid,)).fetchone()
    assert row["body_path"] is None
    assert row["captured_sha256"] is None and row["complete_sha256"] is None
    assert row["error"] == "connection refused"
    assert acq.verify(db, aid) == acq.LEGACY_UNVERIFIABLE


def test_a_non_200_body_is_kept(db):
    """A 403 challenge page is what the site served an investigator. It is
    among the most useful things to keep, and the reason blockedsite.example's
    2026-08-05 observation cannot be reacquired."""
    challenge = b"<html><body>Just a moment...</body></html>"
    aid = acq.record_fetch(db, requested_url="https://w.test/ads.txt",
                           status="non_200", status_code=403, body=challenge)
    row = db.execute("SELECT * FROM acquisitions WHERE id=?", (aid,)).fetchone()
    assert row["status_code"] == 403
    with open(row["body_path"], "rb") as fh:
        assert fh.read() == challenge


# ── append only ───────────────────────────────────────────────────────────

def test_the_module_never_updates_or_deletes(db):
    """An acquisition record describes a moment; a later moment is a different
    record. Asserted against the parsed source, because this is the property
    that makes an earlier observation survive a re-fetch."""
    import ast
    import inspect

    src = inspect.getsource(acq)
    for banned in ("UPDATE ", "DELETE FROM", "DROP "):
        assert banned not in src.upper(), banned

    destructive = {"remove", "unlink", "rmtree", "replace", "rename",
                   "truncate", "write_text", "write_bytes"}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            fn = node.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                    else fn.id if isinstance(fn, ast.Name) else "")
            assert name not in destructive, f"{name}() at line {node.lineno}"


def test_a_refetch_inserts_and_leaves_the_earlier_body_intact(db):
    first = acq.record_fetch(db, requested_url="https://w.test/ads.txt",
                             status="ok", status_code=200,
                             body=b"google.com, pub-1, DIRECT\n")
    first_path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                            (first,)).fetchone()["body_path"]

    second = acq.record_fetch(db, requested_url="https://w.test/ads.txt",
                              status="non_200", status_code=403,
                              body=b"blocked")

    assert second != first
    assert db.execute("SELECT COUNT(*) FROM acquisitions").fetchone()[0] == 2
    assert os.path.isfile(first_path)
    with open(first_path, "rb") as fh:
        assert fh.read() == b"google.com, pub-1, DIRECT\n"
    assert acq.verify(db, first) == acq.VERIFIED


def test_two_bodies_never_share_a_file(db):
    paths = {db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                        (acq.record_fetch(db, requested_url="https://a.test/x",
                                          status="ok", body=b"same"),)
                        ).fetchone()["body_path"] for _ in range(5)}
    assert len(paths) == 5, "an identical body reused an artifact path"


# ── verification ──────────────────────────────────────────────────────────

def test_an_altered_body_fails_verification(db):
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"original\n")
    path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                      (aid,)).fetchone()["body_path"]
    with open(path, "wb") as fh:
        fh.write(b"tampered\n")

    assert acq.verify(db, aid) == acq.BODY_MISMATCH
    assert acq.identity_hash(db, aid) is None


def test_a_deleted_body_fails_verification(db):
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"original\n")
    path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                      (aid,)).fetchone()["body_path"]
    os.remove(path)

    assert acq.verify(db, aid) == acq.BODY_MISSING
    assert acq.identity_hash(db, aid) is None


def test_only_a_verified_row_yields_an_identity_hash(db):
    body = b"google.com, pub-1, DIRECT\n"
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=body)
    assert acq.identity_hash(db, aid) == hashlib.sha256(body).hexdigest()


# ── acquisition context ───────────────────────────────────────────────────

def test_duplicate_response_headers_are_all_kept(db):
    """A response repeats Set-Cookie routinely, and a dict keeps only the
    last. Cookie domain leakage is one of the header-forensics signals."""
    headers = [["Set-Cookie", "a=1; Domain=.origin.test"],
               ["Set-Cookie", "b=2; Domain=.cdn.test"],
               ["Server", "nginx"]]
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"x",
                           response_headers=headers)
    stored = json.loads(db.execute(
        "SELECT response_headers_json FROM acquisitions WHERE id=?",
        (aid,)).fetchone()["response_headers_json"])
    assert stored == headers
    assert sum(1 for k, _ in stored if k == "Set-Cookie") == 2


def test_the_tool_version_is_recorded(db):
    aid = acq.record_fetch(db, requested_url="https://a.test/x", status="ok",
                           body=b"x")
    row = db.execute("SELECT tool_version, user_agent FROM acquisitions "
                     "WHERE id=?", (aid,)).fetchone()
    assert row["tool_version"] and row["tool_version"] != "unknown"


def test_headers_as_pairs_keeps_repeats_from_a_urllib3_style_mapping():
    class Raw:
        def keys(self):
            return ["Set-Cookie", "Server"]

        def getlist(self, name):
            return {"Set-Cookie": ["a=1", "b=2"], "Server": ["nginx"]}[name]

    assert acq.headers_as_pairs(Raw()) == [
        ["Set-Cookie", "a=1"], ["Set-Cookie", "b=2"], ["Server", "nginx"]]


def test_headers_as_pairs_falls_back_to_a_plain_mapping():
    assert acq.headers_as_pairs({"Server": "nginx"}) == [["Server", "nginx"]]


# ── through the real case path ────────────────────────────────────────────

def test_the_case_path_persists_the_body_it_parsed(db, site, monkeypatch):
    """End to end: what `run adstxt` stores must be re-hashable, and the hash
    on the derived record must be the hash of the retained bytes."""
    from kwara.adstxt import fetch_and_store_ads_txt

    body = b"clickforce.com.tw, pub-873, DIRECT\r\nOWNERDOMAIN=owner.test\r\n"
    site.route("/ads.txt", body=body)
    sr = _scan_run(db, site.url + "/")

    result = fetch_and_store_ads_txt(db, sr)
    assert result["status"] == "ok"
    assert "acquisition_id" in result, "the fetch was not recorded"

    aid = result["acquisition_id"]
    assert acq.verify(db, aid) == acq.VERIFIED
    assert acq.identity_hash(db, aid) == result["raw_sha256"], \
        "the derived hash and the retained bytes disagree"

    row = db.execute("SELECT * FROM acquisitions WHERE id=?", (aid,)).fetchone()
    with open(row["body_path"], "rb") as fh:
        assert fh.read() == body
    assert row["scan_run_id"] == sr
    assert row["status_code"] == 200


def test_the_case_path_keeps_a_403_body(db, site):
    from kwara.adstxt import fetch_and_store_ads_txt

    site.route("/ads.txt", status=403,
               body=b"<html>Just a moment</html>")
    sr = _scan_run(db, site.url + "/")

    result = fetch_and_store_ads_txt(db, sr)
    assert result["status"] == "non_200"
    row = db.execute("SELECT * FROM acquisitions WHERE id=?",
                     (result["acquisition_id"],)).fetchone()
    assert row["status_code"] == 403
    with open(row["body_path"], "rb") as fh:
        assert b"Just a moment" in fh.read()


def test_a_forced_refetch_keeps_both_observations(db, site):
    """The blockedsite case in miniature: a domain served a real file, then
    started refusing. Both must remain on record, and the earlier one must
    still verify."""
    from kwara.adstxt import fetch_and_store_ads_txt

    site.route("/ads.txt", body=b"google.com, pub-1, DIRECT\n")
    sr = _scan_run(db, site.url + "/")
    first = fetch_and_store_ads_txt(db, sr)["acquisition_id"]

    site.route("/ads.txt", status=403, body=b"blocked")
    second = fetch_and_store_ads_txt(db, sr, force=True)["acquisition_id"]

    assert second != first
    assert acq.verify(db, first) == acq.VERIFIED
    assert acq.identity_hash(db, first) == hashlib.sha256(
        b"google.com, pub-1, DIRECT\n").hexdigest()


# ── what downstream is allowed to call "verified" ─────────────────────────

def _domain_with_ads(conn, url, ads):
    sr = _scan_run(conn, url)
    conn.execute("UPDATE scan_runs SET ads_txt_json=? WHERE id=?",
                 (json.dumps(ads), sr))
    conn.commit()
    return sr


def _ads(sha, *, acquisition_id=None, records=(("clickforce.com.tw", "873"),)):
    out = {"url": "https://x/ads.txt", "status": "ok", "status_code": 200,
           "raw_sha256": sha, "record_count": len(records),
           "records": [{"adsystem": a, "seller_id": s, "relationship": "DIRECT",
                        "cert_authority_id": None} for a, s in records],
           "owner_domain": None, "manager_domain": None}
    if acquisition_id is not None:
        out["acquisition_id"] = acquisition_id
    return out


def _template(conn):
    from kwara.clustering_infra import shared_ad_accounts
    rows = shared_ad_accounts(conn, 1)["by_template"]
    return rows[0] if rows else None


def test_a_template_match_is_verified_only_when_both_bodies_re_hash(db):
    body = b"clickforce.com.tw, pub-873, DIRECT\n"
    sha = hashlib.sha256(body).hexdigest()
    ids = []
    for host in ("a.test", "b.test"):
        ids.append(acq.record_fetch(db, requested_url=f"https://{host}/ads.txt",
                                    status="ok", status_code=200, body=body))
    for host, aid in zip(("a.test", "b.test"), ids):
        _domain_with_ads(db, f"https://{host}/", _ads(sha, acquisition_id=aid))

    t = _template(db)
    assert t["domain_count"] == 2
    assert t["verification"] == acq.VERIFIED


def test_a_template_match_with_no_retained_bytes_is_legacy_unverifiable(db):
    """Every observation made before retention existed. The cluster is still
    reported — it is real historical evidence — but it cannot be called
    verified, and the label says which."""
    sha = "d" * 64
    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads(sha))

    t = _template(db)
    assert t["domain_count"] == 2
    assert t["verification"] == acq.LEGACY_UNVERIFIABLE
    assert set(t["verification_by_domain"].values()) == {acq.LEGACY_UNVERIFIABLE}


def test_one_altered_body_downgrades_the_whole_cluster(db):
    """A cluster is only as checkable as its weakest side: byte-identity is a
    claim about BOTH files."""
    body = b"clickforce.com.tw, pub-873, DIRECT\n"
    sha = hashlib.sha256(body).hexdigest()
    ids = []
    for host in ("a.test", "b.test"):
        ids.append(acq.record_fetch(db, requested_url=f"https://{host}/ads.txt",
                                    status="ok", status_code=200, body=body))
    for host, aid in zip(("a.test", "b.test"), ids):
        _domain_with_ads(db, f"https://{host}/", _ads(sha, acquisition_id=aid))

    path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                      (ids[1],)).fetchone()["body_path"]
    with open(path, "wb") as fh:
        fh.write(b"tampered\n")

    t = _template(db)
    assert t["verification"] == acq.BODY_MISMATCH
    assert t["verification_by_domain"]["b.test"] == acq.BODY_MISMATCH
    assert t["verification_by_domain"]["a.test"] == acq.VERIFIED


def test_a_half_retained_cluster_is_not_verified(db):
    """The state the corpus is actually in during the transition: one side
    fetched before retention, one after."""
    body = b"clickforce.com.tw, pub-873, DIRECT\n"
    sha = hashlib.sha256(body).hexdigest()
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=body)
    _domain_with_ads(db, "https://a.test/", _ads(sha, acquisition_id=aid))
    _domain_with_ads(db, "https://b.test/", _ads(sha))

    t = _template(db)
    assert t["verification"] == acq.LEGACY_UNVERIFIABLE
    assert t["verification_by_domain"] == {"a.test": acq.VERIFIED,
                                           "b.test": acq.LEGACY_UNVERIFIABLE}


# ── the evidence pack ─────────────────────────────────────────────────────

def _export(conn):
    from kwara.exporter import export_case
    return export_case(conn, 1)


def test_the_pack_carries_the_bytes_and_they_re_hash(db, tmp_path, monkeypatch):
    """Until 2026-08-12 a pack carried no ads.txt evidence at all — not the
    bodies, not even the derived JSON. A recipient had to trust the number."""
    import zipfile

    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    body = b"clickforce.com.tw, pub-873, DIRECT\r\n"
    sr = _scan_run(db, "https://a.test/")
    aid = acq.record_fetch(db, scan_run_id=sr,
                           requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=body)
    db.execute("UPDATE scan_runs SET ads_txt_json=? WHERE id=?",
               (json.dumps(_ads(hashlib.sha256(body).hexdigest(),
                                acquisition_id=aid)), sr))
    db.commit()

    with zipfile.ZipFile(_export(db)) as zf:
        names = zf.namelist()
        assert "acquisitions/acquisitions.csv" in names
        body_arc = next(n for n in names
                        if n.startswith("acquisitions/") and n.endswith(".body"))
        assert zf.read(body_arc) == body, "the pack's bytes are not the fetched bytes"

        import csv as _csv
        import io as _io
        row = list(_csv.DictReader(_io.StringIO(
            zf.read("acquisitions/acquisitions.csv").decode())))[0]
        assert row["complete_sha256"] == hashlib.sha256(body).hexdigest()
        # The manifest must cover the body, or the pack cannot vouch for it.
        manifest = json.loads(zf.read("manifest.json"))
        assert body_arc in manifest["files"]


def test_export_refuses_when_a_referenced_body_is_gone(db, tmp_path, monkeypatch):
    """Fail closed. A pack that silently omits the bytes a finding rests on
    is worse than no pack, because it looks complete."""
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    sr = _scan_run(db, "https://a.test/")
    aid = acq.record_fetch(db, scan_run_id=sr,
                           requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"x")
    os.remove(db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                         (aid,)).fetchone()["body_path"])

    with pytest.raises(ValueError, match="not.*on disk|missing"):
        _export(db)


def test_export_refuses_when_a_body_no_longer_matches_its_hash(db, tmp_path,
                                                               monkeypatch):
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    sr = _scan_run(db, "https://a.test/")
    aid = acq.record_fetch(db, scan_run_id=sr,
                           requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=b"original")
    path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                      (aid,)).fetchone()["body_path"]
    with open(path, "wb") as fh:
        fh.write(b"tampered")

    with pytest.raises(ValueError, match="does not match"):
        _export(db)


def test_a_body_less_row_still_exports(db, tmp_path, monkeypatch):
    """Network errors and pre-retention rows must travel too — their absence
    is what tells a reader the finding is unverifiable."""
    import zipfile

    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    sr = _scan_run(db, "https://a.test/")
    acq.record_fetch(db, scan_run_id=sr, requested_url="https://a.test/ads.txt",
                     status="error", error="connection refused")

    with zipfile.ZipFile(_export(db)) as zf:
        import csv as _csv
        import io as _io
        row = list(_csv.DictReader(_io.StringIO(
            zf.read("acquisitions/acquisitions.csv").decode())))[0]
        assert row["body_file"] == ""
        assert row["error"] == "connection refused"


# ── discovery banking: immutable, automatic, incremental ──────────────────

def test_an_existing_bank_is_refused_before_any_request(tmp_path, monkeypatch):
    """The refusal has to be free. Discovering it after a five-figure sweep
    has already contacted every candidate spends the exposure twice."""
    from kwara import discovery

    existing = tmp_path / "round1.jsonl"
    existing.write_text('{"domain":"a.test"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        discovery.open_run(str(existing))

    assert existing.read_text(encoding="utf-8") == '{"domain":"a.test"}\n', \
        "the earlier run was modified"


def test_omitting_a_bank_still_banks(tmp_path, monkeypatch):
    """`--bank` was documented as the default and was not one. Omitting it
    threw away the sweep's raw hashes and account lists — the historical
    screen_results.jsonl has no raw_sha256, so clustering it returns nothing
    to this day."""
    from kwara import discovery

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    path = discovery.open_run(None)
    assert path.startswith(str(tmp_path / "data" / "discovery-runs"))
    assert path.endswith(".jsonl")
    assert not os.path.exists(path), "allocation must not create the file yet"


def test_two_auto_named_runs_never_collide(tmp_path, monkeypatch):
    from kwara import discovery

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    first = discovery.open_run(None)
    open(first, "w").close()
    assert discovery.open_run(None) != first


def test_an_interrupted_sweep_keeps_what_it_paid_for(tmp_path, monkeypatch, site):
    """A sweep that dies has still spent its outbound requests, and those
    responses are the part that cannot be recreated cheaply. The bank is
    written per candidate, not at the end."""
    from kwara.cli import build_parser

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    site.route("/ads.txt", body=b"clickforce.com.tw, pub-1, DIRECT\n")

    # Full URL, scheme included: fetch_for_screening only prepends https://
    # when the candidate has no scheme, and the local test server is http.
    domains = tmp_path / "candidates.txt"
    domains.write_text(f"{site.url}\n{site.url}/x\n", encoding="utf-8")

    bank = str(tmp_path / "run.jsonl")
    boom = RuntimeError("interrupted mid-sweep")

    from kwara import discovery
    real = discovery.screen_domains

    def die_after_one(doms, known, **kw):
        cb = kw.get("on_result")
        out = real(doms, known, **{**kw, "on_result": None})
        for o in out[:1]:
            cb(o)
        raise boom

    monkeypatch.setattr(discovery, "screen_domains", die_after_one)
    ns = build_parser().parse_args(
        ["discover", "screen", "--domains", str(domains), "--bank", bank,
         "--db", str(tmp_path / "c.db"), "--quiet"])
    with pytest.raises(RuntimeError):
        ns.fn(ns)

    with open(bank, encoding="utf-8") as fh:
        rows = [json.loads(l) for l in fh if l.strip()]
    assert len(rows) == 1, "the completed observation was lost"
    assert rows[0]["domain"]


def test_a_banked_observation_carries_what_clustering_needs(tmp_path,
                                                            monkeypatch, site):
    """The defect that made screen_results.jsonl useless: without raw_sha256
    and accounts, the clustering stage has no input at all."""
    from kwara.cli import build_parser

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    site.route("/ads.txt", body=b"clickforce.com.tw, pub-873, DIRECT\n")

    domains = tmp_path / "candidates.txt"
    domains.write_text(site.url + "\n", encoding="utf-8")

    ns = build_parser().parse_args(
        ["discover", "screen", "--domains", str(domains),
         "--db", str(tmp_path / "c.db"), "--quiet"])
    out = ns.fn(ns)

    with open(out["banked_to"], encoding="utf-8") as fh:
        row = json.loads(fh.readline())
    assert row["raw_sha256"], "no hash banked — clustering would return nothing"
    assert row["accounts"], "no accounts banked — the reference population is empty"


def test_the_sweep_retains_the_bodies_it_screened(tmp_path, monkeypatch, site):
    """The gap that produced the whole problem. The 2026-08-05 sweep hashed
    each ads.txt and dropped it, so blockedsite.example's file — which the site began
    refusing the next day — exists nowhere."""
    from kwara.cli import build_parser

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    body = b"clickforce.com.tw, pub-873, DIRECT\r\nOWNERDOMAIN=owner.test\r\n"
    site.route("/ads.txt", body=body)

    domains = tmp_path / "candidates.txt"
    domains.write_text(site.url + "\n", encoding="utf-8")

    ns = build_parser().parse_args(
        ["discover", "screen", "--domains", str(domains),
         "--db", str(tmp_path / "c.db"), "--quiet"])
    out = ns.fn(ns)

    with open(out["banked_to"], encoding="utf-8") as fh:
        row = json.loads(fh.readline())
    assert "_body" not in row, "raw bytes leaked into the JSONL"
    assert row["body_file"], "no body retained"

    stored = os.path.join(os.path.dirname(out["banked_to"]), row["body_file"])
    with open(stored, "rb") as fh:
        data = fh.read()
    assert data == body, "the retained bytes are not the fetched bytes"
    assert hashlib.sha256(data).hexdigest() == row["body_sha256"]
    assert row["body_sha256"] == row["raw_sha256"], \
        "the identity hash and the retained bytes disagree"
