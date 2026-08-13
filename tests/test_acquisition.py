"""Acquisition records — keeping the bytes an analysis was derived from.

kwara read an ads.txt response, hashed it, parsed the DIRECT accounts and
discarded the bytes. So its strongest binding signal — two domains serving a
byte-identical ads.txt — was a claim a recipient had to take on trust: they
could not recompute either hash, and where the site had since started refusing
requests they could not re-fetch it. blocked-site.example was recorded on 2026-08-05
serving sha 3bb8f682471e, 278 accounts, identical to sibling-site.example, and returned
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
    among the most useful things to keep, and the reason blocked-site.example's
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

def _domain_with_ads(conn, url, ads, *, body=None):
    """Seed a scanned domain, optionally with the response bytes retained.

    `record_fetch` is given the scan_run: verification checks that the
    acquisition belongs to the scan_run making the claim, so an acquisition
    floating free of one cannot vouch for it.
    """
    sr = _scan_run(conn, url)
    if body is not None:
        ads = {**ads, "acquisition_id": acq.record_fetch(
            conn, scan_run_id=sr, requested_url=url + "ads.txt",
            status="ok", status_code=200, body=body)}
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
    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads(sha), body=body)

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
    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads(sha), body=body)

    path = db.execute("SELECT body_path FROM acquisitions ORDER BY id DESC "
                      "LIMIT 1").fetchone()["body_path"]
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
    _domain_with_ads(db, "https://a.test/", _ads(sha), body=body)
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
    # Creating the file IS the reservation. Returning a name that does not
    # exist yet leaves a window in which something else can take it — or
    # replace it with a symlink the sweep would then write through.
    assert os.path.isfile(path) and os.path.getsize(path) == 0


def test_two_auto_named_runs_never_collide(tmp_path, monkeypatch):
    from kwara import discovery

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    first = discovery.open_run(None)
    assert discovery.open_run(None) != first


def test_a_symlink_at_the_bank_path_is_refused(tmp_path, monkeypatch):
    """The check-then-open version could be pointed at anything: plant a link
    after the existence check and the sweep writes through it."""
    from kwara import discovery

    target = tmp_path / "precious.txt"
    target.write_text("do not overwrite", encoding="utf-8")
    link = tmp_path / "bank.jsonl"
    os.symlink(str(target), str(link))

    with pytest.raises(ValueError, match="already exists"):
        discovery.open_run(str(link))
    assert target.read_text(encoding="utf-8") == "do not overwrite"


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
    each ads.txt and dropped it, so blocked-site.example's file — which the site began
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


# ── verification must check the CLAIM, not just the bytes ─────────────────

def test_a_retained_body_cannot_vouch_for_a_different_hash(db):
    """Reproduced by review on 2026-08-12: an ads_txt_json claiming sha
    `aaaa…` was reported `verified` because a retained body hashed to its own
    recorded value and nothing compared the two. Checking that some bytes are
    intact answers a question nobody asked."""
    body = b"real bytes\n"
    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads("a" * 64), body=body)

    t = _template(db)
    assert t["verification"] == acq.HASH_DISAGREES
    assert hashlib.sha256(body).hexdigest() != "a" * 64


def test_an_acquisition_from_another_scan_run_cannot_vouch(db):
    """Otherwise any retained body anywhere in the database would do."""
    body = b"clickforce.com.tw, pub-873, DIRECT\n"
    sha = hashlib.sha256(body).hexdigest()
    other = _scan_run(db, "https://unrelated.test/")
    stray = acq.record_fetch(db, scan_run_id=other,
                             requested_url="https://unrelated.test/ads.txt",
                             status="ok", status_code=200, body=body)

    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/",
                         _ads(sha, acquisition_id=stray))

    assert _template(db)["verification"] == acq.WRONG_SCAN_RUN


def test_the_wrong_kind_of_artifact_cannot_vouch(db):
    sr = _scan_run(db, "https://a.test/")
    aid = acq.record_fetch(db, scan_run_id=sr, requested_url="https://a.test/x",
                           status="ok", status_code=200, body=b"x")
    db.execute("UPDATE acquisitions SET kind='screenshot' WHERE id=?", (aid,))
    db.commit()
    assert acq.verify(db, aid, expect_kind=acq.KIND_ADS_TXT) == acq.WRONG_KIND


def test_a_body_replaced_by_a_symlink_is_not_followed(db, tmp_path):
    """Same defect the corpus manifest had: isfile() then open() both follow
    links, so an edit could hide behind the target."""
    body = b"original\n"
    aid = acq.record_fetch(db, requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=body)
    path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                      (aid,)).fetchone()["body_path"]
    decoy = tmp_path / "decoy.body"
    decoy.write_bytes(body)                       # identical content
    os.remove(path)
    os.symlink(str(decoy), path)

    assert acq.verify(db, aid) == acq.BODY_MISSING


def test_an_unknown_kind_is_refused_before_it_becomes_a_path(db):
    """`kind` is a path component. Free text there is a traversal."""
    with pytest.raises(ValueError, match="unknown acquisition kind"):
        acq.write_body(b"x", kind="../../escape")


def test_the_records_come_from_the_persisted_artifact(db, site, monkeypatch):
    """"We parsed what we kept" has to be a fact, not an intention. Handing the
    same in-memory object to write() and to the parser proves neither. The
    proof: corrupt the artifact between write and read-back and the parse must
    follow the artifact, not the memory copy."""
    from kwara import acquisition, adstxt

    site.route("/ads.txt", body=b"clickforce.com.tw, pub-873, DIRECT\n")
    sr = _scan_run(db, site.url + "/")

    real_read = acquisition.read_back
    seen = {}

    def read_and_swap(path):
        seen["path"] = path
        data = real_read(path)
        assert data == b"clickforce.com.tw, pub-873, DIRECT\n"
        return b"someone.else.com, pub-999, DIRECT\n"

    monkeypatch.setattr(adstxt, "read_back", read_and_swap, raising=False)
    monkeypatch.setattr(acquisition, "read_back", read_and_swap)

    result = adstxt.fetch_and_store_ads_txt(db, sr)
    assert seen["path"], "the artifact was never read back"
    assert result["records"][0]["seller_id"] == "pub-999", \
        "the parse used the in-memory copy, not the persisted artifact"


def test_read_back_refuses_a_symlink(tmp_path):
    from kwara.acquisition import read_back

    real = tmp_path / "real.body"
    real.write_bytes(b"payload")
    link = tmp_path / "link.body"
    os.symlink(str(real), str(link))

    assert read_back(str(real)) == b"payload"
    with pytest.raises(OSError):
        read_back(str(link))


def test_an_off_site_redirect_body_is_retained(tmp_path, monkeypatch, site):
    """A farm parking its ads.txt request on someone else's domain is doing
    something worth keeping the evidence of. The early return dropped it."""
    from kwara import discovery

    site.route("/ads.txt", body=b"redirected content\n")
    ads = discovery.fetch_for_screening(site.url)
    assert "_body" in ads


# ── export → restore → reanalysis ─────────────────────────────────────────

def test_a_pack_survives_restore_and_reproduces_the_analysis(db, tmp_path,
                                                             monkeypatch):
    """The point of carrying the bytes. A recipient must be able to rebuild
    the database from the pack and get the SAME verification verdicts and the
    SAME clusters — otherwise the pack proves the bytes exist without proving
    they support anything.

    Two clusters on purpose: one whose bytes were retained, and one fetched
    before retention existed. A round trip that only preserved the positive
    verdict would let the recipient's analysis bind a group ours refused to.
    """
    import subprocess
    import sys
    import zipfile

    from kwara.clusters import case_clusters
    from kwara.clustering_infra import shared_ad_accounts

    kept = b"clickforce.com.tw, pub-873, DIRECT\r\n"
    kept_sha = hashlib.sha256(kept).hexdigest()
    lost_sha = "e" * 64

    for host in ("g1.test", "g2.test"):
        _domain_with_ads(db, f"https://{host}/", _ads(kept_sha), body=kept)
    for host in ("u1.test", "u2.test"):
        _domain_with_ads(db, f"https://{host}/", _ads(lost_sha))

    before_t = {t["sha256"]: t["verification"]
                for t in shared_ad_accounts(db, 1)["by_template"]}
    assert before_t[kept_sha] == acq.VERIFIED
    assert before_t[lost_sha] == acq.LEGACY_UNVERIFIABLE
    before = case_clusters(db, 1)
    before_groups = {tuple(sorted(g["domains"])) for g in before["groups"]}
    assert before_groups == {("g1.test", "g2.test")}

    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    zip_path = _export(db)

    extracted = tmp_path / "unpacked"
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extracted)

    restored_home = tmp_path / "restored"
    env = {**os.environ, "KWARA_DATA_DIR": str(restored_home),
           "KWARA_DB_PATH": str(restored_home / "kwara.db")}
    out = subprocess.run(
        [sys.executable, "restore_from_export.py", str(extracted)],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr

    rdb = get_conn(str(restored_home / "kwara.db"))
    monkeypatch.setattr(config, "DATA_DIR", str(restored_home))

    # Without ads_txt_json the restored database would hold the bytes and no
    # record naming their hash, so nothing could be re-derived.
    assert rdb.execute("SELECT COUNT(*) FROM scan_runs WHERE ads_txt_json "
                       "IS NOT NULL").fetchone()[0] == 4

    after_t = {t["sha256"]: t["verification"]
               for t in shared_ad_accounts(rdb, 1)["by_template"]}
    assert after_t[kept_sha] == acq.VERIFIED, \
        "a verified cluster did not survive the round trip"
    assert after_t[lost_sha] == acq.LEGACY_UNVERIFIABLE, \
        "an unverifiable cluster came back verified"

    # "Identical" means identical: the same groups bound by the same named
    # signals, and the same unverified observations with the same verdicts and
    # remedies. Comparing domain tuples alone would pass a restore that lost
    # every signal and kept the shape.
    def shape(r):
        return (
            sorted(
                (tuple(sorted(g["domains"])),
                 sorted((s["type"], s["value"], tuple(sorted(s["domains"])))
                        for s in g["signals"]))
                for g in r["groups"]),
            sorted(
                (u["claimed_sha256"], tuple(sorted(u["domains"])),
                 u["verification"], u["why"], u["action"],
                 tuple(sorted(u["verification_by_domain"].items())))
                for u in r["unverified_templates"]),
        )

    after = case_clusters(rdb, 1)
    assert shape(after) == shape(before), \
        "the restored analysis is not the analysis the pack was built from"
    assert {tuple(sorted(g["domains"])) for g in after["groups"]} == before_groups
    assert [u["claimed_sha256"] for u in after["unverified_templates"]] == [lost_sha]


def test_a_pack_whose_body_is_altered_after_restore_fails_verification(
        db, tmp_path, monkeypatch):
    """The negative half: tampering on the RECIPIENT's side must show up when
    they re-run the analysis, not pass because we vouched for it."""
    from kwara.clustering_infra import shared_ad_accounts

    body = b"clickforce.com.tw, pub-873, DIRECT\r\n"
    sha = hashlib.sha256(body).hexdigest()
    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads(sha), body=body)
    assert shared_ad_accounts(db, 1)["by_template"][0]["verification"] \
        == acq.VERIFIED

    path = db.execute("SELECT body_path FROM acquisitions ORDER BY id DESC "
                      "LIMIT 1").fetchone()["body_path"]
    with open(path, "wb") as fh:
        fh.write(b"different bytes entirely\r\n")

    assert shared_ad_accounts(db, 1)["by_template"][0]["verification"] \
        == acq.BODY_MISMATCH


def test_an_unverifiable_template_is_reported_with_its_remedy(db):
    """Ruling: do not let it form a group at a softer tier — that keeps the
    same inference under a gentler label. Return the observation, the domains,
    the claimed hash, why it cannot be verified, and what would settle it."""
    from kwara.clusters import case_clusters

    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads("f" * 64))

    r = case_clusters(db, 1)
    assert not any(s["type"] == "ads_template"
                   for g in r["groups"] for s in g["signals"])
    u = r["unverified_templates"]
    assert len(u) == 1
    assert sorted(u[0]["domains"]) == ["a.test", "b.test"]
    assert u[0]["claimed_sha256"] == "f" * 64
    assert u[0]["verification"] == acq.LEGACY_UNVERIFIABLE
    assert u[0]["why"] and u[0]["action"]


def test_an_unverifiable_template_does_not_seed_the_discovery_index(db,
                                                                    tmp_path):
    """The template index screens future candidates. A hash nobody can check
    would propagate into every later sweep, and every promotion it produced
    would inherit the same weakness."""
    from kwara.index_db import SIGNAL_ADS_TXT_TEMPLATE, extract_case_signals

    body = b"clickforce.com.tw, pub-873, DIRECT\r\n"
    sha = hashlib.sha256(body).hexdigest()
    _domain_with_ads(db, "https://kept.test/", _ads(sha), body=body)
    _domain_with_ads(db, "https://lost.test/", _ads("e" * 64))

    seeded = {s["signal_value"] for s in extract_case_signals(db, 1, "db", "t")
              if s["signal_type"] == SIGNAL_ADS_TXT_TEMPLATE}
    assert sha in seeded
    assert "e" * 64 not in seeded, "an unverifiable hash seeded the funnel"


def test_the_narrative_does_not_call_an_unverifiable_template_strong(db):
    from kwara.narrative import signal_summary

    for host in ("a.test", "b.test"):
        _domain_with_ads(db, f"https://{host}/", _ads("c" * 64))
    s = signal_summary(db, 1)
    assert s["ads_template"] == 0
    assert s["ads_template_unverified"] == 1


def test_reserve_run_never_reopens_the_pathname(tmp_path, monkeypatch):
    """One O_CREAT|O_EXCL open, and that descriptor is what gets written.
    Creating the file, closing it, and reopening the NAME still races anything
    that can put a different regular file there in between — O_NOFOLLOW only
    rejects symlinks."""
    import ast
    import inspect

    from kwara import discovery

    src = inspect.getsource(discovery.reserve_run)
    opens = [n for n in ast.walk(ast.parse(src))
             if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and n.func.attr == "open"]
    assert len(opens) <= 2, "more than one open path — is the name reopened?"
    for call in opens:
        flags = ast.dump(call)
        assert "O_EXCL" in flags and "O_CREAT" in flags, \
            "an open without exclusive creation"

    monkeypatch.setattr(config, "DATA_DIR", str(tmp_path / "data"))
    path, fh = discovery.reserve_run(None)
    with fh:
        fh.write("x\n")
    with open(path, encoding="utf-8") as f:
        assert f.read() == "x\n"


def test_reserve_run_refuses_an_existing_destination(tmp_path):
    from kwara import discovery

    existing = tmp_path / "round1.jsonl"
    existing.write_text("prior sweep\n", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        discovery.reserve_run(str(existing))
    assert existing.read_text(encoding="utf-8") == "prior sweep\n"


def test_export_refuses_a_body_that_is_a_symlink(db, tmp_path, monkeypatch):
    """verify() refuses links; export read by pathname, so a link planted at
    the artifact would have shipped someone else's bytes under this
    acquisition's hash."""
    monkeypatch.setattr(config, "EXPORTS_DIR", str(tmp_path / "exports"))
    body = b"clickforce.com.tw, pub-873, DIRECT\n"
    sr = _scan_run(db, "https://a.test/")
    aid = acq.record_fetch(db, scan_run_id=sr,
                           requested_url="https://a.test/ads.txt",
                           status="ok", status_code=200, body=body)
    path = db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                      (aid,)).fetchone()["body_path"]
    decoy = tmp_path / "decoy.body"
    decoy.write_bytes(body)                      # identical content
    os.remove(path)
    os.symlink(str(decoy), path)

    with pytest.raises(ValueError, match="regular file"):
        _export(db)


# ── acquisition health, as reconcile reports it ───────────────────────────

def test_reconcile_reports_detached_missing_and_altered_acquisitions(
        db, tmp_path):
    """The other half of "evidence nothing points at". SET NULL makes detached
    rows accumulate by design, so something has to look for them."""
    from kwara import reconcile

    sr = _scan_run(db, "https://a.test/")
    good = acq.record_fetch(db, scan_run_id=sr, requested_url="https://a/1",
                            status="ok", body=b"intact")
    gone = acq.record_fetch(db, scan_run_id=sr, requested_url="https://a/2",
                            status="ok", body=b"will vanish")
    bent = acq.record_fetch(db, scan_run_id=sr, requested_url="https://a/3",
                            status="ok", body=b"will change")
    loose = acq.record_fetch(db, requested_url="https://a/4", status="ok",
                             body=b"no scan_run")

    os.remove(db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                         (gone,)).fetchone()["body_path"])
    with open(db.execute("SELECT body_path FROM acquisitions WHERE id=?",
                         (bent,)).fetchone()["body_path"], "wb") as fh:
        fh.write(b"tampered")

    db_path = db.execute("PRAGMA database_list").fetchone()[2]
    db.commit()
    h = reconcile.acquisition_health([db_path])

    assert h["verified_bodies"] == 2                      # good + loose
    assert [d["id"] for d in h["detached"]] == [loose]
    assert [m["id"] for m in h["missing_bodies"]] == [gone]
    assert [a["id"] for a in h["altered_bodies"]] == [bent]


def test_acquisition_health_only_reports(db):
    """No auto-delete, no auto-reattach: an acquisition is an append-only
    record and deciding what to do about a broken one is the analyst's call."""
    import ast
    import inspect

    from kwara import reconcile

    src = inspect.getsource(reconcile.acquisition_health)
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            fn = node.func
            name = (fn.attr if isinstance(fn, ast.Attribute)
                    else fn.id if isinstance(fn, ast.Name) else "")
            assert name not in {"remove", "unlink", "rmtree", "rename",
                                "replace"}, name
    assert "UPDATE" not in src.upper() and "DELETE FROM" not in src.upper()
