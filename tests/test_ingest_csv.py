"""`ingest csv` is a documented public surface, so its input comes from outside
kwara, where the encoding and the timestamp format are not controlled.

Nothing exercised it before. Both bugs pinned here failed silently — the row
was ingested and the CLI exited 0, and the only trace was a column that was
empty or a timestamp that had quietly become unusable. A round-trip test is
what distinguishes "ingested" from "ingested correctly".
"""
import os
import tempfile

import pytest

from kwara.ingestion import ingest_csv
from kwara.pipeline import _parse_posted_at

HEADER = "platform,permalink,actor_label,posted_at,message_text\n"
ROW = ("threads,https://threads.net/@acct/post/1,acct,"
       "2025-05-18T17:29:25.000Z,see https://evil.example/landing\n")


@pytest.fixture
def conn():
    td = tempfile.mkdtemp()
    from kwara.db import get_conn, init_db, migrate_db
    c = get_conn(os.path.join(td, "kwara.db"))
    init_db(c)
    migrate_db(c)
    yield c
    c.close()


@pytest.fixture
def case_id(conn):
    cid = conn.execute(
        "INSERT INTO cases (title, description, created_at, updated_at) "
        "VALUES ('csv', '', '', '')"
    ).lastrowid
    conn.commit()
    return cid


def _write(tmp_path, text: str, encoding: str) -> str:
    p = tmp_path / "posts.csv"
    p.write_bytes(text.encode(encoding))
    return str(p)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_ingest_csv_round_trip(conn, case_id, tmp_path, encoding):
    """Every documented column survives, with or without a BOM.

    utf-8-sig is the parametrised case that used to fail: csv.DictReader folds
    the BOM into the first header name, so `platform` — whichever column
    happens to be first — came back empty for every row, with no exception and
    no warning.
    """
    rows = ingest_csv(conn, case_id, _write(tmp_path, HEADER + ROW, encoding))

    assert len(rows) == 1
    assert rows[0]["url_count"] == 1

    msg = conn.execute(
        "SELECT platform, permalink, actor_label, posted_at, message_text "
        "FROM message_evidence WHERE case_id = ?", (case_id,)).fetchone()
    assert msg["platform"] == "threads"
    assert msg["permalink"] == "https://threads.net/@acct/post/1"
    assert msg["actor_label"] == "acct"
    assert msg["posted_at"] == "2025-05-18T17:29:25.000Z"
    assert msg["message_text"].startswith("see ")

    # The URL-extraction contract, pinned alongside the column mapping.
    art = conn.execute(
        "SELECT original_url, domain, url_order FROM url_artifacts "
        "WHERE case_id = ?", (case_id,)).fetchone()
    assert art["original_url"] == "https://evil.example/landing"
    assert art["domain"] == "evil.example"
    assert art["url_order"] == 0


def test_ingest_csv_bom_does_not_reorder_damage(conn, case_id, tmp_path):
    """The BOM hits whichever column is first, not `platform` specifically."""
    header = "message_text,platform,permalink,actor_label,posted_at\n"
    row = "go to https://evil.example/x,threads,https://p/1,acct,2025-05-18\n"
    ingest_csv(conn, case_id, _write(tmp_path, header + row, "utf-8-sig"))

    msg = conn.execute(
        "SELECT message_text, platform FROM message_evidence WHERE case_id = ?",
        (case_id,)).fetchone()
    assert msg["message_text"] == "go to https://evil.example/x"
    assert msg["platform"] == "threads"


# ---------------------------------------------------------------------------
# posted_at — the value ingest_csv stores verbatim, read back by the domain
# intel step to date a domain against the post that carried it.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    # ISO-8601, the default of essentially every API and export tool.
    ("2025-05-18T17:29:25.000Z", "2025-05-18 17:29:25"),
    ("2025-05-18T17:29:25Z", "2025-05-18 17:29:25"),
    ("2025-05-18T17:29:25", "2025-05-18 17:29:25"),
    ("2025-05-18T17:29:25+08:00", "2025-05-18 09:29:25"),  # normalised to UTC
    # The six formats that already worked, kept from regressing.
    ("2025-05-18 17:29:25", "2025-05-18 17:29:25"),
    ("2025-05-18 17:29", "2025-05-18 17:29:00"),
    ("2025-05-18", "2025-05-18 00:00:00"),
    ("2025/05/18", "2025-05-18 00:00:00"),
    ("18-05-2025", "2025-05-18 00:00:00"),
    ("05/18/2025", "2025-05-18 00:00:00"),
    ("2025-05-18 17:29:25 UTC", "2025-05-18 17:29:25"),
])
def test_parse_posted_at_accepts(raw, expected):
    assert str(_parse_posted_at(raw)) == expected


@pytest.mark.parametrize("raw", ["", "   ", "garbage", "not a date", None])
def test_parse_posted_at_rejects(raw):
    assert _parse_posted_at(raw) is None


def test_parse_posted_at_is_naive():
    """Aware datetimes would break the caller.

    _enrich_domain_for_scan_run subtracts a strptime()'d WHOIS creation date
    from this value, and aware-minus-naive raises TypeError, which that call
    site catches only ValueError for. An offset-bearing input must therefore
    come back converted, not annotated.
    """
    assert _parse_posted_at("2025-05-18T17:29:25+08:00").tzinfo is None


def test_ingest_csv_posted_at_survives_to_the_intel_reference_date(
        conn, case_id, tmp_path):
    """The end-to-end point of the two fixes above.

    A BOM'd CSV carrying an ISO-8601 timestamp used to lose the timestamp
    twice over, and the domain-age comparison then silently fell back to
    now() — widening the age and suppressing the new_domain tag.
    """
    ingest_csv(conn, case_id, _write(tmp_path, HEADER + ROW, "utf-8-sig"))
    stored = conn.execute(
        "SELECT posted_at FROM message_evidence WHERE case_id = ?",
        (case_id,)).fetchone()["posted_at"]
    assert _parse_posted_at(stored) is not None
