"""The latest-scan-run macros must run on every SQLite a Python build ships.

SQLite 3.47–3.51 reject an outer-table reference inside a correlated
subquery's ORDER BY; 3.53 accepts it. The original macros used exactly that,
so 152 tests failed on one machine and passed on another with no code change
between them. These pin the portable form and its meaning.
"""
import re
import sqlite3

from kwara.sql import LATEST_DONE_SCAN_RUN_FOR_URL, LATEST_SCAN_RUN_FOR_URL


def _db():
    c = sqlite3.connect(":memory:")
    c.executescript("""
        CREATE TABLE url_artifacts(id INTEGER PRIMARY KEY, case_id INT, original_url TEXT);
        CREATE TABLE scan_runs(id INTEGER PRIMARY KEY, url_artifact_id INT, status TEXT);
        -- case 1: rows 1 and 2 carry the same URL; row 3 a different one.
        -- case 2: row 4 carries case 1's URL but must never be borrowed across cases.
        INSERT INTO url_artifacts VALUES (1,1,'https://a/'),(2,1,'https://a/'),
                                         (3,1,'https://b/'),(4,2,'https://a/');
        INSERT INTO scan_runs VALUES (10,1,'done'),(11,2,'done'),(12,3,'error'),
                                     (13,4,'done'),(14,1,'error'),(15,3,'done');
    """)
    return c


def _pick(macro):
    return _db().execute(
        f"SELECT ua.id, sr.id FROM url_artifacts ua "
        f"JOIN scan_runs sr ON sr.id = {macro} ORDER BY ua.id").fetchall()


def test_no_outer_reference_inside_an_order_by():
    for macro in (LATEST_DONE_SCAN_RUN_FOR_URL, LATEST_SCAN_RUN_FOR_URL):
        for clause in re.findall(r"ORDER BY ([^)]*)", macro):
            assert "ua." not in clause, clause


def test_done_macro_prefers_own_scan_then_a_sibling_with_the_same_url():
    # row 1: own done scan 10 (14 is an error and must not win on recency)
    # row 2: own done scan 11
    # row 3: own done scan 15
    # row 4: own done scan 13, and case 1's rows are never borrowed
    assert _pick(LATEST_DONE_SCAN_RUN_FOR_URL) == [(1, 10), (2, 11), (3, 15), (4, 13)]


def test_done_macro_borrows_a_sibling_when_the_row_has_no_done_scan():
    c = _db()
    c.execute("DELETE FROM scan_runs WHERE id = 10")  # row 1 keeps only its error
    rows = c.execute(
        f"SELECT ua.id, sr.id FROM url_artifacts ua "
        f"JOIN scan_runs sr ON sr.id = {LATEST_DONE_SCAN_RUN_FOR_URL} "
        f"WHERE ua.id = 1").fetchall()
    assert rows == [(1, 11)]  # sibling row 2's done scan, not row 4's in case 2


def test_any_status_macro_takes_the_newest_own_scan_whatever_its_status():
    assert _pick(LATEST_SCAN_RUN_FOR_URL) == [(1, 14), (2, 11), (3, 15), (4, 13)]
