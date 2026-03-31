import os
import tempfile

from db import get_conn, init_db, migrate_db


def test_init_and_migrate_on_temp_db():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "data", "test.db")
        conn = get_conn(path)
        try:
            init_db(conn)
            migrate_db(conn)
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='cases'"
            ).fetchone()
            assert row is not None
        finally:
            conn.close()
