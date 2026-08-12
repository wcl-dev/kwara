"""Acquisition records: keep the bytes, not just what we concluded from them.

kwara used to read an ads.txt response, hash it, parse out the DIRECT accounts
and throw the bytes away. `ads_txt_json` carried `raw_sha256` and the parsed
records; there was no body anywhere, and the evidence exporter did not carry
ads.txt at all.

That made the tool's strongest binding signal — two domains serving a
byte-identical ads.txt — a claim a recipient had to take on trust. They could
not recompute either hash. Where the site had since started refusing requests
they could not re-fetch it either: blockedsite.example was recorded on 2026-08-05
serving sha 3bb8f682471e, 278 accounts, identical to siblingsite.example, and returned
HTTP 403 the next day. That binding is now unobtainable by probing, and
un-recheckable from what was kept.

This module stores the response body as an immutable artifact and records the
acquisition context beside it, so a later reader can re-derive the hash rather
than believe ours.

TWO HASHES, NEVER ONE
    `captured_sha256` is over the bytes actually written. `complete_sha256` is
    over the whole response, and is NULL when the read hit the size ceiling.
    They differ precisely when a capture is truncated, and conflating them is
    how a prefix hash gets matched as byte-identity by template clustering
    downstream. Only `complete_sha256` may be compared for identity.

APPEND ONLY
    A forced re-fetch INSERTS. Nothing here updates or deletes a fetch row or
    a body file, and a test asserts that against the parsed source. An
    acquisition record describes a moment; a later moment is a different
    record. Bodies are created with O_EXCL, so a name collision raises rather
    than overwriting an earlier capture.

WHAT THIS STILL DOES NOT ESTABLISH
    Retention makes a hash recomputable. It does not establish WHEN the
    request happened — `fetched_at` is this machine's clock, self-asserted —
    and two identical bodies prove identical captured bytes, not a common
    operator. Platform-generated ads.txt templates are common; the clustering
    layer guards against them separately.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone

from . import config

# Response kinds get their own subtree so a reader can tell at a glance what a
# body is without consulting the database.
KIND_ADS_TXT = "ads_txt"

# `kind` becomes a path component, so it is an allow-list rather than free
# text: a caller-supplied "../.." would otherwise write outside the store.
KINDS = frozenset({KIND_ADS_TXT})

# Recorded on every row so a later reader knows which code produced it.
try:
    from . import __version__ as TOOL_VERSION
except ImportError:                                    # pragma: no cover
    TOOL_VERSION = "unknown"


def acquisition_root() -> str:
    """Read `config.DATA_DIR` at CALL time so tests can redirect it."""
    return os.path.join(config.DATA_DIR, "acquisitions")


def _now() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_body(data: bytes, *, kind: str = KIND_ADS_TXT) -> tuple[str, str]:
    """Write a response body to a fresh immutable artifact.

    Returns (path, sha256 of what was written). Exclusive creation: a
    collision raises rather than overwriting bytes an earlier row points at.
    """
    if kind not in KINDS:
        raise ValueError(f"unknown acquisition kind {kind!r}; "
                         f"add it to acquisition.KINDS deliberately")
    day = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    parent = os.path.join(acquisition_root(), kind, day)
    os.makedirs(parent, exist_ok=True)

    for _ in range(8):
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        path = os.path.join(parent, f"{stamp}_{secrets.token_hex(3)}.body")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return path, hashlib.sha256(data).hexdigest()
    raise RuntimeError(f"could not allocate an acquisition body under {parent}")


def read_back(path: str) -> bytes:
    """Re-open a persisted artifact and return its bytes, refusing symlinks.

    Handing the same in-memory object to `write()` and to the parser
    establishes intent, not that the parse used what was persisted. Reading it
    back closes that gap: after this, `captured_sha256` is literally the hash
    of the artifact on disk, and the records were derived from those bytes.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb") as fh:
            return fh.read()
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def sha256_file(path: str) -> str | None:
    d = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                d.update(block)
    except OSError:
        return None
    return d.hexdigest()


def record_fetch(
    conn: sqlite3.Connection,
    *,
    kind: str = KIND_ADS_TXT,
    scan_run_id: int | None = None,
    requested_url: str,
    final_url: str | None = None,
    redirect_chain: list | None = None,
    status: str,
    status_code: int | None = None,
    response_headers: list | None = None,
    user_agent: str | None = None,
    truncated: bool = False,
    body: bytes | None = None,
    error: str | None = None,
    fetched_at: str | None = None,
) -> int:
    """Insert one acquisition record. Never updates, never deletes.

    `response_headers` is a list of [name, value] pairs, NOT a dict: a
    response may repeat a header (Set-Cookie routinely does) and a dict
    silently keeps the last one.

    A network error has no body — `body_path` stays NULL and both hashes are
    NULL. That is a real acquisition outcome and is recorded, not dropped;
    a 403 with a challenge page in it IS a body and is kept.
    """
    body_path = captured = complete = None
    captured_bytes = 0
    if body is not None:
        body_path, captured = write_body(body, kind=kind)
        captured_bytes = len(body)
        # A prefix hash must never be offered as the identity of the whole
        # response. Truncated means we do not know the complete hash.
        complete = None if truncated else captured

    cur = conn.execute(
        """INSERT INTO acquisitions
             (kind, scan_run_id, requested_url, final_url, redirect_chain_json,
              status, status_code, fetched_at, response_headers_json,
              user_agent, tool_version, truncated, captured_bytes, body_path,
              captured_sha256, complete_sha256, error)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (kind, scan_run_id, requested_url, final_url,
         json.dumps(redirect_chain) if redirect_chain else None,
         status, status_code, fetched_at or _now(),
         json.dumps(response_headers) if response_headers else None,
         user_agent, TOOL_VERSION, 1 if truncated else 0, captured_bytes,
         body_path, captured, complete, error),
    )
    conn.commit()
    return cur.lastrowid


def headers_as_pairs(headers) -> list:
    """requests' CaseInsensitiveDict -> [[name, value], ...], duplicates kept.

    `resp.raw.headers` preserves repeats where the mapping view does not; fall
    back to the collapsed view when the raw object is unavailable.
    """
    raw = getattr(headers, "getlist", None)
    if raw is None:
        try:
            return [[k, v] for k, v in headers.items()]
        except AttributeError:
            return []
    out = []
    for name in headers.keys():
        for value in headers.getlist(name):
            out.append([name, value])
    return out


# ---------------------------------------------------------------------------
# Reading back
# ---------------------------------------------------------------------------

VERIFIED = "verified"
LEGACY_UNVERIFIABLE = "legacy_unverifiable"
BODY_MISSING = "body_missing"
BODY_MISMATCH = "body_mismatch"
TRUNCATED = "truncated"
WRONG_KIND = "wrong_kind"
WRONG_SCAN_RUN = "wrong_scan_run"
HASH_DISAGREES = "hash_disagrees"


def verify(conn: sqlite3.Connection, acquisition_id: int, *,
           expect_kind: str | None = None,
           expect_scan_run_id: int | None = None,
           expect_sha256: str | None = None) -> str:
    """Does this acquisition support the claim being made ON it?

    THE CALLER MUST SAY WHAT IT IS CLAIMING. Checking only that a body still
    hashes to its own recorded value answers a question nobody asked: it
    establishes that some bytes are intact, not that they are the bytes the
    finding rests on. A review on 2026-08-12 demonstrated the gap — an
    `ads_txt_json` claiming sha `aaaa…` was reported `verified` on the
    strength of a retained body hashing to `2ecabb0f`, because nothing
    compared the two.

    So a caller passes what it believes: the kind of artifact, the scan_run it
    belongs to, and the hash the derived record claims. Any disagreement is
    its own verdict, never a pass.
    """
    row = conn.execute(
        "SELECT kind, scan_run_id, body_path, captured_sha256, "
        "complete_sha256, truncated FROM acquisitions WHERE id = ?",
        (acquisition_id,)).fetchone()
    if row is None:
        return BODY_MISSING

    if expect_kind is not None and row["kind"] != expect_kind:
        return WRONG_KIND
    # A row belonging to a different scan_run may be a perfectly good
    # acquisition of something else entirely.
    if (expect_scan_run_id is not None
            and row["scan_run_id"] != expect_scan_run_id):
        return WRONG_SCAN_RUN

    path, captured, complete, truncated = (
        row["body_path"], row["captured_sha256"], row["complete_sha256"],
        row["truncated"])
    if not path:
        return LEGACY_UNVERIFIABLE
    if os.path.islink(path) or not os.path.isfile(path):
        # A link where a body should be is not a body: it points somewhere the
        # acquisition never wrote.
        return BODY_MISSING
    if sha256_file(path) != captured:
        return BODY_MISMATCH
    # The bytes are intact, but a prefix cannot establish identity.
    if truncated or not complete:
        return TRUNCATED
    if expect_sha256 is not None and complete != expect_sha256:
        # The bytes are fine and they are not the ones being claimed.
        return HASH_DISAGREES
    return VERIFIED


def identity_hash(conn: sqlite3.Connection, acquisition_id: int, **expect
                  ) -> str | None:
    """The only hash that may be compared for byte-identity, or None.

    None means "cannot support an identity claim" — truncated, body gone,
    body altered, wrong kind, wrong scan_run, disagreeing with the derived
    record, or a legacy row that never had a body.
    """
    if verify(conn, acquisition_id, **expect) != VERIFIED:
        return None
    row = conn.execute("SELECT complete_sha256 FROM acquisitions WHERE id = ?",
                       (acquisition_id,)).fetchone()
    return row["complete_sha256"] if row else None
