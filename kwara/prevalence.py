"""Reference prevalence for ads.txt DIRECT accounts.

The problem this exists to solve: every domain in an investigation is a
suspect, so "rare within this case" measures nothing. Accounts that looked
rare enough to be operator evidence turned out to sit on a third to a half of
all ordinary publishers — kargo|8955 on 30%, smaato|1100004890 on 51%. Rarity
only means something against a population of NORMAL sites.

This module loads such a population: a table of how many reference publishers
carry each DIRECT account, built by sweeping the publisher lists that SSPs
publish in their sellers.json. It is reference DATA, not case evidence, so it
lives outside the case DB and outside the repo.

ABSENCE IS NORMAL. The table is a local artifact that a given machine may
simply not have, so every caller must work without it — the analysis falls
back to its thresholds and says so, rather than silently scoring everything as
rare. `load()` returns None instead of raising, and never guesses.

Dependency-free apart from config so the core analysis layer can use it
without pulling in the discovery/network stack.
"""
from __future__ import annotations

import json
import os
from typing import Any

from config import ADS_TXT_PREVALENCE_PATH

SCHEMA = "kwara-ads-prevalence/1"


class Prevalence:
    """How common each (adsystem, seller_id) is among ordinary publishers."""

    def __init__(self, accounts: dict[str, int], site_count: int,
                 source: str = "") -> None:
        self._accounts = accounts
        self.site_count = site_count
        self.source = source

    def ratio(self, adsystem: str, seller_id: str) -> float | None:
        """Fraction of reference sites carrying this account, or None when the
        account was never seen. None is NOT zero — an unseen account may be
        genuinely rare or may simply be outside the reference population's
        reach, and those must not be conflated."""
        if self.site_count <= 0:
            return None
        key = f"{(adsystem or '').lower()}|{(seller_id or '').strip()}"
        hits = self._accounts.get(key)
        if hits is None:
            return None
        return hits / self.site_count

    def __len__(self) -> int:
        return len(self._accounts)


_cache: dict[tuple, Prevalence | None] = {}


def load(path: str | None = None) -> Prevalence | None:
    """Load the reference table, or None when it is absent or unreadable.

    Never raises on a missing or malformed file: the table is optional and an
    analysis run must not fail because a machine has not built one.

    Cached on (path, mtime, size) — the file runs to megabytes and the
    analysis layer calls this per aggregation, but a rebuilt table must still
    be picked up without restarting.
    """
    p = os.path.expanduser(path or ADS_TXT_PREVALENCE_PATH)
    if not p or not os.path.isfile(p):
        return None
    try:
        st = os.stat(p)
        key = (p, st.st_mtime_ns, st.st_size)
    except OSError:
        return None
    if key in _cache:
        return _cache[key]
    result = _read(p)
    _cache.clear()          # only ever one table in play; do not grow unbounded
    _cache[key] = result
    return result


def _read(p: str) -> Prevalence | None:
    try:
        with open(p, encoding="utf-8") as fh:
            blob: Any = json.load(fh)
        if not isinstance(blob, dict) or blob.get("schema") != SCHEMA:
            return None
        accounts = blob.get("accounts")
        site_count = int(blob.get("site_count") or 0)
        if not isinstance(accounts, dict) or site_count <= 0:
            return None
        return Prevalence(accounts, site_count, blob.get("source") or "")
    except (OSError, ValueError, TypeError):
        return None
