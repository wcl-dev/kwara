"""Reference prevalence — the outside population that makes "rare" mean something.

Every domain in an investigation is a suspect, so rarity measured inside a case
measures nothing: accounts that read as operator evidence turned out to sit on
30-51% of ordinary publishers. These tests lock in the two properties that make
the table safe to depend on — it is optional, and "never seen" is not "rare".
"""
import json
import os
import sqlite3
import tempfile

import prevalence
from clustering_infra import shared_ad_accounts
from test_shared_ad_accounts import _add, _ads_json, _filler, _make_case, _make_db


def _table(accounts, site_count=1000, path=None):
    path = path or os.path.join(tempfile.mkdtemp(), "prev.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"schema": prevalence.SCHEMA, "site_count": site_count,
                   "accounts": accounts}, fh)
    return path


# ── loading ───────────────────────────────────────────────────────────────

def test_missing_table_returns_none_rather_than_raising():
    """A machine may simply not have built one; analysis must still run."""
    assert prevalence.load("/nonexistent/prevalence.json") is None


def test_malformed_or_foreign_table_is_refused():
    bad = os.path.join(tempfile.mkdtemp(), "bad.json")
    with open(bad, "w") as fh:
        fh.write("{not json")
    assert prevalence.load(bad) is None

    wrong = _table({"a|1": 5})
    with open(wrong, "w") as fh:
        json.dump({"schema": "something-else", "site_count": 10,
                   "accounts": {}}, fh)
    assert prevalence.load(wrong) is None


def test_unseen_account_is_none_not_zero():
    """The distinction the whole design rests on: an account the reference
    population never saw may be genuinely rare OR simply out of its reach.
    Reporting 0.0 would silently promote every unknown account to 'rare'."""
    p = prevalence.load(_table({"kargo.com|8955": 300}, site_count=1000))
    assert p.ratio("kargo.com", "8955") == 0.3
    assert p.ratio("nobody.com", "999") is None


def test_reload_picks_up_a_rebuilt_table():
    path = _table({"a.com|1": 10}, site_count=100)
    assert prevalence.load(path).ratio("a.com", "1") == 0.1
    _table({"a.com|1": 50}, site_count=100, path=path)
    os.utime(path, (0, 0))          # force a distinct mtime
    assert prevalence.load(path).ratio("a.com", "1") == 0.5


# ── effect on tier ────────────────────────────────────────────────────────

def _case_with_shared_account(conn, acct):
    cid = _make_case(conn)
    for d in ("a.com", "b.com"):
        _add(conn, cid, f"https://{d}/", d, _ads_json([acct], raw_text=d))
    _filler(conn, cid, 5)
    return cid


def test_commodity_account_is_demoted_on_measured_prevalence(monkeypatch):
    """Every threshold says operator — 2 of 7 domains, 2 apexes, no template
    overlap. The measurement says a third of ordinary publishers carry it."""
    conn = _make_db()
    acct = ("clickforce.com.tw", "pub-COMMON")
    cid = _case_with_shared_account(conn, acct)
    path = _table({"clickforce.com.tw|pub-COMMON": 300}, site_count=1000)
    monkeypatch.setattr(prevalence, "ADS_TXT_PREVALENCE_PATH", path)

    row = next(a for a in shared_ad_accounts(conn, cid)["by_account"]
               if (a["adsystem"], a["seller_id"]) == acct)
    assert row["reference_prevalence"] == 0.3
    assert row["tier"] == "manager"


def test_account_unknown_to_the_table_is_not_demoted(monkeypatch):
    """Absence of evidence must not act as evidence of commonness."""
    conn = _make_db()
    acct = ("clickforce.com.tw", "pub-UNSEEN")
    cid = _case_with_shared_account(conn, acct)
    path = _table({"other.com|x": 900}, site_count=1000)
    monkeypatch.setattr(prevalence, "ADS_TXT_PREVALENCE_PATH", path)

    row = next(a for a in shared_ad_accounts(conn, cid)["by_account"]
               if (a["adsystem"], a["seller_id"]) == acct)
    assert row["reference_prevalence"] is None
    assert row["tier"] == "operator"


def test_analysis_runs_unchanged_with_no_table_at_all(monkeypatch):
    """The table is optional. Without it the tier falls back to its thresholds
    rather than treating everything as rare or refusing to run."""
    conn = _make_db()
    acct = ("clickforce.com.tw", "pub-NOTABLE")
    cid = _case_with_shared_account(conn, acct)
    monkeypatch.setattr(prevalence, "ADS_TXT_PREVALENCE_PATH",
                        "/nonexistent/prev.json")

    row = next(a for a in shared_ad_accounts(conn, cid)["by_account"]
               if (a["adsystem"], a["seller_id"]) == acct)
    assert row["reference_prevalence"] is None
    assert row["tier"] == "operator"
