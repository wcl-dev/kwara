"""narrative.evidence_coverage() — the evidence-coverage figure must not be
ownable by any single evidence class.

Regression for 2026-08-05: coverage was a raw weighted count capped at 100, so
a case carrying 193 operator-tier ads.txt accounts scored 1544 on that term
alone. The weakest evidence class saturated the figure by itself and every
well-populated case reported the same number.
"""
from config import COVERAGE_CLASS_CAP, COVERAGE_WEIGHTS
from narrative import evidence_coverage, verdict


def _share(cls: str) -> int:
    return round(100 * COVERAGE_WEIGHTS[cls] / sum(COVERAGE_WEIGHTS.values()))


def test_no_evidence_is_zero():
    assert evidence_coverage(0, 0, 0) == 0


def test_all_classes_saturated_is_full():
    n = COVERAGE_CLASS_CAP
    assert evidence_coverage(n, n, n) == 100


def test_monetisation_alone_cannot_dominate():
    """The headline regression: ads.txt accounts are corroborating and
    explicitly non-binding (clusters.py refuses them as a grouping signal), so
    no quantity of them may carry the figure."""
    assert evidence_coverage(0, 0, 999) == _share("money")
    assert evidence_coverage(0, 0, 999) < evidence_coverage(1, 0, 0)


def test_each_class_holds_its_share():
    n = COVERAGE_CLASS_CAP
    assert evidence_coverage(n, 0, 0) == _share("grouping")
    assert evidence_coverage(0, n, 0) == _share("behaviour")
    assert evidence_coverage(0, 0, n) == _share("money")


def test_class_count_saturates_at_cap():
    """More instances of the same class stop adding once the cap is reached —
    ten cert clusters are not ten times the coverage of one."""
    n = COVERAGE_CLASS_CAP
    assert evidence_coverage(n, 0, 0) == evidence_coverage(n * 10, 0, 0)


def test_grouping_outranks_behaviour_outranks_money():
    assert (evidence_coverage(1, 0, 0)
            > evidence_coverage(0, 1, 0)
            > evidence_coverage(0, 0, 1))


def test_coverage_never_exceeds_100():
    assert evidence_coverage(10_000, 10_000, 10_000) == 100


# ── verdict() — coverage must not leak into the grouping determination ────

def _sig(**kw):
    base = {"tracking": 0, "certs": 0, "hdr_tmpl": 0, "ads_template": 0,
            "cloaking": 0, "fake_ver": 0, "opsec": 0, "ads_operator": 0}
    base.update(kw)
    return base


def test_ads_accounts_alone_do_not_make_a_grouping_determination():
    """Money evidence raises coverage but must never assert same-group — that
    claim belongs to grouping signals only."""
    v = verdict(_sig(ads_operator=50))
    assert v["grouping"] == "none"
    assert v["coverage"] == _share("money")


def test_one_grouping_signal_makes_the_determination():
    v = verdict(_sig(tracking=1))
    assert v["grouping"] == "strong"
