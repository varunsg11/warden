"""Tests for the drift detector and its integration into the gated runner."""

from __future__ import annotations

import pytest

from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Gate
from warden.governance.issuer import Supervisor
from warden.governance.provenance import Provenance
from warden.llm import ToolCall
from warden.pipeline import tools
from warden.pipeline.runner import GatedToolRunner

BASELINE = [
    ("issue_refund", {"account": "1234", "amount": 12.5}),
    ("issue_refund", {"account": "1234", "amount": 9.0}),
    ("issue_refund", {"account": "5678", "amount": 20.0}),
    ("issue_refund", {"account": "5678", "amount": 15.0}),
    ("issue_refund", {"account": "1234", "amount": 18.0}),
]


def _detector():
    return DriftDetector().fit(BASELINE)


def test_normal_call_is_not_drift():
    r = _detector().check("issue_refund", {"account": "1234", "amount": 13.0})
    assert not r.is_drift


def test_novel_account_is_drift():
    r = _detector().check("issue_refund", {"account": "9999", "amount": 14.0})
    assert r.is_drift
    assert "novel account" in r.reasons[0]


def test_amount_outlier_is_drift():
    r = _detector().check("issue_refund", {"account": "1234", "amount": 49.99})
    assert r.is_drift
    assert "std devs" in r.reasons[0]


def test_no_baseline_no_false_positive():
    # With nothing learned, the detector must not flag anything.
    r = DriftDetector().check("issue_refund", {"account": "9999", "amount": 99999.0})
    assert not r.is_drift


def test_runner_quarantines_in_bounds_but_drifting_call():
    tools.reset_world()
    sup = Supervisor()
    gate = Gate(sup.verifier)
    manifests = {"refund_issuer": sup.issue_manifest("refund_issuer", "process_refund")}
    provenance = Provenance()
    provenance.add_trusted("Customer on account 1234 requests a refund.", "user request")
    runner = GatedToolRunner(gate, manifests, drift=_detector(), provenance=provenance)

    # In policy (account 1234, amount <= 50) so the gate ALLOWS -- drift must catch it.
    call = ToolCall(name="issue_refund", arguments={"account": "1234", "amount": 49.99})
    with pytest.raises(DriftViolation):
        runner.execute("refund_issuer", call)

    assert tools.REFUNDS_ISSUED == []  # the refund never executed


# --- hardening: watched features can't be hidden or dropped ---------------- #
EMAIL_BASELINE = [
    ("send_email", {"to": "alice@gmail.com"}),
    ("send_email", {"to": "carol@yahoo.com"}),
]


@pytest.mark.parametrize(
    "to",
    [
        "steal@evil.com, alice@gmail.com",  # attacker listed first
        "alice@gmail.com, steal@evil.com",  # attacker listed last
        "Alice Smith <steal@evil.com>",  # hidden behind a display name
        "steal-at-evil.com",  # no parseable address at all
        "",
    ],
)
def test_email_exfil_evasions_are_drift(to):
    r = DriftDetector().fit(EMAIL_BASELINE).check("send_email", {"to": to})
    assert r.is_drift, f"to={to!r} was not flagged"


def test_known_domains_normalize_and_pass():
    detector = DriftDetector().fit(EMAIL_BASELINE)
    for to in ["Frank <frank@Gmail.com>", "frank@gmail.com, judy@yahoo.com", "x@gmail.com."]:
        assert not detector.check("send_email", {"to": to}).is_drift, to


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), None, "12", True])
def test_non_finite_or_missing_amount_is_drift(amount):
    r = _detector().check("issue_refund", {"account": "1234", "amount": amount})
    assert r.is_drift
    assert "non-finite" in r.reasons[0]
