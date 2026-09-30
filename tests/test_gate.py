"""Unit tests for the enforcement gate — one test per way a call can be denied.

These are deterministic and need no LLM: the gate is pure logic, which is the
whole point. If any of these ever fails, a hole has opened in the security core.
"""

from __future__ import annotations

import time

import pytest

from warden.governance.audit import AuditLog
from warden.governance.capability import Capability
from warden.governance.gate import Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.governance.provenance import Provenance
from warden.llm import ToolCall
from warden.pipeline import tools
from warden.pipeline.runner import GatedToolRunner
from warden.pipeline.tools import TOOL_SPECS

# The session's trusted input: the refund policy requires the account to come from it.
TRUSTED = Provenance()
TRUSTED.add_trusted("Customer on account 1234 requests a refund.", "user request")


def _setup():
    supervisor = Supervisor()
    gate = Gate(supervisor.verifier)
    return supervisor, gate


# --- the happy paths: authorized calls are allowed -------------------------- #
def test_allows_valid_read():
    sup, gate = _setup()
    manifest = sup.issue_manifest("retriever")
    d = gate.check("retriever", "search_docs", {"query": "hi"}, "read", manifest)
    assert d.allowed


def test_allows_in_bounds_refund():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    d = gate.check(
        "refund_issuer",
        "issue_refund",
        {"account": "1234", "amount": 25.0},
        "write",
        manifest,
        provenance=TRUSTED,
    )
    assert d.allowed


# --- the core denial modes --------------------------------------------------- #
def test_denies_missing_capability():
    sup, gate = _setup()
    manifest = sup.issue_manifest("summarizer")  # summarizer gets nothing
    d = gate.check(
        "summarizer", "issue_refund", {"account": "1234", "amount": 10.0}, "write", manifest
    )
    assert not d.allowed
    assert "no capability" in d.reason


def test_summarize_task_grants_refund_agent_no_authority():
    """The JIT point: under a read-only task, the refund agent holds nothing, so
    an injected refund is denied at the first check."""
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "summarize")
    assert manifest == []
    d = gate.check(
        "refund_issuer",
        "issue_refund",
        {"account": "ATTACKER-0001", "amount": 999.99},
        "write",
        manifest,
    )
    assert not d.allowed
    assert "no capability" in d.reason


def test_denies_tampered_signature():
    sup, gate = _setup()
    [cap] = sup.issue_manifest("refund_issuer", "process_refund")
    # Attacker widens the amount cap AFTER signing; the old signature no longer fits.
    tampered = Capability(
        tool=cap.tool,
        scope=cap.scope,
        params={"amount": {"max": 100000.0}},
        ttl=cap.ttl,
        issued_at=cap.issued_at,
        nonce=cap.nonce,
        issuer=cap.issuer,
        subject=cap.subject,
        signature=cap.signature,
    )
    d = gate.check(
        "refund_issuer", "issue_refund", {"account": "1234", "amount": 999.99}, "write", [tampered]
    )
    assert not d.allowed
    assert "signature" in d.reason


def test_denies_expired_ttl():
    sup, gate = _setup()
    stale = Capability(
        tool="issue_refund",
        scope="write",
        params={},
        ttl=1.0,
        issued_at=time.time() - 60,
        nonce="n",
        issuer="s",
        subject="refund_issuer",
    ).signed(sup.signer)  # validly signed, but issued a minute ago with 1s ttl
    d = gate.check(
        "refund_issuer", "issue_refund", {"account": "1234", "amount": 10.0}, "write", [stale]
    )
    assert not d.allowed
    assert "expired" in d.reason


def test_denies_scope_mismatch():
    sup, gate = _setup()
    read_only = Capability(
        tool="issue_refund",
        scope="read",
        params={},
        ttl=30.0,
        nonce="n",
        issuer="s",
        subject="refund_issuer",
    ).signed(sup.signer)
    d = gate.check(
        "refund_issuer", "issue_refund", {"account": "1234", "amount": 10.0}, "write", [read_only]
    )
    assert not d.allowed
    assert "scope" in d.reason


def test_denies_amount_over_max():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    d = gate.check(
        "refund_issuer", "issue_refund", {"account": "1234", "amount": 999.99}, "write", manifest
    )
    assert not d.allowed
    assert "max" in d.reason


def test_denies_account_not_in_allowlist():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    d = gate.check(
        "refund_issuer",
        "issue_refund",
        {"account": "ATTACKER-0001", "amount": 10.0},
        "write",
        manifest,
    )
    assert not d.allowed
    assert "allowlist" in d.reason


# --- hardening: malformed arguments can't dodge the bounds ------------------ #
REFUND_SCHEMA = TOOL_SPECS["issue_refund"].parameters


@pytest.mark.parametrize(
    "amount", [float("nan"), float("inf"), float("-inf"), True, "25", None, -5000.0, 0.0]
)
def test_denies_malformed_or_out_of_range_amount(amount):
    """NaN compares False against every bound; strings/bools aren't amounts; a
    negative refund charges the customer. None of these may pass -- with or
    without the schema check in front of the envelope."""
    sup, gate = _setup()
    for schema in (REFUND_SCHEMA, None):
        manifest = sup.issue_manifest("refund_issuer", "process_refund")
        d = gate.check(
            "refund_issuer",
            "issue_refund",
            {"account": "1234", "amount": amount},
            "write",
            manifest,
            arg_schema=schema,
        )
        assert not d.allowed, f"amount={amount!r} allowed (schema={schema is not None})"


def test_denies_unexpected_argument():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    d = gate.check(
        "refund_issuer",
        "issue_refund",
        {"account": "1234", "amount": 10.0, "currency": "BTC"},
        "write",
        manifest,
        arg_schema=REFUND_SCHEMA,
    )
    assert not d.allowed
    assert "unexpected argument" in d.reason


def test_denies_capability_borrowed_from_another_role():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    d = gate.check(
        "summarizer", "issue_refund", {"account": "1234", "amount": 10.0}, "write", manifest
    )
    assert not d.allowed
    assert "issued to 'refund_issuer'" in d.reason


def test_single_use_capability_cannot_be_replayed():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    args = {"account": "1234", "amount": 49.0}
    check = [args, "write", manifest]
    assert gate.check("refund_issuer", "issue_refund", *check, provenance=TRUSTED).allowed
    d = gate.check("refund_issuer", "issue_refund", *check, provenance=TRUSTED)
    assert not d.allowed
    assert "already used" in d.reason


def test_evaluate_does_not_consume_a_use():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    args = {"account": "1234", "amount": 10.0}
    for _ in range(3):
        d = gate.evaluate(
            "refund_issuer", "issue_refund", args, "write", manifest, provenance=TRUSTED
        )
        assert d.allowed
    assert gate.check(
        "refund_issuer", "issue_refund", args, "write", manifest, provenance=TRUSTED
    ).allowed


def test_gate_error_fails_closed():
    sup, gate = _setup()
    manifest = sup.issue_manifest("refund_issuer", "process_refund")
    d = gate.check("refund_issuer", "issue_refund", None, "write", manifest)  # type: ignore[arg-type]
    assert not d.allowed
    assert "gate error" in d.reason


def test_runner_denies_unknown_tool_cleanly(tmp_path):
    """A hallucinated/injected tool name is an audited DENY, not a KeyError."""
    tools.reset_world()
    sup, gate = _setup()
    audit = AuditLog("unknown-tool", path=tmp_path / "a.jsonl")
    runner = GatedToolRunner(gate, {"refund_issuer": []}, audit)
    with pytest.raises(GateViolation):
        runner.execute("refund_issuer", ToolCall(name="wire_transfer", arguments={"to": "x"}))
    assert [r["event"] for r in audit.records] == ["tool_proposed", "gate_decision", "quarantine"]


def test_runner_denies_string_amount_without_crashing():
    tools.reset_world()
    sup, gate = _setup()
    manifests = {"refund_issuer": sup.issue_manifest("refund_issuer", "process_refund")}
    runner = GatedToolRunner(gate, manifests)
    call = ToolCall(name="issue_refund", arguments={"account": "1234", "amount": "abc"})
    with pytest.raises(GateViolation):
        runner.execute("refund_issuer", call)
    assert tools.REFUNDS_ISSUED == []
