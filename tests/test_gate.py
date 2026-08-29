"""Unit tests for the enforcement gate — one test per way a call can be denied.

These are deterministic and need no LLM: the gate is pure logic, which is the
whole point. If any of these ever fails, a hole has opened in the security core.
"""

from __future__ import annotations

import time

from warden.governance.capability import Capability
from warden.governance.gate import Gate
from warden.governance.issuer import Supervisor


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
        "refund_issuer", "issue_refund", {"account": "1234", "amount": 25.0}, "write", manifest
    )
    assert d.allowed


# --- the five denial modes -------------------------------------------------- #
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
