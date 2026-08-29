"""Tests for the tamper-evident audit log."""

from __future__ import annotations

from warden.governance.audit import AuditLog


def test_clean_chain_verifies(tmp_path):
    log = AuditLog("t1", path=tmp_path / "t1.jsonl")
    log.record("session_start", task="summarize")
    log.record("gate_decision", allowed=True, reason="ok")
    log.record("session_end", status="completed")
    assert log.verify_chain() is True


def test_tampering_breaks_the_chain(tmp_path):
    log = AuditLog("t2", path=tmp_path / "t2.jsonl")
    log.record("gate_decision", allowed=False, reason="DENY: no capability")
    log.record("session_end", status="quarantined")

    # An attacker rewrites history: flip a past denial into an approval.
    log.records[0]["allowed"] = True
    log.records[0]["reason"] = "ALLOW"

    assert log.verify_chain() is False
