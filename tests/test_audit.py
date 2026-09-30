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


def _closed_log(tmp_path):
    log = AuditLog("t3", path=tmp_path / "t3.jsonl")
    log.record("session_start", task="summarize")
    log.record("gate_decision", allowed=False, reason="DENY: no capability")
    log.record("session_end", status="quarantined")
    return log.path


def test_verify_file_accepts_clean_log(tmp_path):
    ok, detail = AuditLog.verify_file(_closed_log(tmp_path))
    assert ok, detail


def test_verify_file_detects_edited_record(tmp_path):
    path = _closed_log(tmp_path)
    path.write_text(path.read_text().replace('"allowed": false', '"allowed": true'))
    ok, detail = AuditLog.verify_file(path)
    assert not ok
    assert "record 1" in detail


def test_verify_file_detects_deleted_record(tmp_path):
    path = _closed_log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _ = AuditLog.verify_file(path)
    assert not ok


def test_verify_file_detects_truncated_tail(tmp_path):
    """The chain can't see a cut-off tail on its own; the missing session_end can."""
    path = _closed_log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2]) + "\n")
    ok, detail = AuditLog.verify_file(path)
    assert not ok
    assert "session_end" in detail


def test_non_finite_values_are_logged_as_strict_json(tmp_path):
    log = AuditLog("t4", path=tmp_path / "t4.jsonl")
    log.record("tool_proposed", arguments={"amount": float("nan")})
    log.record("session_end", status="quarantined")
    assert "NaN" not in log.path.read_text()
    assert AuditLog.verify_file(log.path)[0]
