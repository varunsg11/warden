"""Tests for the gated runner as a reusable enforcement path."""

from __future__ import annotations

import pytest

from warden.governance.gate import Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.governance.policy_loader import parse_policy
from warden.llm import ToolCall
from warden.pipeline import tools
from warden.pipeline.runner import GatedToolRunner

POLICY = parse_policy(
    {
        "default_task": "work",
        "tools": {"search_docs": "read", "issue_refund": "write"},
        "tasks": {
            "work": {
                "agent": [
                    {"tool": "search_docs", "scope": "read"},
                    {
                        "tool": "issue_refund",
                        "scope": "write",
                        "params": {"account": {"allow": ["1234"]}},
                    },
                ]
            }
        },
    }
)

READ = ToolCall(name="search_docs", arguments={"query": "refund policy"})
BAD_REFUND = ToolCall(name="issue_refund", arguments={"account": "ATTACKER", "amount": 10.0})


def _runner(**kwargs) -> GatedToolRunner:
    sup = Supervisor(policy=POLICY)
    return GatedToolRunner(Gate(sup.verifier), {"agent": sup.issue_manifest("agent")}, **kwargs)


def test_quarantine_denies_every_later_call():
    tools.reset_world()
    runner = _runner()
    runner.execute("agent", READ)
    with pytest.raises(GateViolation):
        runner.execute("agent", BAD_REFUND)
    assert runner.quarantined

    # The read was fine a moment ago; after the violation, nothing gets through.
    with pytest.raises(GateViolation, match="quarantined"):
        runner.execute("agent", READ)


def test_without_quarantine_later_valid_calls_still_run():
    tools.reset_world()
    runner = _runner(quarantine_on_deny=False)
    with pytest.raises(GateViolation):
        runner.execute("agent", BAD_REFUND)
    assert not runner.quarantined
    assert "refund" in runner.execute("agent", READ).lower()


def test_authorize_never_executes():
    tools.reset_world()
    runner = _runner()
    good = ToolCall(name="issue_refund", arguments={"account": "1234", "amount": 10.0})
    assert runner.authorize("agent", good).allowed
    assert tools.REFUNDS_ISSUED == []


def test_custom_registries_are_used():
    """Integrations bring their own tools: scopes, schemas and implementations."""
    sup = Supervisor(
        policy=parse_policy(
            {
                "default_task": "t",
                "tools": {"ping": "read"},
                "tasks": {"t": {"agent": [{"tool": "ping", "scope": "read"}]}},
            }
        )
    )
    runner = GatedToolRunner(
        Gate(sup.verifier),
        {"agent": sup.issue_manifest("agent")},
        scopes={"ping": "read"},
        schemas={
            "ping": {
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            }
        },
        impls={"ping": lambda host: f"pong from {host}"},
    )
    assert runner.execute("agent", ToolCall(name="ping", arguments={"host": "a"})) == "pong from a"
    with pytest.raises(GateViolation, match="malformed"):
        runner.execute("agent", ToolCall(name="ping", arguments={"host": 1}))
