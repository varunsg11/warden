"""Tests for loading and validating policy files.

A policy is security configuration: every malformed shape must be rejected at
load time, because a silently ignored key is a silently missing restriction.
"""

from __future__ import annotations

import pytest

from warden.cli import main as cli_main
from warden.governance.gate import Gate
from warden.governance.issuer import Supervisor
from warden.governance.policy import DEFAULT_POLICY, POLICY
from warden.governance.policy_loader import PolicyError, load_policy, parse_policy
from warden.pipeline.tools import TOOL_SCOPES

# The policy as it was written in Python before it moved to default.toml.
_READ_DOCS = {"tool": "search_docs", "scope": "read", "params": {}, "ttl": 30.0}
_REFUND = {
    "tool": "issue_refund",
    "scope": "write",
    "params": {
        "amount": {"min": 0.01, "max": 50.0},
        "account": {"allow": ["1234", "5678", "4321"]},
    },
    "ttl": 30.0,
    "max_uses": 1,
}
_EMAIL = {"tool": "send_email", "scope": "write", "params": {}, "ttl": 30.0}
LEGACY_POLICY = {
    "summarize": {"retriever": [_READ_DOCS], "summarizer": [], "refund_issuer": []},
    "process_refund": {"retriever": [_READ_DOCS], "summarizer": [], "refund_issuer": [_REFUND]},
    "reply_to_customer": {"responder": [_EMAIL]},
}


def test_default_toml_matches_the_legacy_python_policy():
    assert POLICY == LEGACY_POLICY
    assert DEFAULT_POLICY.default_task == "summarize"


def test_default_tool_scopes_match_the_tool_registry():
    assert DEFAULT_POLICY.tools == TOOL_SCOPES


def _valid() -> dict:
    return {
        "default_task": "t",
        "tools": {"pay": "write", "read": "read"},
        "tasks": {
            "t": {
                "agent": [
                    {
                        "tool": "pay",
                        "scope": "write",
                        "max_uses": 1,
                        "params": {"amount": {"min": 1, "max": 10}, "to": {"allow": ["a"]}},
                    }
                ],
                "idle": [],
            }
        },
    }


def test_valid_policy_parses_with_defaults():
    policy = parse_policy(_valid())
    [template] = policy.templates_for("t", "agent")
    assert template["ttl"] == 30.0
    assert template["max_uses"] == 1
    assert policy.templates_for("t", "idle") == []
    assert policy.templates_for("missing-task", "agent") == []


def _mutate(fn):
    data = _valid()
    fn(data)
    return data


def _template(data: dict) -> dict:
    return data["tasks"]["t"]["agent"][0]


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda d: d.update(extra=1), "unknown top-level key"),
        (lambda d: d.update(tools={}), "[tools]"),
        (lambda d: d["tools"].update(pay="admin"), "scope 'admin'"),
        (lambda d: d.update(tasks={}), "[tasks]"),
        (lambda d: d["tasks"].update(t="oops"), "table of roles"),
        (lambda d: d["tasks"]["t"].update(agent={"tool": "pay"}), "list of capability templates"),
        (lambda d: d.update(default_task="nope"), "default_task"),
        (lambda d: _template(d).update(tool="wire"), "not declared under [tools]"),
        (lambda d: _template(d).update(scope="read"), "can never authorize"),
        (lambda d: _template(d).update(expires=5), "unknown key"),
        (lambda d: _template(d).update(ttl=0), "ttl"),
        (lambda d: _template(d).update(ttl=True), "ttl"),
        (lambda d: _template(d).update(max_uses=0), "max_uses"),
        (lambda d: _template(d).update(max_uses=True), "max_uses"),
        (lambda d: _template(d).update(max_uses=1.5), "max_uses"),
        (lambda d: _template(d).update(params=[]), "params must be a table"),
        (lambda d: _template(d)["params"].update(amount={"maximum": 10}), "unknown rule"),
        (lambda d: _template(d)["params"].update(amount={}), "non-empty table"),
        (lambda d: _template(d)["params"].update(amount={"max": "10"}), "finite number"),
        (lambda d: _template(d)["params"].update(amount={"max": float("nan")}), "finite number"),
        (lambda d: _template(d)["params"].update(amount={"min": 5, "max": 1}), "greater than max"),
        (lambda d: _template(d)["params"].update(to={"allow": []}), "non-empty list"),
        # Not enforced by the gate yet, so it must not be accepted as if it were.
        (lambda d: _template(d)["params"].update(to={"from": "trusted"}), "unknown rule"),
    ],
)
def test_malformed_policies_are_rejected(mutation, expected):
    with pytest.raises(PolicyError) as err:
        parse_policy(_mutate(mutation))
    assert expected in str(err.value)


def test_invalid_toml_is_a_policy_error(tmp_path):
    path = tmp_path / "bad.toml"
    path.write_text("tools = {", encoding="utf-8")
    with pytest.raises(PolicyError, match="invalid TOML"):
        load_policy(path)


def test_supervisor_issues_from_a_custom_policy_file(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text(
        """
default_task = "pay_rent"
[tools]
send_money = "write"
[[tasks.pay_rent.agent]]
tool = "send_money"
scope = "write"
max_uses = 1
params.amount = { min = 1, max = 1200 }
""",
        encoding="utf-8",
    )
    sup = Supervisor(policy=load_policy(path))
    gate = Gate(sup.verifier)
    manifest = sup.issue_manifest("agent")  # default task comes from the file
    assert gate.check("agent", "send_money", {"amount": 1100}, "write", manifest).allowed
    assert not gate.check("agent", "send_money", {"amount": 5000}, "write", manifest).allowed


def test_cli_policy_check(tmp_path, capsys):
    assert cli_main(["policy", "check", "src/warden/policies/default.toml"]) == 0
    assert "issue_refund[write]" in capsys.readouterr().out

    bad = tmp_path / "bad.toml"
    bad.write_text('default_task = "x"\n[tools]\na = "root"\n[tasks.x]\n', encoding="utf-8")
    assert cli_main(["policy", "check", str(bad)]) == 1
    assert "FAIL" in capsys.readouterr().out
