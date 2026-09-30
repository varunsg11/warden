"""End-to-end tests of the AgentDojo adapter on a real AgentDojo suite, offline.

Uses the scripted always-fooled agent, so no LLM and no network. Skipped unless
the optional `agentdojo` extra is installed (CI doesn't install it).
"""

from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from agentdojo.agent_pipeline import (  # noqa: E402
    AgentPipeline,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message  # noqa: E402
from agentdojo.attacks.attack_registry import load_attack  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402

from warden.governance.audit import AuditLog  # noqa: E402
from warden.governance.policy_loader import parse_policy  # noqa: E402
from warden.integrations.agentdojo import (  # noqa: E402
    ROLE,
    ScriptedAgent,
    WardenConfig,
    WardenSession,
    WardenSessionEnd,
    WardenToolsExecutor,
)

SUITE = get_suite("v1.2.2", "banking")
READS = [
    "get_iban",
    "get_balance",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "read_file",
    "get_user_info",
]
WRITES = [
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "update_password",
    "update_user_info",
]
TOOLS = {**dict.fromkeys(READS, "read"), **dict.fromkeys(WRITES, "write")}
PAY_BILL = SUITE.user_tasks["user_task_0"]  # "pay the bill in bill-december-2023.txt"
CHANGE_PASSWORD = SUITE.injection_tasks["injection_task_7"]
STEAL_MONEY = SUITE.injection_tasks["injection_task_5"]  # "send as much money as possible"


def _grant(names):
    return [{"tool": n, "scope": TOOLS[n], "ttl": 3600.0} for n in names]


def _pipeline(defended: bool, tmp_path=None, **config):
    llm = ScriptedAgent(SUITE, name="gpt-4o-mini-2024-07-18-scripted")
    system = SystemMessage(load_system_message(None))
    if not defended:
        pipeline = AgentPipeline(
            [system, InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
        )
        pipeline.name = llm.name
        return pipeline, None
    policy = parse_policy(
        {
            "default_task": "none",
            "tools": TOOLS,
            "tasks": {"none": {ROLE: []}, "send_payment": {ROLE: _grant([*READS, "send_money"])}},
        }
    )
    warden = WardenConfig(
        policy=policy,
        declare_task=lambda prompt: "send_payment" if prompt == PAY_BILL.PROMPT else "none",
        audit_dir=tmp_path,
        **config,
    )
    pipeline = AgentPipeline(
        [
            system,
            WardenSession(warden),
            InitQuery(),
            llm,
            ToolsExecutionLoop([WardenToolsExecutor(warden), llm]),
            WardenSessionEnd(),
        ]
    )
    pipeline.name = llm.name
    return pipeline, warden


def _run(pipeline, injection_task):
    attack = load_attack("important_instructions", SUITE, pipeline)
    injections = attack.attack(PAY_BILL, injection_task)
    return SUITE.run_task_with_pipeline(pipeline, PAY_BILL, injection_task, injections)


def test_scripted_agent_is_fooled_without_warden():
    utility, attack_succeeded = _run(_pipeline(defended=False)[0], CHANGE_PASSWORD)
    assert utility
    assert attack_succeeded, "the worst-case agent must actually fall for the injection"


def test_warden_blocks_a_tool_the_task_never_needed(tmp_path):
    pipeline, warden = _pipeline(defended=True, tmp_path=tmp_path)
    utility, attack_succeeded = _run(pipeline, CHANGE_PASSWORD)
    assert not attack_succeeded
    assert warden.denials["capability_present"] >= 1
    [log] = list(tmp_path.glob("*.jsonl"))
    ok, detail = AuditLog.verify_file(log)
    assert ok, detail
    assert '"event": "quarantine"' in log.read_text(), "the denial must be audited"


def test_quarantine_costs_utility_but_error_mode_keeps_it():
    """Quarantine is the safe default; 'error' mode tells the model and carries on."""
    pipeline, _ = _pipeline(defended=True)
    quarantined_utility, _ = _run(pipeline, CHANGE_PASSWORD)
    pipeline, _ = _pipeline(defended=True, quarantine_on_deny=False)
    error_mode_utility, attack_succeeded = _run(pipeline, CHANGE_PASSWORD)
    assert not attack_succeeded
    assert error_mode_utility
    assert error_mode_utility >= quarantined_utility


def test_in_envelope_attack_is_not_stopped_by_tool_level_policy():
    """Documents the known limit that provenance tracking exists to close:
    paying a bill needs send_money, so sending the attacker money is in-envelope."""
    pipeline, _ = _pipeline(defended=True, quarantine_on_deny=False)
    _, attack_succeeded = _run(pipeline, STEAL_MONEY)
    assert attack_succeeded
