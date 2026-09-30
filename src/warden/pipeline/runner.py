"""The execution seam between the agents and the tools.

An agent never calls a tool directly; it hands a proposed ToolCall to a runner.
Swapping the runner is the ENTIRE difference between the baseline (vulnerable)
and governed (defended) systems:

  * ToolRunner       — runs whatever is proposed. No checks.
  * GatedToolRunner  — consults the gate first, records everything to the audit
                       log, executes only on ALLOW, and raises GateViolation on
                       DENY (which halts / quarantines the session).

The runner is the only place that EXECUTES a tool. The gate only DECIDES. That
separation keeps the security core independent of the pipeline it protects.

`GatedToolRunner.authorize()` is the enforcement path on its own (gate -> drift
-> audit, raising on any violation). `execute()` is authorize + run. Integrations
that execute tools their own way (AgentDojo's runtime, an upstream MCP server)
call `authorize()` and then run the tool themselves -- so every integration goes
through exactly the same checks.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from warden.governance.audit import AuditLog
from warden.governance.capability import Capability
from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Decision, Gate, GateViolation
from warden.llm import ToolCall
from warden.pipeline.tools import TOOL_IMPLS, TOOL_SCOPES, TOOL_SPECS


class Runner(Protocol):
    def execute(self, role: str, call: ToolCall) -> str: ...


class ToolRunner:
    """Ungated baseline: proposal in, action out, no questions asked."""

    def execute(self, role: str, call: ToolCall) -> str:
        return TOOL_IMPLS[call.name](**call.arguments)


class GatedToolRunner:
    """Governed: every call passes through the gate, and every step is audited.

    The tool registries default to the demo pipeline's (`pipeline/tools.py`);
    integrations pass their own:
      * scopes  — tool -> scope its operation requires
      * schemas — tool -> JSON Schema of its arguments (checked by the gate)
      * impls   — tool -> function (only needed if you call `execute()`)

    With `quarantine_on_deny` (the default), the first violation quarantines the
    session: every later call is denied, however harmless it looks.
    """

    def __init__(
        self,
        gate: Gate,
        manifests: dict[str, list[Capability]],
        audit: AuditLog | None = None,
        drift: DriftDetector | None = None,
        *,
        scopes: Mapping[str, str] | None = None,
        schemas: Mapping[str, dict[str, Any]] | None = None,
        impls: Mapping[str, Callable[..., str]] | None = None,
        quarantine_on_deny: bool = True,
    ) -> None:
        self._gate = gate
        self._manifests = manifests
        self._drift = drift
        self._scopes = TOOL_SCOPES if scopes is None else scopes
        self._schemas = (
            {name: spec.parameters for name, spec in TOOL_SPECS.items()}
            if schemas is None
            else schemas
        )
        self._impls = TOOL_IMPLS if impls is None else impls
        self._quarantine_on_deny = quarantine_on_deny
        self.audit = audit
        self.decisions: list[Decision] = []
        self.quarantined = False

    def authorize(self, role: str, call: ToolCall) -> Decision:
        """Run the enforcement checks. Returns the ALLOW decision, or raises
        GateViolation / DriftViolation. Never executes anything."""
        self._record("tool_proposed", role=role, tool=call.name, arguments=call.arguments)

        # --- Stage 0: a quarantined session gets nothing more --------------- #
        if self.quarantined:
            decision = Decision(False, "DENY: session is quarantined after an earlier violation")
            self.decisions.append(decision)
            self._record(
                "gate_decision", role=role, tool=call.name, allowed=False, reason=decision.reason
            )
            raise GateViolation(decision)

        # --- Stage 1: the capability gate (is this call in bounds?) --------- #
        # An unknown tool gets no scope and no schema; it holds no capability
        # either, so the gate denies it (audited) instead of a KeyError here.
        decision = self._gate.check(
            role=role,
            tool_name=call.name,
            arguments=call.arguments,
            required_scope=self._scopes.get(call.name, ""),
            manifest=self._manifests.get(role, []),
            arg_schema=self._schemas.get(call.name),
        )
        self.decisions.append(decision)
        self._record(
            "gate_decision",
            role=role,
            tool=call.name,
            allowed=decision.allowed,
            reason=decision.reason,
            capability_nonce=(decision.capability.nonce if decision.capability else None),
        )
        if not decision.allowed:
            self._quarantine(role, call.name, decision.reason)
            raise GateViolation(decision)

        # --- Stage 2: drift (in bounds, but does it look normal?) ----------- #
        if self._drift is not None:
            drift = self._drift.check(call.name, call.arguments)
            self._record(
                "drift_check",
                role=role,
                tool=call.name,
                is_drift=drift.is_drift,
                reasons=drift.reasons,
                score=round(drift.score, 2),
            )
            if drift.is_drift:
                self._quarantine(role, call.name, "DRIFT: " + "; ".join(drift.reasons))
                raise DriftViolation(drift)

        return decision

    def execute(self, role: str, call: ToolCall) -> str:
        self.authorize(role, call)
        result = self._impls[call.name](**call.arguments)
        self._record("tool_executed", role=role, tool=call.name, result=result)
        return result

    def _quarantine(self, role: str, tool: str, reason: str) -> None:
        if self._quarantine_on_deny:
            self.quarantined = True
            self._record("quarantine", role=role, tool=tool, reason=reason)

    def _record(self, event: str, **fields: Any) -> None:
        if self.audit:
            self.audit.record(event, **fields)
