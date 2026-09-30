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
"""

from __future__ import annotations

from typing import Protocol

from warden.governance.audit import AuditLog
from warden.governance.capability import Capability
from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Gate, GateViolation
from warden.llm import ToolCall
from warden.pipeline.tools import TOOL_IMPLS, TOOL_SCOPES, TOOL_SPECS


class Runner(Protocol):
    def execute(self, role: str, call: ToolCall) -> str: ...


class ToolRunner:
    """Ungated baseline: proposal in, action out, no questions asked."""

    def execute(self, role: str, call: ToolCall) -> str:
        return TOOL_IMPLS[call.name](**call.arguments)


class GatedToolRunner:
    """Governed: every call passes through the gate, and every step is audited."""

    def __init__(
        self,
        gate: Gate,
        manifests: dict[str, list[Capability]],
        audit: AuditLog | None = None,
        drift: DriftDetector | None = None,
    ) -> None:
        self._gate = gate
        self._manifests = manifests
        self._drift = drift
        self.audit = audit
        self.decisions: list = []

    def execute(self, role: str, call: ToolCall) -> str:
        if self.audit:
            self.audit.record("tool_proposed", role=role, tool=call.name, arguments=call.arguments)

        # --- Stage 1: the capability gate (is this call in bounds?) --------- #
        # An unknown tool gets no scope and no schema; it holds no capability
        # either, so the gate denies it (audited) instead of a KeyError here.
        spec = TOOL_SPECS.get(call.name)
        decision = self._gate.check(
            role=role,
            tool_name=call.name,
            arguments=call.arguments,
            required_scope=TOOL_SCOPES.get(call.name, ""),
            manifest=self._manifests.get(role, []),
            arg_schema=spec.parameters if spec else None,
        )
        self.decisions.append(decision)

        if self.audit:
            self.audit.record(
                "gate_decision",
                role=role,
                tool=call.name,
                allowed=decision.allowed,
                reason=decision.reason,
                capability_nonce=(decision.capability.nonce if decision.capability else None),
            )

        if not decision.allowed:
            if self.audit:
                self.audit.record("quarantine", role=role, tool=call.name, reason=decision.reason)
            raise GateViolation(decision)

        # --- Stage 2: drift (in bounds, but does it look normal?) ----------- #
        if self._drift is not None:
            drift = self._drift.check(call.name, call.arguments)
            if self.audit:
                self.audit.record(
                    "drift_check",
                    role=role,
                    tool=call.name,
                    is_drift=drift.is_drift,
                    reasons=drift.reasons,
                    score=round(drift.score, 2),
                )
            if drift.is_drift:
                reason = "DRIFT: " + "; ".join(drift.reasons)
                if self.audit:
                    self.audit.record("quarantine", role=role, tool=call.name, reason=reason)
                raise DriftViolation(drift)

        result = TOOL_IMPLS[call.name](**call.arguments)
        if self.audit:
            self.audit.record("tool_executed", role=role, tool=call.name, result=result)
        return result
