"""The enforcement gate — the deterministic core of Warden.

Every tool call an agent proposes is checked here BEFORE it can run. The gate
answers one question with ordinary code: "does this agent hold a valid, signed,
unexpired, in-scope, in-bounds capability for exactly this call?" If any check
fails, the call never executes.

There is no LLM here and never will be. That is the entire security argument:
an injection can talk a model into proposing issue_refund("ATTACKER-0001", 999.99),
but it cannot talk the five checks below into returning allowed=True.

`evaluate()` returns both the Decision AND a per-check trace (used by the debug
tracer and the audit story). `check()` is the thin wrapper that returns just the
Decision, so there is a single source of truth for the logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from warden.governance.capability import Capability
from warden.governance.signing import Verifier


@dataclass
class CheckStep:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Decision:
    allowed: bool
    reason: str
    capability: Capability | None = None
    steps: list[CheckStep] = field(default_factory=list)


class GateViolation(Exception):
    """Raised when a proposed tool call is denied. Halts the session."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


class Gate:
    def __init__(self, verifier: Verifier) -> None:
        self._verifier = verifier

    def check(self, role, tool_name, arguments, required_scope, manifest, now=None) -> Decision:
        return self.evaluate(role, tool_name, arguments, required_scope, manifest, now)

    def evaluate(
        self,
        role: str,
        tool_name: str,
        arguments: dict[str, Any],
        required_scope: str,
        manifest: list[Capability],
        now: float | None = None,
    ) -> Decision:
        # 1. Does the agent hold ANY capability for this tool this turn?
        candidates = [c for c in manifest if c.tool == tool_name]
        header = [
            CheckStep(
                "capability_present",
                bool(candidates),
                f"{len(candidates)} matching capability(ies) for '{tool_name}'",
            )
        ]
        if not candidates:
            return Decision(
                False,
                f"DENY: role '{role}' holds no capability for tool '{tool_name}'",
                None,
                header,
            )

        last_reason = ""
        decisive: list[CheckStep] = []
        for cap in candidates:
            steps: list[CheckStep] = []

            # 2. Signature: integrity + authenticity. Catches any tampering.
            ok = cap.verify_signature(self._verifier)
            steps.append(CheckStep("signature_valid", ok))
            if not ok:
                last_reason = f"DENY: capability for '{tool_name}' has an invalid signature"
                decisive = steps
                continue

            # 3. TTL: a permission valid at issue time must not be valid forever.
            ok = not cap.is_expired(now)
            steps.append(CheckStep("not_expired", ok, f"ttl={cap.ttl}s"))
            if not ok:
                last_reason = f"DENY: capability for '{tool_name}' has expired (ttl={cap.ttl}s)"
                decisive = steps
                continue

            # 4. Scope: least privilege. A read cap cannot authorize a write.
            ok = cap.scope == required_scope
            steps.append(
                CheckStep("scope_ok", ok, f"grants '{cap.scope}', needs '{required_scope}'")
            )
            if not ok:
                last_reason = (
                    f"DENY: scope mismatch on '{tool_name}': capability grants "
                    f"'{cap.scope}', operation requires '{required_scope}'"
                )
                decisive = steps
                continue

            # 5. Params: the arguments must fall inside the granted envelope.
            ok, why = cap.params_ok(arguments)
            steps.append(CheckStep("params_ok", ok, why or "arguments within envelope"))
            if not ok:
                last_reason = f"DENY: parameter constraint violated on '{tool_name}': {why}"
                decisive = steps
                continue

            return Decision(
                True, f"ALLOW: '{tool_name}' authorized for role '{role}'", cap, header + steps
            )

        return Decision(False, last_reason, candidates[0], header + decisive)
