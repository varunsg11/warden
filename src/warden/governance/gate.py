"""The enforcement gate — the deterministic core of Warden.

Every tool call an agent proposes is checked here BEFORE it can run. The gate
answers one question with ordinary code: "does this agent hold a valid, signed,
unexpired, in-scope, in-bounds, unspent capability for exactly this well-formed
call?" If any check fails, the call never executes.

There is no LLM here and never will be. That is the entire security argument:
an injection can talk a model into proposing issue_refund("ATTACKER-0001", 999.99),
but it cannot talk the checks below into returning allowed=True.

The checks, in order:
  1. capability_present  the role holds some capability for this tool
  2. args_well_formed    arguments match the tool's schema (no NaN, no extra keys)
  then, per candidate capability:
  3. signature_valid     minted by the Supervisor, not a byte changed
  4. bound_to_role       issued to THIS role, not borrowed from another
  5. not_expired         within its ttl
  6. scope_ok            grants the scope the operation needs
  7. params_ok           arguments inside the granted envelope
  8. uses_remaining      not already spent (single-use caps can't be replayed)

`evaluate()` returns both the Decision AND a per-check trace, and has no side
effects. `check()` is what enforcement calls: it records the use on ALLOW, and it
fails CLOSED -- any unexpected error becomes a DENY, never a crash or an allow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from warden.governance.capability import Capability
from warden.governance.schema import validate_args
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
        # nonce -> number of calls this gate has authorized with that capability.
        self._uses: dict[str, int] = {}

    def check(
        self,
        role: str,
        tool_name: str,
        arguments: dict[str, Any],
        required_scope: str,
        manifest: list[Capability],
        now: float | None = None,
        arg_schema: dict[str, Any] | None = None,
    ) -> Decision:
        try:
            decision = self.evaluate(
                role, tool_name, arguments, required_scope, manifest, now, arg_schema
            )
        except Exception as exc:  # fail closed: an error must never become an allow
            return Decision(False, f"DENY: gate error ({type(exc).__name__}: {exc})")
        if decision.allowed and decision.capability is not None:
            nonce = decision.capability.nonce
            self._uses[nonce] = self._uses.get(nonce, 0) + 1
        return decision

    def evaluate(
        self,
        role: str,
        tool_name: str,
        arguments: dict[str, Any],
        required_scope: str,
        manifest: list[Capability],
        now: float | None = None,
        arg_schema: dict[str, Any] | None = None,
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

        # 2. Is the call well-formed? Malformed values (NaN, bools, strings where
        #    numbers belong, unexpected keys) are rejected before any bound is compared.
        if arg_schema is not None:
            ok, why = validate_args(arg_schema, arguments)
            header.append(CheckStep("args_well_formed", ok, why or "arguments match schema"))
            if not ok:
                return Decision(
                    False, f"DENY: malformed arguments for '{tool_name}': {why}", None, header
                )

        last_reason = ""
        decisive: list[CheckStep] = []
        for cap in candidates:
            steps: list[CheckStep] = []

            # 3. Signature: integrity + authenticity. Catches any tampering.
            ok = cap.verify_signature(self._verifier)
            steps.append(CheckStep("signature_valid", ok))
            if not ok:
                last_reason = f"DENY: capability for '{tool_name}' has an invalid signature"
                decisive = steps
                continue

            # 4. Subject: the capability must have been issued to THIS role.
            ok = cap.subject == role
            steps.append(CheckStep("bound_to_role", ok, f"issued to '{cap.subject}'"))
            if not ok:
                last_reason = (
                    f"DENY: capability for '{tool_name}' was issued to '{cap.subject}', "
                    f"not '{role}'"
                )
                decisive = steps
                continue

            # 5. TTL: a permission valid at issue time must not be valid forever.
            ok = not cap.is_expired(now)
            steps.append(CheckStep("not_expired", ok, f"ttl={cap.ttl}s"))
            if not ok:
                last_reason = f"DENY: capability for '{tool_name}' has expired (ttl={cap.ttl}s)"
                decisive = steps
                continue

            # 6. Scope: least privilege. A read cap cannot authorize a write.
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

            # 7. Params: the arguments must fall inside the granted envelope.
            ok, why = cap.params_ok(arguments)
            steps.append(CheckStep("params_ok", ok, why or "arguments within envelope"))
            if not ok:
                last_reason = f"DENY: parameter constraint violated on '{tool_name}': {why}"
                decisive = steps
                continue

            # 8. Uses: a spent capability can't be replayed for another call.
            used = self._uses.get(cap.nonce, 0)
            ok = cap.max_uses is None or used < cap.max_uses
            limit = "unlimited" if cap.max_uses is None else str(cap.max_uses)
            steps.append(CheckStep("uses_remaining", ok, f"used {used} of {limit}"))
            if not ok:
                last_reason = (
                    f"DENY: capability for '{tool_name}' already used {used} of {limit} time(s)"
                )
                decisive = steps
                continue

            return Decision(
                True, f"ALLOW: '{tool_name}' authorized for role '{role}'", cap, header + steps
            )

        return Decision(False, last_reason, candidates[0], header + decisive)
