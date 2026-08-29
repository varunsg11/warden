"""The Capability: a signed, time-limited permission to call ONE tool under
specific constraints.

Formal shape (from the MCP-capability literature):

    c = (tool, params, scope, ttl, nonce, issuer, signature)

  * tool      — the single tool this authorizes (e.g. "issue_refund").
  * scope     — read | write | execute. Least privilege: a "read" cap can never
                authorize a "write" operation.
  * params    — constraints on the arguments (e.g. amount<=50, account in [...]).
  * ttl       — seconds the capability stays valid after issuance. Bounds the
                TOCTOU window: a permission granted now must not live forever.
  * nonce     — unique id, so two otherwise-identical caps are distinguishable
                and a capability can't be trivially replayed as another.
  * issuer    — who minted it (the Supervisor's id).
  * signature — Ed25519 signature binding ALL of the above to the issuer.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, replace
from typing import Any

from warden.governance.signing import Signer, Verifier


@dataclass(frozen=True)
class Capability:
    tool: str
    scope: str  # "read" | "write" | "execute"
    params: dict[str, Any] = field(default_factory=dict)
    ttl: float = 30.0
    issued_at: float = field(default_factory=time.time)
    nonce: str = ""
    issuer: str = ""
    signature: str | None = None

    # --- signing / verification ------------------------------------------- #
    def signing_payload(self) -> bytes:
        """Canonical bytes over everything EXCEPT the signature itself.

        sort_keys + fixed separators make this deterministic, so the issuer and
        the gate always hash exactly the same bytes.
        """
        body = {
            "tool": self.tool,
            "scope": self.scope,
            "params": self.params,
            "ttl": self.ttl,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "issuer": self.issuer,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def signed(self, signer: Signer) -> Capability:
        """Return a copy carrying a valid signature."""
        return replace(self, signature=signer.sign(self.signing_payload()))

    def verify_signature(self, verifier: Verifier) -> bool:
        if not self.signature:
            return False
        return verifier.verify(self.signing_payload(), self.signature)

    # --- runtime checks --------------------------------------------------- #
    def is_expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now > self.issued_at + self.ttl

    def params_ok(self, arguments: dict[str, Any]) -> tuple[bool, str]:
        """Check the proposed arguments against this capability's constraints.

        Supported rules per field: {"max": n}, {"min": n}, {"allow": [...]}.
        A field with no rule is unconstrained; a rule on a missing argument fails.
        """
        for field_name, rule in self.params.items():
            value = arguments.get(field_name)
            if "allow" in rule and value not in rule["allow"]:
                return False, f"{field_name}={value!r} not in allowlist {rule['allow']}"
            if "max" in rule and (value is None or float(value) > rule["max"]):
                return False, f"{field_name}={value} exceeds max {rule['max']}"
            if "min" in rule and (value is None or float(value) < rule["min"]):
                return False, f"{field_name}={value} below min {rule['min']}"
        return True, ""
