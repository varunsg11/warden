"""The Supervisor: issues signed capability manifests, one per agent per turn,
scoped to the TASK the application declared.

It holds the ONLY private key in the system. Agents receive manifests (lists of
signed capabilities) and can verify them, but can never mint their own. This is
what makes the agent a "first-class principal" with its own explicit, scoped
authority rather than inheriting broad ambient permissions.
"""

from __future__ import annotations

import uuid

from warden.governance.capability import Capability
from warden.governance.policy import DEFAULT_POLICY
from warden.governance.policy_loader import Policy
from warden.governance.signing import Signer, Verifier


class Supervisor:
    def __init__(
        self,
        signer: Signer | None = None,
        issuer_id: str = "warden-supervisor",
        policy: Policy | None = None,
    ) -> None:
        self.signer = signer or Signer()
        self.issuer_id = issuer_id
        self.policy = policy or DEFAULT_POLICY

    def issue_manifest(self, role: str, task: str | None = None) -> list[Capability]:
        """Mint fresh, signed capabilities for `role` under `task`, for this turn."""
        task = self.policy.default_task if task is None else task
        manifest: list[Capability] = []
        for template in self.policy.templates_for(task, role):
            cap = Capability(
                tool=template["tool"],
                scope=template["scope"],
                params=template.get("params", {}),
                ttl=template.get("ttl", 30.0),
                nonce=uuid.uuid4().hex,
                issuer=self.issuer_id,
                subject=role,
                max_uses=template.get("max_uses"),
            ).signed(self.signer)
            manifest.append(cap)
        return manifest

    def issue_all(self, roles: list[str], task: str | None = None) -> dict[str, list[Capability]]:
        return {role: self.issue_manifest(role, task) for role in roles}

    @property
    def verifier(self) -> Verifier:
        """The public-key verifier handed to the (untrusted) gate."""
        return self.signer.verifier()
