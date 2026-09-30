"""The static policy: what each ROLE may do, per TASK.

This is the key upgrade from "least privilege by role" to "least privilege by
task" (a.k.a. just-in-time access). Authority is granted for the specific
workflow the application invoked this turn, and no other.

The application declares the task when it starts a session (it knows which
workflow it is running). Crucially, the task comes from the trusted caller — NOT
from retrieved data — so an injection hidden in a document cannot change it.

Read the difference:
  * task "summarize"      -> refund_issuer gets NOTHING. A read-only workflow
                             carries no authority to move money, so an injected
                             "issue a refund" is denied at the very first check:
                             the capability to do it was never handed out.
  * task "process_refund" -> refund_issuer may issue ONE refund per turn, between
                             $0.01 and $50, only to the customer's known accounts.

The policy itself lives in a data file, `warden/policies/default.toml`, loaded
and strictly validated by `policy_loader`. Supply your own with
`Supervisor(policy=load_policy("my_policy.toml"))`.
"""

from __future__ import annotations

import tomllib
from importlib.resources import files
from typing import Any

from warden.governance.policy_loader import Policy, parse_policy

_DEFAULT_FILE = files("warden").joinpath("policies/default.toml")


def _load_default() -> Policy:
    return parse_policy(tomllib.loads(_DEFAULT_FILE.read_text(encoding="utf-8")), "default.toml")


DEFAULT_POLICY: Policy = _load_default()

# task -> role -> list of capability templates
POLICY: dict[str, dict[str, list[dict[str, Any]]]] = DEFAULT_POLICY.tasks
DEFAULT_TASK: str = DEFAULT_POLICY.default_task


def templates_for(task: str, role: str) -> list[dict[str, Any]]:
    return DEFAULT_POLICY.templates_for(task, role)
