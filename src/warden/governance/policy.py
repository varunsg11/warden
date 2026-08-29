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
  * task "process_refund" -> refund_issuer may issue refunds, but only <= $50 and
                             only to the customer's own account (1234).
"""

from __future__ import annotations

from typing import Any

_READ_DOCS = {"tool": "search_docs", "scope": "read", "params": {}, "ttl": 30.0}

_CONSTRAINED_REFUND = {
    "tool": "issue_refund",
    "scope": "write",
    "params": {
        "amount": {"max": 50.0},  # small refunds only
        "account": {"allow": ["1234", "5678", "4321"]},  # the customer's known accounts
    },
    "ttl": 30.0,
}

# send_email can't be tightly param-constrained -- you can't allowlist every
# legitimate recipient. So the gate permits it broadly and DRIFT watches the
# destination domain. This is the division of labour between the two defenses.
_SEND_EMAIL = {"tool": "send_email", "scope": "write", "params": {}, "ttl": 30.0}

# task -> role -> list of capability templates
POLICY: dict[str, dict[str, list[dict[str, Any]]]] = {
    "summarize": {
        "retriever": [_READ_DOCS],
        "summarizer": [],
        "refund_issuer": [],  # <-- no write authority for a read-only task
    },
    "process_refund": {
        "retriever": [_READ_DOCS],
        "summarizer": [],
        "refund_issuer": [_CONSTRAINED_REFUND],
    },
    "reply_to_customer": {
        "responder": [_SEND_EMAIL],
    },
}

DEFAULT_TASK = "summarize"


def templates_for(task: str, role: str) -> list[dict[str, Any]]:
    return POLICY.get(task, {}).get(role, [])
