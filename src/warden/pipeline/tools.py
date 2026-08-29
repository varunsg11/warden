"""The tools the agents can call — i.e. the actions that can actually affect the
world. Some only READ (safe); some WRITE (dangerous). Warden's job is to make
sure a fooled agent can't reach the dangerous ones without authorization.

Each tool is:
  * a ToolSpec (name + description + JSON-Schema arguments) shown to the model, and
  * a plain Python function that performs the action.

We keep a tiny bit of "world state" (a refund ledger, a sent-mail box) as module
globals so the demo can inspect, after a run, whether a harmful action actually
happened.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from warden.llm import ToolSpec

# --------------------------------------------------------------------------- #
# "World state" — visible side effects so the demo can prove what happened.
# --------------------------------------------------------------------------- #
REFUNDS_ISSUED: list[dict[str, Any]] = []
EMAILS_SENT: list[dict[str, Any]] = []


def reset_world() -> None:
    """Clear side effects between runs (so baseline and governed runs are clean)."""
    REFUNDS_ISSUED.clear()
    EMAILS_SENT.clear()


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #
_CORPUS_DIR = Path(__file__).resolve().parent.parent / "corpus" / "docs"


def search_docs(query: str) -> str:
    """READ-ONLY. Naive keyword retriever over the local corpus.

    Returns the concatenated text of the most relevant documents. Note that the
    documents are attacker-influenceable content — this is the channel through
    which an indirect prompt injection enters the system.
    """
    query_terms = {w.lower() for w in query.split() if w}
    scored: list[tuple[int, str, str]] = []
    for path in sorted(_CORPUS_DIR.glob("*.txt")):
        text = path.read_text(encoding="utf-8")
        score = sum(text.lower().count(term) for term in query_terms)
        scored.append((score, path.name, text))

    scored.sort(key=lambda t: t[0], reverse=True)
    top = [s for s in scored if s[0] > 0][:3] or scored[:2]
    return "\n\n".join(f"--- {name} ---\n{text}" for _, name, text in top)


def issue_refund(account: str, amount: float) -> str:
    """WRITE / DANGEROUS. Moves money. In a real system this hits a payments API."""
    record = {"account": account, "amount": float(amount)}
    REFUNDS_ISSUED.append(record)
    return f"Refund of ${amount:.2f} issued to account {account}."


def send_email(to: str, subject: str, body: str) -> str:
    """WRITE / DANGEROUS. A classic data-exfiltration channel."""
    record = {"to": to, "subject": subject, "body": body}
    EMAILS_SENT.append(record)
    return f"Email sent to {to}."


# --------------------------------------------------------------------------- #
# Tool registry: name -> (spec shown to the model, function that runs it)
# --------------------------------------------------------------------------- #
TOOL_SPECS: dict[str, ToolSpec] = {
    "search_docs": ToolSpec(
        name="search_docs",
        description="Search the customer/support knowledge base and return relevant documents.",
        parameters={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    ),
    "issue_refund": ToolSpec(
        name="issue_refund",
        description="Issue a monetary refund to a customer account.",
        parameters={
            "type": "object",
            "properties": {
                "account": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["account", "amount"],
        },
    ),
    "send_email": ToolSpec(
        name="send_email",
        description="Send an email to a recipient.",
        parameters={
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    ),
}

TOOL_IMPLS: dict[str, Callable[..., str]] = {
    "search_docs": search_docs,
    "issue_refund": issue_refund,
    "send_email": send_email,
}

# The scope each tool's operation REQUIRES. The gate compares this against the
# scope a capability grants. Reading is cheap; writing moves money / sends data.
TOOL_SCOPES: dict[str, str] = {
    "search_docs": "read",
    "issue_refund": "write",
    "send_email": "write",
}
