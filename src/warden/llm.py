"""The LLM layer: a small, backend-agnostic interface for talking to a model.

WHY THIS EXISTS
---------------
A LangGraph node just needs to ask a model: "given this context and these tools
you're allowed to use, what do you want to do?" and get back either some text or
a proposed tool call. We wrap that in a tiny interface with two implementations:

  * OpenAIBackend  — the real thing (gpt-4o-mini by default).
  * FakeBackend    — deterministic, no network. Simulates a model that has been
                     FOOLED by an injection, so the whole demo/tests run offline
                     and repeatably. It is a stand-in, not the real security
                     demonstration — that one uses OpenAIBackend.

The key concept to notice: a "tool call" is just structured data the model emits
(a name + arguments). It is a *proposal*, not an action. Nothing happens until
some code actually executes it. Warden's whole job is to sit in that gap.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from warden.settings import settings


# --------------------------------------------------------------------------- #
# Data types shared by both backends
# --------------------------------------------------------------------------- #
@dataclass
class ToolSpec:
    """Describes a tool the model is allowed to propose calling this turn."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON Schema for the arguments

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass
class ToolCall:
    """A tool call the model PROPOSED. Not executed yet — that's the point."""

    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str | None = None
    tool_call: ToolCall | None = None


# --------------------------------------------------------------------------- #
# Backend interface
# --------------------------------------------------------------------------- #
class LLMBackend(Protocol):
    def complete(
        self, system: str, user: str, tools: list[ToolSpec] | None = None
    ) -> LLMResponse: ...


# --------------------------------------------------------------------------- #
# Real backend — OpenAI
# --------------------------------------------------------------------------- #
class OpenAIBackend:
    def __init__(self) -> None:
        if not settings.openai_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Put it in .env, or set WARDEN_FAKE_LLM=1 "
                "to run offline with the fake backend."
            )
        # Imported lazily so the fake backend works without the openai package.
        from openai import OpenAI

        self._client = OpenAI(api_key=settings.openai_api_key)

    def complete(self, system: str, user: str, tools: list[ToolSpec] | None = None) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": settings.model,
            "temperature": settings.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if tools:
            kwargs["tools"] = [t.to_openai() for t in tools]

        completion = self._client.chat.completions.create(**kwargs)
        message = completion.choices[0].message

        if message.tool_calls:
            call = message.tool_calls[0]
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            return LLMResponse(tool_call=ToolCall(name=call.function.name, arguments=args))

        return LLMResponse(text=message.content or "")


# --------------------------------------------------------------------------- #
# Fake backend — deterministic, offline, and "gullible" on purpose
# --------------------------------------------------------------------------- #
# This regex is how the fake model "gets fooled": if an injected instruction of
# the form "refund of $AMOUNT to account ACCOUNT" appears in the DATA it reads,
# it dutifully proposes that call. A real model is fooled by persuasion; the fake
# one is fooled by this pattern. Either way, the POINT of the project is what
# happens next, at the gate. We match the specific imperative structure so we
# don't trip over benign policy text like "refund paid to the account on file".
_REFUND_INJECTION = re.compile(
    r"refund\s+of\s+\$?\s*([0-9]+(?:\.[0-9]{1,2})?)\s+to\s+"
    r"(?:account|acct)\s*[:#]?\s*([A-Za-z0-9\-]+)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class FakeBackend:
    """A stand-in model. No network, fully deterministic.

    Behaviour:
      * If it has a tool available and its context contains a refund injection,
        it proposes that tool call (simulating a fooled agent).
      * If it has no tools, it returns a plain 'summary' (passing text through,
        injection and all — exactly what a naive summarizer does).
      * Otherwise it declines to act.
    """

    tool_calls_seen: list[ToolCall] = field(default_factory=list)

    def complete(self, system: str, user: str, tools: list[ToolSpec] | None = None) -> LLMResponse:
        # Only scan the DATA (`user`), never the trusted system prompt. Injections
        # arrive through data, and the system prompt legitimately mentions refunds.
        if tools:
            refund_tool = next((t for t in tools if t.name == "issue_refund"), None)
            match = _REFUND_INJECTION.search(user)
            if refund_tool is not None and match:
                amount = float(match.group(1))
                account = match.group(2)
                call = ToolCall(
                    name="issue_refund", arguments={"account": account, "amount": amount}
                )
                self.tool_calls_seen.append(call)
                return LLMResponse(tool_call=call)
            # Tool available but nothing tricked us into using it.
            return LLMResponse(text="No action needed.")

        # No tools: behave like a naive summarizer that passes content through.
        return LLMResponse(text=f"Case summary: {user.strip()}")


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def get_llm() -> LLMBackend:
    """Return the configured backend (fake or real) based on settings."""
    if settings.use_fake_llm:
        return FakeBackend()
    return OpenAIBackend()
