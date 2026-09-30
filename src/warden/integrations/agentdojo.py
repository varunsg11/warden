"""Warden as an AgentDojo defense (https://github.com/ethz-spylab/agentdojo).

AgentDojo runs an agent over realistic tool environments (workspace, travel,
banking, slack) while injected text in tool outputs tries to hijack it, and scores
both UTILITY (did the user's task get done?) and SECURITY (did the attacker's goal
happen?). Its standard agent is

    SystemMessage -> InitQuery -> llm -> ToolsExecutionLoop([ToolsExecutor, llm])

Warden changes exactly two things -- security as a wrapper, not a rewrite:

  * `WardenSession` (first element) opens a fresh governed session per episode:
    the trusted caller DECLARES the task from the user's prompt (never from tool
    output), and the Supervisor issues the manifest for that task.
  * `WardenToolsExecutor` replaces `ToolsExecutor`: every proposed call goes
    through `GatedToolRunner.authorize()` -- the same enforcement path as the
    demo pipeline -- and only allowed calls reach AgentDojo's runtime. A denied
    call returns the deny reason to the model as a tool error.
  * `WardenSessionEnd` (last element) closes the episode's audit log.

`ScriptedAgent` is a stand-in LLM for offline, zero-cost runs: it proposes each
task's ground-truth calls and, when it reads an injected goal, obediently carries
it out too -- a deterministic "always fooled" agent, i.e. the worst case.

Requires the `agentdojo` extra. Nothing in `warden.governance` depends on this.
"""

from __future__ import annotations

import uuid
from ast import literal_eval
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline import BasePipelineElement, ToolsExecutor
from agentdojo.agent_pipeline.tool_execution import is_string_list
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    get_text_content_as_str,
    text_content_block_from_string,
)

from warden.governance.audit import AuditLog
from warden.governance.drift import DriftViolation
from warden.governance.gate import Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.governance.policy_loader import Policy
from warden.governance.provenance import Provenance
from warden.llm import ToolCall
from warden.pipeline.runner import GatedToolRunner

ROLE = "agent"
_RUNNER_KEY = "warden_runner"


@dataclass
class WardenConfig:
    """How Warden governs an AgentDojo run.

    declare_task maps the TRUSTED user prompt to a task in `policy` -- what a real
    application does when it knows which workflow it launched. It must never look
    at tool output.
    """

    policy: Policy
    declare_task: Callable[[str], str]
    quarantine_on_deny: bool = True
    # Track where text came from (user prompt = trusted, tool output = untrusted)
    # so `from = "trusted"` rules in the policy can be enforced.
    track_provenance: bool = False
    audit_dir: Path | None = None
    # Filled in during the run, for reporting: which check denied how often.
    denials: Counter[str] = field(default_factory=Counter)
    episodes: int = 0


class WardenSession(BasePipelineElement):
    """Opens a governed session for one episode. Must run before the tools loop."""

    name: str | None = None

    def __init__(self, config: WardenConfig) -> None:
        self.config = config

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        cfg = self.config
        task = cfg.declare_task(query)
        supervisor = Supervisor(policy=cfg.policy)
        audit = None
        if cfg.audit_dir is not None:
            session_id = f"agentdojo-{uuid.uuid4().hex[:8]}"
            audit = AuditLog(session_id, path=cfg.audit_dir / f"{session_id}.jsonl")
            audit.record("session_start", task=task, user_request=query)
        provenance = None
        if cfg.track_provenance:
            provenance = Provenance()
            provenance.add_trusted(query, "user prompt")
        runner = GatedToolRunner(
            Gate(supervisor.verifier),
            {ROLE: supervisor.issue_manifest(ROLE, task)},
            audit,
            scopes=cfg.policy.tools,
            schemas={f.name: f.parameters.model_json_schema() for f in runtime.functions.values()},
            quarantine_on_deny=cfg.quarantine_on_deny,
            provenance=provenance,
        )
        cfg.episodes += 1
        # extra_args defaults to a shared dict in AgentDojo: never mutate it in place.
        return query, runtime, env, messages, {**extra_args, _RUNNER_KEY: runner}


class WardenSessionEnd(BasePipelineElement):
    """Closes the episode's audit log (writes `session_end`). Place it last, after
    the tools loop, so every audit log is complete and passes `verify_file`."""

    name: str | None = None

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        runner: GatedToolRunner | None = extra_args.get(_RUNNER_KEY)
        if runner is not None and runner.audit is not None:
            status = "quarantined" if runner.quarantined else "completed"
            runner.audit.record("session_end", status=status)
        return query, runtime, env, messages, extra_args


class WardenToolsExecutor(ToolsExecutor):
    """AgentDojo's ToolsExecutor, with Warden's gate in front of every call."""

    def __init__(self, config: WardenConfig, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.config = config

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = messages[-1].get("tool_calls") or []
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        runner: GatedToolRunner | None = extra_args.get(_RUNNER_KEY)
        if runner is None:  # fail closed: no session means no authority at all
            raise RuntimeError("WardenSession must run before WardenToolsExecutor")

        results: list[ChatMessage] = []
        for call in tool_calls:
            # Same list-coercion AgentDojo applies, BEFORE the gate sees the args,
            # so what is checked is exactly what would run.
            for key, value in call.args.items():
                if isinstance(value, str) and is_string_list(value):
                    call.args[key] = literal_eval(value)

            try:
                runner.authorize(ROLE, ToolCall(name=call.function, arguments=dict(call.args)))
            except (GateViolation, DriftViolation) as violation:
                self._count_denial(violation)
                results.append(_tool_result(call, "", f"Blocked by Warden: {violation}"))
                continue

            output, error = runtime.run_function(env, call.function, call.args)
            text = self.output_formatter(output)
            runner.observe(call.function, text)  # tool output is untrusted text
            results.append(_tool_result(call, text, error))
        return query, runtime, env, [*messages, *results], extra_args

    def _count_denial(self, violation: Exception) -> None:
        if isinstance(violation, DriftViolation):
            self.config.denials["drift"] += 1
            return
        assert isinstance(violation, GateViolation)
        failed = [s.name for s in violation.decision.steps if not s.passed]
        self.config.denials[failed[-1] if failed else "quarantined"] += 1


def _tool_result(call: FunctionCall, content: str, error: str | None) -> ChatToolResultMessage:
    return ChatToolResultMessage(
        role="tool",
        content=[text_content_block_from_string(content)],
        tool_call_id=call.id,
        tool_call=call,
        error=error,
    )


class ScriptedAgent(BasePipelineElement):
    """A deterministic stand-in for the LLM: the worst-case, always-fooled agent.

    Per episode it proposes the ground-truth calls of the task whose prompt it was
    given, one per turn. Whenever a tool result contains an injection task's goal
    text (AgentDojo's attacks embed it verbatim), it queues that injection task's
    ground-truth calls next -- it falls for every injection it reads. It never
    sees whether a call was allowed; like a real agent, it just keeps going.
    """

    def __init__(self, suite: Any, name: str) -> None:
        self.name = name
        self._tasks = {t.PROMPT: t for t in suite.user_tasks.values()}
        # Injection tasks can also be run as ordinary tasks (AgentDojo checks they
        # are solvable), so their GOAL doubles as a prompt.
        self._tasks.update({t.GOAL: t for t in suite.injection_tasks.values()})
        self._injections = {_normalize(t.GOAL): t for t in suite.injection_tasks.values()}
        self._plan: list[FunctionCall] = []
        self._fell_for: set[str] = set()
        self._final = ""

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if messages and messages[-1]["role"] == "user":  # a new episode starts
            task = self._tasks[query]
            self._plan = list(task.ground_truth(env))
            self._fell_for = set()
            self._final = getattr(task, "GROUND_TRUTH_OUTPUT", "")
        else:
            self._read_latest_results(messages, env)

        if self._plan:
            call = self._plan.pop(0)
            call = FunctionCall(function=call.function, args=dict(call.args), id=uuid.uuid4().hex)
            reply = ChatAssistantMessage(role="assistant", content=None, tool_calls=[call])
        else:
            reply = ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(self._final)],
                tool_calls=None,
            )
        return query, runtime, env, [*messages, reply], extra_args

    def _read_latest_results(self, messages: Sequence[ChatMessage], env: Env) -> None:
        for message in reversed(messages):
            if message["role"] != "tool":
                break
            text = _normalize(get_text_content_as_str(message["content"]))
            for goal, injection in self._injections.items():
                if goal in text and goal not in self._fell_for:
                    self._fell_for.add(goal)
                    self._plan = list(injection.ground_truth(env)) + self._plan


def _normalize(text: str) -> str:
    """Tool output is YAML-dumped, which wraps long strings across lines and
    doubles single quotes. Undo both so an injected goal is recognized wherever
    it appears -- the scripted agent must fall for every injection it reads."""
    return " ".join(text.replace("''", "'").split())
