"""Load a Warden policy from a TOML file and validate it strictly.

A policy is security configuration, so a typo must be an error, never a silently
ignored key. Misspell `max` as `maximum` and a lenient loader would grant an
unbounded refund; this one refuses to start. Every key is checked against what
the gate actually enforces.

Shape:

    default_task = "summarize"

    [tools]                      # tool -> scope its operation REQUIRES
    issue_refund = "write"

    [[tasks.process_refund.refund_issuer]]   # task -> role -> capability templates
    tool = "issue_refund"
    scope = "write"
    ttl = 30.0                   # optional, seconds (default 30)
    max_uses = 1                 # optional, omit for unlimited within ttl
    params.amount  = { min = 0.01, max = 50.0 }
    params.account = { allow = ["1234", "5678"] }

A role with no authority under a task is written as an empty list
(`refund_issuer = []`), which makes "grants nothing" explicit in the file.

Uses only the standard library (tomllib). No LLM, no network.
"""

from __future__ import annotations

import math
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCOPES = frozenset({"read", "write", "execute"})
_TOP_KEYS = frozenset({"default_task", "tools", "tasks"})
_TEMPLATE_KEYS = frozenset({"tool", "scope", "params", "ttl", "max_uses"})
# Only rules Capability.params_ok enforces. A rule the gate can't enforce must be
# rejected here, or the policy would promise a restriction nothing checks.
_RULE_KEYS = frozenset({"min", "max", "allow"})
DEFAULT_TTL = 30.0


class PolicyError(ValueError):
    """The policy file is malformed. Raised at load time, never at call time."""


@dataclass(frozen=True)
class Policy:
    tools: dict[str, str]
    tasks: dict[str, dict[str, list[dict[str, Any]]]]
    default_task: str

    def templates_for(self, task: str, role: str) -> list[dict[str, Any]]:
        return self.tasks.get(task, {}).get(role, [])


def load_policy(path: str | Path) -> Policy:
    path = Path(path)
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path}: invalid TOML: {exc}") from exc
    return parse_policy(data, source=str(path))


def parse_policy(data: dict[str, Any], source: str = "<policy>") -> Policy:
    def fail(msg: str) -> PolicyError:
        return PolicyError(f"{source}: {msg}")

    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise fail(f"unknown top-level key(s): {sorted(unknown)}")

    tools = data.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise fail("[tools] must map at least one tool to its required scope")
    for tool, scope in tools.items():
        if scope not in SCOPES:
            raise fail(f"tools.{tool}: scope {scope!r} not one of {sorted(SCOPES)}")

    raw_tasks = data.get("tasks")
    if not isinstance(raw_tasks, dict) or not raw_tasks:
        raise fail("[tasks] must define at least one task")

    tasks: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for task, roles in raw_tasks.items():
        if not isinstance(roles, dict):
            raise fail(f"tasks.{task} must be a table of roles")
        tasks[task] = {}
        for role, templates in roles.items():
            where = f"tasks.{task}.{role}"
            if not isinstance(templates, list):
                raise fail(f"{where} must be a list of capability templates ([] for none)")
            tasks[task][role] = [
                _parse_template(t, tools, f"{where}[{i}]", fail) for i, t in enumerate(templates)
            ]

    default_task = data.get("default_task")
    if default_task not in tasks:
        raise fail(f"default_task {default_task!r} is not a defined task")

    return Policy(tools=dict(tools), tasks=tasks, default_task=default_task)


def _parse_template(t: Any, tools: dict[str, str], where: str, fail: Any) -> dict[str, Any]:
    if not isinstance(t, dict):
        raise fail(f"{where} must be a table")
    unknown = set(t) - _TEMPLATE_KEYS
    if unknown:
        raise fail(f"{where}: unknown key(s) {sorted(unknown)}")

    tool = t.get("tool")
    if tool not in tools:
        raise fail(f"{where}: tool {tool!r} is not declared under [tools]")
    scope = t.get("scope")
    if scope != tools[tool]:
        # A cap whose scope differs from the tool's required scope can never pass
        # the gate's scope check -- almost certainly a mistake, so say so now.
        raise fail(
            f"{where}: scope {scope!r} can never authorize {tool!r} (requires {tools[tool]!r})"
        )

    ttl = t.get("ttl", DEFAULT_TTL)
    if not _is_number(ttl) or ttl <= 0:
        raise fail(f"{where}: ttl must be a positive number")

    max_uses = t.get("max_uses")
    if max_uses is not None and (
        isinstance(max_uses, bool) or not isinstance(max_uses, int) or max_uses < 1
    ):
        raise fail(f"{where}: max_uses must be an integer >= 1")

    params = t.get("params", {})
    if not isinstance(params, dict):
        raise fail(f"{where}: params must be a table")
    for field_name, rule in params.items():
        _check_rule(rule, f"{where}.params.{field_name}", fail)

    template: dict[str, Any] = {"tool": tool, "scope": scope, "params": params, "ttl": float(ttl)}
    if max_uses is not None:
        template["max_uses"] = max_uses
    return template


def _check_rule(rule: Any, where: str, fail: Any) -> None:
    if not isinstance(rule, dict) or not rule:
        raise fail(f"{where} must be a non-empty table of rules")
    unknown = set(rule) - _RULE_KEYS
    if unknown:
        raise fail(f"{where}: unknown rule(s) {sorted(unknown)}; allowed: {sorted(_RULE_KEYS)}")
    for bound in ("min", "max"):
        if bound in rule and not _is_number(rule[bound]):
            raise fail(f"{where}: {bound} must be a finite number")
    if "min" in rule and "max" in rule and rule["min"] > rule["max"]:
        raise fail(f"{where}: min {rule['min']} is greater than max {rule['max']}")
    if "allow" in rule and (not isinstance(rule["allow"], list) or not rule["allow"]):
        raise fail(f"{where}: allow must be a non-empty list")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
