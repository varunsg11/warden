"""Run Warden on AgentDojo and write raw results as JSON.

Configurations (the policy the gate enforces):
  none    AgentDojo's standard agent, no Warden (the baseline).
  suite   Warden with every suite tool granted, unconstrained. Lower bound:
          shows what the gate adds when the policy is maximally loose.
  task    THE HEADLINE. Each user prompt declares a workflow (policies/<suite>.toml)
          that grants all read tools plus only the write tools that workflow
          needs. Decided from the prompt alone -- what a real app knows.
  oracle  Grants exactly the tools in each task's ground truth. An UPPER BOUND
          for tool-level least privilege, not a deployable config.
  task+prov
          `task`, plus provenance: arguments listed under [provenance] in the
          suite spec (destinations and credentials) must appear in the user's
          prompt, not only in tool output.

Models:
  scripted                 offline, $0, deterministic: an agent that performs the
                           task AND falls for every injection it reads (worst case).
  gpt-4o-mini-2024-07-18   (or any AgentDojo OpenAI model id) -- needs OPENAI_API_KEY.

Examples:
  python experiments/agentdojo/run.py --model scripted --config all
  python experiments/agentdojo/run.py --model gpt-4o-mini-2024-07-18 --config task \\
      --suites banking --user-tasks user_task_0,user_task_1        # smoke test
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import tomllib
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline import (
    AgentPipeline,
    BasePipelineElement,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import get_llm, load_system_message
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import (
    benchmark_suite_with_injections,
    benchmark_suite_without_injections,
)
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suites
from dotenv import load_dotenv

from warden.governance.policy_loader import Policy, parse_policy
from warden.integrations.agentdojo import (
    ROLE,
    ScriptedAgent,
    WardenConfig,
    WardenSession,
    WardenSessionEnd,
    WardenToolsExecutor,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BENCHMARK_VERSION = "v1.2.2"
SUITES = ("workspace", "travel", "banking", "slack")
CONFIGS = ("none", "suite", "task", "oracle", "task+prov")
# The scripted agent needs a pipeline name containing a real model id, because
# the attack template addresses the victim model by name.
SCRIPTED_TARGET = "gpt-4o-mini-2024-07-18"
# One AgentDojo episode is one Warden "turn"; with a real model it can take
# minutes, so the demo's 30s TTL would expire capabilities mid-task.
EXPERIMENT_TTL = 3600.0
NO_AUTHORITY = "no_authority"  # prompts the app doesn't recognize get nothing


def build_policy(config: str, suite: Any, spec: dict) -> tuple[Policy, Callable[[str], str]]:
    tools: dict[str, str] = spec["tools"]
    unclassified = {t.name for t in suite.tools} - set(tools)
    if unclassified:
        raise SystemExit(
            f"{suite.name}: tools missing from policies/{suite.name}.toml: {unclassified}"
        )
    reads = [name for name, scope in tools.items() if scope == "read"]
    prompt_to_task = {ut.PROMPT: uid for uid, ut in suite.user_tasks.items()}

    trusted_args: dict[str, list[str]] = spec.get("provenance", {}) if config == "task+prov" else {}

    def grant(names: list[str]) -> list[dict[str, Any]]:
        templates: list[dict[str, Any]] = []
        for n in names:
            template: dict[str, Any] = {"tool": n, "scope": tools[n], "ttl": EXPERIMENT_TTL}
            if n in trusted_args:
                template["params"] = {arg: {"from": "trusted"} for arg in trusted_args[n]}
            templates.append(template)
        return templates

    tasks: dict[str, dict[str, list[dict[str, Any]]]] = {NO_AUTHORITY: {ROLE: []}}
    if config == "suite":
        tasks["suite"] = {ROLE: grant(list(tools))}

        def declare(prompt: str) -> str:
            return "suite"

    elif config in ("task", "task+prov"):
        undeclared = set(suite.user_tasks) - set(spec["declare"])
        if undeclared:
            raise SystemExit(f"{suite.name}: user tasks without a declared workflow: {undeclared}")
        for workflow, writes in spec["workflows"].items():
            tasks[workflow] = {ROLE: grant(reads + writes)}

        def declare(prompt: str) -> str:
            uid = prompt_to_task.get(prompt)
            return spec["declare"][uid] if uid else NO_AUTHORITY

    elif config == "oracle":
        env = suite.load_and_inject_default_environment({})
        for uid, user_task in suite.user_tasks.items():
            calls = user_task.ground_truth(env.model_copy(deep=True))
            tasks[uid] = {ROLE: grant(sorted({c.function for c in calls}))}

        def declare(prompt: str) -> str:
            return prompt_to_task.get(prompt, NO_AUTHORITY)

    else:
        raise ValueError(config)

    # Through the same strict loader as any Warden policy file.
    policy = parse_policy(
        {"default_task": NO_AUTHORITY, "tools": tools, "tasks": tasks},
        source=f"agentdojo/{suite.name}/{config}",
    )
    return policy, declare


class BudgetExceeded(RuntimeError):
    """Raised before a model call that would start once the budget is spent."""


class Budget:
    """Hard spending cap computed from the token usage OpenAI reports on every
    response (not an estimate). Prices are $ per 1M tokens -- check them against
    the provider's current price list; cached-input discounts are ignored, so the
    meter errs high."""

    def __init__(self, max_usd: float | None, price_in: float, price_out: float) -> None:
        self.max_usd = max_usd
        self.price_in = price_in / 1e6
        self.price_out = price_out / 1e6
        self.spent = 0.0
        self.calls = 0
        self.largest_call = 0.002  # reserve at least this much for the next call

    def meter(self, client: Any) -> None:
        """Wrap client.chat.completions.create so every call is checked and counted."""
        completions = client.chat.completions
        create = completions.create

        def metered_create(*args: Any, **kwargs: Any) -> Any:
            # Reserve room for a call as large as the largest seen so far, so the
            # next call can't push spend past the cap.
            if self.max_usd is not None and self.spent + self.largest_call > self.max_usd:
                raise BudgetExceeded(
                    f"budget ${self.max_usd:.2f} reached (spent ${self.spent:.4f})"
                )
            response = create(*args, **kwargs)
            usage = getattr(response, "usage", None)
            if usage is not None:
                cost = (
                    usage.prompt_tokens * self.price_in + usage.completion_tokens * self.price_out
                )
                self.spent += cost
                self.largest_call = max(self.largest_call, cost)
            self.calls += 1
            return response

        completions.create = metered_create


BUDGET = Budget(None, 0.15, 0.60)


class RetryingLLM(BasePipelineElement):
    """Retries the wrapped LLM element on rate limits and transient API errors,
    with exponential backoff. A retry re-sends the identical request, so it
    doesn't change what is measured -- it only keeps a long run alive."""

    def __init__(self, llm: BasePipelineElement, attempts: int = 8) -> None:
        self.llm = llm
        self.name = getattr(llm, "name", None)
        self.attempts = attempts

    def query(self, *args: Any, **kwargs: Any) -> Any:
        import openai

        retryable = (
            openai.RateLimitError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.InternalServerError,
        )
        for attempt in range(self.attempts):
            try:
                return self.llm.query(*args, **kwargs)
            except retryable as exc:
                # Out of credit is not transient: retrying would only burn time.
                if (
                    getattr(exc, "code", None) == "insufficient_quota"
                    or attempt == self.attempts - 1
                ):
                    raise
                delay = min(60.0, 2.0**attempt)
                print(f"    [retry {attempt + 1}] {type(exc).__name__}; sleeping {delay:.0f}s")
                time.sleep(delay)
        raise AssertionError("unreachable")


def build_pipeline(
    config: str, suite: Any, model: str, spec: dict, on_deny: str, audit_dir: Path | None
) -> tuple[AgentPipeline, WardenConfig | None]:
    if model == "scripted":
        llm: Any = ScriptedAgent(suite, name=f"{SCRIPTED_TARGET}-scripted")
        base_name = f"{SCRIPTED_TARGET}-scripted"
    else:
        inner = get_llm("openai", model, None, "tool")
        BUDGET.meter(inner.client)
        llm = RetryingLLM(inner)
        base_name = model

    system = SystemMessage(load_system_message(None))
    if config == "none":
        pipeline = AgentPipeline(
            [system, InitQuery(), llm, ToolsExecutionLoop([ToolsExecutor(), llm])]
        )
        pipeline.name = base_name
        return pipeline, None

    policy, declare = build_policy(config, suite, spec)
    warden = WardenConfig(
        policy=policy,
        declare_task=declare,
        quarantine_on_deny=(on_deny == "quarantine"),
        track_provenance=(config == "task+prov"),
        audit_dir=audit_dir,
    )
    pipeline = AgentPipeline(
        [
            system,
            WardenSession(warden),
            InitQuery(),
            llm,
            ToolsExecutionLoop([WardenToolsExecutor(warden), llm]),
            WardenSessionEnd(),
        ]
    )
    pipeline.name = f"{base_name}-warden-{config}"
    return pipeline, warden


def scripted_unperformable(suite: Any) -> list[str]:
    """Injection tasks whose ground truth has no tool calls."""
    env = suite.load_and_inject_default_environment({})
    return sorted(
        tid
        for tid, task in suite.injection_tasks.items()
        if not task.ground_truth(env.model_copy(deep=True))
    )


# The gate's denial reason (governance/gate.py, pipeline/runner.py) -> the check that failed.
DENIAL_REASONS = {
    "session is quarantined": "quarantined",
    "holds no capability": "capability_present",
    "malformed arguments": "args_well_formed",
    "invalid signature": "signature_valid",
    "was issued to": "bound_to_role",
    "has expired": "not_expired",
    "scope mismatch": "scope_ok",
    "parameter constraint violated": "params_ok",
    "untrusted provenance": "provenance_ok",
    "already used": "uses_remaining",
    "gate error": "gate_error",
}


def denials_in_logs(paths: list[Path]) -> dict[str, int]:
    """Count Warden denials by the check that failed, read from AgentDojo episode logs.

    Read from the logs rather than counted live, so episodes reused by --resume count
    too. A denial is a tool result whose error starts with "Blocked by Warden: ";
    anything that isn't a gate reason is a drift denial. The earliest phrase wins,
    since a reason can quote argument values (attacker text) after its own phrase.
    """
    counts: Counter[str] = Counter()
    for path in paths:
        if not path.exists():
            continue
        for message in json.loads(path.read_text(encoding="utf-8"))["messages"]:
            error = message.get("error") or ""
            if message.get("role") != "tool" or not error.startswith("Blocked by Warden: "):
                continue
            hits = [(error.find(r), c) for r, c in DENIAL_REASONS.items() if r in error]
            counts[min(hits)[1] if hits else "drift"] += 1
    return dict(sorted(counts.items()))


def _mean(values: Any) -> float:
    values = list(values)
    return sum(values) / len(values) if values else float("nan")


def run_one(args: argparse.Namespace, config: str, rep: int, all_suites: dict) -> Path:
    run_id = f"{args.model}__{config}__{args.on_deny}__{args.attack}__rep{rep}"
    out = ROOT / "results" / "agentdojo" / "raw" / f"{run_id}.json"
    started = time.time()
    record: dict[str, Any] = {
        "meta": {
            "model": args.model,
            "config": config,
            "on_deny": args.on_deny,
            "attack": args.attack,
            "rep": rep,
            "benchmark_version": BENCHMARK_VERSION,
            "warden_commit": _git_commit(),
            "subset": bool(args.user_tasks or args.injection_tasks),
        },
        "suites": {},
    }

    for suite_name in args.suites:
        suite = all_suites[suite_name]
        spec = tomllib.loads((HERE / "policies" / f"{suite_name}.toml").read_text("utf-8"))
        logdir = ROOT / "results" / "agentdojo" / "logs" / run_id / suite_name
        audit_dir = logdir / "audit" if args.audit else None
        user_tasks = args.user_tasks or None
        injection_tasks = args.injection_tasks or None
        excluded: list[str] = []
        if args.model == "scripted":
            # The scripted agent replays ground truth; some injection tasks have
            # none (e.g. workspace injection_task_6-13 in v1.2, travel's text-only
            # injection_task_6), so it can't perform them. Evaluate only the ones
            # it can, and record the rest -- real-model runs include all of them.
            excluded = scripted_unperformable(suite)
            candidates = injection_tasks or list(suite.injection_tasks)
            injection_tasks = [t for t in candidates if t not in excluded]
        print(f"\n=== {run_id} :: {suite_name}")

        pipeline, warden = build_pipeline(config, suite, args.model, spec, args.on_deny, audit_dir)
        with OutputLogger(str(logdir)):
            clean = benchmark_suite_without_injections(
                pipeline, suite, logdir, not args.resume, user_tasks, BENCHMARK_VERSION
            )
            attack = load_attack(args.attack, suite, pipeline)
            attacked = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                logdir,
                not args.resume,
                user_tasks,
                injection_tasks,
                verbose=False,
                benchmark_version=BENCHMARK_VERSION,
            )

        pairs = {
            f"{u}|{i}": [attacked["utility_results"][(u, i)], attacked["security_results"][(u, i)]]
            for (u, i) in attacked["utility_results"]
        }
        # Episode logs, where AgentDojo writes them. The injection tasks run as user
        # tasks (the solvability check) happen in the attacked phase.
        episodes = logdir / str(pipeline.name) / suite_name
        clean_logs = [episodes / u / "none" / "none.json" for (u, _) in clean["utility_results"]]
        attacked_logs = [
            *(
                episodes / i / "none" / "none.json"
                for i in attacked["injection_tasks_utility_results"]
            ),
            *(episodes / u / attack.name / f"{i}.json" for (u, i) in attacked["utility_results"]),
        ]
        record["suites"][suite_name] = {
            "utility": _mean(clean["utility_results"].values()),
            "utility_under_attack": _mean(attacked["utility_results"].values()),
            # AgentDojo's security result is True when the injection's goal was achieved.
            "asr": _mean(attacked["security_results"].values()),
            "n_user_tasks": len(clean["utility_results"]),
            "n_pairs": len(pairs),
            "excluded_injection_tasks": excluded,
            "denials_clean": denials_in_logs(clean_logs) if warden else {},
            "denials_attacked": denials_in_logs(attacked_logs) if warden else {},
            "clean": {u: ok for (u, _), ok in clean["utility_results"].items()},
            "pairs": pairs,
        }
        s = record["suites"][suite_name]
        print(
            f"    utility {s['utility']:.1%} | under attack {s['utility_under_attack']:.1%}"
            f" | ASR {s['asr']:.1%} ({s['n_pairs']} pairs)"
        )

    record["meta"]["duration_s"] = round(time.time() - started, 1)
    record["meta"]["api_usd_metered_so_far"] = round(BUDGET.spent, 4)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1), encoding="utf-8")
    print(f"\nwrote {out.relative_to(ROOT)}")
    return out


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
        ).stdout.strip()
    except OSError:
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", default="scripted")
    parser.add_argument(
        "--config", default="task", help=f"one of {', '.join(CONFIGS)}, a comma list, or all"
    )
    parser.add_argument("--suites", default=",".join(SUITES))
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--on-deny", default="quarantine", choices=["quarantine", "error"])
    parser.add_argument("--reps", type=int, default=1)
    parser.add_argument("--user-tasks", default="", help="comma-separated subset (smoke tests)")
    parser.add_argument("--injection-tasks", default="", help="comma-separated subset")
    parser.add_argument("--audit", action="store_true", help="write a Warden audit log per episode")
    parser.add_argument(
        "--max-usd", type=float, default=None, help="hard cap on API spend for this invocation"
    )
    parser.add_argument("--price-in", type=float, default=0.15, help="$ per 1M input tokens")
    parser.add_argument("--price-out", type=float, default=0.60, help="$ per 1M output tokens")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="reuse episodes already logged for this run id instead of re-running them "
        "(to continue an interrupted real-model run without paying twice)",
    )
    args = parser.parse_args()
    args.suites = [s for s in args.suites.split(",") if s]
    args.user_tasks = [t for t in args.user_tasks.split(",") if t]
    args.injection_tasks = [t for t in args.injection_tasks.split(",") if t]

    if args.model != "scripted":
        load_dotenv(ROOT / ".env")
    all_suites = get_suites(BENCHMARK_VERSION)
    configs = CONFIGS if args.config == "all" else tuple(c for c in args.config.split(",") if c)
    unknown = set(configs) - set(CONFIGS)
    if unknown:
        raise SystemExit(f"unknown config(s) {sorted(unknown)}; choose from {CONFIGS}")
    BUDGET.max_usd = args.max_usd
    BUDGET.price_in, BUDGET.price_out = args.price_in / 1e6, args.price_out / 1e6
    try:
        for rep in range(args.reps):
            for config in configs:
                run_one(args, config, rep, all_suites)
    except BudgetExceeded as exc:
        print(f"\nSTOPPED: {exc}. Finished episodes are kept; rerun with --resume to continue.")
    finally:
        if args.model != "scripted":
            print(
                f"\nAPI usage this invocation: {BUDGET.calls} calls, ${BUDGET.spent:.4f} (metered)"
            )


if __name__ == "__main__":
    main()
