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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline import (
    AgentPipeline,
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
CONFIGS = ("none", "suite", "task", "oracle")
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

    def grant(names: list[str]) -> list[dict[str, Any]]:
        return [{"tool": n, "scope": tools[n], "ttl": EXPERIMENT_TTL} for n in names]

    tasks: dict[str, dict[str, list[dict[str, Any]]]] = {NO_AUTHORITY: {ROLE: []}}
    if config == "suite":
        tasks["suite"] = {ROLE: grant(list(tools))}

        def declare(prompt: str) -> str:
            return "suite"

    elif config == "task":
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


def build_pipeline(
    config: str, suite: Any, model: str, spec: dict, on_deny: str, audit_dir: Path | None
) -> tuple[AgentPipeline, WardenConfig | None]:
    if model == "scripted":
        llm: Any = ScriptedAgent(suite, name=f"{SCRIPTED_TARGET}-scripted")
        base_name = f"{SCRIPTED_TARGET}-scripted"
    else:
        llm = get_llm("openai", model, None, "tool")
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
        print(f"\n=== {run_id} :: {suite_name}")

        pipeline, warden = build_pipeline(config, suite, args.model, spec, args.on_deny, audit_dir)
        with OutputLogger(str(logdir)):
            clean = benchmark_suite_without_injections(
                pipeline, suite, logdir, True, user_tasks, BENCHMARK_VERSION
            )
            clean_denials = dict(warden.denials) if warden else {}
            if warden:
                warden.denials.clear()
            attack = load_attack(args.attack, suite, pipeline)
            attacked = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                logdir,
                True,
                user_tasks,
                injection_tasks,
                verbose=False,
                benchmark_version=BENCHMARK_VERSION,
            )

        pairs = {
            f"{u}|{i}": [attacked["utility_results"][(u, i)], attacked["security_results"][(u, i)]]
            for (u, i) in attacked["utility_results"]
        }
        record["suites"][suite_name] = {
            "utility": _mean(clean["utility_results"].values()),
            "utility_under_attack": _mean(attacked["utility_results"].values()),
            # AgentDojo's security result is True when the injection's goal was achieved.
            "asr": _mean(attacked["security_results"].values()),
            "n_user_tasks": len(clean["utility_results"]),
            "n_pairs": len(pairs),
            "denials_clean": clean_denials,
            "denials_attacked": dict(warden.denials) if warden else {},
            "clean": {u: ok for (u, _), ok in clean["utility_results"].items()},
            "pairs": pairs,
        }
        s = record["suites"][suite_name]
        print(
            f"    utility {s['utility']:.1%} | under attack {s['utility_under_attack']:.1%}"
            f" | ASR {s['asr']:.1%} ({s['n_pairs']} pairs)"
        )

    record["meta"]["duration_s"] = round(time.time() - started, 1)
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
    parser.add_argument("--config", default="task", choices=[*CONFIGS, "all"])
    parser.add_argument("--suites", default=",".join(SUITES))
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--on-deny", default="quarantine", choices=["quarantine", "error"])
    parser.add_argument("--reps", type=int, default=1)
    parser.add_argument("--user-tasks", default="", help="comma-separated subset (smoke tests)")
    parser.add_argument("--injection-tasks", default="", help="comma-separated subset")
    parser.add_argument("--audit", action="store_true", help="write a Warden audit log per episode")
    args = parser.parse_args()
    args.suites = [s for s in args.suites.split(",") if s]
    args.user_tasks = [t for t in args.user_tasks.split(",") if t]
    args.injection_tasks = [t for t in args.injection_tasks.split(",") if t]

    if args.model != "scripted":
        load_dotenv(ROOT / ".env")
    all_suites = get_suites(BENCHMARK_VERSION)
    configs = CONFIGS if args.config == "all" else (args.config,)
    for rep in range(args.reps):
        for config in configs:
            run_one(args, config, rep, all_suites)


if __name__ == "__main__":
    main()
