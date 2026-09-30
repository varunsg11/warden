# Warden on AgentDojo

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is a standard benchmark for
prompt-injection attacks and defenses on tool-using agents. It has four suites of
realistic tools: workspace, travel, banking and slack. Injected text in tool outputs
tries to hijack the agent. AgentDojo scores **utility** (was the user's task done?)
and **security** (did the attacker's goal happen?).

Results: [`results/agentdojo/README.md`](../../results/agentdojo/README.md).

## Setup

AgentDojo pins its own `openai`/`pydantic` versions, so use a separate venv:

```bash
py -3.12 -m venv .venv-agentdojo            # python3.12 -m venv on macOS/Linux
.venv-agentdojo/Scripts/python -m pip install -e ".[agentdojo]" pytest   # bin/python on macOS/Linux
```

## Run

```bash
# Offline, $0, deterministic: the always-fooled scripted agent, every config
.venv-agentdojo/Scripts/python experiments/agentdojo/run.py --model scripted --config all

# Real model (needs OPENAI_API_KEY in .env). Smoke-test a subset first:
.venv-agentdojo/Scripts/python experiments/agentdojo/run.py --model gpt-4o-mini-2024-07-18 \
    --config task --suites banking --user-tasks user_task_0,user_task_1
# Full: all suites, 3 reps per config
.venv-agentdojo/Scripts/python experiments/agentdojo/run.py --model gpt-4o-mini-2024-07-18 \
    --config all --reps 3

.venv-agentdojo/Scripts/python experiments/agentdojo/summarize.py   # -> results/agentdojo/README.md
.venv-agentdojo/Scripts/python -m pytest tests/test_agentdojo_adapter.py
```

On Windows, `experimentsgentdojoun_real.cmd` runs the three headline configs
(`none`, `task`, `task+prov`) one after another with `--resume`, then regenerates the
summary; progress goes to `results/agentdojo/logs/realrun.log`. Re-run it after any
interruption: finished episodes are reused, not re-paid.

A real-model config covers 97 clean episodes, 949 attacked episodes, and 35 episodes
where AgentDojo runs each injection task as a user task to check it's solvable. That's
about 1,080 episodes per config per rep.

## Configurations

| Config | Policy the gate enforces |
|---|---|
| `none` | No Warden: AgentDojo's standard agent (baseline) |
| `suite` | Every suite tool granted, unconstrained (lower bound for Warden) |
| `task` | **Headline.** Each prompt declares a workflow ([`policies/`](policies/)) that grants all read tools plus only the write tools it needs |
| `oracle` | Exactly the tools in each task's ground truth (upper bound for tool-level least privilege, not deployable) |

The `task` mapping was written from the prompt text alone, as an app would declare its
workflow at launch. Disclosure: the author saw banking's ground truth while building the
adapter, before writing the banking mapping. The other three suites were mapped from
prompts only.

## The scripted agent

`ScriptedAgent` (in `src/warden/integrations/agentdojo.py`) stands in for the LLM. It
proposes each task's ground-truth calls. When a tool result contains an injection
task's goal, it performs that goal's ground-truth calls too, so it falls for every
injection it reads. This measures what the **policy** contains when the model offers no
resistance at all. It's the worst case, and real models fall for fewer attacks.

## Findings from the API spike (agentdojo 0.1.35, benchmark v1.2.2)

- The standard pipeline is `SystemMessage → InitQuery → llm → ToolsExecutionLoop([ToolsExecutor, llm])`.
  Warden replaces `ToolsExecutor` with `WardenToolsExecutor`. It adds `WardenSession` (opens a
  governed session per episode) and `WardenSessionEnd` (closes the audit log).
- The pipeline receives the prompt, **not** the task ID. So the declared task is keyed by
  prompt text, the way a real app knows which workflow it launched.
- `security == True` means the injection's goal was achieved (attack success). API
  errors are also scored as attack success.
- Attacks address the victim model by name, so `pipeline.name` must contain a known
  model ID. The scripted agent uses `gpt-4o-mini-2024-07-18-scripted`.
- Tool schemas are pydantic-generated JSON Schema, using arrays, `anyOf` (optionals), and
  `$ref`/`$defs` enums. `governance/schema.py` was extended to cover this subset and
  still fails closed on anything else.
- Tool output is YAML-dumped, which wraps long lines and doubles `'`. The scripted
  agent normalizes before matching injected goals.
- TTL: one episode is one Warden turn and can take minutes with a real model. The
  experiment grants capabilities a 3,600 s TTL; the demo's 30 s would expire mid-task.

## Known limits of tool-level least privilege

This is what Phase 3 (provenance tracking) targets.

- **In-envelope attacks:** a task that legitimately needs `send_money` can be steered
  into sending money to the attacker (`tests/test_agentdojo_adapter.py` pins this down).
- **Read-only attacks:** slack `injection_task_3` only makes the agent *visit* a URL,
  and travel `injection_task_6` only makes it *say* something. Neither needs a write
  tool, so no tool-level policy can stop them.
- **Open-ended prompts:** "do the actions in this email" or "do my TODO list at <url>"
  need broad authority, so the policy has to grant every write tool.
