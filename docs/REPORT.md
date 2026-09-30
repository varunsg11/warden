# Warden: Constraining What a Fooled Agent Can Do

*A capability-based defense against indirect prompt injection, evaluated on AgentDojo.*

## Abstract

An LLM agent that reads untrusted data (documents, email, web pages, tool output) can be
steered by instructions hidden in that data. Warden doesn't try to keep the model from
being fooled. It limits what a fooled agent can *do*: every tool call is authorized by
deterministic code outside the model's reasoning loop.

Each task the application declares gets a manifest of Ed25519-signed, per-role
capabilities. A nine-check gate authorizes each proposed call. A provenance check
requires sensitive arguments, such as recipients, accounts and URLs, to come from the
user's request and not from tool output. On AgentDojo, against a scripted agent that
carries out every injection it reads, attack success falls from 94.9% to 23.5% with
per-task capabilities, at unchanged utility (99.0%), and to 3.8% with provenance, at a
utility cost (76.3%). The full enforcement path costs about 1 ms per call. Warden ships
as a Python library, an AgentDojo defense and an MCP gateway.

## 1. Problem and threat model

To a language model, retrieved data and genuine instructions are the same kind of token.
So an attacker who controls *content the agent reads* can propose actions on the
user's behalf. This is a confused deputy with the agent's authority.

- **Attacker controls:** any text that reaches the agent as data (documents, emails,
  web pages, tool results).
- **Attacker doesn't control:** the application's code and keys, or which workflow
  (task) the application declares. The declared task is the trusted control channel.
- **Goal:** make the agent perform a harmful tool call, such as moving money, sending
  data out, or changing credentials.
- **Non-goal:** stopping the model from being fooled. We assume it will be sometimes, and
  we treat that as given.

## 2. Design

The code is split along the trust boundary. `governance/` is deterministic Python with
no model anywhere. `pipeline/` holds the agents, which can be fooled. Every
authorization decision is in `governance/`.

**Capabilities.** For each turn, a Supervisor holding the only private key mints
`c = (tool, scope, params, ttl, nonce, issuer, subject, max_uses, signature)` for each
role, from a policy keyed by *task → role → templates* (TOML, strictly validated).
Least privilege is per task: a `summarize` task grants the refund agent nothing, so an
injected refund fails the first check.

**Gate.** The gate holds only the public key and runs nine checks: capability present
→ arguments well-formed (the tool's JSON Schema) → signature → bound to the calling role
→ TTL → scope → parameter envelope (min, max, allowlist) → provenance → uses remaining.
It fails closed:
- Malformed values are rejected before any bound is compared. Before this hardening,
  `amount=NaN` passed every numeric bound.
- Schema keywords it doesn't implement are errors, not ignored.
- Any internal error is a deny.

**Provenance.** Envelopes say which values are *allowed*, not which one the user
*meant*. An injection that steers a refund to another allowlisted account passes the
envelope and looks normal statistically. Warden records the session's trusted text (the
request) and untrusted text (every tool output). A `from = "trusted"` rule requires the
argument to occur in trusted text, matched as whole tokens without regard to case. This
is a deterministic, textual approximation of taint tracking.

**Drift.** Calls that are in bounds but abnormal (a never-seen email domain, a z-score
outlier) go to a statistical detector. Its baseline is fitted offline on clean traffic
and never updated from live calls. It has no LLM, because an LLM judge could be injected
the same way.

**Audit.** Every proposal, decision and quarantine is written to a hash-chained JSONL
log. `warden audit-verify` detects edited, inserted, deleted and truncated records.

**The runner seam.** Agents never call tools; they hand proposals to a runner.
`GatedToolRunner.authorize()` is the entire enforcement path, and every integration goes
through it.

## 3. Integrations

- **AgentDojo defense.** It replaces AgentDojo's `ToolsExecutor`. The task is declared
  from the user's prompt, schemas come from AgentDojo's tool definitions, and tool outputs
  are recorded as untrusted.
- **MCP gateway.** `warden mcp-proxy` sits between an MCP host and any MCP server. It
  hides tools the task doesn't grant, gates every call with the upstream schema, and
  treats upstream output as untrusted.

## 4. Evaluation

### 4.1 Setup

AgentDojo v1.2.2 covers all four suites (workspace, travel, banking, slack) with the
`important_instructions` attack. We compare five configurations:

| Config | Policy the gate enforces |
|---|---|
| `none` | No Warden |
| `suite` | Every suite tool granted, unconstrained |
| `task` | Each prompt declares a workflow granting all read tools plus only the write tools it needs, decided from the prompt text alone |
| `oracle` | Exactly each task's ground-truth tools (upper bound, not deployable) |
| `task+prov` | `task`, with destination and credential arguments requiring trusted provenance |

**Two agents.** The **scripted always-fooled agent** replays each task's ground-truth
calls. It also carries out every injection it reads, by replaying that injection's
ground truth. This is a deterministic worst case that measures what the *policy*
contains, independent of any model's gullibility. It can't perform injection tasks that
have no tool-call ground truth: eight workspace tasks and one text-only travel task.
Those are excluded from its numbers. **gpt-4o-mini** is the real-model check (§4.3).

### 4.2 Worst case: the always-fooled agent

| Configuration | Utility | Utility under attack | Attack success |
|---|---|---|---|
| no defense | 99.0% | 41.7% | 94.9% |
| Warden, suite-wide | 99.0% | 41.7% | 94.9% |
| **Warden, per-task** | **99.0%** | 53.7% | **23.5%** |
| Warden, oracle (upper bound) | 99.0% | 51.1% | 16.9% |
| **Warden, per-task + provenance** | 76.3% | 42.7% | **3.8%** |

What the results show:
1. **Tool-level least privilege is most of the win, and costs no utility.** Per-task
   capabilities cut attack success from 94.9% to 23.5% with no utility change. They come
   within 7 points of the oracle, so declaring workflows from prompts alone loses little
   compared with perfect knowledge of the tools each task needs.
2. **What remains is in-envelope.** The per-task residue sits in banking (36.1%) and
   slack (53.3%). There, the attacker's action uses the same tool the task legitimately
   needs: `send_money`, `send_direct_message`, `invite_user_to_slack`.
3. **Provenance closes most of the rest, at a price.** Attack success falls to 3.8%
   (banking 0.0%). Utility drops to 76.3%, concentrated in slack, where users and URLs
   come from channel messages and web pages. The check can't tell those apart from
   injected values. This is the same security/utility trade-off that information-flow
   defenses report.
4. **Quarantine vs. error mode.** Quarantining the session at the first denial is the
   safe default, but it ends tasks. Returning the denial to the agent as a tool error
   instead raises utility under attack from 53.7% to 91.3% (per-task) and from 42.7% to
   79.5% (per-task + provenance), with nearly the same attack success (23.5% and 4.3%).

### 4.3 Real model (gpt-4o-mini)

*In progress.* The gpt-4o-mini runs of `none`, `task` and `task+prov` (one repetition,
all four suites, about 1,080 episodes each) are running. Their numbers go into
[`results/agentdojo/README.md`](../results/agentdojo/README.md) and into this section
when they finish. A two-task smoke run confirmed the real-model path end to end. In
that run the model's own mistakes, such as wrong arithmetic in a final answer, show up
as lost utility with no Warden denial involved. The `none` baseline exists to measure
exactly that.

### 4.4 In-house suite

`warden eval` covers 17 attacks and 26 clean calls. All 17 attacks are contained, the
ungated baseline contains none, and 2 of 26 clean calls are falsely quarantined (two
deliberate unusual-but-legit calls caught by drift). Every extension was measured by
adding its attack class first and confirming it leaked. Four evasions aimed at the
checks (a NaN amount, a negative refund, an attacker address hidden among recipients or
behind a display name) took containment to 87% before the fail-closed hardening. Two
in-envelope redirects took it to 88% before provenance.

## 5. Overhead

`warden bench` gives these per-call costs, measured on the development laptop:

| Operation | Mean |
|---|---|
| Gate, all nine checks (allow) | ~145 µs (mostly Ed25519 verify) |
| Gate, deny (no capability) | ~1 µs |
| Drift check | ~26 µs |
| Provenance lookup | ~2 µs |
| Full `runner.authorize` (gate + drift + 3–4 audit appends) | ~1.1 ms |

The full path is about 0.2% of a 500 ms LLM call. Audit appends account for most of it.

## 6. Limitations

- **Policies are hand-written.** Containment is only as good as the policy. The AgentDojo
  `task` mapping was written from prompts. The author had seen banking's ground truth
  while building the adapter, and disclosed it.
- **Provenance is textual.** It recognizes values copied verbatim, not values that are
  computed or paraphrased. It denies legitimate document-sourced values; a trusted
  directory for those values is the practical remedy. A real data-flow interpreter is
  the principled one.
- **Open-ended prompts** ("do what this email says") need broad grants. An intent the
  prompt doesn't state can't be least-privileged.
- **Text-only and read-only effects.** An injection that only changes what the agent
  *says* makes no tool call. Fetching an attacker's URL is a read. Provenance on URLs
  covers the second case, and nothing tool-level covers the first.
- **Audit anchoring.** Tampering and truncation are detected, but someone who can
  rewrite the whole file can recompute the chain. Anchoring the head hash off-host is
  future work.
- **Evaluation scope.** One attack family, one model, one repetition per configuration.

## 7. Related work

- **AgentDojo** (Debenedetti et al., 2024): the dynamic benchmark used here. It ships
  prompt-level and detector defenses (spotlighting, prompt repetition, a PI detector,
  tool filtering), which are useful baselines for future comparison.
- **InjecAgent** (Zhan et al., 2024): the style of the in-house call-level suite.
- **CaMeL** (Debenedetti et al., 2025): separates control flow from untrusted data with a
  custom interpreter and capabilities on values. Warden's provenance check is a lighter,
  textual approximation of that data-flow idea, placed at the tool boundary.
- **FIDES** (Costa et al., 2025): information-flow control for agents, the other
  principled route to the in-envelope problem.
- **Spotlighting** (Hines et al., 2024) and detector-based defenses try to make the model
  less likely to be fooled. Warden is complementary: it assumes the model *is* fooled.

## 8. Reproducibility

All numbers come from committed code and raw JSON:
- **Scripted runs:** `experiments/agentdojo/run.py --model scripted --config all` ($0,
  deterministic).
- **Real-model runs:** the same with `--model gpt-4o-mini-2024-07-18` (resumable).
- **Tables:** regenerate with `summarize.py`.
- **In-house suite:** `warden eval`.
- **Overhead:** `warden bench`.
