# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-30

Headline: evaluated on AgentDojo (all four suites). Against an always-fooled
worst-case agent, attack success falls from 94.9% with no defense to 23.5% with
per-task policies (utility unchanged at 99.0%), and to 3.8% with provenance
tracking (utility 76.3%). See `results/agentdojo/README.md` for real-model numbers.

### Security
- **Provenance tracking** (`governance/provenance.py`) closes the in-envelope hole: an
  injection that steers the agent to a *different allowed* value (refund allowlisted
  account 5678 when the user named 1234; reply to a known email domain) passed both the
  gate and drift. A signed `from = "trusted"` param rule now requires the value to appear
  in trusted input (the user's request), checked by the new `provenance_ok` gate step.
  Without provenance tracked, the rule fails closed.
- **NaN / non-numeric arguments no longer bypass numeric bounds.** `NaN` compared False
  against `max`, so `amount=NaN` passed the gate (and drift). Bounds now require a
  finite real number.
- **New `args_well_formed` gate check** (`governance/schema.py`): arguments are validated
  against the tool's JSON Schema — no missing or unexpected keys, no bools as numbers,
  no non-finite values — before any envelope check.
- **Negative refunds denied** — the refund capability now carries `min: 0.01`.
- **Capabilities are bound to their role** (`subject`, signed) — new `bound_to_role` check.
- **Single-use capabilities** (`max_uses`, signed) — the gate counts uses by nonce, so a
  refund capability can't be replayed within its TTL. `evaluate()` stays side-effect free.
- **Gate fails closed** — any internal error is a DENY; an unknown tool name is an
  audited DENY instead of a `KeyError` in the runner.
- **Drift checks every email recipient** — `x@evil.com, alice@gmail.com` and
  `Alice <x@evil.com>` no longer hide the attacker's domain.
- **Drift fails closed** on a missing / unparseable / non-finite watched feature.

### Added
- **AgentDojo integration** (`warden.integrations.agentdojo`, extra `[agentdojo]`):
  `WardenSession` / `WardenToolsExecutor` / `WardenSessionEnd` put the gate in front of
  AgentDojo's tool runtime; `ScriptedAgent` is an offline always-fooled agent for $0
  worst-case evaluation. `experiments/agentdojo/` has per-suite policies, a runner
  (`none` / `suite` / `task` / `oracle` / `task+prov`, quarantine or error mode, resumable)
  and a summarizer; results in `results/agentdojo/`.
- **MCP gateway** — `warden mcp-proxy --policy P --task T [--trusted TEXT] -- <server>`
  (extra `[mcp]`) governs any MCP tool server: ungranted tools are hidden, every call is
  gated with the upstream tool's schema, outputs are untrusted provenance.
  `examples/mcp_bank/` is a poisoned toy server + policy.
- **`warden bench`** — per-call overhead of every enforcement stage (~1.1 ms for the full
  path on the dev machine, dominated by audit appends).
- **Policy files** — policies are TOML (`src/warden/policies/default.toml`), loaded by
  `governance/policy_loader.py` with strict validation (unknown keys, unenforceable rules,
  impossible scopes, bad bounds are load-time errors). `Supervisor(policy=...)` accepts a
  custom policy; `warden policy check <file>` validates and prints the grants.
- `warden audit-verify <file>` and `AuditLog.verify_file()` — verify a log on disk,
  including detection of a truncated tail (missing `session_end`).
- Six new attack cases in the eval suite: four evasions and two in-envelope attacks
  (17 total, all contained); `warden eval` shows which check stopped each one.

### Changed
- The gate runs nine checks (added: `args_well_formed`, `bound_to_role`,
  `provenance_ok`, `uses_remaining`).
- `GatedToolRunner` splits into `authorize()` (enforcement only) and `execute()`; tool
  registries are constructor arguments so integrations reuse the same path; quarantine
  is explicit (`quarantine_on_deny`); `provenance=` records tool outputs as untrusted.
- `governance/schema.py` covers the JSON-Schema subset pydantic generates (arrays, null,
  anyOf/oneOf, enum/const, local `$ref`) and fails closed on anything else.
- The default policy requires the refund account and reply recipient to come from the
  user's request.
- Audit records are strict JSON (non-finite floats are logged as strings).

## [0.1.0] - 2026-08-29

### Added
- **Capability model** — Ed25519-signed, time-limited capabilities
  `c = (tool, params, scope, ttl, nonce, issuer, signature)`.
- **Supervisor / issuer** — mints per-role, per-task (just-in-time) signed manifests.
- **Enforcement gate** — five deterministic checks (capability, signature, TTL, scope,
  params) with an `evaluate()` API that exposes a per-check trace.
- **Drift detector** — non-LLM anomaly detection (novel destination, numeric outlier)
  as a second defense stage.
- **Quarantine + tamper-evident audit log** — append-only, hash-chained JSONL.
- **Demo pipeline** — a 3-agent LangGraph pipeline (retriever → summarizer → refund)
  with a poisoned corpus, plus baseline / governed / drift / trace demos.
- **Evaluation harness** — InjecAgent-style suite reporting attack-containment and
  false-quarantine rates.
- **`warden` CLI** and `python -m warden` entry points.
- Tooling: ruff, mypy, pytest + coverage, pre-commit, GitHub Actions CI, Dockerfile.

[Unreleased]: https://github.com/varunsg11/warden/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/varunsg11/warden/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/varunsg11/warden/releases/tag/v0.1.0
