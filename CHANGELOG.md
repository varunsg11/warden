# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
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
- `warden audit-verify <file>` and `AuditLog.verify_file()` — verify a log on disk,
  including detection of a truncated tail (missing `session_end`).
- Four evasion cases in the eval suite (15 attacks total, all contained).

### Changed
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

[Unreleased]: https://github.com/varunsg11/warden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/varunsg11/warden/releases/tag/v0.1.0
