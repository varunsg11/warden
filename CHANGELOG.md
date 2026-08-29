# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/varunsg11/warden-agent-governance/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/varunsg11/warden-agent-governance/releases/tag/v0.1.0
