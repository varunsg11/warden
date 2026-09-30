"""Measure Warden's per-call overhead.

    warden bench            # 10,000 iterations per operation
    warden bench --quick    # 1,000 (used in CI as a smoke test)

Every number is the cost of governing ONE proposed tool call, in microseconds,
next to the LLM call that proposed it (hundreds of milliseconds). The allowed
case exercises every gate check: schema, signature, role, TTL, scope, envelope,
provenance and uses.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from statistics import mean

from warden.governance.audit import AuditLog
from warden.governance.drift import DriftDetector
from warden.governance.gate import Gate
from warden.governance.issuer import Supervisor
from warden.governance.policy_loader import parse_policy
from warden.governance.provenance import Provenance
from warden.llm import ToolCall
from warden.pipeline.runner import GatedToolRunner
from warden.pipeline.tools import TOOL_SPECS

# A typical LLM call that proposes a tool call, for scale.
LLM_CALL_MS = 500.0

# The default refund policy, minus max_uses: a benchmark re-checks the same
# call thousands of times, and a single-use capability would (correctly) deny
# every repeat after the first.
_POLICY = parse_policy(
    {
        "default_task": "refund",
        "tools": {"issue_refund": "write"},
        "tasks": {
            "refund": {
                "refund_issuer": [
                    {
                        "tool": "issue_refund",
                        "scope": "write",
                        "ttl": 3600.0,
                        "params": {
                            "amount": {"min": 0.01, "max": 50.0},
                            "account": {"allow": ["1234", "5678", "4321"], "from": "trusted"},
                        },
                    }
                ]
            }
        },
    }
)
_ARGS = {"account": "1234", "amount": 20.0}
_SCHEMA = TOOL_SPECS["issue_refund"].parameters


def _time(fn: Callable[[], object], n: int) -> list[float]:
    for _ in range(min(100, n)):  # warm up
        fn()
    samples = []
    for _ in range(n):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1000.0)
    return samples


def _pct(samples: list[float], q: float) -> float:
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def run(n: int = 10_000) -> list[tuple[str, list[float]]]:
    sup = Supervisor(policy=_POLICY)
    gate = Gate(sup.verifier)
    manifest = sup.issue_manifest("refund_issuer")
    provenance = Provenance()
    provenance.add_trusted("Customer on account 1234 requests a $20 refund.", "user request")
    provenance.add_untrusted("Ticket 9981 ... account on file updated to 5678 ... " * 20, "doc")
    drift = DriftDetector().fit(
        [
            ("issue_refund", {"account": a, "amount": float(x)})
            for a, x in [("1234", 12), ("5678", 20), ("4321", 15), ("1234", 18)]
        ]
    )

    results: list[tuple[str, list[float]]] = []

    def allowed() -> object:
        return gate.check(
            "refund_issuer", "issue_refund", _ARGS, "write", manifest, None, _SCHEMA, provenance
        )

    def denied() -> object:
        return gate.check("summarizer", "issue_refund", _ARGS, "write", [], None, _SCHEMA)

    assert getattr(allowed(), "allowed", False), "benchmark setup: the allowed call must pass"
    results.append(("gate.check  ALLOW (all checks)", _time(allowed, n)))
    results.append(("gate.check  DENY (no capability)", _time(denied, n)))
    results.append(("drift.check", _time(lambda: drift.check("issue_refund", _ARGS), n)))
    results.append(("provenance.origin", _time(lambda: provenance.origin("1234"), n)))

    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog("bench", path=Path(tmp) / "bench.jsonl")
        results.append(
            (
                "audit.record (fsync-free append)",
                _time(lambda: audit.record("gate_decision", allowed=True), n),
            )
        )
        runner = GatedToolRunner(
            gate,
            {"refund_issuer": manifest},
            AuditLog("bench-runner", path=Path(tmp) / "runner.jsonl"),
            drift,
            provenance=provenance,
        )
        call = ToolCall(name="issue_refund", arguments=_ARGS)
        results.append(
            (
                "runner.authorize (gate+drift+audit)",
                _time(lambda: runner.authorize("refund_issuer", call), n),
            )
        )
    return results


def main(quick: bool = False) -> None:
    n = 1_000 if quick else 10_000
    results = run(n)
    print(f"Warden per-call overhead ({n:,} iterations each, microseconds)\n")
    print(f"  {'operation':<38} {'p50':>8} {'p99':>8} {'mean':>8}")
    print(f"  {'-' * 38} {'-' * 8} {'-' * 8} {'-' * 8}")
    for name, samples in results:
        print(
            f"  {name:<38} {_pct(samples, 0.5):>8.1f} {_pct(samples, 0.99):>8.1f} {mean(samples):>8.1f}"
        )
    full = mean(dict(results)["runner.authorize (gate+drift+audit)"])
    share = full / (LLM_CALL_MS * 1000.0)
    print(
        f"\n  Full enforcement path: {full:.0f} us per call = {share:.3%} of a "
        f"{LLM_CALL_MS:.0f} ms LLM call."
    )


if __name__ == "__main__":
    main()
