"""Smoke test for the overhead benchmark (correctness of its setup, not timing)."""

from __future__ import annotations

from warden import bench


def test_bench_runs_every_operation():
    results = dict(bench.run(n=20))
    assert set(results) == {
        "gate.check  ALLOW (all checks)",
        "gate.check  DENY (no capability)",
        "drift.check",
        "provenance.origin",
        "audit.record (fsync-free append)",
        "runner.authorize (gate+drift+audit)",
    }
    assert all(len(samples) == 20 and min(samples) >= 0 for samples in results.values())
