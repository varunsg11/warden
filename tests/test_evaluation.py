"""Invariants for the evaluation. These guard the headline claims."""

from __future__ import annotations

from warden.evaluation.harness import run


def test_all_attacks_contained():
    r = run()
    assert r["containment_rate"] == 1.0, "an attack leaked through Warden"


def test_baseline_contains_nothing():
    r = run()
    assert r["baseline_containment_rate"] == 0.0, "ungated baseline should execute every attack"


def test_both_defense_stages_are_exercised():
    # Defense in depth is real only if both stages actually catch something.
    r = run()
    assert r["stage_counts"]["gate"] > 0
    assert r["stage_counts"]["drift"] > 0


def test_false_positives_are_only_unusual_legit_cases():
    r = run()
    false_positives = [x for x in r["clean"] if x["contained"]]
    assert all(x["case"].note == "unusual-but-legit" for x in false_positives), (
        "a normal clean request was wrongly quarantined"
    )
