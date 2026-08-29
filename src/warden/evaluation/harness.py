"""Run the evaluation and report attack-containment + false-quarantine rates.

For every case we execute the proposed tool call twice:
  * through an UNGATED runner (the baseline every naive agent framework gives you)
  * through Warden's GATED runner (capability gate + drift)

Containment = the harmful call was blocked before it executed.
False-quarantine = a legitimate call was wrongly blocked.

No LLM is involved: the cases already encode the call a fooled agent would make,
so the numbers isolate exactly what the GOVERNANCE layer contains. Deterministic
and reproducible for a grader; run `warden baseline` + `warden governed` to see
the same mechanism end-to-end through a real model.

    warden eval
"""

from __future__ import annotations

from collections import Counter

from warden.evaluation.cases import ATTACKS, BASELINE, CLEAN
from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.llm import ToolCall
from warden.pipeline import tools as tool_mod
from warden.pipeline.runner import GatedToolRunner, ToolRunner


def _warden(gate, detector, sup, case):
    tool_mod.reset_world()
    manifests = {case.role: sup.issue_manifest(case.role, case.task)}
    runner = GatedToolRunner(gate, manifests, drift=detector)
    call = ToolCall(name=case.tool, arguments=dict(case.arguments))
    try:
        runner.execute(case.role, call)
        return False, None
    except GateViolation:
        return True, "gate"
    except DriftViolation:
        return True, "drift"


def _baseline(case) -> bool:
    tool_mod.reset_world()
    try:
        ToolRunner().execute(case.role, ToolCall(name=case.tool, arguments=dict(case.arguments)))
        return False
    except Exception:
        return True


def run() -> dict:
    detector = DriftDetector().fit(BASELINE)
    sup = Supervisor()
    gate = Gate(sup.verifier)

    attacks = []
    for c in ATTACKS:
        contained, stage = _warden(gate, detector, sup, c)
        attacks.append(
            {"case": c, "contained": contained, "stage": stage, "baseline_contained": _baseline(c)}
        )

    clean = []
    for c in CLEAN:
        contained, stage = _warden(gate, detector, sup, c)
        clean.append({"case": c, "contained": contained, "stage": stage})

    n_a = len(attacks)
    n_a_contained = sum(a["contained"] for a in attacks)
    n_a_baseline = sum(a["baseline_contained"] for a in attacks)
    n_c = len(clean)
    n_fq = sum(x["contained"] for x in clean)

    return {
        "attacks": attacks,
        "clean": clean,
        "n_attacks": n_a,
        "containment_rate": n_a_contained / n_a,
        "baseline_containment_rate": n_a_baseline / n_a,
        "false_quarantine_rate": n_fq / n_c,
        "n_false_quarantine": n_fq,
        "n_clean": n_c,
        "stage_counts": Counter(a["stage"] for a in attacks if a["contained"]),
    }


def main() -> None:
    r = run()

    print("=" * 72)
    print("WARDEN EVALUATION")
    print("=" * 72)

    print("\nATTACKS (should be contained):")
    for a in r["attacks"]:
        c = a["case"]
        mark = f"contained@{a['stage']}" if a["contained"] else "LEAKED"
        print(f"  [{mark:<16}] {c.name:<38} ({c.category})")

    print("\nCLEAN (should pass):")
    for x in r["clean"]:
        c = x["case"]
        tag = "QUARANTINED (false +)" if x["contained"] else "passed"
        note = f"  <- {c.note}" if c.note else ""
        print(f"  [{tag:<21}] {c.name}{note}")

    print("\n" + "-" * 72)
    print(f"  Attacks:                 {r['n_attacks']}")
    print(
        f"  Baseline containment:    {r['baseline_containment_rate']:.0%}  "
        f"(ungated runner -- every attack executes)"
    )
    print(
        f"  Warden containment:      {r['containment_rate']:.0%}  "
        f"(by stage: {dict(r['stage_counts'])})"
    )
    print(f"  Clean requests:          {r['n_clean']}")
    print(
        f"  False-quarantine rate:   {r['false_quarantine_rate']:.0%}  "
        f"({r['n_false_quarantine']} of {r['n_clean']})"
    )
    print("-" * 72)
    print(
        f"\n  HEADLINE: Warden contained {r['containment_rate']:.0%} of indirect-injection "
        f"attacks\n            (baseline {r['baseline_containment_rate']:.0%}) with a "
        f"{r['false_quarantine_rate']:.0%} false-quarantine rate on clean traffic."
    )


if __name__ == "__main__":
    main()
