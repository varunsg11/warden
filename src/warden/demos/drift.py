"""DRIFT demo — the second line of defense.

Part A shows the detector in isolation: given a baseline of normal refunds, which
proposed calls does it flag? Part B shows it wired into the runtime as stage 2:
a refund that PASSES the capability gate (in policy) is still quarantined because
it doesn't look like anything the business normally does.

    warden drift
"""

from __future__ import annotations

from warden.governance.audit import AuditLog
from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Gate
from warden.governance.issuer import Supervisor
from warden.llm import ToolCall
from warden.pipeline.runner import GatedToolRunner
from warden.pipeline.tools import REFUNDS_ISSUED, reset_world

# A baseline of NORMAL, legitimate refunds (learned offline from clean traffic).
BASELINE = [
    ("issue_refund", {"account": "1234", "amount": 12.50}),
    ("issue_refund", {"account": "1234", "amount": 9.00}),
    ("issue_refund", {"account": "5678", "amount": 20.00}),
    ("issue_refund", {"account": "5678", "amount": 15.00}),
    ("issue_refund", {"account": "1234", "amount": 18.00}),
    ("issue_refund", {"account": "4321", "amount": 11.00}),
]

# Proposed calls to score. All are UNDER the $50 cap; the gate would allow them.
PROBES = [
    ("normal small refund", {"account": "1234", "amount": 13.00}),
    ("refund to a NEW account", {"account": "9999", "amount": 14.00}),
    ("in-cap but unusual amount", {"account": "1234", "amount": 49.99}),
    ("normal refund", {"account": "5678", "amount": 19.00}),
]


def part_a(detector: DriftDetector) -> None:
    print("PART A - drift detector over proposed calls (baseline = 6 normal refunds)\n")
    for label, args in PROBES:
        r = detector.check("issue_refund", args)
        verdict = "DRIFT" if r.is_drift else "ok   "
        why = ("  <- " + "; ".join(r.reasons)) if r.is_drift else ""
        print(f"  [{verdict}] {label:<28} {args}{why}")
    print()


def part_b(detector: DriftDetector) -> None:
    print("PART B - two-stage runtime: gate ALLOWS, drift QUARANTINES\n")
    reset_world()
    sup = Supervisor()
    gate = Gate(sup.verifier)
    manifests = {"refund_issuer": sup.issue_manifest("refund_issuer", "process_refund")}
    audit = AuditLog("drift-demo")
    runner = GatedToolRunner(gate, manifests, audit, drift=detector)

    # In policy: account 1234 is allowlisted and 49.99 <= 50 cap. Gate says ALLOW.
    call = ToolCall(name="issue_refund", arguments={"account": "1234", "amount": 49.99})
    print(f"  Proposed: issue_refund {call.arguments}")
    try:
        runner.execute("refund_issuer", call)
        print("  Executed (no quarantine).")
    except DriftViolation as v:
        print("  Stage 1 (gate):  ALLOW  (in policy: account allowlisted, amount <= 50)")
        print(f"  Stage 2 (drift): DENY   {v}")
        print("  -> Session quarantined by drift. No refund issued.")
    print(f"\n  Refund actually issued? {'YES (bad)' if REFUNDS_ISSUED else 'no'}")
    print(f"  Audit chain intact: {audit.verify_chain()}")


def main() -> None:
    detector = DriftDetector().fit(BASELINE)
    print("=" * 70)
    print("DRIFT DETECTION DEMO")
    print("=" * 70 + "\n")
    part_a(detector)
    part_b(detector)


if __name__ == "__main__":
    main()
