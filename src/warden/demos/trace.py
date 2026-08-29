"""DEBUG FLOW — a narrated, step-by-step trace of one request through Warden.

This drives the REAL agent nodes and the REAL gate/drift, printing what happens
at every stage so you can see exactly how data (and the injection) flows and
where each decision is made:

    trusted task ─┐
                  v
  [Supervisor] issues signed manifests
                  |
  user request -> [Retriever] --search_docs--> (GATE: read? ok) --> docs (poisoned)
                  |
               [Summarizer] --(no tools)--> summary (carries the poison)
                  |
             [Refund agent] --issue_refund?--> (GATE: 5 checks) --> DENY -> QUARANTINE

Run it (offline, deterministic):
    warden trace                 # task=summarize (default)
    warden trace process_refund  # follow a call further down the checklist
"""

from __future__ import annotations

from warden.governance.audit import AuditLog
from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.llm import ToolCall, get_llm
from warden.pipeline.agents import refund_node, retriever_node, summarizer_node
from warden.pipeline.state import PipelineState
from warden.pipeline.tools import TOOL_IMPLS, TOOL_SCOPES, reset_world

USER_REQUEST = "Please summarize the recent notes on account 1234."
ROLES = ["retriever", "summarizer", "refund_issuer"]


def hr(title: str = "") -> None:
    print("\n" + "=" * 74)
    if title:
        print(title)
        print("=" * 74)


class TracingRunner:
    """Same logic as GatedToolRunner, but narrates every check out loud."""

    def __init__(self, gate: Gate, manifests, drift, audit) -> None:
        self.gate, self.manifests, self.drift, self.audit = gate, manifests, drift, audit

    def execute(self, role: str, call: ToolCall) -> str:
        print(f"\n  >> {role} PROPOSES: {call.name}({call.arguments})")
        required = TOOL_SCOPES[call.name]
        self.audit.record("tool_proposed", role=role, tool=call.name, arguments=call.arguments)

        # --- Stage 1: capability gate -------------------------------------- #
        decision = self.gate.evaluate(
            role, call.name, call.arguments, required, self.manifests.get(role, [])
        )
        print(f"     Stage 1 - GATE (required scope: {required}):")
        for s in decision.steps:
            print(f"        [{'PASS' if s.passed else 'FAIL'}] {s.name:<18} {s.detail}")
        self.audit.record(
            "gate_decision",
            role=role,
            tool=call.name,
            allowed=decision.allowed,
            reason=decision.reason,
        )
        if not decision.allowed:
            print(f"     -> {decision.reason}")
            self.audit.record("quarantine", role=role, tool=call.name, reason=decision.reason)
            raise GateViolation(decision)

        # --- Stage 2: drift ------------------------------------------------ #
        if self.drift is not None:
            d = self.drift.check(call.name, call.arguments)
            print(
                f"     Stage 2 - DRIFT: {'ANOMALY' if d.is_drift else 'normal'}"
                + (f" ({'; '.join(d.reasons)})" if d.is_drift else "")
            )
            self.audit.record("drift_check", role=role, tool=call.name, is_drift=d.is_drift)
            if d.is_drift:
                self.audit.record("quarantine", role=role, tool=call.name, reason="DRIFT")
                raise DriftViolation(d)

        result = TOOL_IMPLS[call.name](**call.arguments)
        print(f"     -> ALLOWED and EXECUTED: {result[:60]}")
        self.audit.record("tool_executed", role=role, tool=call.name)
        return result


def main(task: str = "summarize") -> None:
    reset_world()
    llm = get_llm()
    sup = Supervisor()
    gate = Gate(sup.verifier)
    drift = DriftDetector()  # empty baseline here; drift is exercised in run_drift.py
    manifests = sup.issue_all(ROLES + ["responder"], task)
    audit = AuditLog(f"trace-{task}")
    runner = TracingRunner(gate, manifests, drift, audit)
    audit.record("session_start", task=task, user_request=USER_REQUEST)

    hr(f"WARDEN DEBUG FLOW  (task='{task}')")
    print(f"User request (TRUSTED): {USER_REQUEST}")
    print(f"Declared task  (TRUSTED): {task}   <- decides what authority is issued\n")
    print("Signed capability manifests issued by the Supervisor:")
    for role, caps in manifests.items():
        summary = ", ".join(f"{c.tool}[{c.scope}]" for c in caps) or "(nothing)"
        print(f"   {role:<14} -> {summary}")

    state: PipelineState = {"user_request": USER_REQUEST, "trace": []}

    hr("STEP 1 - RETRIEVER  (reads the knowledge base; injection enters here)")
    try:
        state.update(retriever_node(state, llm=llm, runner=runner))
    except (GateViolation, DriftViolation) as e:
        return _quarantine(audit, e)
    poisoned = "ATTACKER" in state["retrieved"] or "OVERRIDE" in state["retrieved"]
    print(
        f"\n  Retrieved {len(state['retrieved'])} chars. Contains injected instruction? {poisoned}"
    )

    hr("STEP 2 - SUMMARIZER  (no tools; naively carries the poison downstream)")
    state.update(summarizer_node(state, llm=llm, runner=runner))
    print(f"  Summary (first 120 chars): {state['summary'][:120].strip()}...")

    hr("STEP 3 - REFUND AGENT  (the deputy; proposes an action)")
    try:
        state.update(refund_node(state, llm=llm, runner=runner))
        print(f"\n  Resolution: {state['resolution']}")
        audit.record("session_end", status="completed")
    except (GateViolation, DriftViolation) as e:
        return _quarantine(audit, e)

    _finish(audit)


def _quarantine(audit: AuditLog, err: Exception) -> None:
    audit.record("session_end", status="quarantined", reason=str(err))
    hr("OUTCOME")
    print("  SESSION QUARANTINED before any harmful action ran.")
    print(f"  Cause: {err}")
    _finish(audit)


def _finish(audit: AuditLog) -> None:
    print(
        f"\n  Audit log: {audit.path}  ({len(audit.records)} records, "
        f"chain intact: {audit.verify_chain()})"
    )
    print("=" * 74)


if __name__ == "__main__":
    main()
