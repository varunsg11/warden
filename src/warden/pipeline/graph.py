"""Wires the three agents into a LangGraph pipeline.

    START -> retriever -> summarizer -> refund_issuer -> END

The topology is IDENTICAL for baseline and governed runs. Governance is added by
swapping the runner the nodes use -- not by changing the graph. Security as a
wrapper, not a rewrite.
"""

from __future__ import annotations

import uuid
from functools import partial

from langgraph.graph import END, START, StateGraph

from warden.governance.audit import AuditLog
from warden.governance.gate import Gate
from warden.governance.issuer import Supervisor
from warden.governance.policy import DEFAULT_TASK
from warden.governance.provenance import Provenance
from warden.llm import LLMBackend, get_llm
from warden.pipeline.agents import refund_node, retriever_node, summarizer_node
from warden.pipeline.runner import GatedToolRunner, Runner, ToolRunner
from warden.pipeline.state import PipelineState

ROLES = ["retriever", "summarizer", "refund_issuer"]


def _compile(llm: LLMBackend, runner: Runner):
    graph = StateGraph(PipelineState)
    graph.add_node("retriever", partial(retriever_node, llm=llm, runner=runner))
    graph.add_node("summarizer", partial(summarizer_node, llm=llm, runner=runner))
    graph.add_node("refund_issuer", partial(refund_node, llm=llm, runner=runner))

    graph.add_edge(START, "retriever")
    graph.add_edge("retriever", "summarizer")
    graph.add_edge("summarizer", "refund_issuer")
    graph.add_edge("refund_issuer", END)
    return graph.compile()


def build_pipeline(llm: LLMBackend | None = None, runner: Runner | None = None):
    """Baseline (ungoverned) pipeline: proposals execute with no checks."""
    llm = llm or get_llm()
    runner = runner or ToolRunner()
    return _compile(llm, runner)


def build_governed_pipeline(
    task: str = DEFAULT_TASK,
    user_request: str = "",
    llm: LLMBackend | None = None,
    supervisor: Supervisor | None = None,
    session_id: str | None = None,
    drift=None,
):
    """Governed pipeline for a declared `task`. Returns
    (compiled_graph, supervisor, manifests, runner, audit) so the demo/eval can
    display exactly what each agent was authorized to do and read the audit trail."""
    llm = llm or get_llm()
    supervisor = supervisor or Supervisor()
    session_id = session_id or f"sess-{uuid.uuid4().hex[:8]}"

    audit = AuditLog(session_id)
    audit.record("session_start", task=task, user_request=user_request)

    # The Supervisor issues each role's signed capabilities for this task/turn.
    manifests = supervisor.issue_all(ROLES, task)
    for role, caps in manifests.items():
        audit.record(
            "manifest_issued",
            role=role,
            capabilities=[
                {
                    "tool": c.tool,
                    "scope": c.scope,
                    "params": c.params,
                    "ttl": c.ttl,
                    "nonce": c.nonce,
                }
                for c in caps
            ],
        )

    # Provenance: the user's request is the trusted input; the runner adds every
    # tool output (e.g. retrieved documents) as untrusted.
    provenance = Provenance()
    provenance.add_trusted(user_request, "user request")

    # The gate gets only the PUBLIC verify key -- it can check, never mint.
    gate = Gate(supervisor.verifier)
    runner = GatedToolRunner(gate, manifests, audit, drift=drift, provenance=provenance)

    return _compile(llm, runner), supervisor, manifests, runner, audit
