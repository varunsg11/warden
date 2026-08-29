"""Warden — a capability-governed runtime for LLM agents.

The design in one sentence: we assume the agent *can* be fooled by a prompt
injection, so we put authorization in deterministic code OUTSIDE the agent's
reasoning loop, where no amount of persuasive text can talk its way past it.
"""

__version__ = "0.1.0"

# Convenience re-exports for library users. Kept lightweight: importing `warden`
# pulls in the governance core but NOT langgraph (only warden.pipeline.graph does).
from warden.governance.audit import AuditLog
from warden.governance.capability import Capability
from warden.governance.drift import DriftDetector, DriftViolation
from warden.governance.gate import Decision, Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.pipeline.runner import GatedToolRunner, ToolRunner

__all__ = [
    "__version__",
    "AuditLog",
    "Capability",
    "Decision",
    "DriftDetector",
    "DriftViolation",
    "Gate",
    "GateViolation",
    "GatedToolRunner",
    "Supervisor",
    "ToolRunner",
]
