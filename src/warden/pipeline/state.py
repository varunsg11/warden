"""The shared state that flows through the LangGraph pipeline.

LangGraph passes a single state object from node to node. Each node returns a
partial dict, which LangGraph merges into the state. For most fields "merge"
means "overwrite"; for `trace` we attach a reducer (operator.add) so every node
can APPEND to a running list of proposed tool calls without clobbering it.
That accumulated trace is what the audit log and the demo read afterwards.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


class PipelineState(TypedDict, total=False):
    user_request: str  # what the (legitimate) user asked
    retrieved: str  # docs returned by search_docs (may be poisoned)
    summary: str  # summarizer output
    resolution: str  # what the refund agent ended up doing
    trace: Annotated[list[dict[str, Any]], operator.add]  # every proposed tool call
