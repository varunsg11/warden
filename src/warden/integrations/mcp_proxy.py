"""Warden as an MCP gateway: a proxy that governs any MCP tool server.

    MCP host (Claude Desktop, an IDE, an agent)  <-- stdio -->  warden mcp-proxy
                                                                  |  gate: every call
                                                                  v
                                                    upstream MCP server (stdio)

The proxy connects to the upstream server, lists its tools, and re-exposes them
to the host -- minus any tool the session holds no capability for (least
privilege extends to what the model can even see). Every `tools/call` goes
through `GatedToolRunner.authorize()`, the same enforcement path as the rest of
Warden, with the upstream tool's own input schema as the `args_well_formed`
schema. Allowed calls are forwarded; denied calls come back as an MCP tool error
("Blocked by Warden: ..."). Every upstream output is recorded as UNTRUSTED
provenance, because tool output is where injections live.

Trusted input: the proxy never sees the user's conversation (the host owns it),
so `from = "trusted"` rules are satisfied only by text the operator supplies with
`--trusted` (e.g. "pay rent of 1200 to GB29NWBK60161331926819"). Without it, such
rules fail closed.

    warden mcp-proxy --policy policy.toml --task pay_rent \\
        --trusted "Pay rent of 1200 to GB29NWBK60161331926819" -- python server.py

Requires the `mcp` extra. Nothing in `warden.governance` depends on this.
"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp import Client, StdioServerParameters
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from warden.governance.audit import AuditLog
from warden.governance.drift import DriftViolation
from warden.governance.gate import Gate, GateViolation
from warden.governance.issuer import Supervisor
from warden.governance.policy_loader import Policy, load_policy
from warden.governance.provenance import Provenance
from warden.llm import ToolCall
from warden.pipeline.runner import GatedToolRunner

ROLE = "mcp-client"
Forward = Callable[[str, dict[str, Any]], Awaitable[CallToolResult]]


class WardenMCPProxy:
    """The transport-free core: decides, forwards, records. Testable in-process."""

    def __init__(
        self,
        policy: Policy,
        task: str,
        *,
        trusted: str = "",
        audit: AuditLog | None = None,
        quarantine_on_deny: bool = True,
    ) -> None:
        self.policy = policy
        self.task = task
        self.audit = audit
        self.provenance = Provenance()
        if trusted:
            self.provenance.add_trusted(trusted, "operator")
        supervisor = Supervisor(policy=policy)
        self._gate = Gate(supervisor.verifier)
        self._manifest = supervisor.issue_manifest(ROLE, task)
        self._quarantine_on_deny = quarantine_on_deny
        self._tools: list[Tool] = []
        self.runner: GatedToolRunner | None = None

    def bind_tools(self, upstream_tools: list[Tool]) -> None:
        """Adopt the upstream server's tools (and their schemas)."""
        self._tools = list(upstream_tools)
        self.runner = GatedToolRunner(
            self._gate,
            {ROLE: self._manifest},
            self.audit,
            scopes=self.policy.tools,
            schemas={t.name: t.input_schema for t in self._tools},
            quarantine_on_deny=self._quarantine_on_deny,
            provenance=self.provenance,
        )
        if self.audit:
            self.audit.record(
                "session_start",
                task=self.task,
                upstream_tools=[t.name for t in self._tools],
                granted=sorted({c.tool for c in self._manifest}),
            )

    def visible_tools(self) -> list[Tool]:
        """Only the tools this session may call: the model never sees the rest."""
        granted = {c.tool for c in self._manifest}
        return [t for t in self._tools if t.name in granted]

    async def handle_call(
        self, name: str, arguments: dict[str, Any] | None, forward: Forward
    ) -> CallToolResult:
        if self.runner is None:  # fail closed: no tools bound means no authority
            return _error("Blocked by Warden: proxy has not bound the upstream tools")
        args = dict(arguments or {})
        try:
            self.runner.authorize(ROLE, ToolCall(name=name, arguments=args))
        except (GateViolation, DriftViolation) as violation:
            return _error(f"Blocked by Warden: {violation}")

        result = await forward(name, args)
        self.runner.observe(name, _result_text(result))
        return result

    def close(self) -> None:
        if self.audit:
            quarantined = self.runner is not None and self.runner.quarantined
            self.audit.record("session_end", status="quarantined" if quarantined else "completed")


def build_server(proxy: WardenMCPProxy, forward: Forward) -> Server[Any]:
    """The MCP server the host talks to, backed by `proxy`."""

    async def on_list_tools(ctx: Any, params: Any) -> ListToolsResult:
        return ListToolsResult(tools=proxy.visible_tools())

    async def on_call_tool(ctx: Any, params: Any) -> CallToolResult:
        return await proxy.handle_call(params.name, params.arguments, forward)

    return Server("warden-proxy", on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def list_all_tools(client: Client) -> list[Tool]:
    tools: list[Tool] = []
    cursor: str | None = None
    while True:
        page = await client.list_tools(cursor=cursor)
        tools.extend(page.tools)
        cursor = page.next_cursor
        if not cursor:
            return tools


async def serve(
    policy_path: str,
    task: str,
    upstream: list[str],
    *,
    trusted: str = "",
    audit_dir: str | None = "audit",
) -> None:
    """Run the proxy over stdio in front of the `upstream` command."""
    policy = load_policy(policy_path)
    audit = None
    if audit_dir:
        session_id = f"mcp-{uuid.uuid4().hex[:8]}"
        audit = AuditLog(session_id, path=Path(audit_dir) / f"{session_id}.jsonl")
    proxy = WardenMCPProxy(policy, task, trusted=trusted, audit=audit)

    params = StdioServerParameters(command=upstream[0], args=upstream[1:])
    try:
        async with Client(params) as client:
            proxy.bind_tools(await list_all_tools(client))
            print(
                f"warden mcp-proxy: task={task}, exposing "
                f"{[t.name for t in proxy.visible_tools()]}",
                file=sys.stderr,
            )
            server = build_server(proxy, client.call_tool)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
    finally:
        proxy.close()


def _error(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], is_error=True)


def _result_text(result: CallToolResult) -> str:
    parts = [c.text for c in result.content if isinstance(c, TextContent)]
    if result.structured_content is not None:
        parts.append(json.dumps(result.structured_content, default=str))
    return "\n".join(parts)
