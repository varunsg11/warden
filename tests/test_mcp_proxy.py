"""Tests for the MCP gateway, fully in-process: the toy bank server is the upstream,
the proxy sits in front of it, and a real MCP client plays the host.

Skipped unless the optional `mcp` extra is installed.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402
from mcp import Client  # noqa: E402

from warden.governance.audit import AuditLog  # noqa: E402
from warden.governance.policy_loader import load_policy  # noqa: E402
from warden.integrations.mcp_proxy import (  # noqa: E402
    WardenMCPProxy,
    build_server,
    list_all_tools,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "mcp_bank"
POLICY = load_policy(EXAMPLE / "policy.toml")
TRUSTED = "Pay this month's rent of 1200 to my landlord GB29NWBK60161331926819"


def _bank():
    spec = importlib.util.spec_from_file_location("toy_bank", EXAMPLE / "server.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(scenario, *, task="pay_rent", trusted=TRUSTED, audit=None):
    """Wire upstream -> proxy -> host in memory and run `scenario(host, proxy, bank)`."""
    bank = _bank()

    async def main():
        proxy = WardenMCPProxy(POLICY, task, trusted=trusted, audit=audit)
        async with Client(bank.mcp) as upstream:
            proxy.bind_tools(await list_all_tools(upstream))
            async with Client(build_server(proxy, upstream.call_tool)) as host:
                await scenario(host, proxy, bank)
        proxy.close()

    anyio.run(main)
    return bank


def _text(result) -> str:
    return "\n".join(c.text for c in result.content if hasattr(c, "text"))


def test_host_only_sees_granted_tools():
    seen = {}

    async def scenario(host, proxy, bank):
        seen["view"] = {t.name for t in (await host.list_tools()).tools}

    _run(scenario, task="view")
    assert seen["view"] == {"read_statement", "get_balance"}  # no send_money, no close_account


def test_injected_payment_is_blocked_and_the_real_one_goes_through():
    results = {}

    async def scenario(host, proxy, bank):
        results["statement"] = await host.call_tool("read_statement", {})
        results["attack"] = await host.call_tool(
            "send_money", {"recipient": bank.ATTACKER, "amount": 1200.0}
        )

    bank = _run(scenario)
    assert not results["statement"].is_error
    assert results["attack"].is_error
    assert "Blocked by Warden" in _text(results["attack"])
    assert "untrusted provenance" in _text(results["attack"])
    assert bank.SENT == []  # the upstream never saw the call


def test_legitimate_payment_to_the_trusted_recipient_is_forwarded():
    results = {}

    async def scenario(host, proxy, bank):
        await host.call_tool("read_statement", {})
        results["pay"] = await host.call_tool(
            "send_money", {"recipient": bank.LANDLORD, "amount": 1200.0}
        )

    bank = _run(scenario)
    assert not results["pay"].is_error
    assert bank.SENT == [{"recipient": bank.LANDLORD, "amount": 1200.0}]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"recipient": "GB29NWBK60161331926819", "amount": "lots"}, "malformed arguments"),
        ({"recipient": "GB29NWBK60161331926819", "amount": 9000.0}, "exceeds max"),
    ],
)
def test_upstream_schema_and_policy_bounds_are_enforced(args, expected):
    results = {}

    async def scenario(host, proxy, bank):
        results["r"] = await host.call_tool("send_money", args)

    bank = _run(scenario)
    assert results["r"].is_error
    assert expected in _text(results["r"])
    assert bank.SENT == []


def test_a_denial_quarantines_the_proxy_session(tmp_path):
    results = {}
    audit = AuditLog("mcp-test", path=tmp_path / "mcp.jsonl")

    async def scenario(host, proxy, bank):
        await host.call_tool("send_money", {"recipient": bank.ATTACKER, "amount": 5.0})
        results["after"] = await host.call_tool("get_balance", {})

    _run(scenario, audit=audit)
    assert results["after"].is_error
    assert "quarantined" in _text(results["after"])
    ok, detail = AuditLog.verify_file(tmp_path / "mcp.jsonl")
    assert ok, detail


def test_provenance_rules_fail_closed_without_trusted_input():
    results = {}

    async def scenario(host, proxy, bank):
        results["pay"] = await host.call_tool(
            "send_money", {"recipient": bank.LANDLORD, "amount": 1200.0}
        )

    _run(scenario, trusted="")
    assert results["pay"].is_error
