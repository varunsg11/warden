"""Structural validation of a proposed call's arguments — before any policy check.

A model's tool call is untrusted data. Before the gate asks "is this call inside
the granted envelope?", it must ask "is this call even well-formed?" Otherwise the
envelope checks can be dodged by values they were never written to handle: a NaN
compares False against every bound, a bool is an int, a string reaches `float()`.

This validates against the small JSON-Schema subset the tool specs use (object,
properties, required, primitive types). Anything unexpected is rejected: unknown
keys, missing keys, wrong types, non-finite numbers. Pure Python, no LLM.
"""

from __future__ import annotations

import math
from typing import Any


def _type_ok(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected in ("number", "integer"):
        # bool is a subclass of int; True must not pass as a refund of $1.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if not math.isfinite(value):
            return False
        return expected == "number" or float(value).is_integer()
    return False  # unknown type in the schema: fail closed


def validate_args(schema: dict[str, Any], arguments: Any) -> tuple[bool, str]:
    """Return (ok, reason). `reason` is empty when ok."""
    if not isinstance(arguments, dict):
        return False, f"arguments must be an object, got {type(arguments).__name__}"

    properties: dict[str, Any] = schema.get("properties", {})
    for name in schema.get("required", []):
        if name not in arguments:
            return False, f"missing required argument '{name}'"

    for name, value in arguments.items():
        if name not in properties:
            return False, f"unexpected argument '{name}'"
        expected = properties[name].get("type")
        if expected is not None and not _type_ok(expected, value):
            return False, f"argument '{name}'={value!r} is not a valid {expected}"

    return True, ""
