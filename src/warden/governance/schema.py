"""Structural validation of a proposed call's arguments — before any policy check.

A model's tool call is untrusted data. Before the gate asks "is this call inside
the granted envelope?", it must ask "is this call even well-formed?" Otherwise the
envelope checks can be dodged by values they were never written to handle: a NaN
compares False against every bound, a bool is an int, a string reaches `float()`.

This validates against the JSON-Schema subset that tool specs actually use —
including the schemas pydantic generates for AgentDojo and MCP tools:
type (incl. null and unions), properties / required / additionalProperties,
items, anyOf / oneOf, enum / const, and local $ref into $defs.

It fails CLOSED: a constraint keyword it doesn't implement (pattern, minimum, ...)
makes validation fail rather than being ignored, because an ignored constraint is
a silently missing check. At the top level, unexpected arguments are rejected
unless the schema explicitly allows extra properties. Pure Python, no LLM.
"""

from __future__ import annotations

import math
from typing import Any

# Keywords that only annotate; they never constrain a value.
_ANNOTATIONS = frozenset(
    {"title", "description", "default", "examples", "$defs", "definitions", "$schema"}
)
_SUPPORTED = _ANNOTATIONS | frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "anyOf",
        "oneOf",
        "enum",
        "const",
        "$ref",
    }
)


def validate_args(schema: dict[str, Any], arguments: Any) -> tuple[bool, str]:
    """Return (ok, reason). `reason` is empty when ok."""
    if not isinstance(arguments, dict):
        return False, f"arguments must be an object, got {type(arguments).__name__}"
    try:
        error = _validate(schema, arguments, "", schema)
    except RecursionError:
        error = "arguments are nested too deeply"
    return not error, error


def _validate(s: Any, value: Any, path: str, root: dict[str, Any]) -> str:
    """Return "" if `value` satisfies schema `s`, else the first problem found."""
    if not isinstance(s, dict):
        return f"{_label(path)}: invalid schema"
    unsupported = set(s) - _SUPPORTED
    if unsupported:
        return f"{_label(path)}: unsupported schema keyword(s) {sorted(unsupported)}"

    if "$ref" in s:
        target = _resolve(s["$ref"], root)
        if target is None:
            return f"{_label(path)}: unresolvable $ref {s['$ref']!r}"
        error = _validate(target, value, path, root)
        if error:
            return error

    for key in ("anyOf", "oneOf"):
        if key in s:
            branches = s[key] if isinstance(s[key], list) else []
            if not any(not _validate(b, value, path, root) for b in branches):
                return f"{_label(path)}={value!r} matches none of the allowed forms"

    if "enum" in s and not any(_same(value, e) for e in s["enum"]):
        return f"{_label(path)}={value!r} not one of {s['enum']}"
    if "const" in s and not _same(value, s["const"]):
        return f"{_label(path)}={value!r} must be {s['const']!r}"

    if "type" in s:
        types = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if not any(_type_ok(t, value) for t in types):
            return f"{_label(path)}={value!r} is not a valid {'/'.join(map(str, types))}"

    if isinstance(value, list) and "items" in s:
        for i, item in enumerate(value):
            error = _validate(s["items"], item, f"{path}[{i}]", root)
            if error:
                return error

    if isinstance(value, dict) and ({"properties", "required", "additionalProperties"} & set(s)):
        return _validate_object(s, value, path, root)
    return ""


def _validate_object(s: dict[str, Any], value: dict[str, Any], path: str, root: dict) -> str:
    props: dict[str, Any] = s.get("properties", {})
    for name in s.get("required", []):
        if name not in value:
            return f"missing required argument '{_join(path, name)}'"
    # Declared properties make the object closed unless extras are allowed explicitly.
    extra = s.get("additionalProperties", not props)
    for name, item in value.items():
        child = _join(path, name)
        if name in props:
            error = _validate(props[name], item, child, root)
        elif extra is True:
            error = ""
        elif isinstance(extra, dict):
            error = _validate(extra, item, child, root)
        else:
            error = f"unexpected argument '{child}'"
        if error:
            return error
    return ""


def _type_ok(expected: str, value: Any) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected in ("number", "integer"):
        # bool is a subclass of int; True must not pass as a refund of $1.
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if not math.isfinite(value):
            return False
        return expected == "number" or float(value).is_integer()
    return False  # unknown type in the schema: fail closed


def _same(a: Any, b: Any) -> bool:
    """Equality that doesn't let True stand in for 1 (or 1.0 for True)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    return bool(a == b)


def _resolve(ref: Any, root: dict[str, Any]) -> Any:
    """Resolve a local '#/$defs/Name' (or '#/definitions/Name') reference."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: Any = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _join(path: str, name: str) -> str:
    return f"{path}.{name}" if path else name


def _label(path: str) -> str:
    return f"argument '{path}'" if path else "arguments"
