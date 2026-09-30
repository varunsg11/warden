"""Tests for the structural argument validator the gate runs before any bound."""

from __future__ import annotations

import pytest

from warden.governance.schema import validate_args

SCHEMA = {
    "type": "object",
    "properties": {
        "account": {"type": "string"},
        "amount": {"type": "number"},
        "count": {"type": "integer"},
        "urgent": {"type": "boolean"},
    },
    "required": ["account", "amount"],
}


def test_accepts_well_formed_arguments():
    assert validate_args(SCHEMA, {"account": "1234", "amount": 10, "count": 2, "urgent": True})[0]


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({"amount": 10.0}, "missing required"),
        ({"account": "1234", "amount": 10.0, "memo": "x"}, "unexpected argument"),
        ({"account": 1234, "amount": 10.0}, "not a valid string"),
        ({"account": "1234", "amount": "10"}, "not a valid number"),
        ({"account": "1234", "amount": float("nan")}, "not a valid number"),
        ({"account": "1234", "amount": float("inf")}, "not a valid number"),
        ({"account": "1234", "amount": True}, "not a valid number"),
        ({"account": "1234", "amount": 1.0, "count": 1.5}, "not a valid integer"),
        ({"account": "1234", "amount": 1.0, "urgent": 1}, "not a valid boolean"),
    ],
)
def test_rejects_malformed_arguments(args, expected):
    ok, why = validate_args(SCHEMA, args)
    assert not ok
    assert expected in why


def test_rejects_non_object_arguments():
    assert not validate_args(SCHEMA, ["1234", 10.0])[0]


def test_unknown_schema_type_fails_closed():
    assert not validate_args({"properties": {"x": {"type": "date"}}}, {"x": "2026-01-01"})[0]


# --- the richer subset real tool schemas use (pydantic / AgentDojo / MCP) ---- #
# Verbatim from AgentDojo v1.2.2's workspace suite (descriptions stripped).
SEND_EMAIL = {
    "properties": {
        "recipients": {"items": {"type": "string"}, "title": "Recipients", "type": "array"},
        "subject": {"title": "Subject", "type": "string"},
        "body": {"title": "Body", "type": "string"},
        "attachments": {
            "anyOf": [
                {"items": {"additionalProperties": True, "type": "object"}, "type": "array"},
                {"type": "null"},
            ],
            "default": None,
            "title": "Attachments",
        },
        "cc": {"anyOf": [{"items": {"type": "string"}, "type": "array"}, {"type": "null"}]},
    },
    "required": ["recipients", "subject", "body"],
    "title": "Input schema for `send_email`",
    "type": "object",
}
SHARE_FILE = {
    "$defs": {"SharingPermission": {"enum": ["r", "rw"], "type": "string"}},
    "properties": {
        "file_id": {"type": "string"},
        "email": {"type": "string"},
        "permission": {"$ref": "#/$defs/SharingPermission"},
    },
    "required": ["file_id", "email", "permission"],
    "type": "object",
}


def test_real_schemas_accept_legitimate_calls():
    mail = {"recipients": ["a@b.com"], "subject": "s", "body": "b"}
    assert validate_args(SEND_EMAIL, mail)[0]
    assert validate_args(SEND_EMAIL, {**mail, "cc": None, "attachments": [{"type": "file"}]})[0]
    assert validate_args(SHARE_FILE, {"file_id": "1", "email": "a@b.com", "permission": "rw"})[0]


@pytest.mark.parametrize(
    ("schema", "args", "expected"),
    [
        (SEND_EMAIL, {"recipients": "a@b.com", "subject": "s", "body": "b"}, "not a valid array"),
        (
            SEND_EMAIL,
            {"recipients": ["a@b.com", 7], "subject": "s", "body": "b"},
            "'recipients[1]'",
        ),
        (SEND_EMAIL, {"recipients": [], "subject": "s", "body": "b", "cc": "x"}, "none of the"),
        (SEND_EMAIL, {"recipients": [], "subject": "s", "body": "b", "bcc": []}, "unexpected"),
        (SHARE_FILE, {"file_id": "1", "email": "e", "permission": "admin"}, "not one of"),
    ],
)
def test_real_schemas_reject_malformed_calls(schema, args, expected):
    ok, why = validate_args(schema, args)
    assert not ok
    assert expected in why


def test_nested_objects_are_closed_when_properties_are_declared():
    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "object", "properties": {"iban": {"type": "string"}}},
        },
    }
    assert validate_args(schema, {"to": {"iban": "X"}})[0]
    ok, why = validate_args(schema, {"to": {"iban": "X", "memo": "y"}})
    assert not ok
    assert "unexpected argument 'to.memo'" in why


def test_additional_properties_schema_is_enforced():
    schema = {"type": "object", "additionalProperties": {"type": "number"}}
    assert validate_args(schema, {"a": 1.0})[0]
    assert not validate_args(schema, {"a": float("nan")})[0]


def test_unsupported_constraint_keywords_fail_closed():
    """Ignoring `maximum` would silently drop a check -- so it must fail instead."""
    schema = {"type": "object", "properties": {"amount": {"type": "number", "maximum": 50}}}
    ok, why = validate_args(schema, {"amount": 10})
    assert not ok
    assert "unsupported schema keyword" in why


def test_enum_does_not_confuse_bools_and_numbers():
    schema = {"type": "object", "properties": {"n": {"enum": [1, 2]}}}
    assert validate_args(schema, {"n": 1})[0]
    assert not validate_args(schema, {"n": True})[0]


def test_unresolvable_ref_fails_closed():
    schema = {"type": "object", "properties": {"p": {"$ref": "#/$defs/Missing"}}}
    assert not validate_args(schema, {"p": "x"})[0]


def test_absurdly_deep_arguments_fail_cleanly():
    deep: list = []
    for _ in range(5000):
        deep = [deep]
    schema = {"type": "object", "properties": {"x": {}}}
    nested = {"type": "array"}
    for _ in range(5000):
        nested = {"type": "array", "items": nested}
    ok, _ = validate_args({"type": "object", "properties": {"x": nested}}, {"x": deep})
    assert not ok
    assert validate_args(schema, {"x": deep})[0]  # no constraints on x: accepted as-is
