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
