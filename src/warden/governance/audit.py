"""The audit log — Warden's evidentiary trail.

Every governance-relevant event is appended here as one JSON line: which manifest
was issued, what each agent proposed, how the gate ruled, and any quarantine.

WHY A HASH CHAIN?
-----------------
In a regulated setting the audit log isn't a nicety, it's evidence — so it must
be tamper-EVIDENT. Each record carries the hash of the record before it (like a
tiny blockchain). Change or delete any past line and every hash downstream stops
matching, so `verify_chain()` returns False. You can't quietly rewrite history.

There is deliberately no LLM anywhere near this. It records facts; it doesn't
reason about them.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, session_id: str, path: str | Path | None = None) -> None:
        self.session_id = session_id
        self.records: list[dict[str, Any]] = []
        self._prev = GENESIS
        self.path = Path(path) if path else Path("audit") / f"{session_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate any prior file for this session id, then append line by line.
        self.path.write_text("", encoding="utf-8")

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "seq": len(self.records),
            "ts": datetime.now(UTC).isoformat(),
            "session_id": self.session_id,
            "event": event,
            **_jsonable(fields),
            "prev_hash": self._prev,
        }
        rec["hash"] = self._digest(rec)
        self.records.append(rec)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, allow_nan=False) + "\n")
        self._prev = rec["hash"]
        return rec

    @staticmethod
    def _digest(rec: dict[str, Any]) -> str:
        body = {k: v for k, v in rec.items() if k != "hash"}
        material = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @classmethod
    def _chain_error(cls, records: list[dict[str, Any]]) -> str:
        """Empty string if the chain is intact, else a description of the first break."""
        prev = GENESIS
        for i, rec in enumerate(records):
            if rec.get("prev_hash") != prev:
                return f"record {i}: prev_hash does not match (record inserted or removed)"
            if cls._digest(rec) != rec.get("hash"):
                return f"record {i}: hash mismatch (record altered)"
            prev = rec["hash"]
        return ""

    def verify_chain(self) -> bool:
        """Return True iff no record has been altered, inserted, or removed."""
        return not self._chain_error(self.records)

    @classmethod
    def verify_file(cls, path: str | Path) -> tuple[bool, str]:
        """Verify an audit file on disk. Returns (ok, detail).

        Besides the hash chain, the log must end in a `session_end` record: the
        chain alone can't tell a complete log from one whose tail was cut off.
        """
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
            records = [json.loads(line) for line in lines if line.strip()]
        except (OSError, ValueError) as exc:
            return False, f"unreadable: {exc}"
        if not records:
            return False, "empty log"
        error = cls._chain_error(records)
        if error:
            return False, error
        if records[-1].get("event") != "session_end":
            return False, "no terminal session_end record (log truncated or session still open)"
        return True, f"{len(records)} records, chain intact, session closed"


def _jsonable(value: Any) -> Any:
    """Make a value strict-JSON safe: NaN/inf (e.g. from a malicious tool call)
    are recorded as strings rather than emitting non-standard JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return repr(value)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    return value
