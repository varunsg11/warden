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
            **fields,
            "prev_hash": self._prev,
        }
        rec["hash"] = self._digest(rec)
        self.records.append(rec)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        self._prev = rec["hash"]
        return rec

    @staticmethod
    def _digest(rec: dict[str, Any]) -> str:
        body = {k: v for k, v in rec.items() if k != "hash"}
        material = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def verify_chain(self) -> bool:
        """Return True iff no record has been altered, inserted, or removed."""
        prev = GENESIS
        for rec in self.records:
            if rec.get("prev_hash") != prev:
                return False
            if self._digest(rec) != rec.get("hash"):
                return False
            prev = rec["hash"]
        return True
