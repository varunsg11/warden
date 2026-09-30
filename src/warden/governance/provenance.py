"""Provenance: where did an argument's value come from?

The gate's envelope asks "is this value allowed?" -- account 5678 is on the
allowlist, so a refund to 5678 passes. But an injection doesn't need to leave the
envelope. It only needs to steer the agent to a DIFFERENT allowed value than the
user meant: refund 5678 when the customer on account 1234 asked. Drift won't
notice either; 5678 is a normal account.

What gives it away is provenance. The user's request named 1234. The value 5678
appears only in a retrieved document -- attacker-influenceable data. So a policy
can require that a sensitive argument come from TRUSTED text:

    params.account = { allow = ["1234", "5678"], from = "trusted" }

The session records every piece of text it handles and where it came from:
  * trusted   -- the user's request, the application's own records
  * untrusted -- every tool output (documents, emails, web pages, ...)

and `origin(value)` answers "trusted" if the value appears in trusted text,
"untrusted" if it appears only in untrusted text, "unknown" if nowhere (the
model made it up). Only "trusted" satisfies a `from = "trusted"` rule.

This is a deterministic approximation of taint tracking (cf. CaMeL, FIDES): it
matches values textually rather than tracking data flow through the model. It
works for the values that matter most -- identifiers like accounts, IBANs, email
addresses, URLs -- which a model copies verbatim. Its cost is utility: a task
that legitimately takes a recipient from a document (e.g. "pay the bill in
bill.txt") is denied too. That trade-off is measured, not hidden.

No LLM, pure Python.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Literal

Origin = Literal["trusted", "untrusted", "unknown"]


@dataclass
class Provenance:
    _trusted: list[tuple[str, str]] = field(default_factory=list)
    _untrusted: list[tuple[str, str]] = field(default_factory=list)

    def add_trusted(self, text: str, source: str) -> None:
        self._trusted.append((_fold(text), source))

    def add_untrusted(self, text: str, source: str) -> None:
        self._untrusted.append((_fold(text), source))

    def origin(self, value: Any) -> Origin:
        """Where `value` came from. A list is trusted only if every item is."""
        if isinstance(value, list):
            origins = [self.origin(v) for v in value]
            if origins and all(o == "trusted" for o in origins):
                return "trusted"
            return "untrusted" if "untrusted" in origins else "unknown"
        forms = _forms(value)
        if not forms:
            return "unknown"
        if any(_occurs(f, text) for f in forms for text, _ in self._trusted):
            return "trusted"
        if any(_occurs(f, text) for f in forms for text, _ in self._untrusted):
            return "untrusted"
        return "unknown"

    def untrusted_sources(self, value: Any) -> list[str]:
        """Which untrusted sources mention `value` (for deny messages)."""
        items = value if isinstance(value, list) else [value]
        found: list[str] = []
        for item in items:
            for form in _forms(item):
                for text, source in self._untrusted:
                    if _occurs(form, text) and source not in found:
                        found.append(source)
        return found


def _fold(text: str) -> str:
    return " ".join(str(text).casefold().split())


def _forms(value: Any) -> list[str]:
    """The textual forms a value may take. Numbers match as written in prose
    (20, 20.0, 20.00); non-finite numbers and empty strings have no valid form."""
    if isinstance(value, bool) or value is None:
        return []
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            return []
        forms = {repr(value), f"{value:.2f}"}
        if float(value).is_integer():
            forms.add(str(int(value)))
        return sorted(forms)
    if isinstance(value, str):
        folded = _fold(value)
        return [folded] if folded else []
    return []


def _occurs(needle: str, haystack: str) -> bool:
    """Whole-token occurrence: '12' does not occur in '1234', and 'a@b.co' does
    not occur in 'a@b.com'. Alphanumerics on either side break the match."""
    pattern = r"(?<![0-9a-z])" + re.escape(needle) + r"(?![0-9a-z])"
    return re.search(pattern, haystack) is not None
