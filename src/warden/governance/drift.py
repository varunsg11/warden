"""The drift detector — Warden's second line of defense.

The gate catches calls that are OUT OF BOUNDS (no capability, over the cap, wrong
account). Drift catches calls that are IN BOUNDS BUT ABNORMAL: a call the policy
permits, yet nothing like anything the business normally does.

Drift earns its keep exactly where the gate CAN'T help. You can allowlist the
handful of accounts a refund may go to -- but you cannot allowlist every email
address a support agent may legitimately reply to. So send_email must be broadly
permitted, and the only signal that "reply to steal@evil.com" is wrong is that
its DOMAIN has never been seen before. That's drift's job.

DESIGN CHOICES worth defending in an interview:
  * NO LLM. An "LLM-as-judge" would be injectable by the same prompt injection we
    defend against. Drift is pure statistics + rules over the tool-call stream.
  * The baseline is learned from CLEAN traffic offline and is NOT updated from
    live calls -- otherwise an attacker "boils the frog," drifting the norm until
    the abnormal looks normal.

Two simple, explainable signals:
  * novel categorical value -- a destination (account, or email DOMAIN) unseen.
  * numeric outlier -- a value many standard deviations from the baseline mean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Any

# tool -> what to watch. numeric maps field -> z-score threshold.
FEATURE_SPEC: dict[str, dict[str, Any]] = {
    "issue_refund": {"categorical": ["account"], "numeric": {"amount": 3.0}},
    "send_email": {"categorical": ["to_domain"], "numeric": {}},
}


def _derive(tool: str, args: dict) -> dict:
    """Add derived features. For email we watch the DOMAIN, not the full address,
    so a new legitimate customer at a known provider isn't flagged."""
    if tool == "send_email":
        to = args.get("to", "")
        if isinstance(to, str) and "@" in to:
            return {**args, "to_domain": to.rsplit("@", 1)[-1].lower()}
    return dict(args)


@dataclass
class DriftResult:
    is_drift: bool
    reasons: list[str] = field(default_factory=list)
    score: float = 0.0


class DriftViolation(Exception):
    """Raised when a proposed call is in-bounds but anomalous."""

    def __init__(self, result: DriftResult) -> None:
        self.result = result
        super().__init__("; ".join(result.reasons) or "drift detected")


class DriftDetector:
    def __init__(self, spec: dict | None = None, min_samples: int = 3) -> None:
        self.spec = spec if spec is not None else FEATURE_SPEC
        self.min_samples = min_samples
        self._categorical: dict[str, dict[str, set]] = {}
        self._numeric: dict[str, dict[str, list[float]]] = {}

    # --- learning the baseline (offline, from CLEAN traffic only) ---------- #
    def fit(self, calls: list[tuple[str, dict]]) -> DriftDetector:
        for tool, args in calls:
            self._observe(tool, args)
        return self

    def _observe(self, tool: str, args: dict) -> None:
        spec = self.spec.get(tool)
        if not spec:
            return
        feats = _derive(tool, args)
        for f in spec.get("categorical", []):
            if f in feats:
                self._categorical.setdefault(tool, {}).setdefault(f, set()).add(feats[f])
        for f in spec.get("numeric", {}):
            if feats.get(f) is not None:
                self._numeric.setdefault(tool, {}).setdefault(f, []).append(float(feats[f]))

    # --- runtime check (does NOT learn from what it sees) ------------------ #
    def check(self, tool: str, args: dict) -> DriftResult:
        spec = self.spec.get(tool)
        if not spec:
            return DriftResult(False)

        feats = _derive(tool, args)
        reasons: list[str] = []
        score = 0.0

        for f in spec.get("categorical", []):
            seen = self._categorical.get(tool, {}).get(f, set())
            if seen and f in feats and feats[f] not in seen:
                reasons.append(
                    f"novel {f}={feats[f]!r} (never seen in {len(seen)} baseline values)"
                )
                score = max(score, 1.0)

        for f, z_threshold in spec.get("numeric", {}).items():
            values = self._numeric.get(tool, {}).get(f, [])
            if feats.get(f) is None or len(values) < self.min_samples:
                continue
            mu = mean(values)
            sd = pstdev(values)
            value = float(feats[f])
            if sd == 0:
                if value != mu:
                    reasons.append(f"{f}={value} differs from constant baseline {mu}")
                    score = max(score, 1.0)
            else:
                z = abs(value - mu) / sd
                if z > z_threshold:
                    reasons.append(f"{f}={value} is {z:.1f} std devs from baseline mean {mu:.2f}")
                    score = max(score, z / z_threshold)

        return DriftResult(bool(reasons), reasons, score)
