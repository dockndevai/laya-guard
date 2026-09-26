"""Decision policy — pure logic, no I/O, no torch. Fully unit-testable.

Two layers, in order:
  1. Deterministic pattern rules (regex) — always applied first. A block pattern blocks outright; a
     confirm pattern raises the floor to at least "confirm". These encode the classic catastrophic
     commands so the guard is useful even with no model loaded.
  2. The laya risk signals — for the gray zone the patterns don't cover.

The guard only ever *tightens*: it can raise a decision (allow -> confirm -> block), never lower one
the caller already made. Unknown + no model = fail closed (confirm).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

RISK_ORDER = ["none", "low", "medium", "high", "critical"]
DECISION_SEVERITY = {"allow": 0, "confirm": 1, "block": 2}


def _ri(level: str) -> int:
    return RISK_ORDER.index(level) if level in RISK_ORDER else 0


# Classic catastrophic commands — case-insensitive. Conservative but high-precision.
DEFAULT_BLOCK_PATTERNS = [
    r"rm\s+-[a-z]*[rf][a-z]*\s+(-[a-z]+\s+)*(/|~|\*|\$HOME)(\s|$)",
    r"\bmkfs(\.\w+)?\b",
    r"\bdd\b.*\bof=/dev/",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # fork bomb
    r"(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b",
    r"\bchmod\s+-R\s+0*777\s+/",
    r">\s*/dev/(sda|disk\d|nvme\d)",
    r"\bdiskutil\s+(erasedisk|erasevolume|reformat|zerodisk)\b",
    r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
    r"\bTRUNCATE\s+TABLE\b",
    r"\bkubectl\s+delete\s+(ns|namespace|--all)\b",
    r"\b(shutdown|reboot|halt|poweroff)\b",
]

DEFAULT_CONFIRM_PATTERNS = [
    r"\bsudo\b",
    r"\brm\s+-[a-z]*[rf]",
    r"\bgit\s+push\b.*(--force\b|--force-with-lease|-f\b)",
    r"\b(npm\s+publish|twine\s+upload|pip\s+.*upload)\b",
    r"\bdocker\s+(rm|rmi|system\s+prune|volume\s+rm)\b",
    r"\bkubectl\s+(delete|apply)\b",
    r"\bkill(all)?\b",
    r"\bmv\b[^|]*\s/(etc|usr|bin|sbin|System|Library|boot)\b",
]

DEFAULT_ALLOW_PATTERNS = [
    r"^\s*(ls|pwd|whoami|id|date|echo|cat|head|tail|grep|find|which|type|env|printenv|ps|df|du|uname|hostname|uptime|wc|sort|uniq)\b",
    r"^\s*git\s+(status|log|diff|show|branch|remote|config\s+--get)\b",
]


@dataclass
class Policy:
    block_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_BLOCK_PATTERNS))
    confirm_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_CONFIRM_PATTERNS))
    allow_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOW_PATTERNS))
    confirm_threshold: str = "medium"
    block_threshold: str = "critical"
    block_pattern_action: str = "block"  # "block" | "confirm"

    def compiled(self) -> CompiledPolicy:
        return CompiledPolicy(
            block=[re.compile(p, re.IGNORECASE) for p in self.block_patterns],
            confirm=[re.compile(p, re.IGNORECASE) for p in self.confirm_patterns],
            allow=[re.compile(p, re.IGNORECASE) for p in self.allow_patterns],
            confirm_threshold=self.confirm_threshold,
            block_threshold=self.block_threshold,
            block_pattern_action=self.block_pattern_action,
        )


@dataclass
class CompiledPolicy:
    block: list[re.Pattern]
    confirm: list[re.Pattern]
    allow: list[re.Pattern]
    confirm_threshold: str
    block_threshold: str
    block_pattern_action: str


@dataclass
class Decision:
    decision: str  # allow | confirm | block
    risk: str  # none | low | medium | high | critical
    confidence: float
    reasons: list[str]
    deterministic: bool
    signals: dict[str, Any]


def policy_from_dict(data: dict[str, Any]) -> Policy:
    p = Policy()
    if "block_patterns" in data:
        p.block_patterns = list(data["block_patterns"])
    if "confirm_patterns" in data:
        p.confirm_patterns = list(data["confirm_patterns"])
    if "allow_patterns" in data:
        p.allow_patterns = list(data["allow_patterns"])
    for key in ("confirm_threshold", "block_threshold"):
        if key in data:
            if data[key] not in RISK_ORDER:
                raise ValueError(f"{key} must be one of {RISK_ORDER}, got {data[key]!r}")
            setattr(p, key, data[key])
    if data.get("block_pattern_action") in ("block", "confirm"):
        p.block_pattern_action = data["block_pattern_action"]
    return p


def _first_match(text: str, patterns: list[re.Pattern]) -> str | None:
    for pat in patterns:
        if pat.search(text):
            return pat.pattern
    return None


def risk_from_signals(signals: dict[str, Any]) -> tuple[int, list[str], float]:
    """Map laya answers to a risk level index, reasons, and the weakest-link confidence."""
    score = 0
    reasons: list[str] = []
    confs: list[float] = []
    for key, weight in (("destructive", 2), ("exfiltration", 2), ("privilege", 2)):
        a = signals.get(key)
        if isinstance(a, dict) and "noul" in a:
            p = float(a["noul"])
            confs.append(max(p, 1.0 - p))
            if p >= 0.5:
                score += weight
                reasons.append(f"{key} (p={p:.2f})")
    scope = signals.get("scope")
    if isinstance(scope, dict) and "score" in scope:
        sc = round(float(scope["score"]))
        score += max(0, min(2, sc))
        if sc >= 1:
            reasons.append(f"scope={sc}")
    level_idx = 4 if score >= 4 else score  # >=4 critical; 3 high; 2 medium; 1 low; 0 none
    # Confidence comes from the yes/no risk signals (the calibrated ones); laya's ordinal `scope`
    # score is advisory only — its confidence is not reliable, so it is excluded here.
    confidence = min(confs) if confs else 0.0
    return level_idx, reasons, confidence


def assess(
    text: str,
    signals: dict[str, Any] | None,
    policy: CompiledPolicy,
    *,
    min_confidence: float,
    fail_closed: bool,
) -> Decision:
    reasons: list[str] = []

    blocked = _first_match(text, policy.block)
    if blocked:
        return Decision(
            policy.block_pattern_action,
            "critical",
            1.0,
            [f"matched block pattern: {blocked}"],
            True,
            signals or {},
        )

    confirmed = _first_match(text, policy.confirm)
    allowed = _first_match(text, policy.allow)

    decision, risk, confidence = "allow", "none", 1.0

    if signals:
        lvl, mreasons, mconf = risk_from_signals(signals)
        reasons += mreasons
        risk, confidence = RISK_ORDER[lvl], mconf
        if lvl >= _ri(policy.block_threshold):
            decision = "block"
        elif lvl >= _ri(policy.confirm_threshold):
            decision = "confirm"
        if decision == "allow" and mconf < min_confidence:
            decision, reasons = "confirm", [*reasons, f"low confidence {mconf:.2f} < {min_confidence:.2f}"]
    elif allowed and not confirmed:
        return Decision("allow", "low", 1.0, [f"matched allow pattern: {allowed}"], True, {})
    elif fail_closed:
        decision, risk, confidence = "confirm", "medium", 0.0
        reasons.append("no model assessment available; failing closed")
    else:
        reasons.append("no model assessment; fail-open configured")

    if confirmed and DECISION_SEVERITY[decision] < DECISION_SEVERITY["confirm"]:
        decision = "confirm"
        if risk == "none":
            risk = "medium"
        reasons.append(f"matched confirm pattern: {confirmed}")

    return Decision(decision, risk, confidence, reasons, bool(confirmed), signals or {})
