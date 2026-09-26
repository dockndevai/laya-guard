"""laya-backed risk scoring for a command/event.

Lazy-imports laya (torch) so the daemon starts and the deterministic layer works even if the model
isn't present. Returns laya's raw per-question answers, which policy.py turns into a risk level.
"""
from __future__ import annotations

import os
from typing import Any

from .config import Config

# Typed yes/no + scope questions that define "risk" for a shell command or tool action.
RISK_QUESTIONS: dict[str, dict[str, Any]] = {
    "destructive": {
        "type": "noul",
        "instructions": "Does this command or action irreversibly delete, destroy, overwrite, "
        "format, or corrupt data, files, databases, or systems?",
    },
    "exfiltration": {
        "type": "noul",
        "instructions": "Does this send data to an external network destination, upload, publish, "
        "or otherwise exfiltrate information off this machine?",
    },
    "privilege": {
        "type": "noul",
        "instructions": "Does this escalate privileges (sudo/root) or change system, security, "
        "authentication, or firewall settings?",
    },
    "scope": {
        "type": "score",
        "instructions": "How large is the blast radius if this goes wrong?",
        "criteria": [
            "a single file or a harmless, easily reversible action",
            "the user's data, app state, or a single service",
            "the whole machine, production infrastructure, or many systems",
        ],
    },
}


class GuardEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._router: Any = None
        self._unavailable_reason: str | None = None

    def _get_router(self) -> Any:
        if self._router is not None:
            return self._router
        if not self.config.allow_download:
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        import laya

        device = None if self.config.device == "auto" else self.config.device
        self._router = laya.Router(device=device, preload=False)
        return self._router

    def warmup(self) -> bool:
        try:
            self._get_router()
            return True
        except Exception as e:  # model missing / offline / no torch
            self._unavailable_reason = str(e)
            return False

    @property
    def available(self) -> bool:
        return self._router is not None or self.warmup()

    def assess(self, text: str) -> dict[str, Any] | None:
        """Return laya's per-question answers, or None if the model can't run (caller fails closed)."""
        try:
            router = self._get_router()
        except Exception as e:
            self._unavailable_reason = str(e)
            return None
        model = None if self.config.model == "auto" else self.config.model
        try:
            result = router.predict(text, RISK_QUESTIONS, model=model)
        except Exception as e:
            self._unavailable_reason = str(e)
            return None
        return result.get("answers", {})
