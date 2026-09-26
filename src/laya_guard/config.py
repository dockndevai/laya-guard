"""Configuration for the laya-guard daemon.

laya-guard is a **local** risk assessor for high-risk commands. A suite MCP server, when it is about to
run a dangerous operation in a permissive mode, asks the daemon "how risky is this?" and gets back
allow / confirm / block with a reason — computed by deterministic pattern rules first, then the local
laya decision model for the gray zone. Nothing leaves the machine.

Design invariant: the guard only ever *tightens*. It can add a confirm/block; it can never grant a
permission the calling server's own deterministic gates denied. When in doubt it fails closed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        v = os.environ.get(name)
        return int(v) if v not in (None, "") else default
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        v = os.environ.get(name)
        return float(v) if v not in (None, "") else default
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    host: str = "127.0.0.1"
    port: int = 8799
    allow_remote: bool = False
    policy_path: str | None = None
    model: str = "auto"  # auto | english | multilingual | typed-decisions
    device: str = "auto"
    allow_download: bool = False
    min_confidence: float = 0.55
    fail_closed: bool = True
    audit_log: bool = True
    max_input_chars: int = 8000


def load_config() -> Config:
    host = (os.environ.get("LAYA_GUARD_HOST") or "127.0.0.1").strip()
    allow_remote = _bool("LAYA_GUARD_ALLOW_REMOTE", False)
    if host not in LOOPBACK and not allow_remote:
        raise ValueError(
            f"LAYA_GUARD_HOST '{host}' is not loopback. The guard makes allow/block decisions for "
            "dangerous commands; exposing it off-host is unsafe. Set LAYA_GUARD_ALLOW_REMOTE=true only "
            "if you fully control the network."
        )
    return Config(
        host=host,
        port=max(1, min(65535, _int("LAYA_GUARD_PORT", 8799))),
        allow_remote=allow_remote,
        policy_path=(os.environ.get("LAYA_GUARD_POLICY") or None),
        model=(os.environ.get("LAYA_GUARD_MODEL") or "auto").strip().lower(),
        device=(os.environ.get("LAYA_GUARD_DEVICE") or "auto").strip().lower(),
        allow_download=_bool("LAYA_GUARD_ALLOW_DOWNLOAD", False),
        min_confidence=min(1.0, max(0.0, _float("LAYA_GUARD_MIN_CONFIDENCE", 0.55))),
        fail_closed=_bool("LAYA_GUARD_FAIL_CLOSED", True),
        audit_log=_bool("LAYA_GUARD_AUDIT_LOG", True),
        max_input_chars=max(256, _int("LAYA_GUARD_MAX_INPUT_CHARS", 8000)),
    )
