"""The laya-guard daemon: a tiny local HTTP service that scores high-risk commands.

POST /evaluate  {"tool": "...", "command": "...", "context": "..."}  ->
    {"decision": "allow|confirm|block", "risk": "...", "confidence": 0.0, "reasons": [...],
     "deterministic": bool, "model_available": bool}
GET  /health    -> {"status": "ok", "model_available": bool, "policy": {...}}

Stdlib only. Binds loopback by default. The daemon returns an assessment; the *calling server* decides
what monitor vs enforce does with it (see the clients). The guard only tightens; it never grants.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .config import Config, load_config
from .engine import GuardEngine
from .policy import CompiledPolicy, Policy, _first_match, assess, policy_from_dict


def load_policy(config: Config) -> Policy:
    if not config.policy_path:
        return Policy()
    with open(config.policy_path, encoding="utf-8") as f:
        return policy_from_dict(json.load(f))


class GuardState:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.policy: CompiledPolicy = load_policy(config).compiled()
        self.engine = GuardEngine(config)

    def evaluate(self, tool: str, command: str, context: str | None) -> dict[str, Any]:
        command = (command or "")[: self.config.max_input_chars]
        model_text = command
        if context:
            model_text = f"{command}\n\nContext: {context[: self.config.max_input_chars]}"

        # Only invoke the model for the gray zone: not a hard block, not a fast-allow.
        signals = None
        called_model = False
        if _first_match(command, self.policy.block):
            pass  # deterministic block; no model needed
        elif _first_match(command, self.policy.allow) and not _first_match(command, self.policy.confirm):
            pass  # fast allow
        else:
            signals = self.engine.assess(model_text)
            called_model = signals is not None

        d = assess(
            command,
            signals,
            self.policy,
            min_confidence=self.config.min_confidence,
            fail_closed=self.config.fail_closed,
        )
        out = {
            "decision": d.decision,
            "risk": d.risk,
            "confidence": round(d.confidence, 4),
            "reasons": d.reasons,
            "deterministic": d.deterministic,
            "model_available": called_model,
            "tool": tool,
        }
        if self.config.audit_log:
            sys.stderr.write(
                json.dumps(
                    {
                        "audit": "laya-guard",
                        "tool": tool,
                        "decision": d.decision,
                        "risk": d.risk,
                        "deterministic": d.deterministic,
                        "model": called_model,
                        "command": command[:200],
                        "reasons": d.reasons,
                    }
                )
                + "\n"
            )
        return out


def make_handler(state: GuardState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence default access logging
            return

        def _send(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path.rstrip("/") == "/health":
                self._send(
                    200,
                    {
                        "status": "ok",
                        "model_available": state.engine.available,
                        "policy": {
                            "block_patterns": len(state.policy.block),
                            "confirm_patterns": len(state.policy.confirm),
                            "allow_patterns": len(state.policy.allow),
                            "confirm_threshold": state.policy.confirm_threshold,
                            "block_threshold": state.policy.block_threshold,
                        },
                    },
                )
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path.rstrip("/") != "/evaluate":
                self._send(404, {"error": "not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, {"error": "invalid JSON body"})
                return
            command = data.get("command")
            if not isinstance(command, str) or not command.strip():
                self._send(400, {"error": "'command' (non-empty string) is required"})
                return
            result = state.evaluate(
                tool=str(data.get("tool", "")),
                command=command,
                context=data.get("context") if isinstance(data.get("context"), str) else None,
            )
            self._send(200, result)

    return Handler


def serve(config: Config | None = None) -> None:
    config = config or load_config()
    state = GuardState(config)
    ok = state.engine.warmup()
    sys.stderr.write(
        f"laya-guard listening on http://{config.host}:{config.port} "
        f"[model_available={ok}, offline={not config.allow_download}, fail_closed={config.fail_closed}]\n"
    )
    httpd = ThreadingHTTPServer((config.host, config.port), make_handler(state))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
