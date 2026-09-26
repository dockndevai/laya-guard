"""Entry point: `laya-guard` / `python -m laya_guard`.

  laya-guard              run the daemon
  laya-guard evaluate '<command>'   one-shot assessment (prints JSON), for testing/CI
"""
from __future__ import annotations

import json
import sys


def main() -> None:
    from .config import load_config

    args = sys.argv[1:]
    if args and args[0] == "evaluate":
        from .server import GuardState

        command = args[1] if len(args) > 1 else ""
        state = GuardState(load_config())
        print(json.dumps(state.evaluate(tool="cli", command=command, context=None), indent=2))
        return

    from .server import serve

    serve(load_config())


if __name__ == "__main__":
    main()
