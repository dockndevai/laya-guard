# laya-guard

[![PyPI](https://img.shields.io/pypi/v/laya-guard)](https://pypi.org/project/laya-guard/)
[![CI](https://github.com/dockndevai/laya-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/dockndevai/laya-guard/actions/workflows/ci.yml)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A **local, safe-by-default AI risk guard** for high-risk commands — deterministic pattern rules first, then the [Laya](https://github.com/NandhaKishorM/laya) decision model for the gray zone. It's defense-in-depth for the [dockndevai MCP server suite](https://dockndevai.github.io/): when a server runs in a permissive ("full permission") mode and is about to do something dangerous, it asks laya-guard *"how risky is this?"* and gets back **allow / confirm / block** with a reason — in milliseconds, on-device, nothing leaving the machine.

## The one rule it obeys

**The guard only ever tightens.** It runs *after* a server's own deterministic gates have already permitted an action, and it can only add a confirmation or a block — it can **never grant** a permission those gates denied. When the model is unsure, unavailable, or the input looks adversarial, it **fails closed** (confirm/block, not allow). So turning it on is strictly safer than leaving it off — never weaker.

## How it decides

1. **Deterministic patterns (always first).** A block pattern (`rm -rf /`, `mkfs`, `curl … | sh`, `DROP TABLE`, `kubectl delete ns`, `shutdown`, …) blocks outright; a confirm pattern (`sudo`, `git push --force`, `docker rm`, …) raises the floor to at least *confirm*. These make the guard useful even with **no model loaded**.
2. **The laya model (gray zone).** For everything else it asks four typed questions — is this **destructive**, **exfiltration**, **privilege**-escalating, and how large is the **blast radius** — and maps the answers (with calibrated confidence) to a risk level and a decision.

## Run it

```bash
pipx install laya-guard
# fetch the laya model once (downloads are off by default):
LAYA_GUARD_ALLOW_DOWNLOAD=true python -c "import laya; laya.Router(preload=True)"
laya-guard          # starts the daemon on http://127.0.0.1:8799
```

One-shot assessment (no server), handy for testing:

```bash
laya-guard evaluate "rm -rf /"          # -> {"decision":"block","risk":"critical",...}
laya-guard evaluate "ls -la"            # -> {"decision":"allow",...}
```

## API

```
GET  /health    -> {"status":"ok","model_available":bool,"policy":{...}}
POST /evaluate  {"tool":"run_command","command":"...","context":"..."}
             -> {"decision":"allow|confirm|block","risk":"...","confidence":0.0,
                 "reasons":[...],"deterministic":bool,"model_available":bool}
```

## Using it from an MCP server

The daemon returns an assessment; the **calling server** decides what to do per its mode. In the suite, `mcp-mac-control` (0.3.0+) ships a client that calls the guard from its high-risk tools:

- `MACCTL_GUARD_MODE=off` (default) — disabled, no behaviour change.
- `MACCTL_GUARD_MODE=monitor` — assess and log what it *would* do; never blocks.
- `MACCTL_GUARD_MODE=enforce` — act: block, or require a human confirmation.

Start in `monitor` to see what it would catch, then flip to `enforce`.

## Organization control

Point `LAYA_GUARD_POLICY` at a JSON file (see [`policy.example.json`](policy.example.json)) to set your own block/confirm/allow patterns and thresholds, and ship it org-wide. Omitted keys fall back to the built-in defaults.

## Safe by default

- **Local & offline** — the model runs on-device; the only network touch is the one-time laya checkpoint download, gated by `LAYA_GUARD_ALLOW_DOWNLOAD`.
- **Loopback only** — binds `127.0.0.1` unless `LAYA_GUARD_ALLOW_REMOTE=true`.
- **Fail-closed** — unavailable/low-confidence/unknown ⇒ confirm or block, never a silent allow.
- **Only tightens** — never grants a permission the caller's deterministic gates denied.

See [SECURITY.md](SECURITY.md).

## Developing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests && mypy src && pytest      # the policy tests need no model
```

## Credits

Built on **[laya](https://github.com/NandhaKishorM/laya)** by Convai Innovations (Apache-2.0), a dependency, not vendored. See [NOTICE](NOTICE).

## Licence

MIT
