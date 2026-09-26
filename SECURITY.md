# Security

`laya-guard` is a **local risk assessor** for high-risk commands. It makes allow / confirm / block
recommendations; it does not execute anything itself. It exists to make the suite's permissive modes
safer, and its whole design is built around one rule.

## The rule: only tighten, never grant

The guard runs **after** a calling server's own deterministic gates have already permitted an action.
It may **raise** the outcome (allow → confirm → block); it may **never lower** one. It cannot approve
anything the caller's static policy denied. A probabilistic model has false negatives and false
positives, so it is never the *sole* control — it is one layer on top of allowlists, capability gates,
and human-in-the-loop confirmation, all of which remain the floor.

## Fail-closed

- **Model unavailable** (not downloaded, offline, no torch) → deterministic patterns still apply; for
  anything they don't match, the daemon returns **confirm** (with `LAYA_GUARD_FAIL_CLOSED=true`,
  the default).
- **Low confidence** → an "allow" is escalated to "confirm" below `LAYA_GUARD_MIN_CONFIDENCE`.
- **Daemon unreachable** (from the calling server's side) → the client fails closed too: in enforce
  mode it requires a human confirmation rather than proceeding silently.

## Locality & exposure

- The model runs **on-device**; the command text never leaves the machine. The only network access is
  the one-time laya checkpoint download, gated by `LAYA_GUARD_ALLOW_DOWNLOAD` (off by default).
- The daemon binds **loopback** (`127.0.0.1`). `LAYA_GUARD_ALLOW_REMOTE=true` is required to bind
  elsewhere and is strongly discouraged: anything that can reach the port influences allow/block
  decisions for dangerous operations.
- The audit log records decisions and a truncated command on stderr; treat those logs as sensitive.

## Limitations

- Pattern rules are high-precision but not exhaustive; the model covers the gray zone but can be wrong.
  Keep the calling server's deterministic gates enabled — the guard supplements them, never replaces.
- The model can be influenced by adversarial phrasing of a command. Because laya is non-generative it
  cannot be "jailbroken" into emitting text, but treat its decision as a strong heuristic, not a proof.
- Some laya checkpoints report uncalibrated confidence on the ordinal `scope` question; the guard
  therefore derives confidence from the yes/no risk signals and treats `scope` as advisory.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue. Issues in
the underlying model belong upstream at the [laya](https://github.com/NandhaKishorM/laya) project.
