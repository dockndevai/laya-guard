# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-26

### Added
- Initial release: a local, safe-by-default AI risk guard for high-risk commands. A small stdlib HTTP
  daemon (`/evaluate`, `/health`) plus a one-shot `laya-guard evaluate` CLI.
- Two-layer decision engine: deterministic regex rules first (block / confirm / allow patterns for the
  classic catastrophic commands), then the Laya decision model for the gray zone (destructive /
  exfiltration / privilege / blast-radius questions → risk level → decision), with calibrated
  confidence.
- **Only-tightens** design and **fail-closed** behaviour: unavailable model, low confidence, or
  unknown command ⇒ confirm/block, never a silent allow. Loopback-only; offline by default.
- Org-level control via a JSON policy file (`LAYA_GUARD_POLICY`); tunable thresholds and patterns.
- Pairs with `mcp-mac-control` 0.3.0+, which calls the guard from its high-risk tools with an
  off / monitor / enforce mode.
- Built on the Apache-2.0 [laya](https://github.com/NandhaKishorM/laya) library by Convai Innovations
  (a dependency, not vendored). See NOTICE.
