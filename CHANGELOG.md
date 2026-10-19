# Changelog

## 1.3.0 — 2026-10-19

- **Orchestration layer.** The mesh hub now hosts a peer-to-peer coordination
  board: enrolled instances exchange directed messages, publish to channels,
  claim assets, and update a shared objective board. Every signed instance
  endpoint is ed25519-authenticated (RFC 8032 reference, zero dependencies),
  nonces are replay-windowed, revoked keys are refused, and credential-shaped
  payloads are blocked. Hub state is journaled under
  `$XDG_STATE_HOME/evilkit/mesh-hub/<id>/journal.jsonl` and replayed on
  restart. Coordination events feed the Keystone dashboard through
  `orchestration_send`, `orchestration_claim`, `orchestration_objective`.
  New CLI: `evilkit mesh keygen|enroll|revoke|instance|send|broadcast|inbox|
  peers|claim|release|claims|objective|objectives`. New MCP tools:
  `send_message`, `broadcast`, `read_inbox`, `claim_asset`, `release_asset`,
  `list_claims`, `set_objective`, `list_objectives`, `list_peers`,
  `request_from_peer`. See `docs/orchestration.md`.

## 1.2.0 — 2026-10-16

- Unified Kimi and Qwen adapters behind one scope and deny policy.
- Added run profiles, preflight checks, canonical telemetry, dashboard control,
  audit tooling, and reversible learning records.
- Added an explicitly enrolled worker mesh with token, sandbox, allowlist, and
  kill-switch controls.
- Published sanitized Keystone Run 6 and Run 7 analysis, including the decision
  that Run 7 is not a valid cold-start benchmark.
- Added public-release hygiene, security reporting guidance, and CI.

