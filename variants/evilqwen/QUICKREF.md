# evilkit qwen-3.6-plus-brain — Quick Reference

Created 2026-10-04

## Location

`~/orca/workspaces/evilkit/qwen-3.6-plus-brain/`

## ModelStack

```
┌─────────────────────────────────────┐
│ EvilKit Operator Brain              │
│ Qwen 3.6 Plus Uncensored (1.2)     │
│ Venice API →  https://api.venice.ai│
└─────────────────────────────────────┘
              │
              ├─► Auditor (Qwen 1.2)
              │    → Validates claims, enforces scope
              │
              └─► MCP Tools → malware-gen service
                   → Generate, deploy, test payload
```

## Architecture

1. **Operator (Qwen 1.2)** — Initiates pentest turns, proposes commands
2. **Auditor (Qwen 1.2)** — Verifies evidence, blocks unsafe actions
3. **MCP Tools** — Token-wrapped malware generator:
   - `malware_generate` → Generates C code
   - `malware_deploy` → Stages payload
   - `malware_test` → Tests binary
   - `malware_get_logs` → Pulls telemetry
4. **Mission contract layer** — the objective contract, the declaration gate and
   the proof ledger (see `docs/mission-contract.md`):
   - `mission_contract` → Load objectives, prerequisites, witnesses, budget
   - `mission_declare` → Declare intent before a sensitive action (the gate
     refuses `malware_persist`/`malware_c2`/`malware_worm`/`malware_classify`
     without it)
   - `mission_status` → Objective states, missing witnesses, budget
   - `mission_verify` → Record one witness that proves part of an outcome

## Lab Topology

```
Range A (Detonation Cage):
  det-net 10.99.99.0/24 (no uplink)
    .10     inetsim VM
    .100    victim-linux ← Initial infection target
    Management: 10.99.1.2 (desktop, no gateway)

Range B (Pivot Range):
  vmbr9 10.99.50.0/24 (no uplink)
    .254   range-gw (SSH jump host)
    .11    edge01      (initial access, web + SSH)
    .21    bot01       (pivot 1, forwarding/proxy)
    .22    bot02       (pivot 2, different service)
    .31    crown01     (crown jewel: payroll + clients)

Chain: edge01 → bot01 → bot02 → crown01
Mission: Payload → victim-linux → edge01 → ... → crown01
```

## Quick Start

```bash
cd ~/orca/workspaces/evilkit/qwen-3.6-plus-brain

# Set Venice API key
export VENICE_API_KEY="your-key"

# Dry run (no API calls)
./run-malware-lab.sh --dry-run

# Full run (15 iterations)
./run-malware-lab.sh --iterations 15
```

## Key Files

| File | Purpose |
|------|---------|
| `mcp-malware-generator.py` | MCP tool server (stdio) exposing 4 tools |
| `.mcp.json` | Evilkit's scan config with malware-generator server |
| `run-malware-lab.sh` | Orchestrates C2 → brain launch |
| `lab-docs/topology.md` | Lab topology for the generator |
| `evilkit/prompts.py` | Operator/auditor prompts with two-lab context |
| `evilkit/tools.py` | 55-binaries allowlist (SSH, SCP, virsh, tcpdump, etc.) |

## Runtime Flow

1. `run-malware-lab.sh` starts C2 server on port 8080
2. Evilkit brain launched with live executor
3. Operator model (Qwen 1.2) proposes turn actions:
   - Recon on victim-linux
   - Run `malware_generate` tool for payload
   - Deploy payload via `malware_deploy`
   - Test via `malware_test`
   - Pivot chain anyway → edge01 → bot01 → bot02 → crown01
4. Auditor (Qwen 1.2) validates each step
5. Telemetry written to `runs/<run-id>/trace.jsonl`

## Replay Telemetry

```bash
pentest-viewer --trace runs/<run-id>/trace.jsonl
```

## Prerequisites

- [ ] VENICE_API_KEY set
- [ ] Lab ranges built and `verify-isolation.sh` → 0 exit
- [ ] victim-linux snapshot "clean"
- [ ] pivot range VMs (edge01, bot01, bot02, crown01) created

## Cost Note

Operating on Venice uncensored-1.2 (same for operator/auditor). C2 server runs independently. Leverage `--dry-run` for cost-free workflow testing.
