# evilkit — qwen-3.6-plus-brain

Scope-gated operator-auditor brain for the malware lab, powered by **Qwen 3.6 Plus Uncensored** via the Venice API, with integrated malware generator MCP tool.

## Model config

| Role | Model | Endpoint | Purpose |
|------|-------|----------|---------|
| Operator | `venice-uncensored-1.2` | `https://api.venice.ai/v1` | Drives the pentest, generates intentions |
| Auditor | `venice-uncensored-1.2` | `https://api.venice.ai/v1` | Validates claims, enforces scope |
| Malware Tool (MCP) | `venice-uncensored-1.2` | `https://api.venice.ai/v1` | Generates/C2 deploys payload |

Uses the same Venice API key throughout. The auditor and malware tool both use the cheaper 1.2 model to control costs.

## Lab topology

Two isolated ranges:

**(A) Detonation Cage** — E7470 laptop, libvirt, air-gapped
- `10.99.99.0/24` — no uplink, INetSim at `.10`, victim-linux at `.100`
- Arduino UNO R4 BadUSB delivery, UART keystroke trace

**(B) Pivot Range** — Proxmox brain, vmbr9, no uplink
- `10.99.50.0/24` — edge01 → bot01 → bot02 → crown01
- Crown jewel: payroll + client accounts + financial data

## Quick start

```bash
# Set your Venice API key
export VENICE_API_KEY="your-key"

# Dry run with the run script (simplified)
cd ~/orca/workspaces/evilkit/qwen-3.6-plus-brain
./run-malware-lab.sh --dry-run

# Full run
./run-malware-lab.sh
```

The `run-malware-lab.sh` script now:
1. Starts C2 server (background)
2. Uses evilkit's internal malware generator MCP tool (called by the brain during engagement)
3. Launches the evilkit brain in live mode
4. Collects telemetry into `runs/<run-id>/`

## Run outputs

Each run creates `runs/<run-id>/`:
- `trace.jsonl` — per-turn JSONL trace (operator intentions, execution, auditor verdicts, MCP tool calls)
- `state.json` — final mission state
- `brain.log` — full brain output
- `c2-logs/` — C2 server activity logs

## Replay

```bash
pentest-viewer --trace runs/<run-id>/trace.jsonl
```

## Architecture

Fork of `minimax-brain` evilkit, adapted for Venice API backend:

- **Operator model:** Qwen 3.6 Plus Uncensored (1.2) — drives pentest intentions
- **Auditor model:** Qwen 3.6 Plus Uncensored (1.2) — cheaper for frequent validation calls  
- **MCP tools:** Integrated malware generator service (scope-safe code generation, deployment, testing)
- **Two-lab topology:** Detonation cage (A) + pivot range (B) designed for a-payload-to-pivot mission
- **Expanded tool allowlist:** 55 binaries including SSH, SCP, virsh, bash, python3, tcpdump

## MCP Tools

The malware generator is exposed as an MCP tool available to the brain:

- `malware_generate` — Generate rootkit/botnet C code targeting lab IPs
- `malware_deploy` — Stage payload to VMs when ready
- `malware_test` — Test binary behavior on target
- `malware_get_logs` — Pull C2/brain/trace logs

The operator brain can chain these tools during its turns (operator → tool execution → auditor validation).

## Mission contract and proof ledger

`lib/mission_contract.py` turns the scored objectives into something the tool
layer can enforce. It owns four things:

- **The contract** (`contracts/mission.json`) — objectives, prerequisites, the
  witness set that proves each one, the approved sink, the action budget and its
  verification reserve. `mission_contract` loads it and prints every dependency.
- **The declaration gate** — persistence, propagation, channel switching and
  crown access are refused until `mission_declare` has recorded the intent. A
  declaration is appended with a sequence number, so it cannot be back-dated.
- **The objective state machine** — blocked → ready → attempted → partial →
  verified / failed, with prerequisites enforced. Installing something is
  `partial`; only the witnesses make it `verified`.
- **The proof ledger and budget** — every attempt and witness is journalled, two
  equivalent failures stop a branch instead of retrying it, and a slice of the
  action budget is held back for proving what was already done.

`malware_persist` now deploys on the *named* host over an injected transport and
probes the four lifecycle facts (installed, activated, callback, survived a
restart), reporting `partial` until they all hold. Without SSH credentials it
refuses rather than installing on the MCP host. `lib/persistence_lifecycle.py`
holds that logic; it is transport-agnostic, so it is tested without a range.
