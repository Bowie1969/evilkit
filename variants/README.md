# Evilkit variants

The repo is split into sections: the canonical **core** launcher lives at the repo
root, and experimental/alternate architectures live under `variants/`. Each variant
is a self-contained working tree (its own `evilkit/` package, `tests/`, `pyproject.toml`,
`install.sh`).

| Variant | Path | What it is | Model backend |
|---|---|---|---|
| core | `.` (repo root) | Scope-gated launcher for the Kimi Code CLI; osint stage, watch, mobile companion | Kimi Code CLI |
| brain | `variants/brain/` | Brain loop (`brain.py`, `brain_state.py`, `models.py`) driving a model through a tool loop | Kimi / Laguna / MiniMax |
| mesh | `variants/mesh/` | Scoped, brief-based worker mesh (`mesh.py`, `mesh_mcp.py`) with Windows + WSL workers | Kimi workers |
| evilqwen | `variants/evilqwen/` | Brain loop + the `redteamscripting` MCP (`mcp-malware-generator.py` + `lib/`), mission contract + proof ledger | **Venice-hosted Qwen** |

## evilqwen notes

- `mcp-malware-generator.py` is the `redteamscripting` MCP server; `lib/` is its
  library (mission contract, credential harvester, trust mapper, range adapter, etc.).
- Its `.mcp.json` (holds the live MCP scope/tokens) is gitignored; copy
  `examples/.mcp.json.example` to configure.
- `contracts/`, `evidence/`, and `lab-docs/` are engagement artefacts, not reusable code.
