"""Harness-level guards: objective tracking, budgets, circuit breakers, loop detection, evidence journal.

The harness owns the canonical facts ledger, checks success after every tool
result, enforces attempt caps, detects reasoning spirals, and auto-journals
every command/output/artifact to evidence/ with timestamps.

v2 — rewritten after pcap analysis of the 2026-10-04 pivot range run. Key fixes:
  - Objective re-evaluation after every data pull (not just final check)
  - Relay/proxy detection: unauthenticated HTTP returning sensitive data triggers
    provenance alert and blocks local-FS claims
  - Tighter attempt budgets: 3 per-cred-per-host (L3), 5 per-host, 50 global
  - MCP tool enforcement: harness tracks whether the agent uses first-class tools
    vs raw shell equivalents, and injects nudges
  - Network truth grounding: TCP path tracking correlated with agent claims
  - Phase-aware objectives: ordered phases with dependency gates
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "Objective",
    "FactsLedger",
    "AttemptBudget",
    "CircuitBreaker",
    "LoopDetector",
    "EvidenceJournal",
    "ProvenanceChecker",
    "ToolAffordanceTracker",
    "HarnessState",
]


# ---------------------------------------------------------------------------
# Objective tracking — phase-aware with dependency gates
# ---------------------------------------------------------------------------

_PREDICATES = {
    "crown01_records": lambda raw, ledger: (
        "/srv/records" in raw
        and ("payroll" in raw.lower() or "client" in raw.lower() or "financial" in raw.lower())
        and _has_provenance(ledger, "10.99.50.31")
    ),
    "host_discovered": lambda raw, ledger: bool(
        re.search(r"\b10\.99\.50\.\d{1,3}\b", raw)
    ),
    "cred_recovered": lambda raw, ledger: any(
        marker in raw.lower()
        for marker in ("password", "credential", "shadow", "id_rsa", "authorized_keys")
    ),
    "flag_captured": lambda raw, ledger: bool(
        re.search(r"flag\{[^}]+\}", raw)
    ),
    "ssh_pivot": lambda raw, ledger: (
        "authenticated" in raw.lower()
        or "welcome" in raw.lower()
        or "last login" in raw.lower()
    ),
    "relay_chain": lambda raw, ledger: (
        "chain complete" in raw.lower()
        or "relay established" in raw.lower()
    ),
    "implant_deployed": lambda raw, ledger: (
        "beacon" in raw.lower()
        or "check-in" in raw.lower()
        or "implant active" in raw.lower()
    ),
    "data_exfiltrated": lambda raw, ledger: (
        len(ledger.files_captured) > 0
        and any(f.get("host") == "10.99.50.31" for f in ledger.files_captured)
    ),
}


def _has_provenance(ledger: "FactsLedger", host: str) -> bool:
    """Check if we have a confirmed network path to this host."""
    return any(
        np["dst"] == host or np["src"] == host
        for np in ledger.network_paths
    )


@dataclass
class Objective:
    """A machine-readable goal with a success predicate and phase dependency."""
    name: str
    description: str
    success_predicate: str
    check_fn: str
    phase: int = 0
    depends_on: list[str] = field(default_factory=list)
    met: bool = False
    met_at: str = ""
    evidence_ref: int = -1

    def check(self, raw_output: str, ledger: "FactsLedger") -> bool:
        if self.met:
            return True
        predicate = _PREDICATES.get(self.check_fn)
        if predicate and predicate(raw_output, ledger):
            self.met = True
            self.met_at = _utc_now_iso()
            return True
        if self.check_fn == "custom":
            if self.success_predicate.lower() in raw_output.lower():
                self.met = True
                self.met_at = _utc_now_iso()
                return True
        return False

    def deps_met(self, all_objectives: list["Objective"]) -> bool:
        if not self.depends_on:
            return True
        by_name = {o.name: o for o in all_objectives}
        return all(by_name.get(d, Objective(name=d, description="", success_predicate="", check_fn="")).met for d in self.depends_on)


# ---------------------------------------------------------------------------
# Facts ledger — running beliefs the harness owns
# ---------------------------------------------------------------------------

@dataclass
class FactsLedger:
    """Append-only ledger of confirmed facts. The harness owns this, not the model."""
    hosts: list[dict] = field(default_factory=list)
    creds: list[dict] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)
    files_captured: list[dict] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)
    network_paths: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    access_levels: dict[str, str] = field(default_factory=dict)

    def add_host(self, address: str, hostname: str = "", services: list | None = None, source: str = "") -> None:
        existing = next((h for h in self.hosts if h["address"] == address), None)
        if not existing:
            self.hosts.append({
                "address": address,
                "hostname": hostname,
                "services": services or [],
                "source": source,
                "discovered_at": _utc_now_iso(),
            })
        elif services:
            for svc in services:
                if svc not in existing.get("services", []):
                    existing.setdefault("services", []).append(svc)

    def add_cred(self, host: str, username: str, password: str, source: str = "") -> None:
        existing = next((c for c in self.creds if c["host"] == host and c["username"] == username), None)
        if not existing:
            self.creds.append({
                "host": host,
                "username": username,
                "password_redacted": password[:2] + "***" if len(password) > 2 else "***",
                "source": source,
                "recovered_at": _utc_now_iso(),
            })

    def add_flag(self, flag: str, host: str = "", source: str = "") -> None:
        existing = next((f for f in self.flags if f["flag"] == flag), None)
        if not existing:
            self.flags.append({
                "flag": flag,
                "host": host,
                "source": source,
                "captured_at": _utc_now_iso(),
            })

    def add_file(self, path: str, content: str, host: str = "", source: str = "") -> bool:
        """Record a captured file. Returns False if already captured (same hash)."""
        h = hashlib.sha256(content.encode()).hexdigest()
        if path in self.file_hashes and self.file_hashes[path] == h:
            return False
        self.file_hashes[path] = h
        self.files_captured.append({
            "path": path,
            "sha256": h,
            "host": host,
            "source": source,
            "captured_at": _utc_now_iso(),
        })
        return True

    def add_network_path(self, src: str, dst: str, port: int, protocol: str = "tcp") -> None:
        key = (src, dst, port, protocol)
        existing = any(
            (np["src"], np["dst"], np["port"], np["protocol"]) == key
            for np in self.network_paths
        )
        if not existing:
            self.network_paths.append({
                "src": src, "dst": dst, "port": port, "protocol": protocol,
                "recorded_at": _utc_now_iso(),
            })

    def set_access_level(self, host: str, level: str) -> None:
        """Track the proven access level per host.
        Levels: discovered < readable < authenticated < executable < writable < root
        """
        _LEVELS = {"discovered": 0, "readable": 1, "authenticated": 2, "executable": 3, "writable": 4, "root": 5}
        current = self.access_levels.get(host, "discovered")
        if _LEVELS.get(level, 0) > _LEVELS.get(current, 0):
            self.access_levels[host] = level

    def hosts_at_level(self, min_level: str) -> list[str]:
        _LEVELS = {"discovered": 0, "readable": 1, "authenticated": 2, "executable": 3, "writable": 4, "root": 5}
        min_ord = _LEVELS.get(min_level, 0)
        return [h for h, lv in self.access_levels.items() if _LEVELS.get(lv, 0) >= min_ord]

    def summary(self) -> str:
        lines = [f"HOSTS: {len(self.hosts)}"]
        for h in self.hosts:
            svcs = ", ".join(f"{s.get('port', '?')}/{s.get('protocol', '?')}" for s in h.get("services", []))
            level = self.access_levels.get(h["address"], "discovered")
            lines.append(f"  {h['address']} ({h.get('hostname', '?')}) [{svcs or 'no services'}] access={level}")
        lines.append(f"CREDENTIALS: {len(self.creds)}")
        for c in self.creds:
            lines.append(f"  {c['username']}@{c['host']} ({c['source']})")
        lines.append(f"FLAGS: {len(self.flags)}")
        for f in self.flags:
            lines.append(f"  {f['flag']} ({f['host']})")
        lines.append(f"FILES CAPTURED: {len(self.files_captured)}")
        for fc in self.files_captured:
            lines.append(f"  {fc['path']} (sha256:{fc['sha256'][:12]}...) from {fc.get('host', '?')}")
        lines.append(f"NETWORK PATHS: {len(self.network_paths)}")
        for np in self.network_paths:
            lines.append(f"  {np['src']} -> {np['dst']}:{np['port']}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "hosts": self.hosts,
            "creds": self.creds,
            "flags": self.flags,
            "files_captured": self.files_captured,
            "file_hashes": self.file_hashes,
            "network_paths": self.network_paths,
            "findings": self.findings,
            "access_levels": self.access_levels,
        }


# ---------------------------------------------------------------------------
# Attempt budgets & circuit breakers — tighter defaults from pcap analysis
# ---------------------------------------------------------------------------

@dataclass
class AttemptBudget:
    """Per-host/per-service/per-credential attempt caps enforced by the harness.

    Defaults tightened after the 2026-10-04 run where 227 SSH attempts hit bot01
    with zero success. The L3 per-(host, cred) cap fires first, so a credential
    that fails 3x is locked before the host cap kicks in.
    """
    max_per_host_auth: int = 5
    max_per_service_auth: int = 3
    max_per_cred_per_host: int = 3
    max_global_actions: int = 50
    max_per_technique: int = 10
    max_consecutive_failures: int = 5

    host_attempts: dict[str, int] = field(default_factory=dict)
    service_attempts: dict[str, int] = field(default_factory=dict)
    cred_attempts: dict[str, int] = field(default_factory=dict)
    technique_counts: dict[str, int] = field(default_factory=dict)
    total_actions: int = 0
    consecutive_failures: int = 0
    locked_vectors: list[str] = field(default_factory=list)
    locked_creds: list[str] = field(default_factory=list)

    def record_action(self, technique: str = "", succeeded: bool = True) -> list[str]:
        warnings = []
        self.total_actions += 1
        if technique:
            self.technique_counts[technique] = self.technique_counts.get(technique, 0) + 1
        if succeeded:
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
            if self.consecutive_failures >= self.max_consecutive_failures:
                warnings.append(
                    f"FAILURE STREAK: {self.consecutive_failures} consecutive failures — "
                    f"stop and replan strategy."
                )
        return warnings

    def record_auth_attempt(self, host: str, service: str = "", credential: str = "") -> str | None:
        self.host_attempts[host] = self.host_attempts.get(host, 0) + 1
        key = f"{host}:{service}" if service else host
        self.service_attempts[key] = self.service_attempts.get(key, 0) + 1

        if credential:
            cred_key = f"{host}|{credential}"
            self.cred_attempts[cred_key] = self.cred_attempts.get(cred_key, 0) + 1
            if self.cred_attempts[cred_key] >= self.max_per_cred_per_host:
                msg = (f"CRED LOCK: credential '{credential}' failed "
                       f"{self.cred_attempts[cred_key]}x on {host} — "
                       f"stop retrying this cred here (L3). Harvest a new cred or pivot.")
                if cred_key not in self.locked_creds:
                    self.locked_creds.append(cred_key)
                return msg

        if self.host_attempts[host] >= self.max_per_host_auth:
            msg = f"AUTH LOCK: {host} — {self.host_attempts[host]} failed attempts, pivot."
            if key not in self.locked_vectors:
                self.locked_vectors.append(key)
            return msg
        if service and self.service_attempts[key] >= self.max_per_service_auth:
            msg = f"AUTH LOCK: {key} — {self.service_attempts[key]} failed attempts, pivot."
            if key not in self.locked_vectors:
                self.locked_vectors.append(key)
            return msg
        return None

    def is_locked(self, key: str) -> bool:
        return key in self.locked_vectors

    def is_cred_locked(self, host: str, credential: str) -> bool:
        return f"{host}|{credential}" in self.locked_creds

    def is_exhausted(self) -> bool:
        return self.total_actions >= self.max_global_actions

    def technique_exhausted(self, technique: str) -> bool:
        return self.technique_counts.get(technique, 0) >= self.max_per_technique

    def budget_remaining(self) -> int:
        return max(0, self.max_global_actions - self.total_actions)

    def summary(self) -> str:
        lines = [
            f"ACTION BUDGET: {self.total_actions}/{self.max_global_actions} (remaining: {self.budget_remaining()})",
            f"CONSECUTIVE FAILURES: {self.consecutive_failures}/{self.max_consecutive_failures}",
            f"LOCKED VECTORS: {', '.join(self.locked_vectors) or 'none'}",
            f"LOCKED CREDS: {', '.join(self.locked_creds) or 'none'}",
        ]
        for host, count in sorted(self.host_attempts.items()):
            lines.append(f"  {host}: {count}/{self.max_per_host_auth} auth attempts")
        for cred_key, count in sorted(self.cred_attempts.items()):
            lines.append(f"  {cred_key}: {count}/{self.max_per_cred_per_host} same-cred attempts")
        for tech, count in sorted(self.technique_counts.items()):
            lines.append(f"  {tech}: {count}/{self.max_per_technique}")
        return "\n".join(lines)


class CircuitBreaker:
    """Hard-locks a vector when attempts exceed the budget."""

    def __init__(self, budget: AttemptBudget) -> None:
        self.budget = budget

    def check(self, host: str, service: str = "", technique: str = "", credential: str = "") -> str | None:
        if host and credential and self.budget.is_cred_locked(host, credential):
            return (f"CIRCUIT BREAKER: credential '{credential}' is cred-locked on {host} "
                    f"(L3: same cred failed >={self.budget.max_per_cred_per_host}x) — "
                    f"use a different credential or pivot.")
        if technique and self.budget.technique_exhausted(technique):
            return f"CIRCUIT BREAKER: technique '{technique}' exhausted ({self.budget.max_per_technique} attempts) — replan strategy."
        if self.budget.is_exhausted():
            return f"CIRCUIT BREAKER: global action budget exhausted ({self.budget.max_global_actions}) — replan strategy."
        key = f"{host}:{service}" if service else host
        if self.budget.is_locked(key):
            return f"CIRCUIT BREAKER: {key} is hard-locked — pivot to another vector."
        if self.budget.consecutive_failures >= self.budget.max_consecutive_failures:
            return f"CIRCUIT BREAKER: {self.budget.consecutive_failures} consecutive failures — replan strategy."
        return None


# ---------------------------------------------------------------------------
# Loop & stall guards
# ---------------------------------------------------------------------------

@dataclass
class LoopDetector:
    """Detects reasoning spirals and command repetition."""
    recent_commands: list[str] = field(default_factory=list)
    recent_thoughts: list[str] = field(default_factory=list)
    recent_goals: list[str] = field(default_factory=list)
    max_window: int = 7
    ngram_size: int = 3
    last_action_time: float = field(default_factory=time.time)
    stall_timeout: int = 120

    def record_command(self, cmd: str) -> list[str]:
        self.recent_commands.append(cmd)
        if len(self.recent_commands) > self.max_window:
            self.recent_commands = self.recent_commands[-self.max_window:]
        return self._check_repetition()

    def record_thought(self, thought: str) -> list[str]:
        self.recent_thoughts.append(thought)
        if len(self.recent_thoughts) > self.max_window:
            self.recent_thoughts = self.recent_thoughts[-self.max_window:]
        return self._check_thought_repetition()

    def record_goal(self, goal: str) -> list[str]:
        """Track goal repetition — a spinning agent restates the same goal."""
        self.recent_goals.append(goal.lower().strip())
        if len(self.recent_goals) > self.max_window:
            self.recent_goals = self.recent_goals[-self.max_window:]
        warnings = []
        if len(self.recent_goals) >= 3 and len(set(self.recent_goals[-3:])) == 1:
            warnings.append(
                f"GOAL REPETITION: identical goal stated 3x: '{self.recent_goals[-1][:60]}...' — "
                f"change vector or declare blocked."
            )
        return warnings

    def check_stall(self) -> str | None:
        elapsed = time.time() - self.last_action_time
        if elapsed > self.stall_timeout:
            return f"STALL WATCHDOG: {int(elapsed)}s without a tool call — emit one concrete action or declare blocked."
        return None

    def touch(self) -> None:
        self.last_action_time = time.time()

    def _check_repetition(self) -> list[str]:
        warnings = []
        cmds = self.recent_commands
        if len(cmds) < 3:
            return warnings
        if len(set(cmds[-3:])) == 1:
            warnings.append(f"REPETITION: identical command repeated 3x: {cmds[-1][:60]}...")
        if len(cmds) >= self.ngram_size:
            ngrams = []
            for i in range(len(cmds) - self.ngram_size + 1):
                ngram = " ".join(cmds[i:i + self.ngram_size])
                ngrams.append(ngram)
            if len(ngrams) != len(set(ngrams)):
                warnings.append(f"REPETITION: similar command pattern repeated (n={self.ngram_size})")
        return warnings

    def _check_thought_repetition(self) -> list[str]:
        warnings = []
        thoughts = self.recent_thoughts
        if len(thoughts) < 3:
            return warnings
        prefixes = [t[:80] for t in thoughts[-5:]]
        if len(set(prefixes)) == 1:
            warnings.append("REPETITION: identical reasoning pattern repeated — demand a different vector.")
        return warnings


# ---------------------------------------------------------------------------
# Evidence journal — auto-persisted, structured
# ---------------------------------------------------------------------------

@dataclass
class EvidenceJournal:
    """Auto-journals every command, output, and artifact to evidence/ with timestamps."""
    evidence_dir: Path

    def __post_init__(self) -> None:
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def record(self, turn: int, kind: str, data: dict) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"turn-{turn:03d}-{kind}-{ts}.json"
        path = self.evidence_dir / filename
        entry = {
            "ts": _utc_now_iso(),
            "turn": turn,
            "kind": kind,
            **data,
        }
        path.write_text(json.dumps(entry, indent=2, default=str) + "\n", encoding="utf-8")
        return path

    def record_command(self, turn: int, command: str, stdout: str, stderr: str, returncode: int) -> Path:
        return self.record(turn, "command", {
            "command": command,
            "returncode": returncode,
            "stdout_chars": len(stdout),
            "stderr_chars": len(stderr),
            "stdout_truncated": stdout[:4000],
            "stderr_truncated": stderr[:2000],
        })

    def record_artifact(self, turn: int, name: str, content: str, host: str = "") -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"turn-{turn:03d}-artifact-{name}-{ts}"
        path = self.evidence_dir / filename
        path.write_text(content, encoding="utf-8")
        self.record(turn, "artifact", {
            "name": name,
            "path": str(path),
            "host": host,
            "size": len(content),
        })
        return path

    def build_report_skeleton(self, ledger: FactsLedger, objectives: list[Objective]) -> str:
        lines = [
            "# Engagement Report",
            f"Generated: {_utc_now_iso()}",
            "",
            "## Objectives",
        ]
        for obj in objectives:
            status = "MET" if obj.met else "PENDING"
            deps = f" (depends: {', '.join(obj.depends_on)})" if obj.depends_on else ""
            lines.append(f"- [{status}] {obj.name}: {obj.description}{deps}")

        lines += ["", "## Facts Ledger", "", ledger.summary(), ""]
        lines += ["## Findings", ""]
        for f in ledger.findings:
            lines.append(f"- [{f.get('severity', 'info')}] {f.get('title', 'unknown')} on {f.get('host', '?')}")
        lines += ["", "## Evidence Files", ""]
        for p in sorted(self.evidence_dir.glob("*")):
            lines.append(f"- `{p.name}`")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Provenance checker — enhanced relay detection from pcap analysis
# ---------------------------------------------------------------------------

class ProvenanceChecker:
    """Correlates agent actions with network truth; flags suspicious provenance.

    Enhanced after the 2026-10-04 run where the agent got data from crown01 via
    a relay chain (.11->.21:9001->.22:9001->.31:8080) but claimed local FS access.
    """

    def __init__(self, ledger: FactsLedger) -> None:
        self.ledger = ledger
        self.relay_suspects: set[str] = set()

    def check_unauthenticated_success(self, command: str, raw_output: str, claimed_host: str = "") -> str | None:
        lower_cmd = command.lower()
        lower_out = raw_output.lower()

        is_http = any(kw in lower_cmd for kw in ("curl", "wget", "http", "requests"))
        has_sensitive = any(marker in lower_out for marker in (
            "directory", "index of", "parent directory",
            "payroll", "client", "financial", "records",
            "password", "shadow", "id_rsa", "private key",
        ))

        if is_http and has_sensitive:
            port_match = re.search(r":(\d{4,5})", command)
            port_str = f" on port {port_match.group(1)}" if port_match else ""
            if claimed_host:
                self.relay_suspects.add(claimed_host)
            return (
                f"PROVENANCE ALERT: unauthenticated HTTP success returned sensitive data{port_str}. "
                f"This is likely a relay/proxy, NOT local FS access on the target. "
                f"Confirm the actual serving host before claiming filesystem access. "
                f"Use malware_harvest or SSH to verify."
            )

        if is_http and not has_sensitive and raw_output and len(raw_output) > 500:
            port_match = re.search(r":(\d{4,5})", command)
            if port_match:
                port = int(port_match.group(1))
                if port in (9001, 9080, 18080):
                    return (
                        f"PROVENANCE NOTE: traffic on port {port} may be a relay/proxy service. "
                        f"Data obtained this way came THROUGH a proxy, not from local FS."
                    )
        return None

    def check_access_claim(self, claimed_host: str, claimed_level: str, command: str) -> str | None:
        """Reject inflated access claims that aren't supported by evidence."""
        _ESCALATION_MAP = {
            "readable": {"curl", "wget", "http"},
            "authenticated": {"ssh", "sshpass", "netexec", "nxc"},
            "executable": {"ssh", "bash", "sh", "python3"},
            "root": {"sudo", "pkexec", "su"},
        }
        required_tools = _ESCALATION_MAP.get(claimed_level, set())
        if required_tools and not any(t in command.lower() for t in required_tools):
            if claimed_host in self.relay_suspects:
                return (
                    f"PROVENANCE BLOCK: {claimed_host} is a relay suspect. "
                    f"Cannot claim '{claimed_level}' access via relay. "
                    f"Establish direct SSH/exec access first."
                )
        return None

    def correlate_network_path(self, src: str, dst: str, port: int) -> str:
        self.ledger.add_network_path(src, dst, port)
        chain = self._build_chain(dst)
        if chain:
            return f"NETWORK TRUTH: actual TCP path: {' -> '.join(chain)}"
        return f"NETWORK TRUTH: direct {src} -> {dst}:{port}"

    def _build_chain(self, target: str) -> list[str] | None:
        visited = set()
        chain = [target]
        current = target
        for _ in range(10):
            if current in visited:
                break
            visited.add(current)
            for np in self.ledger.network_paths:
                if np["dst"] == current and np["src"] not in visited:
                    chain.insert(0, np["src"])
                    current = np["src"]
                    break
            else:
                break
        return chain if len(chain) > 1 else None


# ---------------------------------------------------------------------------
# Tool affordance tracker — nudge toward MCP tools
# ---------------------------------------------------------------------------

_TOOL_EQUIVALENTS: dict[str, str] = {
    "grep.*password": "malware_harvest",
    "cat.*/etc/shadow": "malware_harvest",
    "cat.*id_rsa": "malware_harvest",
    "cat.*authorized_keys": "malware_harvest",
    "find.*-name.*pass": "malware_harvest",
    "ssh-keyscan": "malware_map_trust",
    "cat.*ssh/config": "malware_map_trust",
    "cat.*known_hosts": "malware_map_trust",
    "searchsploit": "malware_vuln_research",
    "sshpass": "netexec (nxc)",
    r"for.*in.*ssh": "malware_worm",
    "crontab": "malware_persist",
    "echo.*cron": "malware_persist",
    r"curl.*loop": "ffuf or nuclei",
    r"while.*curl": "ffuf or nuclei",
}


class ToolAffordanceTracker:
    """Detect when the agent shells out instead of using first-class MCP tools."""

    def __init__(self) -> None:
        self.nudges_given: dict[str, int] = {}
        self.mcp_calls: int = 0
        self.shell_calls: int = 0

    def check_command(self, command: str) -> str | None:
        self.shell_calls += 1
        for pattern, tool in _TOOL_EQUIVALENTS.items():
            if re.search(pattern, command, re.IGNORECASE):
                self.nudges_given[tool] = self.nudges_given.get(tool, 0) + 1
                count = self.nudges_given[tool]
                if count <= 2:
                    return (
                        f"TOOL NUDGE: use `{tool}` MCP tool instead of raw shell. "
                        f"MCP tools are scope-gated and evidence-aware."
                    )
                else:
                    return (
                        f"TOOL ENFORCEMENT: you have been nudged {count}x to use `{tool}`. "
                        f"Raw shell bypass is being logged. Use the MCP tool."
                    )
        return None

    def record_mcp_call(self, tool_name: str) -> None:
        self.mcp_calls += 1

    def ratio_summary(self) -> str:
        total = self.mcp_calls + self.shell_calls
        if total == 0:
            return "TOOL USAGE: no actions yet"
        mcp_pct = (self.mcp_calls / total) * 100
        return f"TOOL USAGE: {self.mcp_calls} MCP / {self.shell_calls} shell ({mcp_pct:.0f}% MCP)"


# ---------------------------------------------------------------------------
# Harness state — bundles everything
# ---------------------------------------------------------------------------

@dataclass
class HarnessState:
    """Top-level harness state combining all guard components."""
    objectives: list[Objective] = field(default_factory=list)
    ledger: FactsLedger = field(default_factory=FactsLedger)
    budget: AttemptBudget = field(default_factory=AttemptBudget)
    circuit_breaker: CircuitBreaker = field(default_factory=lambda: CircuitBreaker(AttemptBudget()))
    loop_detector: LoopDetector = field(default_factory=LoopDetector)
    evidence_journal: EvidenceJournal | None = None
    provenance: ProvenanceChecker | None = None
    tool_tracker: ToolAffordanceTracker = field(default_factory=ToolAffordanceTracker)
    objective_met_injection: str = ""
    _last_objective_check_turn: int = -1

    def __post_init__(self) -> None:
        if self.evidence_journal is None:
            self.evidence_journal = EvidenceJournal(evidence_dir=Path("evidence"))
        if self.provenance is None:
            self.provenance = ProvenanceChecker(self.ledger)
        self.circuit_breaker = CircuitBreaker(self.budget)

    def check_objectives(self, raw_output: str, turn: int = -1) -> str | None:
        """Check all objectives after every action. Return injection if any newly met."""
        newly_met = []
        for obj in self.objectives:
            if not obj.met and obj.deps_met(self.objectives) and obj.check(raw_output, self.ledger):
                obj.evidence_ref = turn
                newly_met.append(obj)

        if newly_met:
            names = ", ".join(o.name for o in newly_met)
            pending = [o for o in self.objectives if not o.met]
            if not pending:
                return (
                    f"ALL OBJECTIVES MET — {names} completed. "
                    f"Stop and declare completion. Do not continue attacking."
                )
            return (
                f"OBJECTIVE MET — {names}. "
                f"Remaining: {', '.join(o.name for o in pending)}. "
                f"Re-evaluate strategy before next action."
            )
        return None

    def pre_action_check(self, host: str = "", service: str = "", technique: str = "",
                         credential: str = "", command: str = "") -> str | None:
        cb = self.circuit_breaker.check(host, service, technique, credential=credential)
        if cb:
            return cb
        if self.budget.is_exhausted():
            return "BUDGET EXHAUSTED: global action limit reached — force strategy replan."
        if command:
            nudge = self.tool_tracker.check_command(command)
            if nudge:
                return nudge
        return None

    def record_action(self, turn: int, command: str, stdout: str, stderr: str, returncode: int,
                      goal: str = "", reasoning: str = "", tool_call: dict | None = None) -> list[str]:
        warnings = []

        succeeded = returncode == 0
        technique = _extract_technique(command) if command else ""
        if tool_call:
            technique = f"mcp_{tool_call.get('name', 'unknown')}"
            self.tool_tracker.record_mcp_call(tool_call.get("name", ""))

        budget_warnings = self.budget.record_action(technique=technique, succeeded=succeeded)
        warnings.extend(budget_warnings)

        if command and _is_auth_command(command):
            host = _extract_host(command)
            credential = _extract_credential(command)
            combined = f"{stdout}\n{stderr}".lower()
            failure_signals = (
                "permission denied", "authentication failure", "failed password",
                "access denied", "login incorrect", "invalid credentials",
                "connection closed by authenticating user", "no route to host",
                "connection refused", "connection timed out",
            )
            auth_succeeded = returncode == 0 and not any(s in combined for s in failure_signals)
            if not auth_succeeded:
                lock_msg = self.budget.record_auth_attempt(
                    host=host, credential=credential,
                )
                if lock_msg:
                    warnings.append(lock_msg)
            else:
                if host:
                    self.ledger.set_access_level(host, "authenticated")

        self.loop_detector.touch()
        warnings.extend(self.loop_detector.record_command(command or str(tool_call)))
        if reasoning:
            warnings.extend(self.loop_detector.record_thought(reasoning))
        if goal:
            warnings.extend(self.loop_detector.record_goal(goal))

        stall = self.loop_detector.check_stall()
        if stall:
            warnings.append(stall)

        if self.evidence_journal:
            self.evidence_journal.record_command(turn, command or str(tool_call), stdout, stderr, returncode)

        raw_output = stdout + "\n" + stderr if stderr else stdout

        if command:
            prov_alert = self.provenance.check_unauthenticated_success(command, raw_output)
            if prov_alert:
                warnings.append(prov_alert)

        obj_msg = self.check_objectives(raw_output, turn=turn)
        if obj_msg:
            warnings.append(obj_msg)

        return warnings

    def inject_context(self, state_summary: str = "") -> str:
        parts = []

        met_objs = [o for o in self.objectives if o.met]
        pending_objs = [o for o in self.objectives if not o.met]
        if met_objs or pending_objs:
            obj_lines = ["OBJECTIVES:"]
            for o in met_objs:
                obj_lines.append(f"  [MET] {o.name}: {o.description} (at {o.met_at})")
            for o in pending_objs:
                deps = f" (needs: {', '.join(o.depends_on)})" if o.depends_on else ""
                deps_ok = "ready" if o.deps_met(self.objectives) else "blocked"
                obj_lines.append(f"  [PENDING/{deps_ok}] {o.name}: {o.description}{deps}")
            parts.append("\n".join(obj_lines))

        if self.ledger.hosts or self.ledger.creds or self.ledger.flags:
            parts.append(f"FACTS LEDGER:\n{self.ledger.summary()}")

        if self.budget.total_actions > 0:
            parts.append(f"BUDGET:\n{self.budget.summary()}")

        parts.append(self.tool_tracker.ratio_summary())

        if self.budget.locked_vectors or self.budget.locked_creds:
            lock_lines = ["LOCKED (do NOT retry):"]
            for v in self.budget.locked_vectors:
                lock_lines.append(f"  vector: {v}")
            for c in self.budget.locked_creds:
                lock_lines.append(f"  cred: {c}")
            parts.append("\n".join(lock_lines))

        if self.provenance.relay_suspects:
            parts.append(
                f"RELAY SUSPECTS (do NOT claim local FS): {', '.join(self.provenance.relay_suspects)}"
            )

        if state_summary:
            parts.append(f"STATE: {state_summary}")

        return "\n\n".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_technique(command: str) -> str:
    lower = command.lower()
    if "nmap" in lower:
        return "nmap_scan"
    if "nuclei" in lower:
        return "nuclei_scan"
    if "ffuf" in lower or "gobuster" in lower:
        return "directory_fuzz"
    if "ssh" in lower or "sshpass" in lower:
        return "ssh_auth"
    if "netexec" in lower or "nxc" in lower:
        return "netexec_auth"
    if "curl" in lower or "wget" in lower:
        return "http_request"
    if "sqlmap" in lower:
        return "sql_injection"
    if "hashcat" in lower or "john" in lower:
        return "password_crack"
    if "ping" in lower:
        return "icmp_recon"
    if "hydra" in lower or "medusa" in lower:
        return "brute_force"
    return "other"


def _is_auth_command(command: str) -> bool:
    lower = command.lower()
    return any(x in lower for x in [
        "ssh", "sshpass", "netexec", "nxc", "login",
        "spray", "crack", "hashcat", "john", "hydra", "medusa",
    ])


def _extract_host(command: str) -> str:
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", command)
    return match.group(0) if match else ""


_CRED_PATTERNS = (
    (re.compile(r"sshpass\s+-p\s+['\"]?([^'\"\s]+)['\"]?\s+ssh\s+(?:-[^\s]+\s+)*([A-Za-z0-9._\-]+)@"), "{1}:{0}"),
    (re.compile(r"\bssh\s+(?:-[^\s]+\s+)*([A-Za-z0-9._\-]+)@\d"), "{0}"),
    (re.compile(r"\b(?:nxc|netexec)\s+\S+\s+\S+(?:\s+-\S+\s+\S+)*?\s+-u\s+([^\s]+)\s+-p\s+['\"]?([^'\"\s]+)['\"]?"), "{0}:{1}"),
    (re.compile(r"\bcurl\b[^|]*?\s+-u\s+['\"]?([^'\"\s:]+):([^'\"\s]+)['\"]?"), "{0}:{1}"),
    (re.compile(r"\b(?:hydra|medusa|patator)\b[^|]*?\s+-l\s+([^\s]+)\s+-p\s+([^\s]+)"), "{0}:{1}"),
    (re.compile(r"-U\s+['\"]?([^'\"\s%]+)%([^'\"\s]+)['\"]?"), "{0}:{1}"),
)


def _extract_credential(command: str) -> str:
    for pattern, template in _CRED_PATTERNS:
        match = pattern.search(command)
        if match:
            groups = match.groups()
            return template.format(*groups)
    return ""
