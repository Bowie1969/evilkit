"""Harness-level guards: objective tracking, budgets, circuit breakers, loop detection, evidence journal.

The harness owns the canonical facts ledger, checks success after every tool
result, enforces attempt caps, detects reasoning spirals, and auto-journals
every command/output/artifact to evidence/ with timestamps.
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
    "HarnessState",
]


# ---------------------------------------------------------------------------
# Objective tracking
# ---------------------------------------------------------------------------

@dataclass
class Objective:
    """A machine-readable goal with a success predicate."""
    name: str
    description: str
    success_predicate: str  # human-readable condition
    check_fn: str  # key in raw_output that proves success
    met: bool = False
    met_at: str = ""

    def check(self, raw_output: str, ledger: "FactsLedger") -> bool:
        """Return True when the predicate is satisfied."""
        if self.met:
            return True
        if self.check_fn == "crown01_records":
            # Look for evidence of /srv/records content from crown01
            if "/srv/records" in raw_output and ("payroll" in raw_output.lower() or "client" in raw_output.lower()):
                self.met = True
                self.met_at = _utc_now_iso()
                return True
        elif self.check_fn == "host_discovered":
            # Check if the target host is in the ledger
            if self.name.lower() in raw_output.lower():
                ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw_output)
                if ip_match:
                    self.met = True
                    self.met_at = _utc_now_iso()
                    return True
        elif self.check_fn == "cred_recovered":
            if "password" in raw_output.lower() or "credential" in raw_output.lower():
                self.met = True
                self.met_at = _utc_now_iso()
                return True
        elif self.check_fn == "flag_captured":
            if re.search(r"flag\{[^}]+\}", raw_output):
                self.met = True
                self.met_at = _utc_now_iso()
                return True
        elif self.check_fn == "custom":
            # Generic: the predicate text appears in output
            if self.success_predicate.lower() in raw_output.lower():
                self.met = True
                self.met_at = _utc_now_iso()
                return True
        return False


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
    file_hashes: dict[str, str] = field(default_factory=dict)  # path -> sha256
    network_paths: list[dict] = field(default_factory=list)  # actual TCP routes
    findings: list[dict] = field(default_factory=list)

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

    def add_cred(self, host: str, username: str, password: str, source: str = "") -> None:
        key = f"{host}:{username}"
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
            return False  # already captured
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
        entry = {"src": src, "dst": dst, "port": port, "protocol": protocol, "recorded_at": _utc_now_iso()}
        if entry not in self.network_paths:
            self.network_paths.append(entry)

    def summary(self) -> str:
        lines = [
            f"HOSTS: {len(self.hosts)}",
        ]
        for h in self.hosts:
            svcs = ", ".join(f"{s.get('port', '?')}/{s.get('protocol', '?')}" for s in h.get("services", []))
            lines.append(f"  {h['address']} ({h.get('hostname', '?')}) [{svcs or 'no services'}]")
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
        }


# ---------------------------------------------------------------------------
# Attempt budgets & circuit breakers
# ---------------------------------------------------------------------------

@dataclass
class AttemptBudget:
    """Per-host/per-service/per-credential attempt caps enforced by the harness."""
    max_per_host_auth: int = 5       # failed auths per host before hard-lock
    max_per_service_auth: int = 3    # failed auths per service before hard-lock
    max_per_cred_per_host: int = 3   # L3: same (host, cred) pair before cred lock
    max_global_actions: int = 100    # total action budget
    max_per_technique: int = 15      # per-technique budget (e.g. brute-force)

    host_attempts: dict[str, int] = field(default_factory=dict)
    service_attempts: dict[str, int] = field(default_factory=dict)
    cred_attempts: dict[str, int] = field(default_factory=dict)
    technique_counts: dict[str, int] = field(default_factory=dict)
    total_actions: int = 0
    locked_vectors: list[str] = field(default_factory=list)
    locked_creds: list[str] = field(default_factory=list)

    def record_action(self, technique: str = "") -> None:
        self.total_actions += 1
        if technique:
            self.technique_counts[technique] = self.technique_counts.get(technique, 0) + 1

    def record_auth_attempt(self, host: str, service: str = "", credential: str = "") -> str | None:
        """Record an auth attempt. Returns a lock message if cap exceeded, else None.

        L3 graduation: a per-(host, credential) cap fires BEFORE the per-host cap, so a
        single credential that fails N times against one host is hard-locked while the
        host itself remains open to other credentials.
        """
        self.host_attempts[host] = self.host_attempts.get(host, 0) + 1
        key = f"{host}:{service}" if service else host
        self.service_attempts[key] = self.service_attempts.get(key, 0) + 1

        if credential:
            cred_key = f"{host}|{credential}"
            self.cred_attempts[cred_key] = self.cred_attempts.get(cred_key, 0) + 1
            if self.cred_attempts[cred_key] >= self.max_per_cred_per_host:
                msg = (f"CRED LOCK: credential '{credential}' failed "
                       f"{self.cred_attempts[cred_key]}× on {host} — "
                       f"stop retrying this cred here (L3). Harvest a new cred or pivot.")
                if cred_key not in self.locked_creds:
                    self.locked_creds.append(cred_key)
                return msg

        if self.host_attempts[host] >= self.max_per_host_auth:
            msg = f"AUTH LOCK: {host} — {self.host_attempts[host]} failed attempts, no cred exists here, pivot."
            self.locked_vectors.append(key)
            return msg
        if service and self.service_attempts[key] >= self.max_per_service_auth:
            msg = f"AUTH LOCK: {key} — {self.service_attempts[key]} failed attempts, no cred exists here, pivot."
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

    def summary(self) -> str:
        lines = [
            f"ACTION BUDGET: {self.total_actions}/{self.max_global_actions}",
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
        """Return a lock message if the vector should be blocked, else None."""
        if host and credential and self.budget.is_cred_locked(host, credential):
            return (f"CIRCUIT BREAKER: credential '{credential}' is cred-locked on {host} "
                    f"(L3: same cred failed ≥{self.budget.max_per_cred_per_host}×) — "
                    f"use a different credential or pivot.")
        if technique and self.budget.technique_exhausted(technique):
            return f"CIRCUIT BREAKER: technique '{technique}' exhausted ({self.budget.max_per_technique} attempts) — replan strategy."
        if self.budget.is_exhausted():
            return f"CIRCUIT BREAKER: global action budget exhausted ({self.budget.max_global_actions}) — replan strategy."
        key = f"{host}:{service}" if service else host
        if self.budget.is_locked(key):
            return f"CIRCUIT BREAKER: {key} is hard-locked — pivot to another vector."
        return None


# ---------------------------------------------------------------------------
# Loop & stall guards
# ---------------------------------------------------------------------------

@dataclass
class LoopDetector:
    """Detects reasoning spirals and command repetition."""
    recent_commands: list[str] = field(default_factory=list)
    recent_thoughts: list[str] = field(default_factory=list)
    max_window: int = 7
    ngram_size: int = 3
    last_action_time: float = field(default_factory=time.time)
    stall_timeout: int = 120  # seconds without a tool call

    def record_command(self, cmd: str) -> list[str]:
        """Record a command and return warnings if repetition detected."""
        self.recent_commands.append(cmd)
        if len(self.recent_commands) > self.max_window:
            self.recent_commands = self.recent_commands[-self.max_window:]
        return self._check_repetition()

    def record_thought(self, thought: str) -> list[str]:
        self.recent_thoughts.append(thought)
        if len(self.recent_thoughts) > self.max_window:
            self.recent_thoughts = self.recent_thoughts[-self.max_window:]
        return self._check_thought_repetition()

    def check_stall(self) -> str | None:
        """Return a stall warning if no action emitted within timeout."""
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

        # Exact repetition
        if len(set(cmds[-3:])) == 1:
            warnings.append(f"REPETITION: identical command repeated 3x: {cmds[-1][:60]}...")

        # N-gram similarity
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
        # Simple: check for identical thought prefixes
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
        """Write one evidence entry. Returns the file path."""
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
        """Assemble the report skeleton from current evidence."""
        lines = [
            "# Engagement Report",
            f"Generated: {_utc_now_iso()}",
            "",
            "## Objectives",
        ]
        for obj in objectives:
            status = "MET" if obj.met else "PENDING"
            lines.append(f"- [{status}] {obj.name}: {obj.description}")

        lines += ["", "## Facts Ledger", "", ledger.summary(), ""]

        lines += ["## Findings", ""]
        for f in ledger.findings:
            lines.append(f"- [{f.get('severity', 'info')}] {f.get('title', 'unknown')} on {f.get('host', '?')}")

        lines += ["", "## Evidence Files", ""]
        for p in sorted(self.evidence_dir.glob("*")):
            lines.append(f"- `{p.name}`")

        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Provenance checker
# ---------------------------------------------------------------------------

class ProvenanceChecker:
    """Correlates agent actions with network truth; flags suspicious provenance."""

    def __init__(self, ledger: FactsLedger) -> None:
        self.ledger = ledger

    def check_unauthenticated_success(self, command: str, raw_output: str) -> str | None:
        """On unauthenticated success (plain GET returning files, open dir listing),
        auto-raise a 'suspect relay/proxy, not local FS' prompt."""
        lower_cmd = command.lower()
        lower_out = raw_output.lower()

        # Detect plain HTTP GET returning file listings or data
        if ("curl" in lower_cmd or "wget" in lower_cmd or "http" in lower_cmd):
            if any(marker in lower_out for marker in [
                "directory", "index of", "parent directory",
                "payroll", "client", "financial", "records",
            ]):
                # Check if this came through a known pivot path
                pivot_hosts = {h["address"] for h in self.ledger.hosts
                              if any("pivot" in s.get("name", "").lower() or "proxy" in s.get("name", "").lower()
                                     for s in h.get("services", []))}
                if pivot_hosts:
                    return (
                        f"PROVENANCE ALERT: unauthenticated HTTP success returned sensitive data. "
                        f"Suspect relay/proxy via {', '.join(pivot_hosts)}, not local FS — confirm the serving host."
                    )
                return (
                    "PROVENANCE ALERT: unauthenticated HTTP success returned sensitive data. "
                    "Suspect relay/proxy, not local FS — confirm the serving host."
                )
        return None

    def correlate_network_path(self, src: str, dst: str, port: int) -> str:
        """Ground 'where did this really come from' in the TCP path."""
        path_str = f"{src} -> {dst}:{port}"
        self.ledger.add_network_path(src, dst, port)
        # Build the full chain from ledger
        chain = self._build_chain(dst)
        if chain:
            return f"NETWORK TRUTH: actual TCP path: {' -> '.join(chain)}"
        return f"NETWORK TRUTH: direct {path_str}"

    def _build_chain(self, target: str) -> list[str] | None:
        """Walk network_paths backwards from target to find the full chain."""
        # Simple backward walk
        visited = set()
        chain = [target]
        current = target
        for _ in range(10):  # max depth
            if current in visited:
                break
            visited.add(current)
            # Find a path ending at current
            for np in self.ledger.network_paths:
                if np["dst"] == current and np["src"] not in visited:
                    chain.insert(0, np["src"])
                    current = np["src"]
                    break
            else:
                break
        return chain if len(chain) > 1 else None


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
    objective_met_injection: str = ""

    def __post_init__(self) -> None:
        if self.evidence_journal is None:
            self.evidence_journal = EvidenceJournal(evidence_dir=Path("evidence"))
        if self.provenance is None:
            self.provenance = ProvenanceChecker(self.ledger)
        self.circuit_breaker = CircuitBreaker(self.budget)

    def check_objectives(self, raw_output: str) -> str | None:
        """Check all objectives. Return injection message if any newly met."""
        for obj in self.objectives:
            if not obj.met and obj.check(raw_output, self.ledger):
                return f"OBJECTIVE MET — {obj.name}: {obj.description}. Stop or justify continuing."
        return None

    def pre_action_check(self, host: str = "", service: str = "", technique: str = "", credential: str = "") -> str | None:
        """Run circuit breaker + budget checks before allowing an action."""
        cb = self.circuit_breaker.check(host, service, technique, credential=credential)
        if cb:
            return cb
        if self.budget.is_exhausted():
            return "BUDGET EXHAUSTED: global action limit reached — force strategy replan."
        return None

    def record_action(self, turn: int, command: str, stdout: str, stderr: str, returncode: int,
                      goal: str = "", reasoning: str = "") -> list[str]:
        """Record an action and return any warnings generated."""
        warnings = []

        # Budget
        self.budget.record_action(technique=_extract_technique(command))

        # Auth attempt tracking (host + credential-aware for L3)
        if _is_auth_command(command):
            host = _extract_host(command)
            credential = _extract_credential(command)
            # Only count attempts that FAILED. On the brain path we don't yet have a
            # reliable success classifier for every auth command, so key off common
            # failure signatures in stdout/stderr; if neither is present and
            # returncode != 0, treat as failure. This keeps a successful first-try
            # login from being counted toward the L3 cred cap.
            combined = f"{stdout}\n{stderr}".lower()
            failure_signals = (
                "permission denied", "authentication failure", "failed password",
                "access denied", "login incorrect", "invalid credentials",
                "connection closed by authenticating user",
            )
            succeeded = returncode == 0 and not any(s in combined for s in failure_signals)
            if not succeeded:
                lock_msg = self.budget.record_auth_attempt(
                    host=host, credential=credential,
                )
                if lock_msg:
                    warnings.append(lock_msg)

        # Loop detection
        self.loop_detector.touch()
        warnings.extend(self.loop_detector.record_command(command))
        if reasoning:
            warnings.extend(self.loop_detector.record_thought(reasoning))

        # Stall check
        stall = self.loop_detector.check_stall()
        if stall:
            warnings.append(stall)

        # Evidence journal
        if self.evidence_journal:
            self.evidence_journal.record_command(turn, command, stdout, stderr, returncode)

        # Objective check
        obj_msg = self.check_objectives(stdout)
        if obj_msg:
            warnings.append(obj_msg)

        return warnings

    def inject_context(self, state_summary: str = "") -> str:
        """Build enriched context injection for the operator."""
        parts = []
        if self.ledger.hosts or self.ledger.creds or self.ledger.flags:
            parts.append(f"FACTS LEDGER:\n{self.ledger.summary()}")
        if self.budget.total_actions > 0:
            parts.append(f"BUDGET:\n{self.budget.summary()}")
        met_objs = [o.name for o in self.objectives if o.met]
        pending_objs = [o.name for o in self.objectives if not o.met]
        if met_objs or pending_objs:
            parts.append(f"OBJECTIVES: met={met_objs}, pending={pending_objs}")
        if state_summary:
            parts.append(f"STATE: {state_summary}")
        return "\n\n".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_technique(command: str) -> str:
    """Crude technique extraction from command."""
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
    return "other"


def _is_auth_command(command: str) -> bool:
    lower = command.lower()
    return any(x in lower for x in ["ssh", "sshpass", "netexec", "nxc", "login", "spray", "crack", "hashcat", "john"])


def _extract_host(command: str) -> str:
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", command)
    return match.group(0) if match else ""


_CRED_PATTERNS = (
    # sshpass -p 'pw' ssh user@host
    (re.compile(r"sshpass\s+-p\s+['\"]?([^'\"\s]+)['\"]?\s+ssh\s+(?:-[^\s]+\s+)*([A-Za-z0-9._\-]+)@"), "{1}:{0}"),
    # ssh user@host  (user only; cred == username, password unknown)
    (re.compile(r"\bssh\s+(?:-[^\s]+\s+)*([A-Za-z0-9._\-]+)@\d"), "{0}"),
    # nxc/netexec PROTO HOST -u user -p pass
    (re.compile(r"\b(?:nxc|netexec)\s+\S+\s+\S+(?:\s+-\S+\s+\S+)*?\s+-u\s+([^\s]+)\s+-p\s+['\"]?([^'\"\s]+)['\"]?"), "{0}:{1}"),
    # curl -u user:pass
    (re.compile(r"\bcurl\b[^|]*?\s+-u\s+['\"]?([^'\"\s:]+):([^'\"\s]+)['\"]?"), "{0}:{1}"),
    # hydra/medusa -l user -p pass
    (re.compile(r"\b(?:hydra|medusa|patator)\b[^|]*?\s+-l\s+([^\s]+)\s+-p\s+([^\s]+)"), "{0}:{1}"),
    # smbclient //host/share -U user%pass
    (re.compile(r"-U\s+['\"]?([^'\"\s%]+)%([^'\"\s]+)['\"]?"), "{0}:{1}"),
)


def _extract_credential(command: str) -> str:
    """Best-effort credential identifier from a command. '' if nothing recognisable.

    Returns 'user:pass' when both known, 'user' when only the username is visible
    (ssh with key auth or agent). The identifier is only used as a dict key for
    the L3 per-(host, cred) cap, so collisions on 'user' alone are the intended
    behaviour — the operator should not keep retrying the same username either.
    """
    for pattern, template in _CRED_PATTERNS:
        match = pattern.search(command)
        if match:
            groups = match.groups()
            return template.format(*groups)
    return ""
