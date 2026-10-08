"""Canonical mission state for the operator-auditor brain.

The ledger is append-only: every claim, command and raw output keeps its
provenance and a reference so the auditor can verify reality rather than trust
summaries. Hosts, credentials, attack paths and coverage are derived from the
ledger and mutated deterministically by EvilKit.
"""

from __future__ import annotations

import dataclasses
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "EvidenceEntry",
    "Host",
    "Service",
    "Credential",
    "Finding",
    "AttackPath",
    "Coverage",
    "MissionState",
    "utc_now",
    "record_evidence",
    "classify_evidence",
    "add_host",
    "add_service",
    "add_credential",
    "add_finding",
    "add_attack_path",
    "update_coverage",
    "detect_thrashing",
    "state_to_json",
    "state_from_json",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class EvidenceEntry:
    turn: int
    timestamp: str
    claim: str
    command: str
    raw_output: str
    provenance: str
    classification: str = "unverified"

    def __post_init__(self) -> None:
        if self.classification not in {"confirmed", "disputed", "unverified"}:
            raise ValueError(f"invalid classification: {self.classification!r}")


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str | None = None
    banner: str | None = None
    evidence_refs: list[int] = field(default_factory=list)


@dataclass
class Host:
    address: str
    hostname: str | None = None
    interfaces: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    trust_boundary: str | None = None
    reachability: dict[str, str] = field(default_factory=dict)
    evidence_refs: list[int] = field(default_factory=list)


@dataclass
class Credential:
    value: str
    type: str
    origin: str
    hosts_where_worked: list[str] = field(default_factory=list)
    privilege: str = "unknown"
    evidence_refs: list[int] = field(default_factory=list)
    redacted: bool = True

    def display_value(self) -> str:
        if self.redacted and self.value:
            return self.value[:2] + "***"
        return self.value


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    host: str | None = None
    evidence_refs: list[int] = field(default_factory=list)
    verified: bool = False

    def __post_init__(self) -> None:
        if self.severity not in {"critical", "high", "medium", "low", "info"}:
            raise ValueError(f"invalid severity: {self.severity!r}")


@dataclass
class AttackPath:
    source: str
    target: str
    technique: str
    prerequisites: list[str] = field(default_factory=list)
    completed: bool = False
    blocked: bool = False
    evidence_refs: list[int] = field(default_factory=list)


@dataclass
class Coverage:
    phases: list[str] = field(
        default_factory=lambda: [
            "recon",
            "enumeration",
            "exploitation",
            "post-exploitation",
            "reporting",
        ]
    )
    by_host: dict[str, dict[str, set[str]]] = field(default_factory=dict)


@dataclass
class MissionState:
    scope: list[str]
    started_at: str = field(default_factory=utc_now)
    turns: int = 0
    evidence: list[EvidenceEntry] = field(default_factory=list)
    hosts: dict[str, Host] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    completed: bool = False
    paused: bool = False
    completion_reason: str = ""


def record_evidence(
    state: MissionState,
    claim: str,
    command: str,
    raw_output: str,
    provenance: str,
    classification: str = "unverified",
) -> MissionState:
    entry = EvidenceEntry(
        turn=state.turns,
        timestamp=utc_now(),
        claim=claim,
        command=command,
        raw_output=raw_output,
        provenance=provenance,
        classification=classification,
    )
    state.evidence.append(entry)
    return state


def classify_evidence(state: MissionState, index: int, classification: str) -> None:
    if classification not in {"confirmed", "disputed", "unverified"}:
        raise ValueError(f"invalid classification: {classification!r}")
    if not 0 <= index < len(state.evidence):
        raise IndexError(f"evidence index {index} out of range")
    entry = state.evidence[index]
    if entry.classification != classification:
        state.evidence[index] = dataclasses.replace(entry, classification=classification)


def add_host(
    state: MissionState,
    address: str,
    *,
    hostname: str | None = None,
    evidence_ref: int | None = None,
) -> Host:
    address = address.lower().strip()
    if address not in state.hosts:
        state.hosts[address] = Host(address=address)
    host = state.hosts[address]
    if hostname:
        host.hostname = hostname
    if evidence_ref is not None and evidence_ref not in host.evidence_refs:
        host.evidence_refs.append(evidence_ref)
    return host


def add_service(
    state: MissionState,
    host_address: str,
    port: int,
    protocol: str = "tcp",
    *,
    name: str | None = None,
    banner: str | None = None,
    evidence_ref: int | None = None,
) -> Service:
    host = add_host(state, host_address)
    for service in host.services:
        if service.port == port and service.protocol == protocol:
            if name:
                service.name = name
            if banner:
                service.banner = banner
            if evidence_ref is not None and evidence_ref not in service.evidence_refs:
                service.evidence_refs.append(evidence_ref)
            return service
    service = Service(port=port, protocol=protocol, name=name, banner=banner)
    if evidence_ref is not None:
        service.evidence_refs.append(evidence_ref)
    host.services.append(service)
    return service


def add_credential(
    state: MissionState,
    value: str,
    type: str,
    origin: str,
    *,
    host_where_worked: str | None = None,
    privilege: str = "unknown",
    evidence_ref: int | None = None,
    redacted: bool = True,
) -> Credential:
    cred = Credential(
        value=value,
        type=type,
        origin=origin,
        hosts_where_worked=[host_where_worked] if host_where_worked else [],
        privilege=privilege,
        evidence_refs=[evidence_ref] if evidence_ref is not None else [],
        redacted=redacted,
    )
    state.credentials.append(cred)
    return cred


def add_finding(
    state: MissionState,
    title: str,
    severity: str,
    description: str,
    *,
    host: str | None = None,
    evidence_ref: int | None = None,
    verified: bool = False,
) -> Finding:
    finding = Finding(
        title=title,
        severity=severity,
        description=description,
        host=host,
        evidence_refs=[evidence_ref] if evidence_ref is not None else [],
        verified=verified,
    )
    state.findings.append(finding)
    return finding


def add_attack_path(
    state: MissionState,
    source: str,
    target: str,
    technique: str,
    *,
    prerequisites: list[str] | None = None,
    completed: bool = False,
    blocked: bool = False,
    evidence_ref: int | None = None,
) -> AttackPath:
    path = AttackPath(
        source=source,
        target=target,
        technique=technique,
        prerequisites=prerequisites or [],
        completed=completed,
        blocked=blocked,
        evidence_refs=[evidence_ref] if evidence_ref is not None else [],
    )
    state.attack_paths.append(path)
    return path


def update_coverage(
    state: MissionState,
    host_address: str,
    service_label: str,
    phase: str,
) -> None:
    if phase not in state.coverage.phases:
        state.coverage.phases.append(phase)
    by_host = state.coverage.by_host
    if host_address not in by_host:
        by_host[host_address] = defaultdict(set)
    by_host[host_address][service_label].add(phase)


def detect_thrashing(state: MissionState, window: int = 5) -> list[str]:
    """Return warnings when recent commands look repetitive or unproductive."""
    warnings: list[str] = []
    recent = [e.command for e in state.evidence[-window:]]
    if len(recent) < 3:
        return warnings

    commands = [cmd for cmd in recent if cmd]
    if len(set(commands)) == 1 and len(commands) > 1:
        warnings.append("identical command repeated")

    failures = sum(
        1
        for e in state.evidence[-window:]
        if "error" in e.raw_output.lower() or "fail" in e.raw_output.lower()
    )
    if failures >= window // 2:
        warnings.append("high failure rate in recent commands")

    return warnings


class _StateEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        if isinstance(obj, set):
            return sorted(obj)
        return super().default(obj)


def state_to_json(state: MissionState) -> str:
    return json.dumps(state, cls=_StateEncoder, indent=2) + "\n"


def state_from_json(text: str) -> MissionState:
    data = json.loads(text)

    def _evidence(entries: list[dict]) -> list[EvidenceEntry]:
        return [EvidenceEntry(**e) for e in entries]

    def _service(entry: dict) -> Service:
        return Service(**entry)

    def _host(entry: dict) -> Host:
        entry["services"] = [_service(s) for s in entry.get("services", [])]
        return Host(**entry)

    def _credential(entry: dict) -> Credential:
        return Credential(**entry)

    def _finding(entry: dict) -> Finding:
        return Finding(**entry)

    def _path(entry: dict) -> AttackPath:
        return AttackPath(**entry)

    def _coverage(entry: dict) -> Coverage:
        by_host = {
            host: {svc: set(phases) for svc, phases in svcs.items()}
            for host, svcs in entry.get("by_host", {}).items()
        }
        return Coverage(phases=entry.get("phases", Coverage().phases), by_host=by_host)

    return MissionState(
        scope=data.get("scope", []),
        started_at=data.get("started_at", utc_now()),
        turns=data.get("turns", 0),
        evidence=_evidence(data.get("evidence", [])),
        hosts={k: _host(v) for k, v in data.get("hosts", {}).items()},
        credentials=[_credential(c) for c in data.get("credentials", [])],
        findings=[_finding(f) for f in data.get("findings", [])],
        attack_paths=[_path(p) for p in data.get("attack_paths", [])],
        coverage=_coverage(data.get("coverage", {})),
        completed=data.get("completed", False),
        paused=data.get("paused", False),
        completion_reason=data.get("completion_reason", ""),
    )
