"""Trust mapper — discovers trust relationships and maps shortest path to crown jewels.

Read-only scanning of SSH config, sudoers, NFS mounts, network reachability,
and service-to-service trust on Linux systems. Builds a directed graph of trust
edges between hosts and computes BFS shortest paths from the current host to
each crown jewel.

Usage:
    from trust_mapper import build_trust_graph, render_graph_ascii
    graph = build_trust_graph("localhost", scan_range="10.0.0.0/24", crown_jewels=["10.0.0.5"])
    print(render_graph_ascii(graph))
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TrustNode:
    """A host in the trust graph."""
    hostname: str
    ip: str = ""
    compromised: bool = False
    is_crown_jewel: bool = False
    trust_out: list[str] = field(default_factory=list)
    trust_in: list[str] = field(default_factory=list)
    business_value: int = 0  # 0-10, derived from file/share analysis
    data_sensitivity: str = ""  # none/low/medium/high/critical
    org_role: str = ""  # inferred role: fileserver, webserver, workstation, domain_controller, etc


@dataclass
class TrustEdge:
    """A directed trust relationship between two hosts."""
    source_host: str
    target_host: str
    trust_type: str  # ssh_key, shared_cred, nfs, sudo, network
    strength: float = 0.5  # 0.0 - 1.0
    exploitable: bool = False
    evidence: str = ""


@dataclass
class TrustGraph:
    """Complete trust graph for a network segment."""
    nodes: dict[str, TrustNode] = field(default_factory=dict)  # key = ip or hostname
    edges: list[TrustEdge] = field(default_factory=list)
    shortest_paths: dict[str, list[str]] = field(default_factory=dict)  # crown_jewel -> [hop, ...]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_read(path: str) -> str | None:
    """Read a file, returning None on any error."""
    try:
        p = Path(path)
        if not p.is_file():
            return None
        return p.read_text(errors="replace")
    except (OSError, PermissionError, ValueError):
        return None


def _safe_list_dir(path: str) -> list[str]:
    """List directory entries, returning empty list on error."""
    try:
        return os.listdir(path)
    except (OSError, PermissionError):
        return []


def _resolve_hostname(host: str) -> str:
    """Try to resolve a hostname to an IP, return original on failure."""
    try:
        result = subprocess.run(
            ["getent", "ahosts", host],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout:
            first_line = result.stdout.splitlines()[0]
            return first_line.split()[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return host


def _ping_host(host: str, timeout: int = 2) -> bool:
    """Check if a host is reachable via ICMP."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            capture_output=True, text=True, timeout=timeout + 5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR range to a list of IP strings. Caps at 256 hosts."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.prefixlen < 24:
            # Too large — return first and last 128 to cap
            hosts = list(network.hosts())
            return [str(h) for h in hosts[:128]] + [str(h) for h in hosts[-128:]]
        return [str(h) for h in network.hosts()]
    except ValueError:
        return []


def _add_node(graph: TrustGraph, key: str, hostname: str = "", ip: str = "") -> None:
    """Add a node if it does not already exist."""
    if key not in graph.nodes:
        graph.nodes[key] = TrustNode(
            hostname=hostname or key,
            ip=ip or key,
        )


def _add_edge(
    graph: TrustGraph,
    source: str,
    target: str,
    trust_type: str,
    strength: float,
    exploitable: bool,
    evidence: str,
) -> None:
    """Add a directed edge and update node trust lists."""
    edge = TrustEdge(
        source_host=source,
        target_host=target,
        trust_type=trust_type,
        strength=strength,
        exploitable=exploitable,
        evidence=evidence,
    )
    graph.edges.append(edge)
    if source in graph.nodes:
        if target not in graph.nodes[source].trust_out:
            graph.nodes[source].trust_out.append(target)
    if target in graph.nodes:
        if source not in graph.nodes[target].trust_in:
            graph.nodes[target].trust_in.append(source)


# ---------------------------------------------------------------------------
# Scanners — each populates the graph in-place
# ---------------------------------------------------------------------------

def _scan_ssh_known_hosts(graph: TrustGraph, current_ip: str) -> None:
    """Parse ~/.ssh/known_hosts and add edges to discovered hosts."""
    content = _safe_read(os.path.expanduser("~/.ssh/known_hosts"))
    if not content:
        return

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if not parts:
            continue
        host_field = parts[0]
        # known_hosts can have comma-separated aliases
        for alias in host_field.split(","):
            alias = alias.strip()
            if not alias or alias.startswith("|"):  # hashed entries
                continue
            resolved = _resolve_hostname(alias)
            _add_node(graph, resolved, hostname=alias, ip=resolved)
            _add_edge(
                graph,
                source=current_ip,
                target=resolved,
                trust_type="ssh_key",
                strength=0.7,
                exploitable=True,
                evidence="found in ~/.ssh/known_hosts: " + alias,
            )


def _scan_ssh_authorized_keys(graph: TrustGraph, current_ip: str) -> None:
    """Count authorized_keys and add a self-referential trust node."""
    content = _safe_read(os.path.expanduser("~/.ssh/authorized_keys"))
    if not content:
        return

    key_count = 0
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("ssh-"):
            continue
        if line.startswith(("ssh-", "ecdsa-", "sk-")):
            key_count += 1

    if key_count > 0:
        _add_node(graph, current_ip, hostname="localhost", ip=current_ip)
        # High key count = more potential lateral movement vectors
        strength = min(1.0, 0.3 + (key_count * 0.1))
        _add_edge(
            graph,
            source=current_ip,
            target=current_ip,
            trust_type="ssh_key",
            strength=strength,
            exploitable=False,
            evidence=str(key_count) + " authorized_keys entries",
        )


def _scan_ssh_config(graph: TrustGraph, current_ip: str) -> None:
    """Parse ~/.ssh/config for Host/Hostname entries."""
    content = _safe_read(os.path.expanduser("~/.ssh/config"))
    if not content:
        return

    current_host_block: str | None = None
    hostname_for_block: str | None = None

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        lower = stripped.lower()
        if lower.startswith("host ") and not lower.startswith("hostname"):
            # Flush previous block
            if current_host_block and hostname_for_block:
                resolved = _resolve_hostname(hostname_for_block)
                _add_node(graph, resolved, hostname=current_host_block, ip=resolved)
                _add_edge(
                    graph,
                    source=current_ip,
                    target=resolved,
                    trust_type="ssh_key",
                    strength=0.8,
                    exploitable=True,
                    evidence="~/.ssh/config: Host " + current_host_block + " -> " + hostname_for_block,
                )
            current_host_block = stripped.split(None, 1)[-1].strip()
            hostname_for_block = None
        elif lower.startswith("hostname "):
            hostname_for_block = stripped.split(None, 1)[-1].strip()

    # Flush last block
    if current_host_block and hostname_for_block:
        resolved = _resolve_hostname(hostname_for_block)
        _add_node(graph, resolved, hostname=current_host_block, ip=resolved)
        _add_edge(
            graph,
            source=current_ip,
            target=resolved,
            trust_type="ssh_key",
            strength=0.8,
            exploitable=True,
            evidence="~/.ssh/config: Host " + current_host_block + " -> " + hostname_for_block,
        )


def _scan_sudoers(graph: TrustGraph, current_ip: str) -> None:
    """Check /etc/sudoers and /etc/sudoers.d/* for NOPASSWD entries."""
    sudoers_files = ["/etc/sudoers"]
    sudoers_d = "/etc/sudoers.d"
    if os.path.isdir(sudoers_d):
        for entry in _safe_list_dir(sudoers_d):
            full = os.path.join(sudoers_d, entry)
            if os.path.isfile(full):
                sudoers_files.append(full)

    nopasswd_entries: list[str] = []
    for sf in sudoers_files:
        content = _safe_read(sf)
        if not content:
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "NOPASSWD" in line:
                nopasswd_entries.append(line)

    if nopasswd_entries:
        _add_node(graph, current_ip, hostname="localhost", ip=current_ip)
        # NOPASSWD = very strong trust, highly exploitable
        for entry in nopasswd_entries[:10]:  # Cap evidence length
            _add_edge(
                graph,
                source=current_ip,
                target=current_ip,
                trust_type="sudo",
                strength=0.95,
                exploitable=True,
                evidence="sudoers NOPASSWD: " + entry[:120],
            )


def _scan_nfs_mounts(graph: TrustGraph, current_ip: str) -> None:
    """Check /etc/fstab and mount output for NFS shares."""
    # Scan /etc/fstab
    content = _safe_read("/etc/fstab")
    nfs_servers: set[str] = set()
    if content:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 3 and "nfs" in parts[2].lower():
                server = parts[0].split(":")[0] if ":" in parts[0] else parts[0]
                nfs_servers.add(server)

    # Also check live mounts
    try:
        result = subprocess.run(
            ["mount"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if " type nfs " in line or " nfs " in line:
                    # Format: server:/path on /local type nfs ...
                    match = re.match(r"^(\S+):", line)
                    if match:
                        server = match.group(1)
                        nfs_servers.add(server)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    for server in nfs_servers:
        resolved = _resolve_hostname(server)
        _add_node(graph, resolved, hostname=server, ip=resolved)
        _add_edge(
            graph,
            source=current_ip,
            target=resolved,
            trust_type="nfs",
            strength=0.6,
            exploitable=True,
            evidence="NFS mount from: " + server,
        )


def _scan_network_reachability(graph: TrustGraph, current_ip: str, scan_range: str, known_hosts: list[str]) -> None:
    """Ping hosts in scan_range and known_hosts list."""
    targets: set[str] = set(known_hosts)

    if scan_range:
        targets.update(_expand_cidr(scan_range))

    # Cap total pings to avoid long runs
    targets_list = list(targets)[:128]

    for target in targets_list:
        if target == current_ip:
            continue
        if _ping_host(target, timeout=1):
            resolved = _resolve_hostname(target)
            _add_node(graph, resolved, hostname=target, ip=resolved)
            _add_edge(
                graph,
                source=current_ip,
                target=resolved,
                trust_type="network",
                strength=0.3,
                exploitable=False,
                evidence="ICMP reachable: " + target,
            )


def _scan_etc_hosts(graph: TrustGraph, current_ip: str) -> None:
    """Parse /etc/hosts for static hostname-to-IP mappings."""
    content = _safe_read("/etc/hosts")
    if not content:
        return

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip inline comments
        if "#" in line:
            line = line[:line.index("#")].strip()
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_addr = parts[0]
        # Skip loopback and multicast
        if ip_addr.startswith("127.") or ip_addr.startswith("::") or ip_addr == "0.0.0.0":
            continue
        for name in parts[1:]:
            _add_node(graph, ip_addr, hostname=name, ip=ip_addr)
            _add_edge(
                graph,
                source=current_ip,
                target=ip_addr,
                trust_type="network",
                strength=0.4,
                exploitable=False,
                evidence="/etc/hosts: " + ip_addr + " -> " + name,
            )


def _scan_listening_ports(graph: TrustGraph, current_ip: str) -> None:
    """Check listening TCP/UDP ports as service-to-service trust indicators."""
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            # Fallback to netstat
            result = subprocess.run(
                ["netstat", "-tlnp"],
                capture_output=True, text=True, timeout=10
            )
        if result.returncode != 0:
            return

        services: list[str] = []
        for line in result.stdout.splitlines()[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4:
                local_addr = parts[3] if len(parts) > 3 else parts[2]
                # Extract port
                if ":" in local_addr:
                    port = local_addr.rsplit(":", 1)[-1]
                    if port.isdigit():
                        services.append(port)

        if services:
            _add_node(graph, current_ip, hostname="localhost", ip=current_ip)
            unique_ports = sorted(set(services))
            _add_edge(
                graph,
                source=current_ip,
                target=current_ip,
                trust_type="network",
                strength=0.2,
                exploitable=False,
                evidence="listening ports: " + ", ".join(unique_ports[:20]),
            )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


# ---------------------------------------------------------------------------
# BFS shortest paths
# ---------------------------------------------------------------------------

def _compute_shortest_paths(graph: TrustGraph, start_key: str) -> dict[str, list[str]]:
    """BFS from start_key to all crown_jewel nodes. Returns {crown_jewel_key: [path]}."""
    if start_key not in graph.nodes:
        return {}

    crown_jewel_keys = {k for k, v in graph.nodes.items() if v.is_crown_jewel}
    if not crown_jewel_keys:
        return {}

    # BFS
    visited: dict[str, str | None] = {start_key: None}  # node -> parent
    queue = deque([start_key])
    found: set[str] = set()

    while queue:
        current = queue.popleft()
        if current in crown_jewel_keys:
            found.add(current)
            if len(found) == len(crown_jewel_keys):
                break

        node = graph.nodes.get(current)
        if not node:
            continue

        for neighbor in node.trust_out:
            if neighbor not in visited:
                visited[neighbor] = current
                queue.append(neighbor)

    # Reconstruct paths
    paths: dict[str, list[str]] = {}
    for cj_key in crown_jewel_keys:
        if cj_key not in visited:
            continue
        path: list[str] = []
        current: str | None = cj_key
        while current is not None:
            path.append(current)
            current = visited[current]
        path.reverse()
        paths[cj_key] = path

    return paths


# ---------------------------------------------------------------------------
# ASCII renderer
# ---------------------------------------------------------------------------

def render_graph_ascii(graph: TrustGraph) -> str:
    """Return a string visualization of the trust graph."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("TRUST GRAPH")
    lines.append("=" * 60)
    lines.append("")

    # Summary
    lines.append("Nodes: " + str(len(graph.nodes)))
    lines.append("Edges: " + str(len(graph.edges)))
    lines.append("Crown jewels: " + str(sum(1 for n in graph.nodes.values() if n.is_crown_jewel)))
    lines.append("")

    # Node table
    lines.append("-" * 60)
    lines.append("NODES")
    lines.append("-" * 60)
    for key, node in sorted(graph.nodes.items()):
        flags = []
        if node.compromised:
            flags.append("COMPROMISED")
        if node.is_crown_jewel:
            flags.append("CROWN JEWEL")
        flag_str = " [" + ", ".join(flags) + "]" if flags else ""
        lines.append("  " + key + " (" + node.hostname + ")" + flag_str)
        if node.trust_out:
            lines.append("    -> " + ", ".join(node.trust_out))
        if node.trust_in:
            lines.append("    <- " + ", ".join(node.trust_in))
    lines.append("")

    # Edge table
    lines.append("-" * 60)
    lines.append("EDGES")
    lines.append("-" * 60)
    for edge in graph.edges:
        exploit_marker = " [!]" if edge.exploitable else ""
        lines.append(
            "  " + edge.source_host + " --(" + edge.trust_type + ", "
            + str(edge.strength) + ")" + exploit_marker + "-> " + edge.target_host
        )
        if edge.evidence:
            evidence_preview = edge.evidence[:80]
            lines.append("      evidence: " + evidence_preview)
    lines.append("")

    # Shortest paths
    if graph.shortest_paths:
        lines.append("-" * 60)
        lines.append("SHORTEST PATHS TO CROWN JEWELS")
        lines.append("-" * 60)
        for cj_key, path in graph.shortest_paths.items():
            lines.append("  " + " -> ".join(path) + "  (" + str(len(path) - 1) + " hops)")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _assess_business_value(graph: TrustGraph, crown_jewels: list[str]) -> None:
    """Weight each node by business value based on discovered files, shares, and services.

    Scans local filesystem and network shares for organizational clues:
    - File share names (payroll, clients, board, finance → high value)
    - Service types (web server on :8080 serving records → crown jewel)
    - Directory structure (client folders, HR, accounting → high sensitivity)
    - Crown jewel designation (explicit → critical)

    Sets business_value (0-10), data_sensitivity, and org_role on each node.
    """
    # Crown jewels are automatically critical
    for ip, node in graph.nodes.items():
        if node.is_crown_jewel or ip in crown_jewels:
            node.business_value = 10
            node.data_sensitivity = "critical"
            if not node.org_role:
                node.org_role = "crown_jewel"

    # Score based on discovered services
    service_scores = {
        "http": 3, "https": 3, "smb": 5, "nfs": 5,
        "ssh": 2, "rdp": 4, "ldap": 6, "kerberos": 6,
        "mssql": 7, "oracle": 7, "postgresql": 6,
        "ftp": 4, "smtp": 3, "imap": 3,
    }

    for edge in graph.edges:
        target = edge.target_host
        if target in graph.nodes:
            node = graph.nodes[target]
            # Score based on trust type
            type_scores = {
                "nfs": 5, "smb_share": 5, "ssh_key": 4,
                "shared_cred": 4, "sudo": 6, "network": 1,
            }
            node.business_value = max(node.business_value, type_scores.get(edge.trust_type, 1))

            # Score based on services (from edge evidence)
            for svc, score in service_scores.items():
                if svc in edge.evidence.lower():
                    node.business_value = max(node.business_value, score)
                    if score >= 6:
                        node.data_sensitivity = max(node.data_sensitivity, "high", key=lambda x: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(x, 0))

    # Scan local filesystem for org structure clues. One bounded walk per
    # directory — the previous version ran 16 rglob passes over /home, /tmp,
    # /srv, /var/www and /opt (80 full-tree walks) and blocked for minutes
    # on any real disk, taking the MCP server past any client timeout.
    org_indicators = {
        "payroll": (8, "high", "hr_payroll"),
        "client": (7, "high", "client_services"),
        "board": (9, "critical", "executive"),
        "finance": (8, "high", "finance"),
        "accounting": (8, "high", "finance"),
        "tax": (7, "high", "finance"),
        "audit": (6, "medium", "compliance"),
        "hr": (7, "high", "hr_payroll"),
        "medical": (9, "critical", "healthcare"),
        "patient": (9, "critical", "healthcare"),
        "source": (6, "medium", "engineering"),
        "code": (5, "medium", "engineering"),
        "inventory": (5, "medium", "operations"),
        "supply": (6, "medium", "operations"),
    }

    _PRUNE_DIRS = {"node_modules", ".git", "__pycache__", ".cache", ".npm", ".cargo", ".rustup"}
    _MAX_DEPTH = 4
    _SCAN_BUDGET_SECONDS = float(os.environ.get("TRUST_MAPPER_FS_BUDGET", "10"))

    found: set[str] = set()
    deadline = time.monotonic() + _SCAN_BUDGET_SECONDS
    for scan_dir in (Path("/home"), Path("/tmp"), Path("/srv"), Path("/var/www"), Path("/opt")):
        if not scan_dir.is_dir():
            continue
        base_parts = len(scan_dir.parts)
        for root, dirs, files in os.walk(scan_dir, followlinks=False):
            if time.monotonic() > deadline:
                break
            depth = len(Path(root).parts) - base_parts
            if depth >= _MAX_DEPTH:
                dirs[:] = []
            else:
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in _PRUNE_DIRS]
            for name in files:
                if not name.startswith("."):
                    found.add(name.lower())
            if time.monotonic() > deadline:
                break

    for indicator, (score, sensitivity, role) in org_indicators.items():
        if any(indicator in name for name in found):
            # Apply to current host node
            current_node = graph.nodes.get("localhost", graph.nodes.get("127.0.0.1"))
            if current_node:
                current_node.business_value = max(current_node.business_value, score)
                current_node.data_sensitivity = max(
                    current_node.data_sensitivity, sensitivity,
                    key=lambda x: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(x, 0)
                )
                if not current_node.org_role:
                    current_node.org_role = role

    # Default values for unassessed nodes
    for node in graph.nodes.values():
        if not node.data_sensitivity:
            node.data_sensitivity = "low"
        if not node.org_role:
            node.org_role = "unknown"


def build_trust_graph(
    current_host: str = "localhost",
    scan_range: str = "",
    known_hosts: str | list[str] = "",
    crown_jewels: str | list[str] = "",
    json_output: bool = False,
) -> TrustGraph | str:
    """Discover trust relationships and build a trust graph.

    Args:
        current_host: Host identifier for the current machine (default: localhost).
        scan_range: CIDR network range to scan for reachable hosts.
        known_hosts: Comma-separated string or list of known host IPs/hostnames.
        crown_jewels: Comma-separated string or list of crown jewel IPs/hostnames.
        json_output: If True, return a JSON string instead of TrustGraph.

    Returns:
        TrustGraph object or JSON string.
    """
    # Parse inputs — accept both comma-separated strings and lists
    if isinstance(known_hosts, str):
        known_hosts_list = [h.strip() for h in known_hosts.split(",") if h.strip()] if known_hosts else []
    else:
        known_hosts_list = list(known_hosts)

    if isinstance(crown_jewels, str):
        crown_jewels_list = [h.strip() for h in crown_jewels.split(",") if h.strip()] if crown_jewels else []
    else:
        crown_jewels_list = list(crown_jewels)

    # Resolve current host IP
    current_ip = _resolve_hostname(current_host)

    graph = TrustGraph()

    # Ensure current host node exists
    _add_node(graph, current_ip, hostname=current_host, ip=current_ip)

    # Mark crown jewels
    for cj in crown_jewels_list:
        resolved = _resolve_hostname(cj)
        _add_node(graph, resolved, hostname=cj, ip=resolved)
        graph.nodes[resolved].is_crown_jewel = True

    # Run all scanners
    scanners = [
        lambda: _scan_ssh_known_hosts(graph, current_ip),
        lambda: _scan_ssh_authorized_keys(graph, current_ip),
        lambda: _scan_ssh_config(graph, current_ip),
        lambda: _scan_sudoers(graph, current_ip),
        lambda: _scan_nfs_mounts(graph, current_ip),
        lambda: _scan_etc_hosts(graph, current_ip),
        lambda: _scan_listening_ports(graph, current_ip),
        lambda: _scan_network_reachability(graph, current_ip, scan_range, known_hosts_list),
    ]

    for scanner in scanners:
        try:
            scanner()
        except Exception:
            pass

    # Assess business value for each discovered node
    _assess_business_value(graph, crown_jewels_list)

    # Compute shortest paths
    graph.shortest_paths = _compute_shortest_paths(graph, current_ip)

    if json_output:
        nodes_out = {}
        for k, v in graph.nodes.items():
            nodes_out[k] = {
                "hostname": v.hostname,
                "ip": v.ip,
                "compromised": v.compromised,
                "is_crown_jewel": v.is_crown_jewel,
                "trust_out": v.trust_out,
                "trust_in": v.trust_in,
                "business_value": v.business_value,
                "data_sensitivity": v.data_sensitivity,
                "org_role": v.org_role,
            }
        edges_out = []
        for e in graph.edges:
            edges_out.append({
                "source_host": e.source_host,
                "target_host": e.target_host,
                "trust_type": e.trust_type,
                "strength": e.strength,
                "exploitable": e.exploitable,
                "evidence": e.evidence,
            })
        return json.dumps({
            "nodes": nodes_out,
            "edges": edges_out,
            "shortest_paths": graph.shortest_paths,
        }, indent=2)

    return graph


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    g = build_trust_graph(target)
    if isinstance(g, str):
        print(g)
    else:
        print(render_graph_ascii(g))
