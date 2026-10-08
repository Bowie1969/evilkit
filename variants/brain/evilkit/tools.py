"""Scope-safe command executors for the brain proof-of-concept.

The default ``SimulationExecutor`` never touches the network and returns
deterministic synthetic output so the controller loop can be demonstrated and
tested without API keys or live targets. ``ShellExecutor`` runs real commands
after validating them against the authorized scope and a conservative allowlist.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import Protocol

__all__ = [
    "ExecutionResult",
    "Executor",
    "SimulationExecutor",
    "ShellExecutor",
    "ExecutionError",
]


class ExecutionError(Exception):
    """Raised when a command is rejected or fails to execute."""


@dataclass(frozen=True)
class ExecutionResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


class Executor(Protocol):
    def execute(self, command: str) -> ExecutionResult:
        ...


_FORBIDDEN_SHELL_CHARS = re.compile(r"[;|&$`\(\)\{\}\[\]<>\\\*!?~^#\n\r]")
_ALLOWLIST = frozenset({
    "ping",
    "nmap",
    "traceroute",
    "tracepath",
    "curl",
    "wget",
    "nc",
    "netcat",
    "dig",
    "host",
    "nslookup",
})

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_HOST_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\b"
)


def _extract_targets(command: str) -> set[str]:
    """Extract likely target addresses/hostnames from a command's arguments."""
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return set()

    # Skip the binary and any option flags/values.
    args: list[str] = []
    skip_next = False
    for idx, part in enumerate(parts):
        if idx == 0:
            continue
        if skip_next:
            skip_next = False
            continue
        if part.startswith("-"):
            # Simple heuristic: flags that take a value are followed by one.
            if part in {"-c", "-p", "-t", "-i", "-o", "-T", "-s", "-A"}:
                skip_next = True
            continue
        args.append(part)

    targets: set[str] = set()
    ip_spans: set[tuple[int, int]] = set()
    text = " ".join(args)

    for match in _IP_RE.finditer(text):
        targets.add(match.group(0))
        ip_spans.add((match.start(), match.end()))

    for match in _HOST_RE.finditer(text):
        if any(start <= match.start() < end for start, end in ip_spans):
            continue
        token = match.group(0).lower()
        if token in {"http", "https", "localhost", "true", "false"}:
            continue
        if token.isdigit():
            continue
        targets.add(token)
    return targets


def _target_in_scope(target: str, scope: list[str]) -> bool:
    """Return True when ``target`` is contained by any entry in ``scope``."""
    try:
        addr = ipaddress.ip_address(target)
        for entry in scope:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        return False
    except ValueError:
        pass

    # Treat hostnames as in-scope only if they match exactly or end with a
    # scoped hostname. This is deliberately conservative for the PoC.
    target = target.rstrip(".").lower()
    for entry in scope:
        entry = entry.rstrip(".").lower()
        if "/" not in entry:
            if target == entry or target.endswith("." + entry):
                return True
    return False


def validate_command(command: str, scope: list[str]) -> None:
    """Raise ``ExecutionError`` when a command is unsafe or out of scope."""
    if not command.strip():
        raise ExecutionError("empty command")

    if _FORBIDDEN_SHELL_CHARS.search(command):
        raise ExecutionError(
            "command contains forbidden shell characters; use simple arguments only"
        )

    try:
        parts = shlex.split(command)
    except ValueError as exc:
        raise ExecutionError(f"could not parse command: {exc}") from exc

    if not parts:
        raise ExecutionError("empty command after parsing")

    binary = parts[0]
    if binary not in _ALLOWLIST:
        raise ExecutionError(
            f"{binary!r} is not in the brain executor allowlist"
        )

    targets = _extract_targets(command)
    for target in targets:
        if not _target_in_scope(target, scope):
            raise ExecutionError(
                f"target {target!r} is outside the authorized scope"
            )


class SimulationExecutor:
    """Return deterministic synthetic output for common recon commands."""

    def __init__(self, scope: list[str]) -> None:
        self.scope = scope

    def _is_loopback(self, target: str) -> bool:
        return target in {"127.0.0.1", "::1", "localhost"}

    def _first_target(self, command: str) -> str | None:
        targets = _extract_targets(command)
        return next(iter(targets), None)

    def execute(self, command: str) -> ExecutionResult:
        target = self._first_target(command)
        if target is None:
            return ExecutionResult(
                command=command,
                returncode=1,
                stdout="",
                stderr="error: no target detected in simulated command",
            )

        in_scope = _target_in_scope(target, self.scope)
        if not in_scope:
            return ExecutionResult(
                command=command,
                returncode=1,
                stdout="",
                stderr=f"error: target {target!r} is outside the authorized scope",
            )

        parts = command.split()
        tool = parts[0] if parts else ""

        if tool == "ping":
            if self._is_loopback(target):
                return ExecutionResult(
                    command=command,
                    returncode=0,
                    stdout=f"PING {target}: 64 bytes from {target}: icmp_seq=1 ttl=64 time=0.03 ms",
                    stderr="",
                )
            return ExecutionResult(
                command=command,
                returncode=1,
                stdout="",
                stderr=f"Request timeout for icmp_seq=1 (simulated {target})",
            )

        if tool == "nmap":
            if self._is_loopback(target):
                return ExecutionResult(
                    command=command,
                    returncode=0,
                    stdout=(
                        f"Starting Nmap scan against {target}\n"
                        "PORT   STATE SERVICE\n"
                        "22/tcp open  ssh\n"
                        "80/tcp open  http\n"
                    ),
                    stderr="",
                )
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout=f"Starting Nmap scan against {target}\nAll 1000 scanned ports are filtered (simulated)\n",
                stderr="",
            )

        if tool in {"curl", "wget"}:
            if self._is_loopback(target):
                return ExecutionResult(
                    command=command,
                    returncode=0,
                    stdout=(
                        f"<html><head><title>Simulated {target}</title></head>"
                        "<body>It works</body></html>"
                    ),
                    stderr="",
                )
            return ExecutionResult(
                command=command,
                returncode=7,
                stdout="",
                stderr=f"Failed to connect to {target} (simulated)",
            )

        if tool in {"traceroute", "tracepath"}:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout=f" 1  {target}  0.123 ms (simulated)\n",
                stderr="",
            )

        if tool in {"nc", "netcat"}:
            return ExecutionResult(
                command=command,
                returncode=0,
                stdout=f"Connection to {target} succeeded (simulated).\n",
                stderr="",
            )

        return ExecutionResult(
            command=command,
            returncode=0,
            stdout=f"simulated output for {command}\n",
            stderr="",
        )


class ShellExecutor:
    """Run real commands after safety and scope checks."""

    def __init__(self, scope: list[str], timeout: float = 60.0) -> None:
        self.scope = scope
        self.timeout = timeout

    def execute(self, command: str) -> ExecutionResult:
        validate_command(command, self.scope)
        try:
            proc = subprocess.run(
                shlex.split(command),
                shell=False,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ExecutionResult(
                command=command,
                returncode=-1,
                stdout=exc.stdout or "",
                stderr=f"command timed out after {self.timeout}s",
            )
        except FileNotFoundError as exc:
            return ExecutionResult(
                command=command,
                returncode=127,
                stdout="",
                stderr=f"command not found: {exc.filename}",
            )
        return ExecutionResult(
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
