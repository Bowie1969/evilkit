"""
Sandbox Evasion — environment assessment for analysis/sandbox detection.

Checks for VM indicators, debugger presence, sandbox signatures,
time manipulation, and honeypot patterns.
"""

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class EnvironmentCheck:
    name: str
    category: str
    result: str  # "clean", "suspicious", "detected"
    evidence: str
    confidence: float  # 0.0 - 1.0


@dataclass
class EnvironmentReport:
    verdict: str  # "clean", "suspicious", "analysis_detected"
    risk_score: float  # 0.0 - 1.0
    recommended_action: str
    checks: list = field(default_factory=list)


def _read_file_safe(path: str) -> Optional[str]:
    """Read a file, returning None on any error."""
    try:
        return Path(path).read_text().strip()
    except (OSError, PermissionError):
        return None


def _read_proc_file_safe(path: str) -> Optional[str]:
    """Read a /proc file, returning None on any error."""
    return _read_file_safe(path)


def _check_vm_indicators() -> list:
    """Check for virtual machine indicators."""
    checks = []

    # CPU core count — VMs often have 1-2 cores
    try:
        cpu_count = os.cpu_count() or 0
        if cpu_count <= 2:
            checks.append(EnvironmentCheck(
                name="low_cpu_cores",
                category="vm_indicator",
                result="suspicious",
                evidence=f"CPU cores: {cpu_count} (VMs often have 1-2 cores)",
                confidence=0.3,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="low_cpu_cores",
                category="vm_indicator",
                result="clean",
                evidence=f"CPU cores: {cpu_count}",
                confidence=0.8,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="low_cpu_cores",
            category="vm_indicator",
            result="suspicious",
            evidence=f"Could not determine CPU count: {str(e)}",
            confidence=0.2,
        ))

    # RAM amount — VMs often have limited RAM
    try:
        meminfo = _read_proc_file_safe("/proc/meminfo")
        if meminfo:
            for line in meminfo.splitlines():
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    mem_kb = int(parts[1])
                    mem_mb = mem_kb // 1024
                    if mem_mb <= 2048:
                        checks.append(EnvironmentCheck(
                            name="low_memory",
                            category="vm_indicator",
                            result="suspicious",
                            evidence=f"Total RAM: {mem_mb} MB (VMs often have <= 2 GB)",
                            confidence=0.4,
                        ))
                    else:
                        checks.append(EnvironmentCheck(
                            name="low_memory",
                            category="vm_indicator",
                            result="clean",
                            evidence=f"Total RAM: {mem_mb} MB",
                            confidence=0.8,
                        ))
                    break
            else:
                checks.append(EnvironmentCheck(
                    name="low_memory",
                    category="vm_indicator",
                    result="suspicious",
                    evidence="MemTotal not found in /proc/meminfo",
                    confidence=0.2,
                ))
        else:
            checks.append(EnvironmentCheck(
                name="low_memory",
                category="vm_indicator",
                result="suspicious",
                evidence="Cannot read /proc/meminfo",
                confidence=0.3,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="low_memory",
            category="vm_indicator",
            result="suspicious",
            evidence=f"Could not determine RAM: {str(e)}",
            confidence=0.2,
        ))

    # Disk size — VMs often have small disks
    try:
        statvfs = os.statvfs("/")
        disk_total_gb = (statvfs.f_frsize * statvfs.f_blocks) // (1024 * 1024 * 1024)
        if disk_total_gb <= 40:
            checks.append(EnvironmentCheck(
                name="small_disk",
                category="vm_indicator",
                result="suspicious",
                evidence=f"Disk size: {disk_total_gb} GB (VMs often have <= 40 GB)",
                confidence=0.3,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="small_disk",
                category="vm_indicator",
                result="clean",
                evidence=f"Disk size: {disk_total_gb} GB",
                confidence=0.8,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="small_disk",
            category="vm_indicator",
            result="suspicious",
            evidence=f"Could not determine disk size: {str(e)}",
            confidence=0.2,
        ))

    # Hypervisor string in /proc/cpuinfo
    try:
        cpuinfo = _read_file_safe("/proc/cpuinfo")
        if cpuinfo and "hypervisor" in cpuinfo.lower():
            checks.append(EnvironmentCheck(
                name="hypervisor_cpuinfo",
                category="vm_indicator",
                result="detected",
                evidence="'hypervisor' flag found in /proc/cpuinfo",
                confidence=0.95,
            ))
        elif cpuinfo:
            checks.append(EnvironmentCheck(
                name="hypervisor_cpuinfo",
                category="vm_indicator",
                result="clean",
                evidence="No 'hypervisor' flag in /proc/cpuinfo",
                confidence=0.8,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="hypervisor_cpuinfo",
                category="vm_indicator",
                result="suspicious",
                evidence="Cannot read /proc/cpuinfo",
                confidence=0.3,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="hypervisor_cpuinfo",
            category="vm_indicator",
            result="suspicious",
            evidence=f"Error checking /proc/cpuinfo: {str(e)}",
            confidence=0.2,
        ))

    # DMI product name
    try:
        product_name = _read_file_safe("/sys/class/dmi/id/product_name")
        vm_strings = ["virtualbox", "vmware", "kvm", "qemu", "bochs", "xen", "hyper-v"]
        if product_name:
            product_lower = product_name.lower()
            matched = [v for v in vm_strings if v in product_lower]
            if matched:
                checks.append(EnvironmentCheck(
                    name="dmi_product_name",
                    category="vm_indicator",
                    result="detected",
                    evidence=f"DMI product name: {product_name} (matches: {', '.join(matched)})",
                    confidence=0.95,
                ))
            else:
                checks.append(EnvironmentCheck(
                    name="dmi_product_name",
                    category="vm_indicator",
                    result="clean",
                    evidence=f"DMI product name: {product_name}",
                    confidence=0.8,
                ))
        else:
            checks.append(EnvironmentCheck(
                name="dmi_product_name",
                category="vm_indicator",
                result="suspicious",
                evidence="Cannot read /sys/class/dmi/id/product_name",
                confidence=0.3,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="dmi_product_name",
            category="vm_indicator",
            result="suspicious",
            evidence=f"Error checking DMI product: {str(e)}",
            confidence=0.2,
        ))

    # DMI sys_vendor
    try:
        sys_vendor = _read_file_safe("/sys/class/dmi/id/sys_vendor")
        vm_vendors = ["oracle", "vmware", "red hat", "qemu", "xen", "microsoft", "innotek"]
        if sys_vendor:
            vendor_lower = sys_vendor.lower()
            matched = [v for v in vm_vendors if v in vendor_lower]
            if matched:
                checks.append(EnvironmentCheck(
                    name="dmi_sys_vendor",
                    category="vm_indicator",
                    result="detected",
                    evidence=f"DMI sys_vendor: {sys_vendor} (matches: {', '.join(matched)})",
                    confidence=0.95,
                ))
            else:
                checks.append(EnvironmentCheck(
                    name="dmi_sys_vendor",
                    category="vm_indicator",
                    result="clean",
                    evidence=f"DMI sys_vendor: {sys_vendor}",
                    confidence=0.8,
                ))
        else:
            checks.append(EnvironmentCheck(
                name="dmi_sys_vendor",
                category="vm_indicator",
                result="suspicious",
                evidence="Cannot read /sys/class/dmi/id/sys_vendor",
                confidence=0.3,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="dmi_sys_vendor",
            category="vm_indicator",
            result="suspicious",
            evidence=f"Error checking DMI sys_vendor: {str(e)}",
            confidence=0.2,
        ))

    # VM-specific device files
    vm_devices = ["/dev/vboxguest", "/dev/vboxuser"]
    found_devices = []
    for dev in vm_devices:
        if Path(dev).exists():
            found_devices.append(dev)

    if found_devices:
        checks.append(EnvironmentCheck(
            name="vm_device_files",
            category="vm_indicator",
            result="detected",
            evidence="VM device files found: " + ", ".join(found_devices),
            confidence=0.95,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="vm_device_files",
            category="vm_indicator",
            result="clean",
            evidence="No VM-specific device files found",
            confidence=0.8,
        ))

    return checks


def _check_debugger_presence() -> list:
    """Check for debugger/tracer presence."""
    checks = []

    # Check TracerPid in /proc/self/status
    try:
        status = _read_proc_file_safe("/proc/self/status")
        if status:
            for line in status.splitlines():
                if line.startswith("TracerPid:"):
                    tracer_pid = int(line.split(":")[1].strip())
                    if tracer_pid != 0:
                        checks.append(EnvironmentCheck(
                            name="tracer_pid",
                            category="debugger",
                            result="detected",
                            evidence=f"TracerPid: {tracer_pid} (process is being traced)",
                            confidence=1.0,
                        ))
                    else:
                        checks.append(EnvironmentCheck(
                            name="tracer_pid",
                            category="debugger",
                            result="clean",
                            evidence="TracerPid: 0 (not being traced)",
                            confidence=0.9,
                        ))
                    break
            else:
                checks.append(EnvironmentCheck(
                    name="tracer_pid",
                    category="debugger",
                    result="suspicious",
                    evidence="TracerPid not found in /proc/self/status",
                    confidence=0.2,
                ))
        else:
            checks.append(EnvironmentCheck(
                name="tracer_pid",
                category="debugger",
                result="suspicious",
                evidence="Cannot read /proc/self/status",
                confidence=0.3,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="tracer_pid",
            category="debugger",
            result="suspicious",
            evidence=f"Error checking TracerPid: {str(e)}",
            confidence=0.2,
        ))

    # Check for debugger processes
    debugger_procs = ["gdb", "strace", "ltrace", "rr"]
    found_debuggers = []
    try:
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.is_dir():
                continue
            try:
                comm_path = proc_dir / "comm"
                if comm_path.exists():
                    comm = comm_path.read_text().strip()
                    if comm in debugger_procs:
                        found_debuggers.append(comm)
            except (OSError, PermissionError, ValueError):
                continue
    except Exception:
        pass

    if found_debuggers:
        unique_debuggers = sorted(set(found_debuggers))
        checks.append(EnvironmentCheck(
            name="debugger_processes",
            category="debugger",
            result="detected",
            evidence="Debugger processes running: " + ", ".join(unique_debuggers),
            confidence=0.9,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="debugger_processes",
            category="debugger",
            result="clean",
            evidence="No debugger processes detected",
            confidence=0.8,
        ))

    # Check LD_PRELOAD and LD_DEBUG environment variables
    ld_preload = os.environ.get("LD_PRELOAD", "")
    ld_debug = os.environ.get("LD_DEBUG", "")
    evidence_parts = []
    if ld_preload:
        evidence_parts.append(f"LD_PRELOAD={ld_preload}")
    if ld_debug:
        evidence_parts.append(f"LD_DEBUG={ld_debug}")

    if evidence_parts:
        checks.append(EnvironmentCheck(
            name="ld_injection_vars",
            category="debugger",
            result="suspicious",
            evidence="Injection env vars set: " + "; ".join(evidence_parts),
            confidence=0.7,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="ld_injection_vars",
            category="debugger",
            result="clean",
            evidence="No LD_PRELOAD or LD_DEBUG environment variables",
            confidence=0.8,
        ))

    return checks


def _check_sandbox_signatures() -> list:
    """Check for sandbox/analysis environment signatures."""
    checks = []

    # Check for low user activity — count logged-in users
    try:
        result = subprocess.run(["who"], capture_output=True, text=True, timeout=5)
        who_output = result.stdout.strip()
        user_count = len([line for line in who_output.splitlines() if line.strip()]) if who_output else 0
        if user_count == 0:
            checks.append(EnvironmentCheck(
                name="no_logged_in_users",
                category="sandbox",
                result="suspicious",
                evidence="No users logged in (sandboxes often run headless)",
                confidence=0.4,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="no_logged_in_users",
                category="sandbox",
                result="clean",
                evidence=f"{user_count} user(s) logged in",
                confidence=0.7,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="no_logged_in_users",
            category="sandbox",
            result="suspicious",
            evidence=f"Cannot check logged-in users: {str(e)}",
            confidence=0.2,
        ))

    # Check uptime — sandboxes often have very recent boot times
    try:
        uptime = _read_proc_file_safe("/proc/uptime")
        if uptime:
            uptime_secs = float(uptime.split()[0])
            uptime_mins = uptime_secs / 60
            if uptime_mins < 5:
                checks.append(EnvironmentCheck(
                    name="recent_boot",
                    category="sandbox",
                    result="suspicious",
                    evidence=f"System uptime: {uptime_mins:.1f} minutes (sandboxes often boot just before analysis)",
                    confidence=0.5,
                ))
            else:
                checks.append(EnvironmentCheck(
                    name="recent_boot",
                    category="sandbox",
                    result="clean",
                    evidence=f"System uptime: {uptime_mins:.1f} minutes",
                    confidence=0.7,
                ))
        else:
            checks.append(EnvironmentCheck(
                name="recent_boot",
                category="sandbox",
                result="suspicious",
                evidence="Cannot read /proc/uptime",
                confidence=0.2,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="recent_boot",
            category="sandbox",
            result="suspicious",
            evidence=f"Error checking uptime: {str(e)}",
            confidence=0.2,
        ))

    # Check for default/sandbox usernames
    sandbox_usernames = ["admin", "user", "test", "sandbox", "analyst", "cuckoo", "malware"]
    current_user = os.environ.get("USER", "")
    current_home = str(Path.home())
    username_from_home = current_home.rstrip("/").split("/")[-1]

    matched_usernames = []
    for name in sandbox_usernames:
        if name.lower() == current_user.lower() or name.lower() == username_from_home.lower():
            matched_usernames.append(name)

    if matched_usernames:
        checks.append(EnvironmentCheck(
            name="default_username",
            category="sandbox",
            result="suspicious",
            evidence=f"Username matches sandbox defaults: {', '.join(matched_usernames)}",
            confidence=0.6,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="default_username",
            category="sandbox",
            result="clean",
            evidence=f"Username '{current_user or username_from_home}' not in known sandbox defaults",
            confidence=0.7,
        ))

    # Check for INetSim fake services — common ports with known fake responses
    inetsim_ports = {21: "220 INetSim FTP", 25: "220 INetSim", 53: None, 80: None, 110: None, 443: None}
    inetsim_detected = False
    inetsim_evidence = []

    for port, expected_banner in inetsim_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            if result == 0 and expected_banner:
                # Try to read banner
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(1.0)
                    sock2.connect(("127.0.0.1", port))
                    banner = sock2.recv(256).decode(errors="replace").strip()
                    sock2.close()
                    if "inetsim" in banner.lower():
                        inetsim_detected = True
                        inetsim_evidence.append(f"Port {port}: {banner[:80]}")
                except Exception:
                    pass
        except Exception:
            pass

    if inetsim_detected:
        checks.append(EnvironmentCheck(
            name="inetsim_detection",
            category="sandbox",
            result="detected",
            evidence="INetSim fake services detected: " + "; ".join(inetsim_evidence),
            confidence=0.95,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="inetsim_detection",
            category="sandbox",
            result="clean",
            evidence="No INetSim fake services detected on common ports",
            confidence=0.7,
        ))

    # Check for Cuckoo/Joe Sandbox artifacts
    cuckoo_paths = ["/tmp/cuckoo", "/var/lib/cuckoo", "/opt/cuckoo"]
    cuckoo_found = [p for p in cuckoo_paths if Path(p).exists()]

    # Check for known sandbox environment variables
    sandbox_envs = ["CUCKOO", "CWSANDBOX", "JOESANDBOX", "SANDBOX", "VMNAME"]
    sandbox_env_found = {k: os.environ.get(k) for k in sandbox_envs if os.environ.get(k)}

    sandbox_artifacts = []
    if cuckoo_found:
        sandbox_artifacts.append("Cuckoo paths: " + ", ".join(cuckoo_found))
    if sandbox_env_found:
        sandbox_artifacts.append("Sandbox env vars: " + ", ".join(f"{k}={v}" for k, v in sandbox_env_found.items()))

    if sandbox_artifacts:
        checks.append(EnvironmentCheck(
            name="sandbox_artifacts",
            category="sandbox",
            result="detected",
            evidence="; ".join(sandbox_artifacts),
            confidence=0.9,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="sandbox_artifacts",
            category="sandbox",
            result="clean",
            evidence="No known sandbox artifacts found",
            confidence=0.8,
        ))

    return checks


def _check_time_manipulation() -> list:
    """Check for time manipulation and sandbox time acceleration."""
    checks = []

    # Check system time vs file modification times for anomalies
    try:
        now = time.time()
        # Check if key system files have timestamps far in the future or past
        suspicious_timestamps = []
        for check_path in ["/etc/passwd", "/bin/ls", "/usr/bin/python3"]:
            p = Path(check_path)
            if p.exists():
                mtime = p.stat().st_mtime
                age_days = (now - mtime) / 86400
                if mtime > now + 86400:
                    suspicious_timestamps.append(f"{check_path}: mtime is {age_days:.0f} days in the future")
                elif mtime < now - 86400 * 365 * 10:
                    suspicious_timestamps.append(f"{check_path}: mtime is {age_days:.0f} days old (>10 years)")

        if suspicious_timestamps:
            checks.append(EnvironmentCheck(
                name="suspicious_timestamps",
                category="time_manipulation",
                result="suspicious",
                evidence="; ".join(suspicious_timestamps),
                confidence=0.5,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="suspicious_timestamps",
                category="time_manipulation",
                result="clean",
                evidence="System file timestamps are within normal range",
                confidence=0.7,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="suspicious_timestamps",
            category="time_manipulation",
            result="suspicious",
            evidence=f"Error checking timestamps: {str(e)}",
            confidence=0.2,
        ))

    # Check for rapid execution — measure how long basic operations take
    # Sandboxes often speed up time, making sleep() return instantly
    try:
        start = time.monotonic()
        time.sleep(0.5)
        elapsed = time.monotonic() - start
        if elapsed < 0.1:
            checks.append(EnvironmentCheck(
                name="time_acceleration",
                category="time_manipulation",
                result="detected",
                evidence=f"sleep(0.5) returned in {elapsed:.4f}s (time may be accelerated)",
                confidence=0.85,
            ))
        elif elapsed < 0.3:
            checks.append(EnvironmentCheck(
                name="time_acceleration",
                category="time_manipulation",
                result="suspicious",
                evidence=f"sleep(0.5) returned in {elapsed:.4f}s (slightly fast)",
                confidence=0.5,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="time_acceleration",
                category="time_manipulation",
                result="clean",
                evidence=f"sleep(0.5) returned in {elapsed:.4f}s (normal timing)",
                confidence=0.8,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="time_acceleration",
            category="time_manipulation",
            result="suspicious",
            evidence=f"Error checking time acceleration: {str(e)}",
            confidence=0.2,
        ))

    # Check for NTP time difference (best-effort, no external dependency)
    try:
        # Try to read /var/lib/ntp/ntp.conf.d or check if ntpd/chronyd is running
        ntp_running = False
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.is_dir():
                continue
            try:
                cmdline = (proc_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
                if "ntpd" in cmdline or "chronyd" in cmdline or "systemd-timesyncd" in cmdline:
                    ntp_running = True
                    break
            except (OSError, PermissionError):
                continue

        if ntp_running:
            checks.append(EnvironmentCheck(
                name="ntp_sync",
                category="time_manipulation",
                result="clean",
                evidence="NTP/time sync daemon is running",
                confidence=0.7,
            ))
        else:
            checks.append(EnvironmentCheck(
                name="ntp_sync",
                category="time_manipulation",
                result="suspicious",
                evidence="No NTP/time sync daemon detected (time may be manually set)",
                confidence=0.4,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="ntp_sync",
            category="time_manipulation",
            result="suspicious",
            evidence=f"Error checking NTP: {str(e)}",
            confidence=0.2,
        ))

    # Check for VM snapshot artifacts — recent /proc/uptime combined with old file mtimes
    try:
        uptime_content = _read_proc_file_safe("/proc/uptime")
        if uptime_content:
            uptime_secs = float(uptime_content.split()[0])
            # If uptime is very low but filesystem has very old files, could be a snapshot restore
            if uptime_secs < 120:
                # Check age of /etc/hostname or similar
                for snap_path in ["/etc/hostname", "/etc/machine-id"]:
                    p = Path(snap_path)
                    if p.exists():
                        mtime = p.stat().st_mtime
                        age_days = (time.time() - mtime) / 86400
                        if age_days > 30:
                            checks.append(EnvironmentCheck(
                                name="snapshot_artifacts",
                                category="time_manipulation",
                                result="suspicious",
                                evidence=f"Low uptime ({uptime_secs:.0f}s) but {snap_path} is {age_days:.0f} days old — possible snapshot restore",
                                confidence=0.5,
                            ))
                            break
                else:
                    checks.append(EnvironmentCheck(
                        name="snapshot_artifacts",
                        category="time_manipulation",
                        result="clean",
                        evidence="No snapshot restore indicators detected",
                        confidence=0.6,
                    ))
            else:
                checks.append(EnvironmentCheck(
                    name="snapshot_artifacts",
                    category="time_manipulation",
                    result="clean",
                    evidence="Uptime sufficient to rule out recent snapshot restore",
                    confidence=0.7,
                ))
        else:
            checks.append(EnvironmentCheck(
                name="snapshot_artifacts",
                category="time_manipulation",
                result="suspicious",
                evidence="Cannot read /proc/uptime for snapshot check",
                confidence=0.2,
            ))
    except Exception as e:
        checks.append(EnvironmentCheck(
            name="snapshot_artifacts",
            category="time_manipulation",
            result="suspicious",
            evidence=f"Error checking snapshot artifacts: {str(e)}",
            confidence=0.2,
        ))

    return checks


def _check_honeypot_patterns(target_ip: str) -> list:
    """Check for honeypot patterns by probing common services on target_ip."""
    checks = []

    if not target_ip:
        checks.append(EnvironmentCheck(
            name="honeypot_probe",
            category="honeypot",
            result="clean",
            evidence="No target IP provided — honeypot probe skipped",
            confidence=0.5,
        ))
        return checks

    # Common honeypot ports and expected fake responses
    honeypot_checks = [
        (22, "SSH", "ssh"),
        (80, "HTTP", "http"),
        (445, "SMB", "smb"),
        (3389, "RDP", "rdp"),
        (8080, "HTTP-Alt", "http"),
    ]

    open_ports = []
    suspicious_responses = []

    for port, service_name, proto in honeypot_checks:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
                # Try to read banner for TCP services
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(2.0)
                    sock2.connect((target_ip, port))
                    banner = sock2.recv(512).decode(errors="replace").strip()
                    sock2.close()
                    # Check for known honeypot banners
                    honeypot_indicators = ["cowrie", "kippo", "dionaea", "conpot", "glastopf", "honeytrap", "inetsim"]
                    for indicator in honeypot_indicators:
                        if indicator.lower() in banner.lower():
                            suspicious_responses.append(f"Port {port} ({service_name}): banner contains '{indicator}'")
                            break
                except Exception:
                    pass
        except Exception:
            pass

    if suspicious_responses:
        checks.append(EnvironmentCheck(
            name="honeypot_banner",
            category="honeypot",
            result="detected",
            evidence="; ".join(suspicious_responses),
            confidence=0.9,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="honeypot_banner",
            category="honeypot",
            result="clean",
            evidence="No honeypot banners detected on probed ports",
            confidence=0.6,
        ))

    # Too many common ports open on a single host can indicate a honeypot
    if len(open_ports) >= 4:
        checks.append(EnvironmentCheck(
            name="excessive_open_ports",
            category="honeypot",
            result="suspicious",
            evidence=f"Many common ports open on {target_ip}: {', '.join(str(p) for p in open_ports)} (possible honeypot)",
            confidence=0.5,
        ))
    elif open_ports:
        checks.append(EnvironmentCheck(
            name="excessive_open_ports",
            category="honeypot",
            result="clean",
            evidence=f"Ports open on {target_ip}: {', '.join(str(p) for p in open_ports)} (within normal range)",
            confidence=0.6,
        ))
    else:
        checks.append(EnvironmentCheck(
            name="excessive_open_ports",
            category="honeypot",
            result="clean",
            evidence=f"No common ports open on {target_ip}",
            confidence=0.5,
        ))

    return checks


def assess_environment(target_ip: str = "", json_output: bool = False) -> EnvironmentReport:
    """
    Assess the current environment for sandbox/analysis indicators.

    Args:
        target_ip: Optional target IP for honeypot detection
        json_output: Unused here (handled by caller for serialization)

    Returns:
        EnvironmentReport with verdict, risk_score, recommended_action, and checks
    """
    all_checks = []

    # Run all assessment categories
    all_checks.extend(_check_vm_indicators())
    all_checks.extend(_check_debugger_presence())
    all_checks.extend(_check_sandbox_signatures())
    all_checks.extend(_check_time_manipulation())
    if target_ip:
        all_checks.extend(_check_honeypot_patterns(target_ip))

    # Calculate weighted risk score
    score_map = {"clean": 0.0, "suspicious": 0.5, "detected": 1.0}
    total_weighted = 0.0
    total_weight = 0.0
    for check in all_checks:
        weight = check.confidence
        score = score_map.get(check.result, 0.5)
        total_weighted += score * weight
        total_weight += weight

    risk_score = total_weighted / total_weight if total_weight > 0 else 0.0
    risk_score = round(min(max(risk_score, 0.0), 1.0), 3)

    # Determine verdict
    detected_count = sum(1 for c in all_checks if c.result == "detected")
    suspicious_count = sum(1 for c in all_checks if c.result == "suspicious")

    if detected_count >= 2 or risk_score >= 0.7:
        verdict = "analysis_detected"
        recommended_action = "Abort or switch to stealth mode — analysis environment detected"
    elif detected_count >= 1 or suspicious_count >= 3 or risk_score >= 0.4:
        verdict = "suspicious"
        recommended_action = "Proceed with caution — some indicators suggest analysis environment"
    else:
        verdict = "clean"
        recommended_action = "Environment appears clean — proceed with normal operations"

    return EnvironmentReport(
        verdict=verdict,
        risk_score=risk_score,
        recommended_action=recommended_action,
        checks=all_checks,
    )


if __name__ == "__main__":
    import json
    import dataclasses

    report = assess_environment()
    print(f"Verdict: {report.verdict}")
    print(f"Risk score: {report.risk_score}")
    print(f"Recommended action: {report.recommended_action}")
    print(f"Checks: {len(report.checks)}")
    print()
    for c in report.checks:
        icon = {"clean": "[+]", "suspicious": "[?]", "detected": "[!]"}.get(c.result, "[?]")
        print(f"  {icon} {c.name}: {c.evidence} (confidence: {c.confidence})")
