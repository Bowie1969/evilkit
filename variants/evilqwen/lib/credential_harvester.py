"""Credential harvester — scans local filesystem for credential stores.

Read-only scanning of common credential locations on Linux systems.
Handles permission errors gracefully and redacts values by default.

Usage:
    from credential_harvester import harvest_credentials
    report = harvest_credentials("localhost")
    print(report.summary)
"""

from __future__ import annotations

import glob
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Credential:
    """A single discovered credential."""
    source: str
    type: str
    host: str
    value: str
    confidence: str
    attack_vector: str

    def redact_value(self) -> str:
        """Return redacted version: first 2 chars + asterisks."""
        if not self.value:
            return ""
        if len(self.value) <= 2:
            return "**"
        return self.value[:2] + "*" * (len(self.value) - 2)


@dataclass
class CredentialReport:
    """Aggregated credential harvest report."""
    host: str
    timestamp: str
    credentials: list[Credential] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


def _redact(value: str) -> str:
    """Redact a credential value: first 2 chars + asterisks."""
    if not value:
        return ""
    if len(value) <= 2:
        return "**"
    return value[:2] + "*" * (len(value) - 2)


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


def _expand_home(pattern: str) -> list[str]:
    """Expand a glob pattern under ~, returning existing file paths."""
    try:
        expanded = os.path.expanduser(pattern)
        return [p for p in glob.glob(expanded) if os.path.isfile(p)]
    except (OSError, ValueError):
        return []


# ---------------------------------------------------------------------------
# Scanners — each returns list[Credential]
# ---------------------------------------------------------------------------

def _scan_ssh_keys(home: str, host: str) -> list[Credential]:
    """Scan ~/.ssh/ for private keys and known_hosts."""
    creds: list[Credential] = []
    ssh_dir = os.path.join(home, ".ssh")
    if not os.path.isdir(ssh_dir):
        return creds

    for entry in _safe_list_dir(ssh_dir):
        full = os.path.join(ssh_dir, entry)
        if not os.path.isfile(full):
            continue

        # Private keys
        if entry.startswith("id_") and not entry.endswith(".pub"):
            content = _safe_read(full)
            if content and "PRIVATE KEY" in content:
                creds.append(Credential(
                    source="~/.ssh/" + entry,
                    type="ssh_private_key",
                    host=host,
                    value=_redact(content[:80]),
                    confidence="high",
                    attack_vector="ssh_key_reuse",
                ))

        # authorized_keys
        elif entry == "authorized_keys":
            content = _safe_read(full)
            if content:
                lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
                for i, line in enumerate(lines):
                    parts = line.split()
                    key_type = parts[0] if parts else "unknown"
                    comment = parts[-1] if len(parts) >= 3 else "unknown"
                    creds.append(Credential(
                        source="~/.ssh/authorized_keys",
                        type="ssh_authorized_key",
                        host=host,
                        value=_redact(comment),
                        confidence="medium",
                        attack_vector="ssh_key_reuse",
                    ))

        # known_hosts
        elif entry == "known_hosts":
            content = _safe_read(full)
            if content:
                for line in content.splitlines():
                    if line.strip() and not line.startswith("#"):
                        parts = line.split()
                        if parts:
                            target_host = parts[0].split(",")[0]
                            creds.append(Credential(
                                source="~/.ssh/known_hosts",
                                type="ssh_known_host",
                                host=host,
                                value=_redact(target_host),
                                confidence="low",
                                attack_vector="lateral_movement",
                            ))

        # config file with Host entries
        elif entry == "config":
            content = _safe_read(full)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith("hostname ") or line.lower().startswith("host "):
                        target = line.split(None, 1)[-1]
                        creds.append(Credential(
                            source="~/.ssh/config",
                            type="ssh_config_entry",
                            host=host,
                            value=_redact(target),
                            confidence="medium",
                            attack_vector="lateral_movement",
                        ))

    return creds


def _scan_shell_history(home: str, host: str) -> list[Credential]:
    """Scan shell history files for passwords, tokens, and secrets."""
    creds: list[Credential] = []
    history_files = [".bash_history", ".zsh_history", ".fish_history", ".sh_history"]

    for hf in history_files:
        path = os.path.join(home, hf)
        content = _safe_read(path)
        if not content:
            continue

        # Patterns that suggest credentials in history
        patterns = [
            (r'(?i)(password|passwd|pass)\s*[=:]\s*(\S+)', "password_in_history"),
            (r'(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*(\S+)', "api_key_in_history"),
            (r'(?i)(secret|token)\s*[=:]\s*(\S+)', "secret_in_history"),
            (r'(?i)(mysql|psql|mongo|redis)://\S+:\S+@', "connection_string_in_history"),
            (r'(?i)ssh\s+-i\s+(\S+)', "ssh_key_path_in_history"),
            (r'(?i)(export\s+)?(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*[=:]\s*(\S+)', "aws_key_in_history"),
        ]

        for pattern, attack_vec in patterns:
            for match in re.finditer(pattern, content):
                value = match.group(match.lastindex) if match.lastindex else match.group(0)
                creds.append(Credential(
                    source="~/" + hf,
                    type=attack_vec.replace("_in_history", ""),
                    host=host,
                    value=_redact(value),
                    confidence="medium",
                    attack_vector="history_enumeration",
                ))

    return creds


def _scan_env_files(home: str, host: str) -> list[Credential]:
    """Scan .env files and /proc/*/environ for secrets."""
    creds: list[Credential] = []

    # .env files in home and common project dirs
    env_paths = [
        os.path.join(home, ".env"),
        os.path.join(home, ".env.local"),
        os.path.join(home, ".env.production"),
    ]
    # Also scan subdirectories up to 2 levels deep
    for subdir in _safe_list_dir(home):
        sub_full = os.path.join(home, subdir)
        if os.path.isdir(sub_full):
            env_paths.append(os.path.join(sub_full, ".env"))
            for sub2 in _safe_list_dir(sub_full):
                sub2_full = os.path.join(sub_full, sub2)
                if os.path.isdir(sub2_full):
                    env_paths.append(os.path.join(sub2_full, ".env"))

    for ep in env_paths:
        content = _safe_read(ep)
        if not content:
            continue
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("\"'")
                if val and any(kw in key.upper() for kw in [
                    "PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "AUTH"
                ]):
                    creds.append(Credential(
                        source=ep.replace(home, "~", 1),
                        type="env_variable",
                        host=host,
                        value=_redact(val),
                        confidence="high",
                        attack_vector="env_enumeration",
                    ))

    # /proc/*/environ — requires root or same-user
    try:
        for pid_dir in _safe_list_dir("/proc"):
            if not pid_dir.isdigit():
                continue
            env_file = "/proc/" + pid_dir + "/environ"
            content = _safe_read(env_file)
            if not content:
                continue
            for entry in content.split("\x00"):
                if "=" in entry:
                    key, _, val = entry.partition("=")
                    if val and any(kw in key.upper() for kw in [
                        "PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "AUTH"
                    ]):
                        creds.append(Credential(
                            source="/proc/" + pid_dir + "/environ",
                            type="process_env",
                            host=host,
                            value=_redact(val),
                            confidence="high",
                            attack_vector="process_enumeration",
                        ))
    except (OSError, PermissionError):
        pass

    return creds


def _scan_cloud_credentials(home: str, host: str) -> list[Credential]:
    """Scan for AWS, Azure, and GCP credential files."""
    creds: list[Credential] = []

    # AWS credentials
    aws_creds = os.path.join(home, ".aws", "credentials")
    content = _safe_read(aws_creds)
    if content:
        current_profile = "default"
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current_profile = line[1:-1]
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                if key in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token"):
                    creds.append(Credential(
                        source="~/.aws/credentials",
                        type="aws_credential",
                        host=host,
                        value=_redact(val),
                        confidence="high",
                        attack_vector="cloud_credential_theft",
                    ))

    # AWS config
    aws_config = os.path.join(home, ".aws", "config")
    content = _safe_read(aws_config)
    if content:
        for line in content.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                if "role_arn" in key.lower() or "mfa" in key.lower():
                    creds.append(Credential(
                        source="~/.aws/config",
                        type="aws_config",
                        host=host,
                        value=_redact(val),
                        confidence="medium",
                        attack_vector="cloud_credential_theft",
                    ))

    # Azure
    azure_dir = os.path.join(home, ".azure")
    if os.path.isdir(azure_dir):
        for az_file in ["accessTokens.json", "azureProfile.json", "clouds.config"]:
            path = os.path.join(azure_dir, az_file)
            content = _safe_read(path)
            if content:
                creds.append(Credential(
                    source="~/.azure/" + az_file,
                    type="azure_credential",
                    host=host,
                    value=_redact(content[:60]),
                    confidence="high",
                    attack_vector="cloud_credential_theft",
                ))

    # GCloud
    gcloud_dir = os.path.join(home, ".config", "gcloud")
    if os.path.isdir(gcloud_dir):
        for gc_file in ["credentials", "access_tokens.db", "configurations/config_default"]:
            path = os.path.join(gcloud_dir, gc_file)
            content = _safe_read(path)
            if content:
                creds.append(Credential(
                    source="~/.config/gcloud/" + gc_file,
                    type="gcp_credential",
                    host=host,
                    value=_redact(content[:60]),
                    confidence="high",
                    attack_vector="cloud_credential_theft",
                ))

    return creds


def _scan_database_credentials(home: str, host: str) -> list[Credential]:
    """Scan for MySQL, PostgreSQL, and other database credential files."""
    creds: list[Credential] = []

    # MySQL
    my_cnf = os.path.join(home, ".my.cnf")
    content = _safe_read(my_cnf)
    if content:
        for line in content.splitlines():
            line = line.strip()
            if "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                if key in ("password", "passwd"):
                    creds.append(Credential(
                        source="~/.my.cnf",
                        type="mysql_credential",
                        host=host,
                        value=_redact(val),
                        confidence="high",
                        attack_vector="database_credential_theft",
                    ))

    # PostgreSQL
    pgpass = os.path.join(home, ".pgpass")
    content = _safe_read(pgpass)
    if content:
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 5:
                pg_host, pg_port, pg_db, pg_user, pg_pass = parts[0], parts[1], parts[2], parts[3], parts[4]
                creds.append(Credential(
                    source="~/.pgpass",
                    type="postgresql_credential",
                    host=host,
                    value=_redact(pg_pass),
                    confidence="high",
                    attack_vector="database_credential_theft",
                ))

    # Redis auth
    redis_conf_paths = ["/etc/redis/redis.conf", "/etc/redis.conf"]
    for rc in redis_conf_paths:
        content = _safe_read(rc)
        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.lower().startswith("requirepass"):
                    password = line.split(None, 1)[-1] if len(line.split(None, 1)) > 1 else ""
                    creds.append(Credential(
                        source=rc,
                        type="redis_credential",
                        host=host,
                        value=_redact(password),
                        confidence="high",
                        attack_vector="database_credential_theft",
                    ))

    return creds


def _scan_browser_stores(home: str, host: str) -> list[Credential]:
    """Scan for browser password store indicators (not actual decryption)."""
    creds: list[Credential] = []

    # Chrome/Chromium
    chrome_paths = [
        os.path.join(home, ".config", "google-chrome"),
        os.path.join(home, ".config", "chromium"),
        os.path.join(home, ".config", "google-chrome-beta"),
        os.path.join(home, ".config", "BraveSoftware"),
        os.path.join(home, ".config", "microsoft-edge"),
    ]

    for chrome_path in chrome_paths:
        if not os.path.isdir(chrome_path):
            continue
        browser_name = os.path.basename(chrome_path)

        # Login Data (SQLite)
        login_db = os.path.join(chrome_path, "Default", "Login Data")
        if os.path.isfile(login_db):
            creds.append(Credential(
                source="~/.config/" + browser_name + "/Default/Login Data",
                type="browser_password_store",
                host=host,
                value=_redact(browser_name + " login db exists"),
                confidence="medium",
                attack_vector="browser_credential_extraction",
            ))

        # Cookies
        cookies_db = os.path.join(chrome_path, "Default", "Cookies")
        if os.path.isfile(cookies_db):
            creds.append(Credential(
                source="~/.config/" + browser_name + "/Default/Cookies",
                type="browser_cookie_store",
                host=host,
                value=_redact(browser_name + " cookies db exists"),
                confidence="medium",
                attack_vector="browser_credential_extraction",
            ))

        # Local State (may contain encrypted keys)
        local_state = os.path.join(chrome_path, "Local State")
        content = _safe_read(local_state)
        if content:
            try:
                data = json.loads(content)
                if "os_crypt" in data:
                    creds.append(Credential(
                        source="~/.config/" + browser_name + "/Local State",
                        type="browser_encryption_key",
                        host=host,
                        value=_redact(browser_name + " os_crypt config"),
                        confidence="high",
                        attack_vector="browser_credential_extraction",
                    ))
            except (json.JSONDecodeError, ValueError):
                pass

    # Firefox
    firefox_path = os.path.join(home, ".mozilla", "firefox")
    if os.path.isdir(firefox_path):
        for profile in _safe_list_dir(firefox_path):
            profile_dir = os.path.join(firefox_path, profile)
            if not os.path.isdir(profile_dir):
                continue

            for ff_file in ["logins.json", "key4.db", "cert9.db"]:
                if os.path.isfile(os.path.join(profile_dir, ff_file)):
                    creds.append(Credential(
                        source="~/.mozilla/firefox/" + profile + "/" + ff_file,
                        type="firefox_password_store",
                        host=host,
                        value=_redact("firefox " + ff_file),
                        confidence="medium",
                        attack_vector="browser_credential_extraction",
                    ))

    return creds


def _scan_shadow_file(home: str, host: str) -> list[Credential]:
    """Read /etc/shadow if running as root."""
    creds: list[Credential] = []
    if os.geteuid() != 0:
        return creds

    content = _safe_read("/etc/shadow")
    if not content:
        return creds

    for line in content.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            username = parts[0]
            hash_val = parts[1]
            if hash_val and hash_val not in ("!", "*", "!!", ""):
                creds.append(Credential(
                    source="/etc/shadow",
                    type="password_hash",
                    host=host,
                    value=_redact(hash_val),
                    confidence="high",
                    attack_vector="hash_cracking",
                ))

    return creds


def _scan_config_files(home: str, host: str) -> list[Credential]:
    """Scan common config files for embedded passwords."""
    creds: list[Credential] = []

    config_files = [
        (os.path.join(home, ".netrc"), "netrc", r"password\s+(\S+)"),
        (os.path.join(home, ".git-credentials"), "git_credentials", r"https?://\S+:(\S+)@"),
        (os.path.join(home, ".docker", "config.json"), "docker_config", None),
        (os.path.join(home, ".npmrc"), "npm_config", r"_auth\s*=\s*(\S+)"),
        (os.path.join(home, ".pypirc"), "pypi_config", r"password\s*=\s*(\S+)"),
        (os.path.join(home, ".config", "pip", "pip.conf"), "pip_config", r"password\s*=\s*(\S+)"),
        (os.path.join(home, ".kube", "config"), "kube_config", r"password:\s*(\S+)"),
        (os.path.join(home, ".terraformrc"), "terraform_config", r'password\s*=\s*"(\S+)"'),
        (os.path.join(home, ".config", "htop", "htoprc"), "htop_config", None),
    ]

    for path, cred_type, pattern in config_files:
        content = _safe_read(path)
        if not content:
            continue

        if pattern:
            for match in re.finditer(pattern, content):
                val = match.group(1) if match.lastindex else match.group(0)
                creds.append(Credential(
                    source=path.replace(home, "~", 1),
                    type=cred_type,
                    host=host,
                    value=_redact(val),
                    confidence="high",
                    attack_vector="config_file_enumeration",
                ))
        else:
            # File exists and is sensitive
            creds.append(Credential(
                source=path.replace(home, "~", 1),
                type=cred_type,
                host=host,
                value=_redact(content[:60]),
                confidence="medium",
                attack_vector="config_file_enumeration",
            ))

    return creds


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def harvest_credentials(host: str = "localhost", json_output: bool = False) -> CredentialReport:
    """Scan the local filesystem for credential stores.

    Args:
        host: Host identifier (default: localhost).
        json_output: Unused parameter kept for API compatibility.

    Returns:
        CredentialReport with all discovered credentials and summary.
    """
    home = os.path.expanduser("~")
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    all_creds: list[Credential] = []

    # Run all scanners
    scanners = [
        _scan_ssh_keys,
        _scan_shell_history,
        _scan_env_files,
        _scan_cloud_credentials,
        _scan_database_credentials,
        _scan_browser_stores,
        _scan_shadow_file,
        _scan_config_files,
    ]

    for scanner in scanners:
        try:
            all_creds.extend(scanner(home, host))
        except (OSError, PermissionError, ValueError) as e:
            # Skip expected filesystem errors
            pass
        except KeyboardInterrupt:
            raise
        except Exception as e:
            # Log unexpected errors but don't crash
            print(f"[harvester] Scanner {scanner.__name__} failed: {e}")

    # Build summary
    by_source: dict[str, int] = {}
    by_attack_vector: dict[str, int] = {}

    for c in all_creds:
        by_source[c.source] = by_source.get(c.source, 0) + 1
        by_attack_vector[c.attack_vector] = by_attack_vector.get(c.attack_vector, 0) + 1

    summary = {
        "total_credentials": len(all_creds),
        "by_source": dict(sorted(by_source.items(), key=lambda x: -x[1])),
        "by_attack_vector": dict(sorted(by_attack_vector.items(), key=lambda x: -x[1])),
    }

    return CredentialReport(
        host=host,
        timestamp=timestamp,
        credentials=all_creds,
        summary=summary,
    )


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    report = harvest_credentials(target)
    print(json.dumps({
        "host": report.host,
        "timestamp": report.timestamp,
        "summary": report.summary,
        "credential_count": len(report.credentials),
    }, indent=2))
