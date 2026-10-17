"""User configuration for evilkit.

Config lives in ``$XDG_CONFIG_HOME/evilkit/config.toml`` (``~/.config/evilkit``
by default). Only ``tomllib`` from the standard library is used to read it; the
writer below covers the flat scalar values this config actually holds.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .mcpscope import SCOPE_ENV_KEY
from .scope import SOLO_SCOPE, ScopeError, normalise_scope

__all__ = [
    "Config",
    "OsintConfig",
    "ResearchConfig",
    "config_dir",
    "config_path",
    "load",
    "save",
]

APP_NAME = "evilkit"

_TOML_STRING_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

_BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")


def _escape_string(text: str) -> str:
    """Escape ``text`` for a TOML basic string.

    Everything below 0x20 and 0x7f must be escaped: left raw, ``tomllib``
    refuses the file and the whole configuration reverts to defaults.
    """
    parts = []
    for char in text:
        if char in _TOML_STRING_ESCAPES:
            parts.append(_TOML_STRING_ESCAPES[char])
        elif char < " " or char == "\x7f":
            parts.append(f"\\u{ord(char):04X}")
        else:
            parts.append(char)
    return "".join(parts)


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / APP_NAME


def config_path() -> Path:
    override = os.environ.get("EVILKIT_CONFIG")
    return Path(override) if override else config_dir() / "config.toml"


@dataclass
class OsintConfig:
    """:mod:`evilkit.osint` stage settings. Values may start with ``~``.

    The defaults point at the standalone passive OSINT MCP server; the stage
    is optional and a missing server must degrade to a clear error, never a
    launch.
    """

    python_bin: str = "~/tools/osint-mcp/venv/bin/python"
    script: str = "~/tools/osint-mcp/server.py"
    timeout_each: float = 240.0

    def resolved_python(self) -> str:
        return os.path.expanduser(self.python_bin)

    def resolved_script(self) -> str:
        return os.path.expanduser(self.script)


@dataclass
class ResearchConfig:
    """:mod:`evilkit.research` settings — the passive web-scraping stage.

    The scraper ships with evilkit (no external server to point at), so only
    the knobs that change behaviour live here. ``nvd_api_key`` is optional:
    NVD works without one at a lower rate limit. An ``NVD_API_KEY`` in the
    environment wins over this value, because a key belongs in the process
    environment, not in a config file that may be shared.
    """

    nvd_api_key: str = ""
    timeout_each: float = 30.0
    max_bytes: int = 1_048_576

    def resolved_api_key(self) -> str:
        return os.environ.get("NVD_API_KEY") or self.nvd_api_key or ""


@dataclass
class Config:
    """Resolved settings, with every field defaulted to something safe."""

    kimi_bin: str = "kimi"
    default_scope: str = SOLO_SCOPE
    backup_keep: int = 5
    write_mcp_json: bool = True
    audit: bool = True
    audit_path: str = ""
    extra_env: dict[str, str] = field(default_factory=dict)
    osint: OsintConfig = field(default_factory=OsintConfig)
    research: ResearchConfig = field(default_factory=ResearchConfig)

    #: Populated by :func:`load` so callers can report where settings came from.
    source: Path | None = None

    def resolved_kimi_bin(self) -> str:
        """Return an executable path for the Kimi Code CLI.

        Order: an explicit env override, then the configured value, then a
        lookup on PATH. A configured value wins over PATH so a pinned version
        is honoured, but a bare name is still resolved through PATH.
        """
        import shutil

        override = os.environ.get("EVILKIT_KIMI_BIN")
        if override:
            return override
        if os.sep in self.kimi_bin:
            return os.path.expanduser(self.kimi_bin)
        found = shutil.which(self.kimi_bin)
        return found or self.kimi_bin


def _coerce_osint(raw: dict, problems: list[str]) -> dict:
    """Validate the ``[osint]`` table into raw values for OsintConfig."""
    values: dict = {}
    known = {"python", "script", "timeout_each"}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [osint] key {key!r} ignored")
    if "python" in raw:
        if isinstance(raw["python"], str) and raw["python"].strip():
            values["python_bin"] = raw["python"].strip()
        else:
            problems.append("[osint] python must be a non-empty string")
    if "script" in raw:
        if isinstance(raw["script"], str) and raw["script"].strip():
            values["script"] = raw["script"].strip()
        else:
            problems.append("[osint] script must be a non-empty string")
    if "timeout_each" in raw:
        value = raw["timeout_each"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            problems.append("[osint] timeout_each must be a positive number")
        else:
            values["timeout_each"] = float(value)
    return values


def _coerce_research(raw: dict, problems: list[str]) -> dict:
    """Validate the ``[research]`` table into raw values for ResearchConfig."""
    values: dict = {}
    known = {"nvd_api_key", "timeout_each", "max_bytes"}
    for key in raw:
        if key not in known:
            problems.append(f"unknown [research] key {key!r} ignored")
    if "nvd_api_key" in raw:
        if isinstance(raw["nvd_api_key"], str):
            values["nvd_api_key"] = raw["nvd_api_key"].strip()
        else:
            problems.append("[research] nvd_api_key must be a string")
    if "timeout_each" in raw:
        value = raw["timeout_each"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            problems.append("[research] timeout_each must be a positive number")
        else:
            values["timeout_each"] = float(value)
    if "max_bytes" in raw:
        value = raw["max_bytes"]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            problems.append("[research] max_bytes must be a positive integer")
        else:
            values["max_bytes"] = value
    return values


def _coerce(raw: dict) -> tuple[dict, list[str]]:
    known = {
        "kimi_bin",
        "default_scope",
        "backup_keep",
        "write_mcp_json",
        "audit",
        "audit_path",
        "extra_env",
        "osint",
        "research",
    }
    values: dict = {}
    problems: list[str] = []

    for key in raw:
        if key not in known:
            problems.append(f"unknown key {key!r} ignored")

    if "kimi_bin" in raw:
        if isinstance(raw["kimi_bin"], str) and raw["kimi_bin"].strip():
            values["kimi_bin"] = raw["kimi_bin"].strip()
        else:
            problems.append("kimi_bin must be a non-empty string")

    if "default_scope" in raw:
        try:
            values["default_scope"] = normalise_scope(str(raw["default_scope"]))
        except ScopeError as exc:
            problems.append(f"default_scope rejected ({exc}); using {SOLO_SCOPE}")

    if "backup_keep" in raw:
        keep = raw["backup_keep"]
        if isinstance(keep, bool) or not isinstance(keep, int):
            problems.append("backup_keep must be an integer")
        elif keep < 0:
            problems.append("backup_keep must be zero or greater")
        else:
            values["backup_keep"] = keep

    if "write_mcp_json" in raw:
        if isinstance(raw["write_mcp_json"], bool):
            values["write_mcp_json"] = raw["write_mcp_json"]
        else:
            problems.append("write_mcp_json must be true or false")

    if "audit" in raw:
        if isinstance(raw["audit"], bool):
            values["audit"] = raw["audit"]
        else:
            problems.append("audit must be true or false")

    if "audit_path" in raw:
        if isinstance(raw["audit_path"], str):
            values["audit_path"] = raw["audit_path"].strip()
        else:
            problems.append("audit_path must be a string")

    if "extra_env" in raw:
        if isinstance(raw["extra_env"], dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in raw["extra_env"].items()
        ):
            extra = dict(raw["extra_env"])
            if SCOPE_ENV_KEY in extra:
                del extra[SCOPE_ENV_KEY]
                problems.append(
                    f"extra_env cannot set {SCOPE_ENV_KEY}; "
                    "the authorised scope is the one that is recorded"
                )
            values["extra_env"] = extra
        else:
            problems.append("extra_env must be a table of string values")

    if "osint" in raw:
        if isinstance(raw["osint"], dict):
            values["osint"] = OsintConfig(**_coerce_osint(raw["osint"], problems))
        else:
            problems.append("[osint] must be a table ([osint] python = ...)")

    if "research" in raw:
        if isinstance(raw["research"], dict):
            values["research"] = ResearchConfig(
                **_coerce_research(raw["research"], problems)
            )
        else:
            problems.append("[research] must be a table ([research] timeout_each = ...)")

    return values, problems


def load(path: Path | None = None) -> tuple[Config, list[str]]:
    """Load config from ``path`` (default: the standard location).

    A missing file is not an error — defaults apply. A malformed file is
    reported through the returned problems list rather than raised, so a typo
    in config never stops someone launching a session.
    """
    target = path or config_path()
    if not target.exists():
        return Config(), []

    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return Config(), [f"could not read {target}: {exc}"]
    except RecursionError:
        return Config(), [f"could not read {target}: nested too deeply to parse"]

    values, problems = _coerce(raw)
    config = Config(**values)
    config.source = target
    return config, problems


def _format_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    return f'"{_escape_string(text)}"'


def _format_key(key: str) -> str:
    """Emit ``key`` bare when TOML allows it, quoted otherwise."""
    if _BARE_KEY_RE.fullmatch(key):
        return key
    return _format_value(key)


def dumps(config: Config) -> str:
    lines = [
        "# evilkit configuration",
        "# Docs: https://github.com/Bowie1969/evilkit",
        "",
        "# Command or absolute path for the Kimi Code CLI.",
        f"kimi_bin = {_format_value(config.kimi_bin)}",
        "",
        "# Scope used when you accept the prompt without typing anything.",
        f"default_scope = {_format_value(config.default_scope)}",
        "",
        "# How many .mcp.json backups to keep beside a project (0 disables).",
        f"backup_keep = {config.backup_keep}",
        "",
        "# Set false to launch without touching .mcp.json at all.",
        f"write_mcp_json = {_format_value(config.write_mcp_json)}",
        "",
        "# Record every launch in a local append-only log.",
        f"audit = {_format_value(config.audit)}",
        "",
        "# Where that log lives (empty: $XDG_STATE_HOME/evilkit/launches.jsonl).",
        f"audit_path = {_format_value(config.audit_path)}",
    ]
    if config.extra_env:
        lines += ["", "[extra_env]"]
        lines += [
            f"{_format_key(key)} = {_format_value(val)}"
            for key, val in sorted(config.extra_env.items())
        ]
    lines += [
        "",
        "[osint]",
        "# Passive OSINT stage: the standalone osint MCP server evilkit drives.",
        f"python = {_format_value(config.osint.python_bin)}",
        f"script = {_format_value(config.osint.script)}",
        f"timeout_each = {config.osint.timeout_each:g}",
        "",
        "[research]",
        "# Passive vulnerability research: scrapes NVD / Exploit-DB on the fly.",
        "# Optional NVD API key (raises the rate limit); NVD_API_KEY env wins.",
        f"nvd_api_key = {_format_value(config.research.nvd_api_key)}",
        f"timeout_each = {config.research.timeout_each:g}",
        f"max_bytes = {config.research.max_bytes}",
    ]
    return "\n".join(lines) + "\n"


def save(config: Config, path: Path | None = None) -> Path:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dumps(config), encoding="utf-8")
    return target
