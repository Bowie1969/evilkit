"""Read and update the ``pentest`` server scope inside a project's ``.mcp.json``.

The write is atomic: a candidate file is built and parsed before it replaces
anything, and the previous version is kept as a timestamped backup. A project
must never be left with a half-written ``.mcp.json``, nor briefly with none.

Why the file and not just the environment: the ``env`` block in ``.mcp.json`` is
injected into the MCP child process and wins over the parent environment, so an
exported ``PENTEST_ALLOWED_TARGETS`` does not reach the tool server.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import glob
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "McpError",
    "McpNotFound",
    "NoPentestServer",
    "SCOPE_ENV_KEY",
    "find",
    "read_scope",
    "write_scope",
    "prune_backups",
    "looks_like_backup",
]

SCOPE_ENV_KEY = "PENTEST_ALLOWED_TARGETS"
SERVER_NAME = "pentest"

_BACKUP_RE = re.compile(r"\.(?P<stamp>\d{8}-\d{6})(?:-(?P<suffix>\d+))?\.bak$")


class McpError(Exception):
    """Base class for .mcp.json handling failures."""


class McpNotFound(McpError):
    """No .mcp.json exists at the requested location."""


class NoPentestServer(McpError):
    """The .mcp.json exists but declares no pentest server."""


def find(start: Path | None = None) -> Path:
    """Locate .mcp.json at or above ``start`` (default: the working directory)."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".mcp.json"
        if candidate.is_file():
            return candidate
    raise McpNotFound(f"no .mcp.json found in {current} or any parent directory")


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise McpError(f"could not read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise McpError(f"{path} is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise McpError(f"{path} is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise McpError(f"{path} is nested too deeply to parse") from exc
    if not isinstance(data, dict):
        raise McpError(f"{path} does not contain a JSON object")
    return data


def read_scope(path: Path) -> str | None:
    """Return the configured scope, or None when no pentest server is declared."""
    data = _load(path)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        return None
    server = servers.get(SERVER_NAME)
    if not isinstance(server, dict):
        return None
    env = server.get("env")
    if not isinstance(env, dict):
        return None
    value = env.get(SCOPE_ENV_KEY)
    return value if isinstance(value, str) else None


def looks_like_backup(path: Path) -> bool:
    return bool(_BACKUP_RE.search(path.name))


def _backup_age(path: Path) -> tuple[str, int, str]:
    """Order backups oldest-first, including several written in one second."""
    match = _BACKUP_RE.search(path.name)
    if match is None:
        return ("", 0, path.name)
    return (match["stamp"], int(match["suffix"] or 0), path.name)


def _free_backup_path(path: Path) -> Path:
    """Pick an unused timestamped backup name beside ``path``."""
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.{stamp}.bak")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.{stamp}-{suffix}.bak")
        suffix += 1
    return candidate


def prune_backups(path: Path, keep: int) -> list[Path]:
    """Delete the oldest backups beside ``path``, keeping the newest ``keep``."""
    if keep < 0 or not path.parent.is_dir():
        return []
    prefix = path.name + "."
    backups = sorted(
        (
            candidate
            for candidate in path.parent.glob(f"{glob.escape(path.name)}.*.bak")
            if candidate.name.startswith(prefix) and looks_like_backup(candidate)
        ),
        key=_backup_age,
    )
    stale = backups[: max(0, len(backups) - keep)]
    removed: list[Path] = []
    for old in stale:
        try:
            old.unlink()
        except OSError:
            continue
        removed.append(old)
    return removed


def _discard(staging: Path) -> None:
    try:
        staging.unlink()
    except OSError:
        pass


def _original_mode(path: Path) -> int | None:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None


def _stage(path: Path, payload: str) -> Path:
    """Write ``payload`` to a fresh staging file beside ``path``.

    ``mkstemp`` creates the file with ``O_CREAT|O_EXCL`` under a name that
    cannot be predicted, so no symlink can be planted at the staging path.
    """
    mode = _original_mode(path)
    try:
        fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".new")
    except OSError as exc:
        raise McpError(f"could not stage a new {path.name}: {exc}") from exc

    staging = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if mode is not None:
                os.fchmod(fd, mode)
            handle.write(payload)
    except OSError as exc:
        _discard(staging)
        raise McpError(f"could not stage a new {path.name}: {exc}") from exc
    return staging


def _revalidate(staging: Path, path: Path) -> None:
    try:
        json.loads(staging.read_text(encoding="utf-8"))
    except OSError as exc:
        raise McpError(f"could not read back the staged {path.name}: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise McpError(f"refusing to write invalid JSON to {path.name}: {exc}") from exc
    except RecursionError as exc:
        raise McpError(f"refusing to write deeply nested JSON to {path.name}") from exc


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialise read-modify-write cycles with an advisory lock beside ``path``."""
    lock = path.with_name(path.name + ".lock")
    try:
        handle = open(lock, "a+b")
    except OSError as exc:
        raise McpError(f"could not open {lock}: {exc}") from exc
    with handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except OSError as exc:
            raise McpError(f"could not lock {lock}: {exc}") from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def write_scope(path: Path, scope: str, keep_backups: int = 5, dry_run: bool = False) -> bool:
    """Record ``scope`` in ``path``.

    Returns True when the file changed, False when it already held that scope
    (in which case nothing is written and no backup is created). With
    ``dry_run`` the checks run and the answer is the same, but no file is
    touched.
    """
    if dry_run:
        return _rewrite(path, scope, keep_backups, dry_run=True)
    with _locked(path):
        return _rewrite(path, scope, keep_backups, dry_run=False)


def _rewrite(path: Path, scope: str, keep_backups: int, *, dry_run: bool) -> bool:
    data = _load(path)

    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise McpError(f"{path}: 'mcpServers' is not an object")
    server = servers.get(SERVER_NAME)
    if not isinstance(server, dict):
        raise NoPentestServer(f"{path} declares no '{SERVER_NAME}' server")

    env = server.setdefault("env", {})
    if not isinstance(env, dict):
        raise McpError(f"{path}: '{SERVER_NAME}.env' is not an object")
    if env.get(SCOPE_ENV_KEY) == scope:
        return False
    env[SCOPE_ENV_KEY] = scope

    if dry_run:
        return True

    try:
        payload = json.dumps(data, indent=2) + "\n"
    except RecursionError as exc:
        raise McpError(f"{path} is nested too deeply to rewrite") from exc

    staging = _stage(path, payload)

    try:
        _revalidate(staging, path)

        if keep_backups > 0:
            backup = _free_backup_path(path)
            try:
                shutil.copy2(path, backup)
            except OSError as exc:
                raise McpError(f"could not back up {path}: {exc}") from exc

        try:
            os.replace(staging, path)
        except OSError as exc:
            # The original was copied, never moved, so it is untouched by this.
            raise McpError(f"could not replace {path}: {exc}") from exc
    except BaseException:
        _discard(staging)
        raise

    if keep_backups > 0:
        prune_backups(path, keep_backups)
    return True
