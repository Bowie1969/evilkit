"""evilkit command line interface."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import (
    __version__,
    audit as audit_mod,
    config as config_mod,
    mcpscope,
    scope as scope_mod,
    theme as theme_mod,
    watch as watch_mod,
)

__all__ = ["main", "build_parser"]

PROG = "evilkit"
IDENTITY = "evilkit"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

COMMANDS = ("run", "scope", "log", "watch", "doctor", "theme", "config", "version")

_EPILOG = """\
examples:
  evilkit                            prompt for a scope, then launch
  evilkit --scope 10.0.0.0/24        launch against one network
  evilkit -s 10.0.0.5,app.lan -y     non-interactive, two targets
  evilkit -s solo                    accept the locked-down default
  evilkit --no-write -- -c           leave .mcp.json alone, resume a session
  evilkit scope show                 print the scope recorded in .mcp.json
  evilkit scope add 10.0.0.0/24      widen the record by one network
  evilkit scope remove 10.0.0.0/24   drop one network from the record
  evilkit log                        list the launches recorded locally
  evilkit watch                      watch the scope and alarm if it changes
  evilkit doctor                     check that everything is wired up

Every argument after `--` is passed straight through to the Kimi Code CLI.
"""


def _out(message: str = "") -> None:
    print(message)


def _warn(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Scope-gated launcher for the Kimi Code CLI.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    run = sub.add_parser(
        "run",
        help="set the scope and launch the Kimi Code CLI (default)",
        description="Set the authorized scope, then hand over to the Kimi Code CLI.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run.add_argument(
        "-s",
        "--scope",
        metavar="TARGETS",
        help="comma-separated hosts, IPs or CIDRs; 'solo' for the locked-down default",
    )
    run.add_argument(
        "--mcp-json",
        metavar="PATH",
        type=Path,
        help="path to .mcp.json (default: nearest one at or above the working directory)",
    )
    run.add_argument(
        "--no-write",
        "--read-only",
        dest="no_write",
        action="store_true",
        help="do not modify .mcp.json; only export the environment",
    )
    run.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="never prompt; fall back to the configured default scope",
    )
    run.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="report what would happen without writing or launching",
    )
    run.add_argument(
        "--allow-unscoped",
        action="store_true",
        help="launch even when the requested scope could not be recorded",
    )
    run.add_argument(
        "--allow-any",
        action="store_true",
        help="permit a /0 scope, which authorises every address",
    )
    run.add_argument(
        "--strict",
        action="store_true",
        help="deprecated; an unrecordable scope is already fatal unless --allow-unscoped",
    )
    run.add_argument(
        "--no-audit",
        action="store_true",
        help="do not append this launch to the local log",
    )
    scope_cmd = sub.add_parser("scope", help="inspect or change the recorded scope")
    scope_sub = scope_cmd.add_subparsers(dest="scope_command", metavar="ACTION")
    scope_cmd.set_defaults(
        scope_command=None, mcp_json=None, targets=None, allow_any=False, dry_run=False
    )
    scope_show = scope_sub.add_parser("show", help="print the scope recorded in .mcp.json")
    scope_show.add_argument("--mcp-json", metavar="PATH", type=Path)
    scope_clear = scope_sub.add_parser("clear", help="reset the scope to the locked-down default")
    scope_clear.add_argument("--mcp-json", metavar="PATH", type=Path)

    for action, blurb in (
        ("set", "replace the recorded scope"),
        ("add", "widen the recorded scope by the targets given"),
        ("remove", "narrow the recorded scope by the targets given"),
    ):
        editor = scope_sub.add_parser(action, help=blurb)
        editor.add_argument(
            "targets",
            metavar="TARGETS",
            help="comma-separated hosts, IPs or CIDRs; 'solo' for the locked-down default",
        )
        editor.add_argument("--mcp-json", metavar="PATH", type=Path)
        editor.add_argument(
            "--allow-any",
            action="store_true",
            help="permit a /0 scope, which authorises every address",
        )
        editor.add_argument(
            "--dry-run", action="store_true", help="report the change without writing it"
        )

    log_cmd = sub.add_parser("log", help="list the launches recorded locally")
    log_cmd.add_argument(
        "-n",
        "--limit",
        metavar="N",
        type=int,
        default=20,
        help="show the newest N entries; 0 shows every entry (default: 20)",
    )
    log_cmd.add_argument("--path", metavar="PATH", type=Path, help="read a different log file")
    log_cmd.add_argument("--json", action="store_true", help="print the raw log lines")

    watch_cmd = sub.add_parser(
        "watch", help="watch the recorded scope and alarm if it changes"
    )
    watch_cmd.add_argument(
        "--mcp-json",
        metavar="PATH",
        type=Path,
        help="path to .mcp.json (default: nearest one at or above the working directory)",
    )
    watch_cmd.add_argument(
        "--interval",
        metavar="SECONDS",
        type=float,
        default=1.0,
        help="how often to sample the recorded scope (default: 1.0)",
    )
    watch_cmd.add_argument(
        "--once",
        action="store_true",
        help="print a single frame and exit, for scripts and pipes",
    )
    watch_cmd.add_argument(
        "--no-color", action="store_true", help="never use ANSI colour, even on a terminal"
    )
    watch_cmd.add_argument(
        "-n",
        "--limit",
        metavar="N",
        type=int,
        default=5,
        help="how many recent launches to show; 0 shows none (default: 5)",
    )

    sub.add_parser("doctor", help="check the local installation")

    theme_cmd = sub.add_parser("theme", help="manage the bundled colour theme")
    theme_cmd.add_argument(
        "action", nargs="?", choices=("install", "status"), default="status"
    )
    theme_cmd.add_argument("--force", action="store_true", help="overwrite an existing theme")

    config_cmd = sub.add_parser("config", help="show configuration")
    config_sub = config_cmd.add_subparsers(dest="config_command", metavar="ACTION")
    config_sub.add_parser("path", help="print the config file location")
    config_sub.add_parser("show", help="print the effective configuration")
    config_sub.add_parser("init", help="write a commented default config file")

    sub.add_parser("version", help="print the version")

    return parser


def _resolve_mcp_path(explicit: Path | None) -> Path | None:
    if explicit is not None:
        resolved = explicit.expanduser()
        if not resolved.is_file():
            raise mcpscope.McpNotFound(f"{resolved} does not exist")
        return resolved.resolve()
    try:
        return mcpscope.find()
    except mcpscope.McpNotFound:
        return None


def _prompt_scope(config: config_mod.Config) -> str:
    """Ask for a scope. Returns the raw answer, which may be empty."""
    default = config.default_scope
    hint = f" [enter = {default}]"
    try:
        answer = input(f"scope{hint}> ")
    except (EOFError, KeyboardInterrupt):
        _out()
        return ""
    return answer


def _collect_scope(args, config: config_mod.Config) -> str:
    """Work out the scope to use, from the flag, the prompt, or the default."""
    if args.scope is not None:
        return args.scope.strip()

    env_value = os.environ.get(mcpscope.SCOPE_ENV_KEY, "").strip()
    if env_value:
        return env_value

    if args.yes or not sys.stdin.isatty():
        return config.default_scope

    answer = _prompt_scope(config)
    return answer.strip() or config.default_scope


def _not_recorded(
    normalised: str, message: str, allow_unscoped: bool, dry_run: bool
) -> tuple[str, int, bool]:
    """Decide what to do when the scope could not be recorded.

    Failing closed is the default: the ``.mcp.json`` env block wins over the
    parent environment, so launching here would enforce whatever scope the file
    already held rather than the one the operator asked for.
    """
    if allow_unscoped:
        _warn(f"{message} — launching with the scope NOT recorded")
        _warn(
            "the enforced scope may differ from the one requested; "
            "check .mcp.json before trusting it"
        )
        if dry_run:
            _out(f"{PROG}: would not record {normalised} (unscoped launch allowed)")
        return normalised, EXIT_OK, False
    _warn(message)
    _warn("nothing was launched: the scope could not be recorded")
    _warn("pass --allow-unscoped to launch anyway, knowing the scope may differ")
    return "", EXIT_ERROR, False


def _apply_scope(
    scope_text: str,
    mcp_path: Path | None,
    config: config_mod.Config,
    *,
    write: bool,
    allow_unscoped: bool,
    allow_any: bool,
    dry_run: bool = False,
) -> tuple[str, int, bool]:
    """Validate the scope and record it. Returns (scope, exit_code, enforced).

    ``write`` says whether a write is intended at all; ``dry_run`` says not to
    touch the disk. A dry run therefore inspects the same target and reports the
    same failures as a real run. ``enforced`` is True only when the returned
    scope is genuinely in force, which means it was recorded in the file and
    nothing else. A scope that was deliberately not written cannot be enforced:
    the file still holds whatever it held before.
    """
    try:
        normalised = scope_mod.normalise_scope(scope_text, allow_any=allow_any)
    except scope_mod.ScopeError as exc:
        _warn(f"{exc}")
        _warn("expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'")
        return "", EXIT_USAGE, False

    if not write:
        reason = "--dry-run" if dry_run else "--no-write"
        _out(f"{PROG}: scope -> {normalised} (not written; {reason})")
        return normalised, EXIT_OK, False

    if mcp_path is None:
        return _not_recorded(
            normalised,
            "no .mcp.json here or in any parent directory; nothing to scope",
            allow_unscoped,
            dry_run,
        )

    try:
        changed = mcpscope.write_scope(
            mcp_path, normalised, keep_backups=config.backup_keep, dry_run=dry_run
        )
    except mcpscope.NoPentestServer:
        return _not_recorded(
            normalised,
            f"{mcp_path} declares no 'pentest' server; nothing to scope",
            allow_unscoped,
            dry_run,
        )
    except mcpscope.McpError as exc:
        return _not_recorded(normalised, str(exc), allow_unscoped, dry_run)

    if dry_run:
        if changed:
            _out(f"{PROG}: would record {normalised} in {mcp_path}")
        else:
            _out(f"{PROG}: would leave {mcp_path} at {normalised}")
    elif changed:
        _out(f"{PROG}: scope {normalised} recorded in {mcp_path}")
    else:
        _out(f"{PROG}: scope already {normalised} in {mcp_path}")
    return normalised, EXIT_OK, True


def _audit_path(config: config_mod.Config) -> Path:
    """Where the launch log lives: the configured path, else the state default."""
    if config.audit_path:
        return Path(config.audit_path).expanduser()
    return audit_mod.default_log_path()


def _format_entry(entry: dict) -> str:
    """Render one log entry as a single readable line."""
    at = str(entry.get("at", "?"))
    scope = str(entry.get("scope", "?"))
    state = "enforced" if entry.get("enforced") else "NOT enforced"
    target = entry.get("mcp_json") or "-"
    return f"{at}  {scope}  {state}  {target}"


def _record_launch(
    config: config_mod.Config,
    scope: str,
    *,
    enforced: bool,
    mcp_path: Path | None,
    kimi: str,
    no_audit: bool,
) -> None:
    """Append this launch to the log, or say why it could not be written.

    Never fatal. The log is a record *of* a launch, so refusing to launch
    because the record could not be written would defeat the thing it records.
    The warning goes to stderr, so a caller watching the exit code still sees a
    successful launch.
    """
    if no_audit or not config.audit:
        return

    path = _audit_path(config)
    entry = audit_mod.launch_entry(scope, enforced=enforced, mcp_json=mcp_path, kimi=kimi)
    try:
        audit_mod.record(path, entry)
    except audit_mod.LogError as exc:
        _warn(f"could not record this launch: {exc}")
        _warn("the launch is continuing; set audit = false to silence this")


def _launch_env(config: config_mod.Config, scope_value: str) -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("KIMI_CODE_IDENTITY_NAME", IDENTITY)
    env.setdefault("KIMI_CODE_IDENTITY_SLUG", IDENTITY)
    env.update(config.extra_env)
    # Last, so a stray extra_env entry can never override the authorised scope.
    env[mcpscope.SCOPE_ENV_KEY] = scope_value
    return env


def _cmd_run(args, config: config_mod.Config, problems: list[str]) -> int:
    for problem in problems:
        _warn(problem)

    raw_scope = _collect_scope(args, config)

    try:
        mcp_path = _resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        _warn(str(exc))
        return EXIT_ERROR

    write = not args.no_write and config.write_mcp_json

    if args.dry_run:
        normalised, code, _ = _apply_scope(
            raw_scope,
            mcp_path,
            config,
            write=write,
            allow_unscoped=args.allow_unscoped,
            allow_any=args.allow_any,
            dry_run=True,
        )
        if code != EXIT_OK:
            return code
        _out(f"{PROG}: would launch {config.resolved_kimi_bin()}")
        return EXIT_OK

    normalised, code, enforced = _apply_scope(
        raw_scope,
        mcp_path,
        config,
        write=write,
        allow_unscoped=args.allow_unscoped,
        allow_any=args.allow_any,
    )
    if code != EXIT_OK:
        return code

    kimi = config.resolved_kimi_bin()
    if not (Path(kimi).is_file() or shutil.which(kimi)):
        _warn(f"cannot find the Kimi Code CLI ({kimi!r})")
        _warn("install it, or set kimi_bin in your config, or export EVILKIT_KIMI_BIN")
        return EXIT_ERROR

    _record_launch(
        config,
        normalised,
        enforced=enforced,
        mcp_path=mcp_path,
        kimi=kimi,
        no_audit=args.no_audit,
    )

    passthrough = list(args.passthrough or [])
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]

    if enforced:
        _out(f"{PROG}: authorized scope -> {normalised}")
    else:
        _out(f"{PROG}: scope -> {normalised} (NOT enforced; recorded scope is unchanged)")
    env = _launch_env(config, normalised)
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execvpe(kimi, [kimi, *passthrough], env)
    except OSError as exc:
        _warn(f"could not start {kimi}: {exc}")
        return EXIT_ERROR
    return EXIT_OK


#: Scope actions that change the record without launching anything.
_SCOPE_EDITORS = frozenset({"set", "add", "remove"})


def _cmd_scope(args, config: config_mod.Config) -> int:
    action = args.scope_command or "show"
    try:
        mcp_path = _resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        _warn(str(exc))
        return EXIT_ERROR

    if mcp_path is None:
        _warn("no .mcp.json found")
        return EXIT_ERROR

    if action in _SCOPE_EDITORS:
        return _edit_scope(action, args, config, mcp_path)

    if action == "clear":
        target = scope_mod.SOLO_SCOPE
        try:
            changed = mcpscope.write_scope(mcp_path, target, keep_backups=config.backup_keep)
        except mcpscope.McpError as exc:
            _warn(str(exc))
            return EXIT_ERROR
        verb = "reset to" if changed else "already"
        _out(f"{PROG}: {mcp_path} {verb} {target}")
        return EXIT_OK

    try:
        current = mcpscope.read_scope(mcp_path)
    except mcpscope.McpError as exc:
        _warn(str(exc))
        return EXIT_ERROR
    if current is None:
        _warn(f"{mcp_path} declares no pentest server")
        return EXIT_ERROR
    _out(current)
    return EXIT_OK


def _merge_scope(action: str, recorded: list[str], requested: list[str]) -> list[str]:
    """Fold ``requested`` into ``recorded`` for an add or a remove.

    The recorded order is kept, so a scope reads as the history of how it grew,
    and a target already recorded is not repeated.
    """
    if action == "add":
        known = set(recorded)
        return [*recorded, *(token for token in requested if token not in known)]
    dropped = set(requested)
    return [token for token in recorded if token not in dropped]


def _edit_scope(action: str, args, config: config_mod.Config, mcp_path: Path) -> int:
    """Change the recorded scope in place, without launching the CLI.

    A scope is meant to change mid-engagement — a host is added once the client
    confirms it, or dropped when it is decommissioned — and re-running just to
    repoint the file would also start a session. This edits the record alone,
    through the same validated, atomic, backed-up write the launcher uses.
    """
    try:
        requested = scope_mod.parse_scope(args.targets, allow_any=args.allow_any)
    except scope_mod.ScopeError as exc:
        _warn(f"{exc}")
        _warn("expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'")
        return EXIT_USAGE

    if action == "set":
        # Deliberately no read: replacing a record needs nothing from it, and a
        # file whose scope is already unreadable should still be fixable.
        merged = list(requested)
    else:
        try:
            current = mcpscope.read_scope(mcp_path)
        except mcpscope.McpError as exc:
            _warn(str(exc))
            return EXIT_ERROR
        if current is None:
            if action == "remove":
                _warn(f"nothing to remove: no scope is recorded in {mcp_path}")
                return EXIT_ERROR
            recorded: list[str] = []
        else:
            try:
                # A /0 can only have been written deliberately, with --allow-any,
                # so it must not disqualify the record from being merged.
                recorded = scope_mod.parse_scope(current, allow_any=True)
            except scope_mod.ScopeError as exc:
                _warn(f"the scope recorded in {mcp_path} cannot be merged: {exc}")
                _warn("use 'evilkit scope set' to replace it")
                return EXIT_ERROR
        merged = _merge_scope(action, recorded, requested)

    if not merged:
        _warn("that would leave no target at all; the record was left alone")
        _warn("use 'evilkit scope clear' to reset to the locked-down default")
        return EXIT_ERROR

    target = ",".join(merged)
    try:
        changed = mcpscope.write_scope(
            mcp_path, target, keep_backups=config.backup_keep, dry_run=args.dry_run
        )
    except mcpscope.McpError as exc:
        _warn(str(exc))
        return EXIT_ERROR

    if args.dry_run:
        if changed:
            _out(f"{PROG}: would record {target} in {mcp_path}")
        else:
            _out(f"{PROG}: would leave {mcp_path} at {target}")
    elif changed:
        _out(f"{PROG}: scope {target} recorded in {mcp_path}")
    else:
        _out(f"{PROG}: scope already {target} in {mcp_path}")
    return EXIT_OK


def _cmd_log(args, config: config_mod.Config) -> int:
    path = args.path.expanduser() if args.path is not None else _audit_path(config)
    limit = args.limit if args.limit and args.limit > 0 else None

    try:
        entries, skipped = audit_mod.read(path, limit)
    except audit_mod.LogError as exc:
        _warn(str(exc))
        return EXIT_ERROR

    if not entries:
        if skipped:
            _warn(f"{path} holds no readable entries; {skipped} line(s) were skipped")
            return EXIT_ERROR
        # A fresh install has no log yet. That is a normal state, not a failure.
        _out(f"{PROG}: no launches recorded yet ({path})")
        return EXIT_OK

    if args.json:
        for entry in entries:
            _out(audit_mod.to_line(entry))
    else:
        for entry in reversed(entries):
            _out(_format_entry(entry))

    if skipped:
        _warn(f"{skipped} unreadable line(s) in {path} were skipped")
    return EXIT_OK


def _read_launches(path: Path, limit: int) -> tuple[list[dict], str]:
    """The newest ``limit`` entries, and a note when the log cannot be read."""
    if limit <= 0:
        return [], ""
    try:
        entries, skipped = audit_mod.read(path, limit)
    except audit_mod.LogError as exc:
        return [], f"log unreadable ({exc})"
    return entries, (f"{skipped} unreadable line(s) skipped" if skipped else "")


def _cmd_watch(args, config: config_mod.Config) -> int:
    """Follow the recorded scope for as long as the operator leaves the pane open.

    Nothing here decides a scope or writes a file. The value is that the pane is
    present at the moment the record changes — the moment a session quietly stops
    being the one that was authorised. Exit is ``1`` if any alarm was raised, so
    the same command works as a check in a script.
    """
    import time

    try:
        mcp_path = _resolve_mcp_path(args.mcp_json)
    except mcpscope.McpNotFound as exc:
        _warn(str(exc))
        return EXIT_ERROR
    if mcp_path is None:
        _warn("no .mcp.json found; there is no recorded scope to watch")
        return EXIT_ERROR

    log_path = _audit_path(config)
    interval = max(0.1, args.interval)
    width = max(
        60, min(shutil.get_terminal_size((watch_mod.DEFAULT_WIDTH, 24)).columns, 120)
    )
    interactive = sys.stdout.isatty()
    color = not args.no_color and interactive and os.environ.get("NO_COLOR") is None

    started = time.time()
    state = watch_mod.snapshot(mcp_path)
    alerts: list[watch_mod.Alert] = []

    def frame() -> str:
        launches, note = _read_launches(log_path, args.limit)
        return watch_mod.render(
            state,
            launches,
            alerts,
            started=started,
            now_ts=time.time(),
            width=width,
            color=color,
            log_note=note,
        )

    if args.once:
        # One plain frame and no cursor movement, so it can be piped or diffed.
        _out(frame().rstrip("\n"))
        return EXIT_OK

    alarms = 0
    try:
        while True:
            if interactive:
                sys.stdout.write("\x1b[H\x1b[J")
            sys.stdout.write(frame())
            sys.stdout.flush()
            time.sleep(interval)
            sampled = watch_mod.snapshot(mcp_path)
            change = watch_mod.compare(state, sampled)
            if change is not None:
                alerts.append(change)
                if change.level == watch_mod.ALARM:
                    alarms += 1
            state = sampled
    except KeyboardInterrupt:
        _out()
        _warn(f"watch stopped after {int(time.time() - started)}s with {alarms} alarm(s)")
        return EXIT_ERROR if alarms else EXIT_OK


def _cmd_doctor(config: config_mod.Config, problems: list[str]) -> int:
    ok = True

    kimi = config.resolved_kimi_bin()
    kimi_found = bool(shutil.which(kimi)) or Path(kimi).is_file()
    _out(f"kimi binary        : {kimi} {'ok' if kimi_found else 'MISSING'}")
    ok &= kimi_found

    if config.source:
        config_state = "ok"
    elif problems:
        config_state = "unreadable (using defaults)"
    else:
        config_state = "absent (defaults)"
    _out(f"config file        : {config_mod.config_path()} {config_state}")

    try:
        mcp_path = mcpscope.find()
    except mcpscope.McpNotFound:
        _out("mcp.json           : none in this directory tree")
    else:
        _out(f"mcp.json           : {mcp_path}")
        try:
            _out(f"recorded scope     : {mcpscope.read_scope(mcp_path) or 'none'}")
        except mcpscope.McpError as exc:
            _out(f"recorded scope     : unreadable ({exc})")
            ok = False

    installed = theme_mod.is_installed()
    _out(f"theme installed    : {'yes' if installed else 'no'} ({theme_mod.kimi_themes_dir()})")

    if not config.audit:
        _out("audit log          : disabled")
    else:
        log_path = _audit_path(config)
        try:
            entries, skipped = audit_mod.read(log_path, limit=1)
        except audit_mod.LogError as exc:
            _out(f"audit log          : unreadable ({exc})")
        else:
            note = f"; {skipped} unreadable line(s) skipped" if skipped else ""
            if not entries:
                _out(f"audit log          : {log_path} (nothing recorded yet)")
            else:
                _out(f"audit log          : {log_path} (last launch {entries[-1].get('at', '?')}{note})")

    for problem in problems:
        _warn(problem)

    return EXIT_OK if ok else EXIT_ERROR


def _cmd_theme(args) -> int:
    if args.action == "install":
        edited = theme_mod.is_modified()
        try:
            target = theme_mod.install(force=args.force)
        except (OSError, ValueError, FileNotFoundError) as exc:
            _warn(str(exc))
            return EXIT_ERROR
        if edited and not args.force:
            _warn(f"{target} already exists and differs from the bundled theme")
            _warn("re-run with --force to overwrite it")
            return EXIT_ERROR
        _out(f"{PROG}: theme written to {target}")
        _out(f"{PROG}: set theme = \"{theme_mod.THEME_NAME}\" in your tui.toml to use it")
        return EXIT_OK

    installed = theme_mod.is_installed()
    state = "installed" if installed else "not installed"
    _out(f"{theme_mod.THEME_NAME}: {state} ({theme_mod.kimi_themes_dir()})")
    return EXIT_OK


def _cmd_config(args, config: config_mod.Config, problems: list[str]) -> int:
    action = args.config_command or "show"

    if action == "path":
        _out(str(config_mod.config_path()))
        return EXIT_OK

    if action == "init":
        target = config_mod.config_path()
        if target.exists():
            _warn(f"{target} already exists; leaving it alone")
            return EXIT_ERROR
        try:
            config_mod.save(config, target)
        except OSError as exc:
            _warn(f"could not write {target}: {exc}")
            return EXIT_ERROR
        _out(f"{PROG}: wrote {target}")
        return EXIT_OK

    _out(f"kimi_bin        = {config.kimi_bin}")
    _out(f"default_scope   = {config.default_scope}")
    _out(f"backup_keep     = {config.backup_keep}")
    _out(f"write_mcp_json  = {str(config.write_mcp_json).lower()}")
    resolved_log = _audit_path(config)
    _out(f"audit           = {str(config.audit).lower()}")
    _out(f"audit_path      = {resolved_log}{'' if config.audit_path else ' (default)'}")
    _out(f"config file     = {config.source or config_mod.config_path()}")
    for problem in problems:
        _warn(problem)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)

    # Split on the first standalone "--" by hand: everything after it belongs to
    # the Kimi Code CLI and must survive argparse untouched.
    if "--" in raw:
        cut = raw.index("--")
        raw, passthrough = raw[:cut], raw[cut + 1 :]
    else:
        passthrough = []

    if not raw:
        raw = ["run"]
    elif raw[0] not in COMMANDS and raw[0] not in ("-h", "--help", "-V", "--version"):
        raw = ["run", *raw]

    parser = build_parser()
    args = parser.parse_args(raw)
    args.passthrough = passthrough

    if getattr(args, "command", None) in (None, "version"):
        if args.command is None:
            parser.print_help()
            return EXIT_OK
        _out(f"{PROG} {__version__}")
        return EXIT_OK

    config, problems = config_mod.load()

    if args.command == "run":
        return _cmd_run(args, config, problems)
    if args.command == "scope":
        return _cmd_scope(args, config)
    if args.command == "log":
        return _cmd_log(args, config)
    if args.command == "watch":
        return _cmd_watch(args, config)
    if args.command == "doctor":
        return _cmd_doctor(config, problems)
    if args.command == "theme":
        return _cmd_theme(args)
    if args.command == "config":
        return _cmd_config(args, config, problems)

    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
