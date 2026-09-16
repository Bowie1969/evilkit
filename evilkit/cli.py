"""evilkit command line interface."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from . import __version__, config as config_mod, mcpscope, scope as scope_mod, theme as theme_mod

__all__ = ["main", "build_parser"]

PROG = "evilkit"
IDENTITY = "evilkit"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

COMMANDS = ("run", "scope", "doctor", "theme", "config", "version")

_EPILOG = """\
examples:
  evilkit                            prompt for a scope, then launch
  evilkit --scope 10.0.0.0/24        launch against one network
  evilkit -s 10.0.0.5,app.lan -y     non-interactive, two targets
  evilkit -s solo                    accept the locked-down default
  evilkit --no-write -- -c           leave .mcp.json alone, resume a session
  evilkit scope show                 print the scope recorded in .mcp.json
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
    scope_cmd = sub.add_parser("scope", help="inspect or reset the recorded scope")
    scope_sub = scope_cmd.add_subparsers(dest="scope_command", metavar="ACTION")
    scope_cmd.set_defaults(scope_command=None, mcp_json=None)
    scope_show = scope_sub.add_parser("show", help="print the scope recorded in .mcp.json")
    scope_show.add_argument("--mcp-json", metavar="PATH", type=Path)
    scope_clear = scope_sub.add_parser("clear", help="reset the scope to the locked-down default")
    scope_clear.add_argument("--mcp-json", metavar="PATH", type=Path)

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
