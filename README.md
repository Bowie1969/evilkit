# EvilKit

An evidence-first, scope-gated control plane for authorized AI security
testing. EvilKit gives Kimi Code, Qwen Code, Keystone telemetry, and explicitly
enrolled lab workers one auditable operating layer.

> **Status:** source-available research alpha. Use only on systems you have
> written permission to test. See the [commercial licence](LICENSE) and
> [security policy](SECURITY.md).

[Executive brief for Baidam Solutions](docs/baidam-solutions-brief.md) ·
[Run evidence](docs/runs/README.md) ·
[Operator guide](docs/usage.md) ·
[Architecture and demo](docs/baidam-solutions-brief.md#ten-minute-demo)

## Measured evidence

| Run | Operational result | Evaluation status | What it proved |
|---|---:|---|---|
| Keystone 6 | 68/110; 68/79 reachable points | Valid operational baseline | Three verified footholds, four running workers, scope-gated evidence in 18.7 minutes |
| Keystone 7 | 68/110 | Invalid as a cold-start benchmark | Broader compromise, but stale state and harness leakage exposed measurement weaknesses |
| Keystone 9 | 0/129 | Invalid; evidence binding absent | Useful wire activity, but two dashboard records and no scorer journal or capture evidence |

The second result is as important as the first: EvilKit records enough detail
to distinguish system capability from benchmark contamination. The published
reports retain the analysis and timeline; raw transcripts stay private because
they contain lab credentials and operator infrastructure.

evilkit records two things — the authorized target scope, in the right place, and a line in a local
launch log — then hands over to the Kimi Code CLI. On each launch it collects a scope from
`--scope`, an interactive prompt, or a configured default, validates and normalises it, writes it
into the `PENTEST_ALLOWED_TARGETS` value of the `pentest` MCP server in the nearest `.mcp.json`
(atomically, with a timestamped backup), exports it, and `exec`s the Kimi Code CLI with your
arguments. It also ships a colour theme for the Kimi Code TUI and a `doctor` command.

The point is the thing you would otherwise forget or mistype: a pentest tool server takes its
allowed targets from the `env` block of `.mcp.json`, and that block overrides whatever the parent
shell exported. evilkit writes the file, so the scope is always the one you authorised for this
session rather than the one left over from last week. `--deny` writes the matching denied-target
list into the same block, for the "everything in this range except this one host" case.

It fails closed. If the requested scope cannot be recorded — there is no `.mcp.json`, the file
declares no `pentest` server, the file cannot be read, or the write does not succeed — evilkit stops
and starts nothing. Launching anyway would mean the session ran under whatever scope the file
already held, which is not the one on the command line. `--allow-unscoped` opts back into that, and
says so when it happens.

## What evilkit is not

- **evilkit does not include, ship, or proxy any AI model or API access.** You bring your own Kimi
  Code CLI installation and your own account and credentials. evilkit sells the launcher and the
  workflow, not API capacity.
- **evilkit is not affiliated with, endorsed by, or produced by Moonshot AI or the Kimi Code CLI.**
  Those are third-party products with their own terms, which you must comply with yourself.
- **The scope validation is a typo guard, not a security boundary.** It stops a fat-fingered
  address from being written anywhere. The real enforcement lives in the pentest tool server you
  configure, which reads the scope from its own launch environment.

## Requirements

- Python 3.11 or newer.
- The Kimi Code CLI, installed and authenticated separately. evilkit launches it and never installs,
  configures, or authenticates it.
- A project that declares a `pentest` MCP server in its `.mcp.json`. See
  [`examples/.mcp.json.example`](examples/.mcp.json.example) for the shape evilkit expects. If the
  project is not yours, read that file before you run evilkit in it — see
  [A project's `.mcp.json` is code you did not write](#a-projects-mcpjson-is-code-you-did-not-write).

## Install

From the root of your evilkit checkout:

```bash
./install.sh
```

The script needs `python3`, refuses to run on Python older than 3.11, and installs the CLI with `uv`
if it is present, otherwise `pipx`, otherwise into a private virtual environment at
`~/.local/share/evilkit/venv`, whose `evilkit` script is linked into `~/.local/bin`. The virtual
environment is the fallback rather than `python3 -m pip install --user` because a plain `--user`
install is refused on externally-managed Pythons (Debian, Ubuntu, Parrot) under PEP 668; the `--user`
path is still used, last, on machines that have no `venv` module either. It then copies the colour
theme into `~/.kimi-code/themes/` when `~/.kimi-code` exists. It is safe to re-run.

Manual alternatives, if you would rather not use the script:

```bash
uv tool install .
```

```bash
pipx install .
```

Or, straight from the checkout without installing anything, using the project root as the working
directory:

```bash
python3 -m evilkit --help
```

## Quick start

The consolidated commands are available from one install:

```console
$ evilkit hooks install --engine all
$ evilkit kimi --scope 10.99.50.0/24 --dashboard-run-dir ~/Projects/keystone-range/runs/RUN_ID
$ evilkit qwen --scope 10.99.50.0/24 --dashboard-run-dir ~/Projects/keystone-range/runs/RUN_ID
$ evilkit dashboard status --run-dir ~/Projects/keystone-range/runs/RUN_ID
```

Both CLI adapters use the same scope doctrine, hook journal, reversible learning
ledger, and Keystone bridge. The bridge appends sanitized visualization events
to `dashboard/events.jsonl`, canonical action/session records to `journal.jsonl`,
and merges its own fields into `dashboard/status.json` — it does not replace that
file, which also holds the run's identity and the `started` anchor the board's
run clock counts from. It is disabled unless a concrete run directory is
supplied, so one run cannot silently contaminate another.

### Putting the run on the board, from inside it

A session that reports to the board can also drive it. With a dashboard URL
configured, the launch declares a `dashboard` MCP server and the operator gets
four tools:

| tool | what it does |
|---|---|
| `start_run` | the board's **Start run**: marks the newest prepared run as the one being tracked, so the board leaves the live-brain view. Refused while another run is tracked |
| `stop_run` | the board's **Stop**: marks the tracked run finished, so the live-brain view returns |
| `end_run` | finishes *this* run's own record — `state = "finished"` in the bound run's status file. Works whether or not the board is tracking it |
| `run_status` | reads the board's control state (read-only) |

Those tools run the board's own fixed scripts (`keystone-range/bin/{start,stop}.sh`),
and the scripts are **bookkeeping** (`keystone/run_control.py`): they update a
prepared run's dashboard status. They do not launch or tear down the range, they
do not start or stop an operator session, and no tool here puts traffic on a
target.

```toml
[dashboard]
url = "http://dashboard.example.test:8793"  # empty attaches nothing
attach = true                        # declare the server on every kimi/qwen launch
auto = true                          # put this run on the board, take it off at exit
timeout = 5.0                        # seconds per control request
```

`--attach-dashboard` declares the server for one launch, `--no-dashboard-mcp`
suppresses it together with the automation, and `--dry-run`/`--no-write` report
without writing. The entry goes in the file the CLI actually reads —
`<project>/.kimi-code/mcp.json`, else the user-level one (the Qwen adapter uses
the project `.mcp.json`) — never a plain `.mcp.json`, which the Kimi CLI ignores.

With `auto`, the launcher asks the board whether a run is already being tracked:
if none is, it starts tracking before the session and stops tracking when the
session ends — but only if that launch is what started it, so another session's
run is never taken off the board by someone else's exit. `--no-supervise` leaves
no process behind to stop it, and the launch says so. Each control call is
journaled into the run as `kind = "control"`.

Worth knowing: the board's run-control endpoints carry a same-origin check, not
authentication, so anything able to reach that URL can start or stop tracking.

`evilkit mesh` is the merged hub/worker interface. Hosts join as explicitly
enrolled nodes with a token, a filesystem sandbox, an allowlisted command set,
and a kill switch. Nodes do not copy or install EvilKit on additional systems;
deployment remains an operator-controlled provisioning step.

Completed hook sessions feed deterministic behavior metrics into the learning
ledger. Only thresholded lessons are appended, every automatic batch is tagged,
and `evilkit learn rollback` removes the most recent batch. Use `evilkit learn
status` and `evilkit lessons show` to inspect what changed.

### Seeing the clone's own terminal (attack segment only)

A deployed clone (a Pi, a laptop, any enrolled worker) runs its own terminal: a
systemd unit that polls the hub, claims tasks and drives a local agent. `evilkit
mesh display` watches the **attack segment** for it, proves the host's identity
over SSH, and pops up a desktop terminal window showing that clone's live
terminal — from the moment it is plugged in, and again when the hub deploys a
task to it. If that clone already has a terminal window, a new registration or
deployment raises the existing window to the front instead of silently leaving
it behind other Parrot windows or opening a duplicate.

```console
$ evilkit mesh display                      # watch, and pop up windows, forever
$ evilkit mesh display --once               # one detection pass
$ evilkit mesh display --status             # unit state, targets, open windows
$ evilkit mesh display --install-unit       # keep watching across logins
```

`evilkit mesh lead` and `evilkit mesh start` run the same watcher themselves, so
a clone that appears while the hub is up is displayed without any extra command.
`--no-display-clones` turns that off for one hub, and `--no-window` (or
`EVILKIT_POPUP_WINDOWS=0`) makes the watcher report without opening anything.

The window streams the clone's journal over SSH, and reconnects itself: a dropped
stream is printed, journalled with its exit code as `terminal_stream_ended`, and
re-established after five seconds, so a clone reboot or a brief network drop does
not leave a dead window behind (or open a second one).

The gate is the attack segment and nothing else. An address outside the
configured `segments`, or inside any denied network — the house LAN, the estate,
the WireGuard subnet, Tailscale, the hypervisor bridges, loopback — is refused,
and so is a host that answers but reports a different hostname than the one
configured. Refusals are reported; no window and no SSH session is ever opened
for them. When no segment is configured, nothing is displayable at all.

```console
$ evilkit mesh display --once --host estate-box=10.99.50.60
evilkit mesh: 10.99.50.60 is outside every attack segment (10.10.66.0/24)
$ evilkit mesh display --once --no-window --host not-the-pi=10.10.66.143
[clone-display] clone_refused: clone=not-the-pi, host=10.10.66.143, detail=answered as 'evilkit-pi-01', expected 'not-the-pi' — not this clone
```

Every detection, refusal, window and deployment is journalled with a timestamp
to `$XDG_STATE_HOME/evilkit/clone-display.jsonl`, which is where "where and when"
a clone was deployed is recorded. Open windows are registered in
`clone-display-windows.json`, so a hub and a standalone watcher never open two
windows for the same clone.

Assume your project is `/srv/engagements/acme` and its `.mcp.json` contains the example `pentest`
server. Check what the run would do before it does it:

```console
$ cd /srv/engagements/acme
$ evilkit -s 10.20.30.0/24 -n
evilkit: would record 10.20.30.0/24 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

The dry run inspects the same target a real run would use: a missing `.mcp.json`, a file with no
`pentest` server, and unreadable JSON each produce the same warning and the same exit code they
would in a real run, which is `1`. Only the file mutation is skipped. One thing it cannot tell you is
whether the destination directory is writable, which a real run discovers when it tries to stage the
new file.

Drop `-n` to actually do it:

```console
$ evilkit -s 10.20.30.0/24
evilkit: scope 10.20.30.0/24 recorded in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24
```

That `authorized scope` line is a guarantee: it is printed only when the scope is genuinely in force
for the session. The `env` block of `.mcp.json` changed from the shipped loopback default to your
authorised network:

```diff
       "env": {
-        "PENTEST_ALLOWED_TARGETS": "127.0.0.1/32",
+        "PENTEST_ALLOWED_TARGETS": "10.20.30.0/24",
         "PENTEST_DENIED_TARGETS": "",
```

and the previous version was copied beside it, timestamped:

```text
.mcp.json
.mcp.json.20260916-113217.bak
.mcp.json.lock
```

The backup is a copy, so the target is never briefly absent, and the target's permissions are
preserved, so a `.mcp.json` you hardened to `0600` stays `0600`. `.mcp.json.lock` is the sidecar lock
that serialises concurrent writes to the same file; it appears on the first write and stays there,
and this repository's `.gitignore` covers it.

No other value is changed, though the first write also reformats the file to two-space indentation,
so a diff in your editor will show more than the single line above. Run it again with the same scope
and evilkit leaves the file alone and creates no further backup:

```console
$ evilkit -s 10.20.30.0/24
evilkit: scope already 10.20.30.0/24 in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24
```

If the scope cannot be recorded, nothing launches:

```console
$ evilkit -s 10.20.30.0/24 -y
evilkit: no .mcp.json here or in any parent directory; nothing to scope
evilkit: nothing was launched: the scope could not be recorded
evilkit: pass --allow-unscoped to launch anyway, knowing the scope may differ
$ echo $?
1
```

`--allow-unscoped` restores the older behaviour of launching anyway. It prints the requested scope
but marks it as not enforced, because the `.mcp.json` `env` block still wins for the tool server:

```console
$ evilkit -s 10.20.30.0/24 -y --allow-unscoped
evilkit: no .mcp.json here or in any parent directory; nothing to scope — launching with the scope NOT recorded
evilkit: the enforced scope may differ from the one requested; check .mcp.json before trusting it
evilkit: scope -> 10.20.30.0/24 (NOT enforced; recorded scope is unchanged)
```

Read that as: the session starts, and the targets it can actually reach are the ones already recorded
in the file, which may cover more addresses than the range you just asked for. Use it when you have
checked the file yourself, not to get past an error you do not understand.

Running `evilkit` with no arguments is the same as `evilkit run`: it asks for a scope and launches.
The prompt defaults to the locked-down loopback scope, so pressing enter scopes you to your own
machine and nothing else:

```console
$ evilkit
scope [enter = 127.0.0.1/32]> 10.20.30.7
evilkit: scope 10.20.30.7/32 recorded in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.7/32
```

A scope the parser cannot make sense of is rejected before anything is written:

```console
$ evilkit -s '10.20.30.0/24; rm -rf /' -y
evilkit: '10.20.30.0/24; rm -rf /' contains characters that are not valid in a target
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
$ echo $?
2
```

## Command reference

```console
$ evilkit --help
usage: evilkit [-h] [-V] COMMAND ...

Scope-gated launcher for the Kimi Code CLI.

positional arguments:
  COMMAND
    run          set the scope and launch the Kimi Code CLI (default)
    osint        run the passive OSINT stage; never launches anything
    scope        inspect or change the recorded scope
    log          list the launches recorded locally
    watch        watch the recorded scope and alarm if it changes
    doctor       check the local installation
    theme        manage the bundled colour theme
    config       show configuration
    version      print the version

options:
  -h, --help     show this help message and exit
  -V, --version  show program's version number and exit

examples:
  evilkit                            prompt for a scope, then launch
  evilkit --scope 10.0.0.0/24        launch against one network
  evilkit -s 10.0.0.5,app.lan -y     non-interactive, two targets
  evilkit -s solo                    accept the locked-down default
  evilkit run --osint example.com    passive OSINT first, then pick the scope
  evilkit osint example.com          passive recon only; never launches
  evilkit --no-write -- -c           leave .mcp.json alone, resume a session
  evilkit scope show                 print the scope recorded in .mcp.json
  evilkit scope add 10.0.0.0/24      widen the record by one network
  evilkit scope remove 10.0.0.0/24   drop one network from the record
  evilkit log                        list the launches recorded locally
  evilkit watch                      watch the scope and alarm if it changes
  evilkit doctor                     check that everything is wired up

Every argument after `--` is passed straight through to the Kimi Code CLI.
```

Any first argument that is not one of the commands above is treated as an argument to `run`, so
`evilkit --scope 10.0.0.0/24` and `evilkit run --scope 10.0.0.0/24` are the same thing.

| Flag | Effect |
|---|---|
| `-h`, `--help` | Print help and exit `0`. |
| `-V`, `--version` | Print `evilkit 1.2.0` and exit `0`. |

### `evilkit run`

```console
$ evilkit run --help
usage: evilkit run [-h] [-s TARGETS] [--deny TARGETS] [--mcp-json PATH]
                   [--no-write] [-y] [-n] [--allow-unscoped] [--allow-any]
                   [--osint [SEED ...]] [--osint-accept VALUES]
                   [--no-osint-mcp] [--strict] [--no-audit]

Set the authorized scope, then hand over to the Kimi Code CLI.

options:
  -h, --help            show this help message and exit
  -s, --scope TARGETS   comma-separated hosts, IPs or CIDRs; 'solo' for the
                        locked-down default
  --deny TARGETS        comma-separated targets to refuse even inside the
                        scope; an empty value denies nothing (omit it to leave
                        the record alone)
  --mcp-json PATH       path to .mcp.json (default: nearest one at or above
                        the working directory)
  --no-write, --read-only
                        do not modify .mcp.json; only export the environment
  -y, --yes             never prompt; fall back to the configured default
                        scope
  -n, --dry-run         report what would happen without writing or launching
  --allow-unscoped      launch even when the requested scope could not be
                        recorded
  --allow-any           permit a /0 scope, which authorises every address
  --osint [SEED ...]    run the passive OSINT stage on these seeds first, then
                        choose the scope from the findings (interactive)
  --osint-accept VALUES
                        with --osint: accept exactly these candidates as the
                        scope (required instead of the prompt in --yes / non-
                        tty mode)
  --no-osint-mcp        do not attach the osint MCP server to the launched
                        session
  --strict              deprecated; an unrecordable scope is already fatal
                        unless --allow-unscoped
  --no-audit            do not append this launch to the local log
```

The same `examples:` and `--` epilog that `evilkit --help` prints follows this output; it is omitted
here.

| Flag | Effect |
|---|---|
| `-s`, `--scope TARGETS` | Use this scope instead of prompting. Commas separate targets, so quote the value in your shell. |
| `--deny TARGETS` | Record this as the denied-target list, parsed and normalised exactly like `--scope`, including the range forms. The tool server checks it first, so a target can be inside the scope and still be refused. Omitting the flag leaves whatever deny list is recorded in place. An empty value records "deny nothing" — it is not the `solo` loopback alias. |
| `--osint SEED...` | Run the passive OSINT stage on these seeds first, print the findings, and choose the scope from them. See *The OSINT stage*. The selection wins over `-s`. |
| `--osint-accept VALUES` | With `--osint`: accept exactly these candidate values as the scope instead of prompting. Required in `-y`/non-TTY runs; values must be among the findings. |
| `--no-osint-mcp` | Skip writing the `mcpServers.osint` entry into `.mcp.json` for this run. |
| `--mcp-json PATH` | Record the scope in this file instead of searching upward. A path that does not exist is a fatal error (`exit 1`). |
| `--no-write`, `--read-only` | Leave `.mcp.json` untouched, only export the environment, and launch. See the limitation below. |
| `-y`, `--yes` | Never prompt. Also implied when stdin is not a TTY. |
| `-n`, `--dry-run` | Validate the scope, inspect the `.mcp.json` it would record into, report what would happen, and stop without writing or launching. It exits `1` where a real run would refuse to start. Combined with `--no-write` it stops earlier and checks no target. |
| `--allow-unscoped` | Launch even when the requested scope could not be recorded. The run then enforces whatever scope the file already holds, which may be wider than the one requested; the banner says so. |
| `--allow-any` | Permit a `/0` scope. Without it, `0.0.0.0/0` and `::/0` are refused. |
| `--strict` | Deprecated and does nothing. Failing closed is the default, so an unrecordable scope is already fatal; the flag is still accepted so existing invocations keep working. |
| `--no-audit` | Skip the launch log entry for this run. The launch itself is unchanged. |
| `--` | Everything after it is passed through to the Kimi Code CLI untouched. |

Options intended for the Kimi Code CLI must go after `--`. Any leading argument evilkit does not
recognise is handed to `run`, which rejects it as an unrecognised argument with `exit 2`:

```console
$ evilkit --model kimi-k2
usage: evilkit [-h] [-V] COMMAND ...
evilkit: error: unrecognized arguments: --model kimi-k2
$ evilkit -- --model kimi-k2       # launches the CLI with --model kimi-k2
```

### `evilkit osint`

Passive recon only. Runs the standalone OSINT MCP server (see *The OSINT stage*) against seeds
typed on the command line, prints a findings table, and writes `osint-findings.json` in the
working directory — recording nothing anywhere else and never launching a session.

```console
$ evilkit osint --help
usage: evilkit osint [-h] [--only TOOLS] [--skip TOOLS] [--json PATH]
                     [--attach] SEED [SEED ...]

Passive OSINT recon: public feeds and registries only. Prints findings and
writes osint-findings.json; the candidates are only ever scope when you pass
them to `run --osint-accept` or pick them in the interactive stage.

positional arguments:
  SEED          domains, hostnames, emails, usernames, IPs or phone numbers

options:
  -h, --help    show this help message and exit
  --only TOOLS  comma-separated subset of tools to run
  --skip TOOLS  comma-separated tools to drop
  --json PATH   write findings to PATH (default: osint-findings.json here)
  --attach      also write the osint MCP server into the engagement .mcp.json,
                so the next kimi session here has the recon tools (never
                launches)
```

```console
$ evilkit osint example.com --only subfinder,theharvester
```

The optional `--attach` is the way to give a Kimi session the recon tools without running the
`run --osint` stage: it writes the same `mcpServers.osint` entry `run --osint` writes (additive,
backed up, idempotent) and records nothing else — the scope stays exactly as it was, and nothing
launches. Attach once per engagement; every later `evilkit run` or plain kimi launch in that
directory carries the tools.

### `evilkit scope`

| Command | Effect |
|---|---|
| `evilkit scope show` | Print the scope currently recorded in the `.mcp.json` evilkit finds, plus the deny list on a second line when one is recorded. Exits `1` when no file or no `pentest` server is found. |
| `evilkit scope set TARGETS` | Replace the recorded scope with `TARGETS`. |
| `evilkit scope add TARGETS` | Add `TARGETS` to the recorded scope. A target already recorded is not repeated. |
| `evilkit scope remove TARGETS` | Drop `TARGETS` from the recorded scope. Refused when it would leave no target at all. |
| `evilkit scope clear` | Reset the recorded scope to `127.0.0.1/32`. |

All of them accept `--mcp-json PATH`; `set`, `add` and `remove` also accept `--dry-run` and
`--allow-any`. With no action, `evilkit scope` behaves as `scope show`. The four writing commands go
through the same validated, atomic, backed-up path `run` uses, so a target list that does not parse
changes nothing.

```console
$ evilkit scope show
10.20.30.0/24
$ evilkit scope add 10.20.40.0/24
evilkit: scope 10.20.30.0/24,10.20.40.0/24 recorded in /srv/engagements/acme/.mcp.json
$ evilkit scope clear
evilkit: /srv/engagements/acme/.mcp.json reset to 127.0.0.1/32
```

### `evilkit log`

Prints the launch log: one line per launch, each naming the scope that launch was authorised for. It
reads `$XDG_STATE_HOME/evilkit/launches.jsonl` — `~/.local/state/evilkit/launches.jsonl` by default,
or `audit_path` if you set one — and never writes to it.

| Flag | Effect |
|---|---|
| `-n`, `--limit N` | Show the newest `N` entries. The default is `20`; `0` shows every entry. |
| `--path PATH` | Read this file instead of the configured log. |
| `--json` | Print the stored lines exactly as they were written, one per line, oldest first, ready for `jq`. |

The default output is newest-first, one entry per line:

```text
<timestamp>  <scope>  enforced|NOT enforced  <path to the .mcp.json, or - if none>
```

`enforced` means that scope was written into the `.mcp.json` named beside it, so it is the scope in
force for the session. `NOT enforced` means it was not: `--no-write` left the file's existing `env`
block in charge, and `--allow-unscoped` launched with nothing recorded. A `-` in the last column is
an entry with no `.mcp.json` at all, which is what `--allow-unscoped` records when there was no file
to write to. `--json` follows the file instead, oldest first.

```console
$ evilkit -s 10.20.30.0/24 -y
evilkit: scope 10.20.30.0/24 recorded in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24
$ evilkit -s 10.20.30.9 -y --no-write
evilkit: scope -> 10.20.30.9/32 (not written; --no-write)
evilkit: scope -> 10.20.30.9/32 (NOT enforced; recorded scope is unchanged)
$ evilkit log
2026-09-16T04:24:34Z  10.20.30.9/32  NOT enforced  /srv/engagements/acme/.mcp.json
2026-09-16T04:24:33Z  10.20.30.0/24  enforced  /srv/engagements/acme/.mcp.json
$ evilkit log --json
{"v": 1, "at": "2026-09-16T04:24:33Z", "event": "launch", "scope": "10.20.30.0/24", "enforced": true, "mcp_json": "/srv/engagements/acme/.mcp.json", "cwd": "/srv/engagements/acme", "kimi": "/home/you/.kimi-code/bin/kimi", "pid": 3892270}
{"v": 1, "at": "2026-09-16T04:24:34Z", "event": "launch", "scope": "10.20.30.9/32", "enforced": false, "mcp_json": "/srv/engagements/acme/.mcp.json", "cwd": "/srv/engagements/acme", "kimi": "/home/you/.kimi-code/bin/kimi", "pid": 3892292}
```

Only a launch that happens is logged, so a dry run, a scope the parser rejected, and a run that
could not find the Kimi Code CLI all record nothing. With no log file yet, the command says so and
exits `0` — a fresh install with nothing recorded is a normal state, not an error:

```console
$ evilkit log
evilkit: no launches recorded yet (/home/you/.local/state/evilkit/launches.jsonl)
$ echo $?
0
```

A line that cannot be parsed is skipped and counted on stderr, and the exit code is `1` only when
the log cannot be read at all, or when it holds no readable line.

### `evilkit watch`

A live pane that watches the recorded scope and alarms when it changes. It launches nothing, writes
nothing and decides nothing — it exists because `.mcp.json` *is* the boundary, and anything on the
machine can edit it while a session is open.

| Flag | Effect |
|---|---|
| `--mcp-json PATH` | Watch this file instead of the nearest one found from the working directory. |
| `--interval SECONDS` | How often to sample. The default is `1.0`; the floor is `0.1`. |
| `--once` | Print one frame and exit, for a status script or a pipe. |
| `--no-color` | Never emit ANSI colour, even on a terminal. `NO_COLOR` is honoured too. |
| `-n`, `--limit N` | How many recent launches to list. The default is `5`; `0` lists none. |

```console
$ evilkit watch
evilkit watch                                                         15:03:59
──────────────────────────────────────────────────────────────────────────────
scope in force    10.20.30.0/24
recorded in       /srv/engagements/acme/.mcp.json  (last changed 12m 41s ago)
watching for      12m 44s
──────────────────────────────────────────────────────────────────────────────
ALERTS
  nothing has changed since this pane started
──────────────────────────────────────────────────────────────────────────────
RECENT LAUNCHES
  15:01:15  10.20.30.0/24  enforced
──────────────────────────────────────────────────────────────────────────────
Ctrl-C to stop. This pane only reports; it decides nothing.
```

Then something rewrites the scope — another launcher run, a script, an editor, the agent's own file
tools — and the pane says so at once:

```console
ALERTS (1)
  15:16:40  !!  the recorded scope changed under you: 10.20.30.0/24 ->
                10.0.0.0/8 and it is wider than before
```

An alarm is raised when the scope changes, when the `pentest` server stops declaring one, and when
the file is deleted or becomes unreadable. A rewrite that leaves the scope identical is a note, not
an alarm, so an editor saving the file does not look like an incident.

A change is called out as a *widening* only when that can be proved: every address the old scope
authorised is still authorised, and the new scope authorises at least one address the old one did
not. Hostnames, mixed IPv4/IPv6 lists and anything unparseable are reported as a plain change, never
as a direction.

Exit is `0` if the scope held for the whole run and `1` if any alarm was raised, so the same command
works as a check in a script:

```console
$ evilkit watch --once --no-color > /dev/null
$ echo $?
0
```

### `evilkit doctor`

Reports the resolved Kimi Code binary, the config file in use, the `.mcp.json` it found, the scope
recorded there, whether the theme is installed, and the state of the launch log.

```console
$ evilkit doctor
kimi binary        : /home/you/.kimi-code/bin/kimi ok
config file        : /home/you/.config/evilkit/config.toml absent (defaults)
mcp.json           : /srv/engagements/acme/.mcp.json
recorded scope     : 10.20.30.0/24
theme installed    : yes (/home/you/.kimi-code/themes)
audit log          : /home/you/.local/state/evilkit/launches.jsonl (last launch 2026-09-16T04:24:34Z)
```

The `config file` line distinguishes three states: `ok` when the file was read, `absent (defaults)`
when there is no file at all, and `unreadable (using defaults)` when a file exists but could not be
parsed. Problems with individual keys are printed as `evilkit: ...` warnings above the report, and
leave the line as `ok`, because the file itself parsed.

The `audit log` line names the log file and its newest entry, or says `(nothing recorded yet)` or
`disabled` when `audit = false`.

### `evilkit theme`

```console
$ evilkit theme --help
usage: evilkit theme [-h] [--force] [{install,status}]

positional arguments:
  {install,status}

options:
  -h, --help        show this help message and exit
  --force           overwrite an existing theme
```

| Command | Effect |
|---|---|
| `evilkit theme install` | Copy the bundled theme to `<kimi home>/themes/evilkit.json`. A file that is already there is left untouched, the command exits `1` if it differs from the bundled theme, and a destination that is a symlink is always refused. |
| `evilkit theme status` | Report whether the theme file is present. This is the default, and it does not distinguish a real file from a symlink. |
| `--force` | Let `install` replace an existing file, including one you have edited yourself. It does not override the refusal to write through a symlink. |

### `evilkit config`

```console
$ evilkit config --help
usage: evilkit config [-h] ACTION ...

positional arguments:
  ACTION
    path      print the config file location
    show      print the effective configuration
    init      write a commented default config file

options:
  -h, --help  show this help message and exit
```

| Command | Effect |
|---|---|
| `evilkit config path` | Print the config file location. |
| `evilkit config show` | Print the effective configuration and where it came from. This is the default. |
| `evilkit config init` | Write a commented default config file. Fails with `exit 1` if the file already exists. |

### `evilkit version`, `-V`, `--version`

All three print `evilkit 1.2.0`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. The CLI was launched, or the command did what was asked. |
| `1` | Error: the requested scope could not be recorded (no `.mcp.json`, no `pentest` server, unreadable file, failed write), a missing Kimi Code binary, a `--mcp-json` path that does not exist, `config init` against an existing file, `theme install` against a modified theme file, `evilkit log` against a log it cannot read or that holds no readable line, an OSINT stage with an empty or invalid selection, or an osint server that could not be started. A dry run exits `1` in the same situations. |
| `2` | Usage error: the scope was rejected by the parser, an argument was not recognised, `--osint` was refused where a prompt was impossible, or no OSINT seeds were given. |

## Configuration

Config lives in `$XDG_CONFIG_HOME/evilkit/config.toml`, which is `~/.config/evilkit/config.toml` by
default. `evilkit config init` writes this file, with comments, and refuses to overwrite one that
already exists:

```toml
# evilkit configuration
# Docs: https://github.com/Bowie1969/evilkit

# Command or absolute path for the Kimi Code CLI.
kimi_bin = "kimi"

# Scope used when you accept the prompt without typing anything.
default_scope = "127.0.0.1/32"

# How many .mcp.json backups to keep beside a project (0 disables).
backup_keep = 5

# Set false to launch without touching .mcp.json at all.
write_mcp_json = true

# Record every launch in a local append-only log.
audit = true

# Where that log lives (empty: $XDG_STATE_HOME/evilkit/launches.jsonl).
audit_path = ""

[osint]
# Passive OSINT stage: the standalone osint MCP server evilkit drives.
python = "~/tools/osint-mcp/venv/bin/python"
script = "~/tools/osint-mcp/server.py"
timeout_each = 240

[clone_display]
# Show a deployed clone's live terminal in a desktop window on this box.
# Only addresses inside `segments` (and outside every denied network) are
# ever displayed; identity is proved over SSH before anything opens.
enabled = true
segments = ["10.10.66.0/24"]
deny = []
poll_interval = 5
terminal = ""
log = ""
```

| Key | Default | Effect |
|---|---|---|
| `kimi_bin` | `"kimi"` | Command or absolute path for the Kimi Code CLI. A value containing a path separator is expanded with `~` handling and used as-is; a bare name is resolved on `PATH`. |
| `default_scope` | `"127.0.0.1/32"` | The scope used when you accept the prompt without typing anything, when `-y` is given, or when stdin is not a TTY. Normalised on load; a value the scope parser rejects is ignored with a warning and the loopback default is used instead. |
| `backup_keep` | `5` | How many timestamped `.mcp.json.*.bak` files to keep beside a project. A whole number: `true`, `1.9` and `"5"` are rejected with a warning and the default is used. `0` disables backups entirely; negative values are rejected too. |
| `write_mcp_json` | `true` | Set `false` to launch without touching `.mcp.json` at all, as if `--no-write` had been passed. |
| `audit` | `true` | Set `false` to launch without appending to the launch log, as if `--no-audit` had been passed on every run. |
| `audit_path` | `""` | Where the launch log lives. Empty uses `$XDG_STATE_HOME/evilkit/launches.jsonl`, which is `~/.local/state/evilkit/launches.jsonl` by default; a leading `~` in a value you set is expanded. |
| `[extra_env]` | empty | A table of string values merged into the environment handed to the Kimi Code CLI. It cannot set `PENTEST_ALLOWED_TARGETS`; that entry is dropped and reported. |
| `[osint] python` | `~/tools/osint-mcp/venv/bin/python` | Interpreter for the passive OSINT MCP server that `evilkit osint` and `run --osint` drive. `~` is expanded at use time. |
| `[osint] script` | `~/tools/osint-mcp/server.py` | Server entry point passed to that interpreter. |
| `[osint] timeout_each` | `240` | Per-tool-call timeout in seconds; slower tools bump themselves up (sherlock needs 600). |

`[clone_display]` configures the clone-terminal watcher described above:

```toml
[clone_display]
enabled = true
segments = ["10.10.66.0/24"]   # attack segments; the only displayable networks
deny = []                       # extra networks to refuse (always refused: house, estate, WG, TS, loopback)
poll_interval = 5.0
terminal = ""                   # terminal emulator; empty picks one, or set EVILKIT_TERMINAL_BIN
log = ""                        # empty: $XDG_STATE_HOME/evilkit/clone-display.jsonl

[[clone_display.targets]]
name = "evilkit-pi-01"          # must be the hostname the clone reports
host = "10.10.66.143"
user = "pi"
identity = "~/.ssh/id_ed25519_evilkimi_pi"
unit = "evilk-mesh-worker-pi.service"
```

| Key | Default | Effect |
|---|---|---|
| `[clone_display] enabled` | `true` | Set `false` to report detections and deployments without opening windows. |
| `[clone_display] segments` | `["10.10.66.0/24"]` | The attack segments. Only addresses inside one of these, and outside every denied network, are ever displayed. An invalid CIDR, or a target outside every segment, is reported as a config problem and dropped. |
| `[clone_display] deny` | `[]` | Additional networks to refuse even when a segment covers them. |
| `[clone_display] poll_interval` | `5.0` | Seconds between detection passes. |
| `[clone_display] terminal` | `""` | Terminal emulator to open. Empty auto-detects (konsole, gnome-terminal, xfce4-terminal, kitty, alacritty, xterm, ...). |
| `[clone_display] log` | `""` | Where detection/deployment events are journalled. Empty uses `$XDG_STATE_HOME/evilkit/clone-display.jsonl`. |
| `[[clone_display.targets]]` | none | One table per clone: `name` (the hostname it must report), `host`, `user`, `identity`, `unit`. Both `name` and `host` are required; a target that fails the segment guard is dropped with a warning. |

A malformed file never stops a launch: every bad key falls back to its default and the run
continues. Each problem is reported as an `evilkit: ...` warning on stderr — by `evilkit run` before
it does anything else, and by `evilkit config show` and `evilkit doctor`. For example:

```console
$ evilkit config show
evilkit: unknown key 'unknown_key' ignored
evilkit: kimi_bin must be a non-empty string
evilkit: default_scope rejected ('!!nonsense!!' contains characters that are not valid in a target); using 127.0.0.1/32
evilkit: backup_keep must be an integer
evilkit: write_mcp_json must be true or false
kimi_bin        = kimi
default_scope   = 127.0.0.1/32
backup_keep     = 5
write_mcp_json  = true
audit           = true
audit_path      = /home/you/.local/state/evilkit/launches.jsonl (default)
config file     = /tmp/bad.toml
```

`evilkit config init` does not write an `[extra_env]` table, because there is nothing to put in one.
Add it by hand:

```toml
[extra_env]
PENTEST_ALLOW_PIVOT = "1"
```

Keys that TOML cannot express bare — anything with a space, a colon, or a dot — are quoted when the
config is written, and control characters are escaped, so an unusual key or value survives a save and
reload instead of corrupting the file.

`[extra_env]` cannot set the scope. An entry named `PENTEST_ALLOWED_TARGETS` is dropped and reported
as a config problem, and the scope evilkit exports is the one it recorded:

```console
$ evilkit config show
evilkit: extra_env cannot set PENTEST_ALLOWED_TARGETS; the authorised scope is the one that is recorded
```

## Environment variables

| Variable | Effect |
|---|---|
| `EVILKIT_KIMI_BIN` | Absolute path or command for the Kimi Code CLI. Overrides `kimi_bin` in the config. |
| `EVILKIT_CONFIG` | Use this file as the config file instead of the default location. |
| `EVILKIT_KIMI_HOME` | Kimi Code home directory used to locate `themes/`. Defaults to `~/.kimi-code`. |
| `XDG_STATE_HOME` | Directory the default launch log lives under: the log is `<XDG_STATE_HOME>/evilkit/launches.jsonl`. Defaults to `~/.local/state`. A configured `audit_path` takes precedence. |
| `PENTEST_ALLOWED_TARGETS` | Read as the scope when `--scope` is absent and the value is non-empty. |

evilkit also sets `KIMI_CODE_IDENTITY_NAME` and `KIMI_CODE_IDENTITY_SLUG` to `evilkit` in the
environment it hands to the CLI, unless you have already set them yourself or overridden them
through `[extra_env]`.

## How the scope is resolved and written

The scope comes from the first of these that applies:

1. `--scope` on the command line.
2. A non-empty `PENTEST_ALLOWED_TARGETS` in the environment.
3. The configured `default_scope`, when `-y` was passed or stdin is not a TTY.
4. An interactive prompt. An empty answer is the configured `default_scope`.

Scope is your call. evilkit never substitutes a wider target of its own, never guesses a range, and
the only fallback it applies when it has nothing to go on is the loopback `127.0.0.1/32`. It will not
quietly widen what you typed either: a network whose host bits are set is refused rather than
rounded down.

That is how `run` decides what to enforce. To change what is recorded *without* launching anything,
use `evilkit scope set`, `add` or `remove`, which write through the same validated, atomic,
backed-up path — see [`evilkit scope`](#evilkit-scope).

Whatever the source, the value is normalised before it is written:

| Input | Normalised |
|---|---|
| `10.0.0.5` | `10.0.0.5/32` |
| `10.0.0.0/24` | `10.0.0.0/24` |
| `APP.Example.COM.` | `app.example.com` |
| `solo`, `none`, `off`, empty | `127.0.0.1/32` |
| `2001:db8::1` | `2001:db8::1/128` |
| `2001:db8::/32` | `2001:db8::/32` |

Entries are comma-separated, IPv4 and IPv6 are both accepted, and duplicates are dropped. A token
longer than 253 characters, or any of the characters
`` space " ' ` $ ; & | < > ( ) { } [ ] \ ! * ? ~ ^ # `` and control characters anywhere in an entry,
is rejected with `exit 2`.

Four kinds of entry are refused rather than accepted or adjusted:

| Refused | Message |
|---|---|
| `10.0.0.5/24`, whose host bits are set | `'10.0.0.5/24' has host bits set; did you mean 10.0.0.0/24?` |
| `0.0.0.0/0` or `::/0`, without `--allow-any` | `'0.0.0.0/0' covers every address; pass --allow-any to confirm that is intended` |
| `*.example.com` — wildcards of any sort | `'*.example.com' uses wildcard matching, which the tool server cannot enforce` |
| `0x7f000001`, `0x7f.1` — legacy numeric forms | `'0x7f000001' is a legacy numeric address form that resolvers read as a different host; write it as a dotted-quad address instead` |

The wildcard refusal is deliberate. The companion tool server matches on literal addresses, so a
wildcard entry could never have matched anything; refusing it is better than recording a scope that
looks broader than it is.

Two of those are worth spelling out. Wildcards used to be accepted here and are not any more, so
replace `*.example.com` with the addresses you actually mean. And `curl`, `wget` and friends read the
legacy numeric forms as real addresses — `0x7f000001`, `0x7f.1` and `127.1` all reach `127.0.0.1` —
which would authorise a host nobody typed, so all of them are refused.

An address-shaped typo is caught too. A token made only of digits and dots has to parse as an IP
address or network, so an out-of-range octet fails clearly instead of being stored:

```console
$ evilkit -s 10.0.0.256 -n
evilkit: '10.0.0.256' looks like an IP address but is not valid
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
$ echo $?
2
```

### The deny list

`--deny` records a second value in the same `env` block, `PENTEST_DENIED_TARGETS`. The tool server
checks the deny list first, so a deny entry wins over an allow entry. That is how you authorise a
whole subnet but refuse one host inside it:

```console
$ evilkit -s 10.20.30.0/24 --deny 10.20.30.7 -n
evilkit: would record 10.20.30.0/24 in /srv/engagements/acme/.mcp.json [deny: 10.20.30.7/32]
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

It is parsed and normalised by exactly the same rules as `--scope`, the range forms included, so
`--deny 10.20.30.10-20` expands just as it would as a scope, hostnames are lowercased, and an entry
that would be rejected as a scope is rejected here too — with `exit 2` and nothing written. The one
difference in parsing is the empty value, described below.

Two differences from `--scope` are deliberate:

- **Omitting `--deny` changes nothing.** Whatever deny list is recorded stays recorded, so
  `evilkit -s 10.0.0.0/24` on a project that already denies a host goes on denying it. Only `--deny`
  replaces the list. The same holds for `scope set`, `add` and `remove`, which never touch it.
- **An empty `--deny` means "deny nothing", not the `solo` loopback alias.** The aliases (`solo`,
  `none`, `off`, empty) describe an *allow* scope, where they mean "lock down to loopback". Read the
  same way, `--deny ""` would have denied loopback itself, which is not what clearing a deny list
  means.

`evilkit scope show` prints the deny list on a second line when one is recorded, and a `--dry-run`
names it beside the scope it would write. A change to the deny list alone is a real change: it writes
the file and takes a backup, exactly as a scope change does.

The write itself:

- The nearest `.mcp.json`, at or above the working directory, is used unless `--mcp-json` says
  otherwise.
- Two values can change: `mcpServers.pentest.env.PENTEST_ALLOWED_TARGETS`, and
  `PENTEST_DENIED_TARGETS` when `--deny` is given. Every other key is read, re-serialised and written
  back unchanged. If the file declares no `pentest` server, the run stops with `exit 1` rather than
  launching unscoped.
- A `<name>.lock` file beside the target is locked for the read-modify-write, so two evilkit runs
  against the same project are serialised instead of racing. The lock file is created on first write
  and left in place.
- The new content is written to a staging file whose name is randomised (`.mcp.json.<random>.new`),
  parsed back, then swapped in with `os.replace`. The unpredictable name is the fix for a real
  vulnerability: with a fixed staging name, a hostile repository could have shipped a
  `.mcp.json.new` symlink and evilkit would have written through it.
- The previous version is *copied* to `.mcp.json.<YYYYmmdd-HHMMSS>.bak` before the swap, so the
  target is never briefly missing. A further write in the same second takes a `-1`, `-2` … suffix
  rather than overwriting an existing backup.
- The target keeps its permissions. A `.mcp.json` set to `0600` stays `0600` across a write, rather
  than being reset to the umask on a file that may hold a `PENTEST_TOKEN`.
- When both values already match what was asked for, nothing is written and no backup is created. A
  deny list that changed on its own is not that case: it is written and backed up like any other
  change.
- Backups beyond `backup_keep` are deleted, oldest first, ordered by their timestamp and then by
  that suffix, so the newest survive.
- Input that cannot be read as JSON is reported as a message, not a traceback: invalid UTF-8, invalid
  JSON, and nesting too deep to parse all produce a clean error.
- Under `--dry-run` every check above is evaluated against the same target and only the file mutation
  is skipped, so the answers match a real run. It does not create the staging file or take the lock,
  which is why it cannot report that the directory is unwritable.

Because the whole file is re-serialised, a first run reformats `.mcp.json` to two-space indentation.
Existing keys keep their order, but a missing `env` object is appended to the server entry, and any
formatting you had is not preserved.

## The OSINT stage

The `osint` command and `run --osint` run a **passive** recon stage before any scope is recorded.
Seeds (a domain, hostname, email, username, IP or phone number) are classified and fed to the
standalone osint MCP server (`[osint]` in your config; `python`/`script` point at it), which wraps
third-party data feeds, certificate logs and public registries only: theHarvester, subfinder,
sherlock, crt.sh, DNS records, whois, urlscan.io, the Wayback Machine, Shodan InternetDB, breach
databases, phoneinfoga and dnstwist. No stage tool probes a target host beyond what a browser
request would, and the stage has no scope of its own to grant.

```console
$ evilkit run --osint acme.example
evilkit: osint subfinder acme.example ...
evilkit: osint findings -> osint-findings.json

OSINT findings:
    1  acme.example                   host      [seed]
    2  api.acme.example               host      [crtsh,subfinder,dns:A]
    3  203.0.113.7                    ip        [urlscan]
    4  ops@acme.example               email     [theharvester]   (not scope-eligible)
    5  https://github.com/acme        account   [sherlock]       (not scope-eligible)

select scope candidates (numbers or 1,3-5; 'a' = all; enter = abort)> 1,2
evilkit: osint selection -> acme.example,api.acme.example
evilkit: osint MCP server attached in .mcp.json
evilkit: scope acme.example,api.acme.example recorded in .mcp.json
evilkit: authorized scope -> acme.example,api.acme.example
```

The properties that make this safe, all enforced in code:

- **Selection is manual.** Findings are only ever *candidates*. Nothing is recorded unless a
  human picks it: an interactive run prompts, and `--yes`/non-TTY runs refuse `--osint` unless
  `--osint-accept "value1,value2"` states exactly which candidates become scope.
- **Person data is never scope.** Emails, usernames, social accounts, breach names and phone
  numbers are shown as recon context and marked *not scope-eligible*; picking their number
  warns and skips.
- **Platform infrastructure is never scope.** A GitHub account found for the operator does not
  authorise github.com; candidate hosts under a platform domain are ineligible.
- **The scope gate is unchanged.** Chosen candidates flow through the same `normalise_scope()`
  parser, the same fail-closed `.mcp.json` recording and the same launch path as `-s`. A choice
  the parser rejects is dropped, not recorded around.
- **Passive sources only.** The stage is recon, not enumeration: no port scanning, no
  brute-forcing, no login attempts.

With `--osint` (and without `--no-osint-mcp`), evilkit also writes a `mcpServers.osint` entry
into the engagement's `.mcp.json` — the same stdio registration the GLM/Claude setup uses — so
the launched session can run the same passive tools mid-run; those tools hit third-party feeds,
not the target, and the pentest server's scope gate still applies to everything else.

OSINT findings on other people's assets are not authorisation. Recon tells you what is there;
scope you are entitled to attack is a separate decision you record deliberately.

## Theme

```console
$ evilkit theme install
evilkit: theme written to /home/you/.kimi-code/themes/evilkit.json
evilkit: set theme = "evilkit" in your tui.toml to use it
```

A theme file already in place is never overwritten by accident. If it matches the bundled theme the
command is a no-op that still reports success; if you have edited it, the difference is reported and
nothing is written:

```console
$ evilkit theme install
evilkit: /home/you/.kimi-code/themes/evilkit.json already exists and differs from the bundled theme
evilkit: re-run with --force to overwrite it
$ echo $?
1
```

`evilkit theme install --force` replaces the file, discarding your local edit.

The installer refuses to write through a symlink at the destination, whatever flags you pass. A theme
file that is really a link to somewhere else is a path someone else chose, and evilkit will not follow
it:

```console
$ evilkit theme install
evilkit: /home/you/.kimi-code/themes/evilkit.json is a symlink; refusing to write through it
$ echo $?
1
```

Then set the theme in your Kimi Code TUI config:

```toml
theme = "evilkit"
```

evilkit writes that line nowhere itself. The file is `~/.kimi-code/tui.toml`, the TUI configuration
of the Kimi Code CLI. `EVILKIT_KIMI_HOME` changes only where evilkit looks for and writes the
`themes/` directory; it does not change where the CLI reads its own config, so set it only if you
have deliberately relocated the themes directory. `install.sh` copies the theme unconditionally, so
it will overwrite a local edit that `evilkit theme install` would leave alone, and it has no symlink
check, so it will write through a link where the subcommand refuses to. That copy is also why
`evilkit doctor` usually reports the theme as already installed.

## Limitations

- **The scope check is a typo guard, not a security boundary.** It rejects malformed input and
  normalises what is left. It cannot know what the tool server will accept, and it does not verify
  that the server honours the scope it is given. Enforcement is the tool server's job.
- **evilkit cannot confirm the scope was honoured.** It writes one environment value into one file
  and execs the CLI. If your tool server reads its scope from somewhere else — a command-line flag,
  a database, its own config — writing `.mcp.json` will not change what it allows.
- **`--no-write` only exports the environment.** When you use it, the `env` block already in
  `.mcp.json` still wins for the MCP child process, so a stale value there stays in force. Use
  `--no-write` when the file already holds the scope you want, or when your tool server reads the
  process environment rather than the file.
- **A config problem is warned about, not fixed.** `evilkit run` prints the same warnings
  `evilkit config show` and `evilkit doctor` do, and then launches with the default for every bad
  key — including `default_scope`, which falls back to the loopback `127.0.0.1/32`. Only an
  unrecordable *scope* stops a run; a bad config value does not.
- **`--allow-unscoped` is the one way past the fail-closed default, and it is not free.** The session
  starts with the scope the file already held, which may be wider than the one you asked for, and
  every tool call in it is governed by that. evilkit prints the difference, but nothing else does.
- **`--allow-any` authorises every address.** `0.0.0.0/0` and `::/0` are refused without it precisely
  because accepting one is the largest scope there is.
- **`--dry-run` cannot see an unwritable destination.** It checks the scope and the target file, but
  it creates no staging file and takes no lock, so it cannot tell you the directory is read-only. A
  dry run can therefore report `would record` for a project where the real run then exits `1`.
- **`evilkit doctor` exits `0` when no `.mcp.json` exists.** It reports the absence and then checks
  only the other items. Do not treat `doctor`'s exit code as proof that a project is scoped.
- **evilkit does not install, configure, or authenticate the Kimi Code CLI.** If the binary is not
  found it prints where it looked and exits `1`.
- **There is no Windows support.** The package targets Linux and macOS, `install.sh` is bash, and
  the launcher uses `exec`.
- **evilkit cannot undo a scope it recorded.** Uninstalling leaves `.mcp.json` exactly as your last
  run left it, including the recorded scope. Run `evilkit scope clear` first if that matters.
- **`evilkit scope remove` subtracts entries, not address space.** Removing `10.20.40.5/32` from a
  record that also holds `10.20.40.0/24` takes out only the host entry, so the `/24` still authorises
  it. Overlapping entries are not collapsed either, and nothing checks whether one entry contains
  another.
- **`evilkit watch` watches the record, not the running session.** It samples `.mcp.json` and
  reports what it finds; it cannot see which scope a tool server process has already loaded, and it
  stops nothing. A widening it catches is a warning that a session started from that moment would be
  wider than you authorised — not a claim about what an in-flight process is still doing.
- **There is no verification of `.mcp.json` beyond JSON validity.** A file that is valid JSON but
  structurally wrong for your tool server is written as-is.
- **evilkit does not vet the project you run it in.** It rewrites the `.mcp.json` it finds, and the
  Kimi Code CLI executes that file's `command`. See the warning below.
- **The launch log is a local file that belongs to you, and it is not tamper-proof.** It is appended
  to `$XDG_STATE_HOME/evilkit/launches.jsonl` (`~/.local/state/evilkit/launches.jsonl` by default)
  with mode `0600` in a `0700` directory, and whoever ran the launcher can edit or delete it. Treat
  it as a personal record, not as evidence about a third party.
- **The log records what was asked for, not what was permitted.** `enforced` says only that evilkit
  wrote that value into the `.mcp.json` named on the same line. It does not prove the tool server
  honoured the scope, and nothing in the file shows what the session then did. Nothing reads the log
  to make a decision.
- **A launch is not always logged.** A log that cannot be written never stops a launch: evilkit
  prints `evilkit: could not record this launch: ...` on stderr and carries on, so an unlogged launch
  is possible and that warning is the only signal.
- **The log is a record of launches, not of intent.** A dry run, a scope the parser rejected, and a
  run that could not find the Kimi Code CLI all log nothing — the last of those after the scope has
  already been written into `.mcp.json`.
- **The log is never rotated.** Nothing prunes it and there is no size cap, so it grows by one line
  per launch until you shorten or delete it yourself.

## Tests

`python3 -m unittest discover -s tests -t .` from the project root runs the suite: 233 tests,
covering the scope parser, the `.mcp.json` writer, the config loader, the theme installer, the
launch log and the CLI. It passes. Run it before trusting a scripted pipeline to a change:

```console
$ python3 -m unittest discover -s tests -t .
.........................................................................................................................................................................................................................................
----------------------------------------------------------------------
Ran 233 tests in 2.123s

OK
```

## Do not commit `.mcp.json`

`.mcp.json` contains the scope you are authorised to test — often a client's address range — and it
may contain a tool-server token. Leave it out of version control in your own projects. evilkit writes
its backups, its staging file and its lock file beside the target, so every pattern has to cover any
`*.mcp.json` basename and not just the default `.mcp.json`. The `.gitignore` in this repository is a
reasonable starting point:

```gitignore
.mcp.json
*.mcp.json
.mcp.json.*.bak
*.mcp.json.*.bak
.mcp.json.new
*.mcp.json.new
.mcp.json.*.new
*.mcp.json.*.new
.mcp.json.lock
*.mcp.json.lock
```

### A project's `.mcp.json` is code you did not write

evilkit rewrites whichever `.mcp.json` it finds by walking up from the working directory. It does not
ask who owns the file, and it does not check whether you trust the repository the file came with. And
evilkit is not what runs that file: the Kimi Code CLI executes the `command` in the `pentest` server
entry when it starts the MCP server.

So a cloned repository that ships a `.mcp.json` gets two things as soon as you run evilkit inside it,
before you have read any of it:

- that file's `command` is executed by the Kimi Code CLI, as you, with your credentials within reach;
- that file's scope is rewritten to whatever you passed on the command line.

Every MCP client behaves this way — this is the model rather than a defect in evilkit — but "clone the
repository and run an agent in it" is the workflow that walks straight into it. Read the `.mcp.json` of
any project you did not write before running evilkit there, and look at what the `command` and `args`
point at:

```json
      "command": "python3",
      "args": ["tools_server.py"],
```

A `command` that is an absolute path, a shell, a downloader, or a script you have never seen is a
reason to stop. If you are not sure about the file, leave it alone: run evilkit somewhere else, or
point `--mcp-json` at a file you wrote yourself.

## Licensing and pricing

evilkit is proprietary, commercial, source-available software licensed under the
[EvilKit Commercial License](LICENSE). It is licensed, not sold.

Commercial licensing enquiries: **fullchecksecurity@gmail.com**.

In short, from the licence text:

- **Per seat.** One seat is one individual who installs or operates the software. A seat may be
  reassigned only if the original holder stops using it entirely. The number of seats and the term
  are those stated on your order or receipt.
- **No redistribution.** You may not copy, publish, distribute, sublicense, rent, lease, lend, sell
  or otherwise make evilkit available to any third party.
- **No hosted or service-bureau use.** You may not make evilkit available as part of a hosted,
  managed, or service-bureau offering to third parties, whether or not you charge for it.
- **No derivatives.** You may not modify, adapt, translate, or create derivative works, except where
  that restriction is prohibited by applicable law.
- **Notices stay put.** You may not remove or alter copyright, licence, or attribution notices.
- **Source availability is for inspection only.** The source is provided so you can read, audit, and
  security-review it, not to fork it.
- **No warranty, and liability capped** at what you paid in the twelve months before a claim.
- **It terminates automatically** if you breach the terms, and you must then stop using and delete
  all copies.

See [`docs/pricing.md`](docs/pricing.md) for how the product is sold, and [`LICENSE`](LICENSE) for
the binding text. For anything other than the standard terms, contact the copyright holder.

## Uninstall

```bash
python3 -m pip uninstall evilkit    # or: pipx uninstall evilkit / uv tool uninstall evilkit
rm -rf ~/.local/share/evilkit       # the virtual environment install.sh may have used
rm -f ~/.local/bin/evilkit          # the console script, or the link to it
rm -f ~/.kimi-code/themes/evilkit.json
rm -rf ~/.config/evilkit
```

Then remove `theme = "evilkit"` from `~/.kimi-code/tui.toml`, or set it to another theme. The
timestamped `.mcp.json.*.bak` files and the `.mcp.json.lock` sidecar in your projects are yours to
clean up, and the scope last written into `.mcp.json` stays there until you change it —
`evilkit scope clear` before uninstalling if you want it reset to `127.0.0.1/32`.

## Status

Version 1.2.0 research alpha. The public tree includes the unified Kimi/Qwen adapters, scope and
deny controls, dashboard telemetry, run profiles, learning ledger, and enrolled-worker mesh. It
fails closed by default, and the [Limitations](#limitations) above are the honest list of what it
does not do.

## Disclaimer

Use evilkit only against systems you are authorised to test. You are responsible for having written
permission for every target you put in a scope, and for complying with the terms of service of the
Kimi Code CLI and any other third-party software involved. evilkit is not affiliated with, endorsed
by, or produced by Moonshot AI or the Kimi Code CLI. The software is provided as is, without
warranty, and the licensor's liability is limited as set out in the [licence](LICENSE).
