# evilkit usage

This page goes past the quick start in the [README](../README.md): how the scope is collected and
written, what each flag does in practice, and a set of worked sessions you can copy from.

- [The launch sequence](#the-launch-sequence)
- [Worked example: preparing an engagement](#worked-example-preparing-an-engagement)
- [Worked example: scripted and CI runs](#worked-example-scripted-and-ci-runs)
- [Worked example: several projects on one machine](#worked-example-several-projects-on-one-machine)
- [Worked example: deviating from a project's scope](#worked-example-deviating-from-a-projects-scope)
- [Worked example: inspecting and changing the recorded scope](#worked-example-inspecting-and-changing-the-recorded-scope)
- [Worked example: reading the launch log](#worked-example-reading-the-launch-log)
- [Worked example: watching the scope during a session](#worked-example-watching-the-scope-during-a-session)
- [Worked example: the theme and the doctor command](#worked-example-the-theme-and-the-doctor-command)
- [Worked example: a run profile (the launch contract)](#worked-example-a-run-profile-the-launch-contract)
- [Worked example: reading a run back](#worked-example-reading-a-run-back)
- [Scope syntax reference](#scope-syntax-reference)
- [What gets written to `.mcp.json`](#what-gets-written-to-mcpjson)
- [Recipes](#recipes)
- [Troubleshooting](#troubleshooting)

## The launch sequence

`evilkit run` does this, in order. A rejected scope, a scope that cannot be recorded, or a missing
binary stops it.

1. Report any config problems as `evilkit: ...` warnings on stderr, then carry on using the default
   for each bad key.
2. Collect the scope: `--scope`, then a non-empty `PENTEST_ALLOWED_TARGETS` in the environment, then
   the configured `default_scope` when `-y` was passed or stdin is not a TTY, then an interactive
   prompt.
3. Normalise it. A rejected value prints two lines to stderr and exits `2` without touching
   anything.
4. Resolve where the scope goes: the path from `--mcp-json`, or the nearest `.mcp.json` at or above
   the working directory.
5. Unless `--no-write` was passed or `write_mcp_json` is `false`, record the scope in
   `mcpServers.pentest.env.PENTEST_ALLOWED_TARGETS`, and the `--deny` list in
   `mcpServers.pentest.env.PENTEST_DENIED_TARGETS` when that flag was given. This is the step that
   fails closed: if there is no file, no `pentest` server in it, or the write itself fails, the run
   stops with `exit 1` and the CLI is never started.
6. Resolve the Kimi Code CLI binary. If it is not found, exit `1`.
7. Unless `--no-audit` was passed or `audit` is `false`, append one entry to the local launch log,
   naming the scope and whether it was enforced. A log that cannot be written is a warning on stderr
   and nothing else; the launch carries on.
8. Print `evilkit: authorized scope -> <scope>`, flush stdout and stderr, and `exec` the CLI,
   replacing the evilkit process. Its exit status becomes the session's exit status, and no evilkit
   code runs afterwards.

Because step 8 is an `exec`, the Kimi Code CLI is the process you Ctrl-C out of. evilkit does not run
alongside it, does not read its output, and does not clean up after it. The flush in that step is why
the status lines survive when stdout is a pipe or a log file rather than a terminal.

Step 8 prints `authorized scope -> <scope>` only when that scope is in force: recorded in the file, or
deliberately left unwritten because you asked for that with `--no-write` or
`write_mcp_json = false`. When `--allow-unscoped` lets a run continue after a failed step 5, the line
is different — `scope -> <scope> (NOT enforced; recorded scope is unchanged)` — and the session runs
under whatever scope the file already held.

With `--dry-run`, steps 4 and 5 run against the same target and report the same failures and the same
exit codes, and the write is replaced by a description of what it would have done. The run ends
before step 7, so a dry run is never logged. Adding `--no-write` as well takes a shortcut instead:
the run stops after step 3, checks no target, and launches nothing.

The environment handed to the CLI is your environment, plus `PENTEST_ALLOWED_TARGETS` set to the
normalised scope, plus `KIMI_CODE_IDENTITY_NAME` and `KIMI_CODE_IDENTITY_SLUG` set to `evilkit`
unless they were already set, plus everything in `[extra_env]` from your config. The scope is applied
last, so no `[extra_env]` entry can override it. A deny list is not added to that environment: it is
written to the file, which is the copy the tool server reads, and omitting `--deny` leaves it alone.

`--deny` is the other half of the boundary. It records `PENTEST_DENIED_TARGETS` from the same
comma-separated syntax `--scope` takes — ranges, hostnames and IPv6 included — and the tool server
checks that list first, so a deny entry wins over an allow entry. It is how "all of `10.20.30.0/24`
except `10.20.30.7`" is expressed:

```console
$ evilkit -s 10.20.30.0/24 --deny 10.20.30.7 -n
evilkit: would record 10.20.30.0/24 in /srv/engagements/acme/.mcp.json [deny: 10.20.30.7/32]
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

Omitting `--deny` leaves the recorded deny list exactly as it was, so a bare re-scope never blanks
one. An empty `--deny` records "deny nothing" — the empty value is not the `solo` loopback alias,
because those aliases describe an *allow* scope, where "nothing" means "lock down to loopback".
Both lists are validated before either is written, so a deny entry that does not parse leaves the
file untouched and exits `2`.

One optional step 0 exists: `run --osint SEED...` runs the passive OSINT stage first (the `osint`
command's recon, below), prints the findings, and requires you to pick scope candidates from them.
The picks are validated by the same scope parser and then become `--scope` for steps 3–7; nothing is
recorded until you pick. In `--yes` or non-TTY runs the prompt cannot happen, so `--osint` is refused
unless `--osint-accept "value1,value2"` states the picks explicitly. Unless `--no-osint-mcp` is
passed, the same run also writes a `mcpServers.osint` entry beside the recorded scope so the session
itself can run the passive tools. To give the session the recon tools without running the stage at
all, `evilkit osint --attach SEED...` writes that same entry and never launches anything.

## Worked example: the optional OSINT stage

The stage answers one question before you authorise anything: *what can public sources see about
this seed?* Seeds are typed, not discovered — you hand the stage the domain, email, username, IP or
phone you are entitled to investigate; it enumerates passively and proposes candidates.

```console
$ cd /srv/engagements/acme
$ evilkit osint acme.example --skip wayback_urls
evilkit: osint subfinder acme.example ...
evilkit: osint crtsh_certificates acme.example ...
evilkit: osint findings -> osint-findings.json

OSINT findings (passive public sources only; nothing was probed):
    1  acme.example                   host      [seed]
    2  api.acme.example               host      [crtsh,dns:A]
    3  203.0.113.7                    ip        [urlscan]
    4  ops@acme.example               email     [theharvester]   (not scope-eligible)
    5  https://github.com/acme        account   [sherlock]       (not scope-eligible)

3 candidates (2 scope-eligible)
evilkit: findings -> /srv/engagements/acme/osint-findings.json
```

The JSON file carries the full picture: every seed, every tool run and its status, the raw output of
each (capped), and the deduplicated candidate list with `scope_eligible` per candidate. Keep it with
the engagement — it is the provenance for whatever you authorised next.

To let the recon choose the scope, use `run --osint` and answer the prompt:

```console
$ evilkit run --osint acme.example
... findings table ...
select scope candidates (numbers or 1,3-5; 'a' = all; enter = abort)> 1,2
evilkit: osint selection -> acme.example,api.acme.example
evilkit: would add the osint MCP server in /srv/engagements/acme/.mcp.json
evilkit: would record acme.example,api.acme.example in /srv/engagements/acme/.mcp.json
$ evilkit run --osint acme.example            # the same, recorded and launched
```

Scripted runs pass the picks explicitly instead of prompting:

```console
$ evilkit run --osint acme.example --osint-accept "acme.example,api.acme.example" -y
```

`--osint-accept` values are candidates by their full text (hosts, IPs, CIDRs); anything not
scope-eligible or not parseable as a scope token is warned about and skipped, and a selection that
leaves nothing valid stops the run before any write — exit `1`, nothing recorded, nothing launched.

Boundaries worth restating, because they are enforced rather than promised: the stage never probes a
target (its sources are third-party feeds), candidates that are data about a person (emails,
usernames, accounts, breaches, phones) can never become scope, hosts under platform domains can
never become scope, and findings about somebody else's assets are still not authorisation — the
selection prompt asks you to authorise what you will attack, so pick only what you are entitled to
attack. Configuration lives in the `[osint]` table:

```toml
[osint]
python = "/opt/osint-mcp/venv/bin/python"
script = "/opt/osint-mcp/server.py"
timeout_each = 240
```

## Worked example: preparing an engagement

A project directory needs a `pentest` MCP server before evilkit can do anything useful. The shape it
expects is in `examples/.mcp.json.example`:

```json
{
  "mcpServers": {
    "pentest": {
      "command": "python3",
      "args": ["tools_server.py"],
      "env": {
        "PENTEST_ALLOWED_TARGETS": "127.0.0.1/32",
        "PENTEST_DENIED_TARGETS": "",
        "PENTEST_ALLOW_PIVOT": "0",
        "PENTEST_ALLOW_INTERPRETER": "0",
        "PENTEST_ALLOW_ANY_CMD": "0",
        "PENTEST_TOKEN": ""
      }
    }
  }
}
```

Copy it into your engagement directory, then check the wiring before you launch:

```console
$ cd /srv/engagements/acme
$ cp /path/to/evilkit/examples/.mcp.json.example .mcp.json
$ evilkit doctor
kimi binary        : /home/you/.kimi-code/bin/kimi ok
config file        : /home/you/.config/evilkit/config.toml absent (defaults)
mcp.json           : /srv/engagements/acme/.mcp.json
recorded scope     : 127.0.0.1/32
theme installed    : yes (/home/you/.kimi-code/themes)
audit log          : /home/you/.local/state/evilkit/launches.jsonl (nothing recorded yet)
```

Now launch with the range you are authorised to test. `-n` first if you want to see the plan:

```console
$ evilkit -s 10.20.30.0/24,10.20.40.0/24 -n
evilkit: would record 10.20.30.0/24,10.20.40.0/24 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
$ evilkit -s 10.20.30.0/24,10.20.40.0/24
evilkit: scope 10.20.30.0/24,10.20.40.0/24 recorded in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24,10.20.40.0/24
```

The dry run decides against the same file the real run would use, so it is a genuine preflight for
the ways the scope can fail to be recorded, and it exits non-zero exactly where a real run would
refuse to start. A target with nothing to scope fails the same way a real run does, unless you allow
the unscoped launch:

```console
$ evilkit -s 10.0.0.0/24 -n
evilkit: /srv/engagements/globex/.mcp.json declares no 'pentest' server; nothing to scope
evilkit: nothing was launched: the scope could not be recorded
evilkit: pass --allow-unscoped to launch anyway, knowing the scope may differ
$ echo $?
1
$ evilkit -s 10.0.0.0/24 -n --allow-unscoped
evilkit: /srv/engagements/globex/.mcp.json declares no 'pentest' server; nothing to scope — launching with the scope NOT recorded
evilkit: the enforced scope may differ from the one requested; check .mcp.json before trusting it
evilkit: would not record 10.0.0.0/24 (unscoped launch allowed)
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

When the file already holds the scope you asked for, the dry run says so rather than describing a
write:

```console
$ evilkit -s 10.20.30.0/24,10.20.40.0/24 -n
evilkit: would leave /srv/engagements/acme/.mcp.json at 10.20.30.0/24,10.20.40.0/24
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

What it cannot check is whether the directory can be written to, because only a real run creates the
staging file and takes the lock.

Two networks, one `PENTEST_ALLOWED_TARGETS` value, comma-separated. The `.mcp.json` now holds:

```json
{
  "mcpServers": {
    "pentest": {
      "command": "python3",
      "args": ["tools_server.py"],
      "env": {
        "PENTEST_ALLOWED_TARGETS": "10.20.30.0/24,10.20.40.0/24",
        "PENTEST_DENIED_TARGETS": "",
        "PENTEST_ALLOW_PIVOT": "0",
        "PENTEST_ALLOW_INTERPRETER": "0",
        "PENTEST_ALLOW_ANY_CMD": "0",
        "PENTEST_TOKEN": ""
      }
    }
  }
}
```

and the previous version is beside it as `.mcp.json.<YYYYmmdd-HHMMSS>.bak`.

Because resolution walks upward from the working directory, you do not have to launch from the
project root:

```console
$ cd /srv/engagements/acme/recon/nmap
$ evilkit -s 10.20.30.0/24 -n
evilkit: would record 10.20.30.0/24 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

Pass CLI arguments through after `--`. evilkit does not parse or validate them; they are handed to
the Kimi Code CLI unchanged, so use that CLI's own flags (`-m` for a model, `-c` to continue the
previous session, `-p` for a one-shot prompt):

```console
$ evilkit -s 10.20.30.0/24 -- -m kimi-k2 -c
$ evilkit -s 10.20.30.0/24 -- -p "list the targets you can reach"
```

## Worked example: scripted and CI runs

Prompts are the enemy of a scripted run, so the non-interactive path is worth knowing precisely.
With no `--scope`:

- `-y` skips the prompt and uses `default_scope`.
- A non-TTY stdin (`< /dev/null`, a pipe, a cron job, a CI step) also skips the prompt and uses
  `default_scope`, even without `-y`.
- An empty `PENTEST_ALLOWED_TARGETS` in the environment does not count as a scope, so it falls
  through to the same default.

```console
$ evilkit -y -n
evilkit: would record 127.0.0.1/32 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi

$ evilkit -n < /dev/null
evilkit: would record 127.0.0.1/32 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

Note what the fallback is: the locked-down loopback scope, not the range from last time. A scripted
run that forgets its scope lands on `127.0.0.1/32` rather than silently reusing an old one.

A batch step does not need any extra flag to be safe: an unrecordable scope is fatal on its own, so
`set -e` stops the batch. Dropping `--strict` from an older script changes nothing, because the flag
is deprecated and inert.

```bash
set -euo pipefail
cd /srv/engagements/acme
EVILKIT_KIMI_BIN=/bin/true evilkit -s 10.20.30.0/24 -y
```

Pointing `EVILKIT_KIMI_BIN` at a command that exists and exits immediately — `/bin/true` on Linux,
`/usr/bin/true` on macOS — satisfies the binary check and ends the run as soon as the scope has been
recorded, with no interactive session.

Be careful with `--allow-unscoped` here. It is the one flag that makes the batch continue after a
failure to record the scope, with the session running under whatever the file already held. A
pipeline that must not do that should leave it off and treat any non-zero exit as fatal.

For a scheduled re-scope with no launch at all, the same trick is the whole recipe:

```bash
EVILKIT_KIMI_BIN=/bin/true \
  evilkit -s 10.20.30.0/24 -y   # record the scope, no interactive session
evilkit scope show              # verify
```

Exit code `2` means the scope was rejected by the parser; exit code `1` means it was accepted but
could not be recorded. Both mean the run did not launch, and both are worth failing on:

```bash
if ! EVILKIT_KIMI_BIN=/bin/true evilkit -s "$SCOPE" -y; then
  echo "evilkit could not scope this project to $SCOPE" >&2
  exit 1
fi
```

### Output from a scripted run

Status lines go to stdout and warnings to stderr, and both streams are flushed immediately before
evilkit replaces itself with the Kimi Code CLI, so a run under a pipe, a redirect or a CI step logs
the same lines a terminal shows:

```console
$ evilkit -s 10.20.30.0/24 > run.log 2>/dev/null
$ cat run.log
evilkit: scope already 10.20.30.0/24 in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24
<whatever the Kimi Code CLI writes to stdout>
```

The child process's own output follows, because from that point the CLI has inherited the same
streams. If you want the scope as data rather than as log text, read it back with
`evilkit scope show`, whose first line is the value from the file — a second `deny:` line follows
only when a deny list is recorded.

## Worked example: several projects on one machine

The nearest `.mcp.json` wins, so one machine can hold several engagements with different scopes and
they do not collide:

```text
/srv/engagements/acme/.mcp.json          -> PENTEST_ALLOWED_TARGETS = 10.20.30.0/24
/srv/engagements/globex/.mcp.json        -> PENTEST_ALLOWED_TARGETS = 192.0.2.0/24
/srv/engagements/globex/recon/.mcp.json  -> PENTEST_ALLOWED_TARGETS = 198.51.100.7/32
```

From `/srv/engagements/globex/recon`, evilkit writes to the nested file, not the one above it. That
is the correct behaviour if the nested file is a deliberate narrowing, and a surprise if it is a
stale copy someone left behind. `evilkit scope show` prints the scope of whichever file evilkit
would write, so it is the cheap way to check:

```console
$ cd /srv/engagements/globex/recon
$ evilkit scope show
198.51.100.7/32
```

To target a specific file regardless of where you are:

```console
$ evilkit -s 192.0.2.0/24 --mcp-json /srv/engagements/globex/.mcp.json
evilkit: scope 192.0.2.0/24 recorded in /srv/engagements/globex/.mcp.json
evilkit: authorized scope -> 192.0.2.0/24
```

`--mcp-json` pointing at a file that does not exist is a fatal error, not a create:

```console
$ evilkit -s 192.0.2.0/24 --mcp-json /srv/engagements/globex/.mcp.json.typo
evilkit: /srv/engagements/globex/.mcp.json.typo does not exist
$ echo $?
1
```

## Worked example: deviating from a project's scope

Two reasons to launch without rewriting the file.

### The file already holds the scope you want

The writer is a no-op when the value matches, so you can launch repeatedly without churning backups:

```console
$ evilkit -s 10.20.30.0/24
evilkit: scope already 10.20.30.0/24 in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24
```

### You want the file left alone entirely

`--no-write` (same as `--read-only`) exports the environment and writes nothing:

```console
$ evilkit -s 10.20.30.9 --no-write
evilkit: scope -> 10.20.30.9/32 (not written; --no-write)
evilkit: authorized scope -> 10.20.30.9/32
```

Understand what that does and does not do. evilkit exports `PENTEST_ALLOWED_TARGETS`, but the `env`
block inside `.mcp.json` is injected into the MCP child process and takes precedence over the parent
environment — that precedence is the reason evilkit writes the file at all. So with `--no-write`,
any MCP server started from that file keeps the scope the file already had. `--no-write` is for
situations where the file is already correct, or where your tool server reads the process
environment rather than the file.

This is the one case where the `authorized scope -> <scope>` banner appears without the file having
been touched, because not writing was your instruction rather than a failure. Everything the banner
says about the exported environment holds; it says nothing about the scope recorded in the file,
which `--no-write` left alone. If you need those two to agree, drop `--no-write` and let evilkit
record the scope, or check the file yourself with `evilkit scope show`.

The same switch is available as a setting, for a project where you never want the file touched:

```toml
# ~/.config/evilkit/config.toml
write_mcp_json = false
```

## Worked example: inspecting and changing the recorded scope

```console
$ evilkit scope show
10.20.30.0/24,10.20.40.0/24

$ evilkit scope add 10.20.50.0/24
evilkit: scope 10.20.30.0/24,10.20.40.0/24,10.20.50.0/24 recorded in /srv/engagements/acme/.mcp.json

$ evilkit scope remove 10.20.40.0/24
evilkit: scope 10.20.30.0/24,10.20.50.0/24 recorded in /srv/engagements/acme/.mcp.json

$ evilkit scope set 10.20.30.0/24,app.internal
evilkit: scope 10.20.30.0/24,app.internal recorded in /srv/engagements/acme/.mcp.json
```

`scope set` replaces the record; `add` and `remove` fold a target list into it. All three write
through the same validated, atomic, backed-up path the launcher uses, and all three take `--dry-run`
to report the change without writing it:

```console
$ evilkit scope set solo --dry-run
evilkit: would record 127.0.0.1/32 in /srv/engagements/acme/.mcp.json
```

A scope changes mid-engagement — a host is added once the client confirms it, or dropped when it is
decommissioned — and these are how you change it without also starting a session. `run` writes the
scope it is about to enforce; these commands are for when you want the record changed and nothing
launched.

`remove` subtracts *entries*, not address space: removing `10.20.40.5/32` from a record that holds
`10.20.40.0/24` leaves the `/24` in place, so that host is still authorised. Remove the wider entry,
or `scope set` the exact list you mean. Removing the last remaining target is refused outright, so an
empty scope is never written by accident — use `scope clear` when that is what you want.

`scope clear` writes the loopback default; it does not delete the key or the file. It is the right
last step before archiving an engagement directory, before sharing it, or before uninstalling
evilkit. It leaves any deny list alone: `set`, `add`, `remove` and `clear` all rewrite the scope
value only, and the deny list changes only when `evilkit run --deny` says so.

`scope show` prints the deny list on a second line whenever one is recorded, so the two halves of the
boundary are read back together:

```console
$ evilkit scope show
10.20.30.0/24
deny: 10.20.30.7/32
```

When no deny list is recorded, or the recorded one is empty, only the scope is printed.

When there is nothing to read, each fails loudly rather than printing nothing:

```console
$ evilkit scope show
evilkit: no .mcp.json found
$ echo $?
1

$ cd /tmp/with-a-foreign-config
$ evilkit scope show
evilkit: /tmp/with-a-foreign-config/.mcp.json declares no pentest server
$ echo $?
1
```

Both accept `--mcp-json PATH` so you can inspect a project without `cd`-ing into it:

```console
$ evilkit scope show --mcp-json /srv/engagements/globex/.mcp.json
192.0.2.0/24
```

## Worked example: reading the launch log

Every launch that happens appends one line to the local log, and nothing else writes to it. Two
launches, one of which recorded the scope and one of which deliberately did not:

```console
$ evilkit -s 10.20.30.0/24 -y
evilkit: scope 10.20.30.0/24 recorded in /srv/engagements/acme/.mcp.json
evilkit: authorized scope -> 10.20.30.0/24
$ evilkit -s 10.20.30.9 -y --no-write
evilkit: scope -> 10.20.30.9/32 (not written; --no-write)
evilkit: scope -> 10.20.30.9/32 (NOT enforced; recorded scope is unchanged)
```

`evilkit log` prints them newest-first, and the two rows differ in the column that matters:

```console
$ evilkit log
2026-09-16T04:24:34Z  10.20.30.9/32  NOT enforced  /srv/engagements/acme/.mcp.json
2026-09-16T04:24:33Z  10.20.30.0/24  enforced  /srv/engagements/acme/.mcp.json
```

Both launches are in the log. The `--no-write` one is marked `NOT enforced` because that flag left
the `.mcp.json` `env` block in charge, so that session ran under `10.20.30.0/24` while the command
line asked for `10.20.30.9`. That is what the column is for: the requested scope is recorded either
way, and the flag says whether it was the one actually written to the file. A `-` in the last column
is an entry with no `.mcp.json` at all, which is what `--allow-unscoped` records when there is no
file to write to.

`--json` prints the stored lines themselves, oldest first, which is the form to pipe into `jq`:

```console
$ evilkit log --json
{"v": 1, "at": "2026-09-16T04:24:33Z", "event": "launch", "scope": "10.20.30.0/24", "enforced": true, "mcp_json": "/srv/engagements/acme/.mcp.json", "cwd": "/srv/engagements/acme", "kimi": "/home/you/.kimi-code/bin/kimi", "pid": 3892270}
{"v": 1, "at": "2026-09-16T04:24:34Z", "event": "launch", "scope": "10.20.30.9/32", "enforced": false, "mcp_json": "/srv/engagements/acme/.mcp.json", "cwd": "/srv/engagements/acme", "kimi": "/home/you/.kimi-code/bin/kimi", "pid": 3892292}
```

The file is `$XDG_STATE_HOME/evilkit/launches.jsonl`, or `~/.local/state/evilkit/launches.jsonl` by
default, written `0600` inside a `0700` directory because it names client address ranges. `-n N`
limits the output to the newest `N` entries and `0` means all of them, and `--path` reads a
different file — a log you archived, for instance:

```console
$ evilkit log -n 1
2026-09-16T04:24:34Z  10.20.30.9/32  NOT enforced  /srv/engagements/acme/.mcp.json
```

A launch that never happened is not in there. A dry run, a scope the parser rejected, and a run that
could not find the Kimi Code CLI all log nothing, and with no log file yet the command is not an
error:

```console
$ evilkit log
evilkit: no launches recorded yet (/home/you/.local/state/evilkit/launches.jsonl)
$ echo $?
0
```

## Worked example: watching the scope during a session

The launcher writes the scope and hands over. For the rest of that session the boundary lives in a
file, and `evilkit watch` is what tells you if the file moves. Run it beside the session — a second
terminal, a split pane, or another `tmux` window:

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

Nothing here is privileged. In a second terminal, the same thing any process on the machine could
do:

```console
$ evilkit scope set 10.0.0.0/8
evilkit: scope 10.0.0.0/8 recorded in /srv/engagements/acme/.mcp.json
```

The pane notices on its next sample and says so in the terms that matter — the new scope authorises
addresses the old one did not:

```console
ALERTS (1)
  15:16:40  !!  the recorded scope changed under you: 10.20.30.0/24 ->
                10.0.0.0/8 and it is wider than before
```

A narrowing is reported the same way, but as a note rather than an alarm, because nothing has been
over-authorised:

```console
ALERTS (1)
  15:18:02  --  the recorded scope changed under you: 10.0.0.0/8 -> 10.0.0.0/24
```

Three things raise an alarm: the scope value changing, the `pentest` server disappearing or losing
its scope key, and the file being deleted or becoming unreadable. A rewrite that leaves the scope
byte-identical is a note, so saving the file in an editor is not an incident.

Exit is `0` when the scope held throughout and `1` when any alarm was raised, which is what makes
this usable in a script as well as on screen:

```console
$ evilkit watch --once --no-color | grep -c "scope in force"
1
$ echo $?
0
```

The pane reads the file; it does not police a running process. It cannot see which scope a tool
server already loaded before the change, and it stops nothing — an alarm means a session started
*from that moment* would be wider than the one you authorised, which is exactly the moment worth
knowing about.

## Worked example: the theme and the doctor command

```console
$ evilkit theme status
evilkit: not installed (/home/you/.kimi-code/themes)
$ evilkit theme install
evilkit: theme written to /home/you/.kimi-code/themes/evilkit.json
evilkit: set theme = "evilkit" in your tui.toml to use it
$ evilkit theme status
evilkit: installed (/home/you/.kimi-code/themes)
```

evilkit only copies the file. Activating it is a one-line edit you make yourself, in
`~/.kimi-code/tui.toml`:

```toml
theme = "evilkit"
```

With `EVILKIT_KIMI_HOME` set, both `theme install` and `theme status` use
`$EVILKIT_KIMI_HOME/themes` instead, which is how you test the copy without touching a real Kimi
installation. Note that this variable only relocates the themes directory as far as evilkit is
concerned — the Kimi Code CLI's own config still lives in its usual place, so a relocated themes
directory is only useful if your CLI installation has been set up to match:

```console
$ EVILKIT_KIMI_HOME=/tmp/kimi-test evilkit theme install
evilkit: theme written to /tmp/kimi-test/themes/evilkit.json
evilkit: set theme = "evilkit" in your tui.toml to use it
```

`--force` is for replacing a theme you have edited. Without it, an existing file is never
overwritten: when it already matches the bundled theme the command still reports the theme as
written and exits `0`, and when it differs the difference is reported on stderr, nothing is written,
and the exit code is `1`:

```console
$ evilkit theme install
evilkit: /home/you/.kimi-code/themes/evilkit.json already exists and differs from the bundled theme
evilkit: re-run with --force to overwrite it
$ echo $?
1
$ evilkit theme install --force
evilkit: theme written to /home/you/.kimi-code/themes/evilkit.json
evilkit: set theme = "evilkit" in your tui.toml to use it
```

`install.sh` copies the file unconditionally, so it does overwrite a local edit.

A destination that is a symlink is refused outright, with or without `--force`, so a link someone else
placed there cannot redirect the write:

```console
$ evilkit theme install
evilkit: /home/you/.kimi-code/themes/evilkit.json is a symlink; refusing to write through it
$ echo $?
1
```

Note that `theme status` only asks whether a file is present, so it still reports `installed` for a
symlink that `theme install` will refuse.

`doctor` is the single command to run when something is off:

```console
$ evilkit doctor
kimi binary        : /home/you/.kimi-code/bin/kimi ok
config file        : /home/you/.config/evilkit/config.toml absent (defaults)
mcp.json           : /srv/engagements/acme/.mcp.json
recorded scope     : 10.20.30.0/24
theme installed    : yes (/home/you/.kimi-code/themes)
audit log          : /home/you/.local/state/evilkit/launches.jsonl (last launch 2026-09-16T04:24:34Z)
```

Read it as: the binary resolved, the state of the config file, the file evilkit would write, the
scope currently recorded, whether the theme file is present, and where the launch log is and how
recent its newest entry is (`disabled` when `audit = false`). The `config file` line reads
`ok` when the file loaded, `absent (defaults)` when there is no file, and
`unreadable (using defaults)` when a file is there but could not be parsed. A `MISSING` binary or an
unreadable scope makes it exit `1`, and the `audit log` line does not affect the exit code. Note that
"no `.mcp.json` in this directory tree" does not make it exit `1`, so do not use `doctor` as a gate
for that condition — use `evilkit scope show`, which does fail.

## Worked example: a run profile (the launch contract)

A run profile fixes everything that decides a scored run before the first model turn: the scope the
run is measured on, where the operator launches from, the tools that must resolve, the guest
credentials, the dashboard run that records it, and the topology it is allowed to assume. It is
`examples/keystone-run-profile.toml`:

```toml
name = "keystone-full"
scope = "10.99.50.0/24,10.50.0.0/24"
entry_host = "10.99.50.60"
required_servers = ["pentest", "mission", "redteamscripting"]
required_tools = ["pentest:nmap_scan", "pentest:ssh_tunnel", "redteamscripting:malware_deploy"]
requires_lab_ssh = true
dashboard_run_dir = "~/Projects/keystone-range/runs/<run-id>"
objectives = ["delivery", "persistence", "c2_resilience"]
topology = """DMZ 10.99.50.0/24 — 16 hosts, entry .60. CORP 10.50.0.0/24 behind a pivot."""
```

Launch with it:

```
evilkimi --run-profile examples/keystone-run-profile.toml
```

The profile's scope is used when `--scope` is not given, and must match it when it is. Preflight
then holds the launch to the rest, and **fails the launch** (exit 1, nothing starts) when:

- a required tool is not advertised by the server it is pinned to — `["pentest:nmap_scan"]` fails if
  the pentest server serves no `nmap_scan`, which is the deferred-tool refusal that cost Run 1 eight
  calls, moved from turn three to preflight;
- guest credentials do not resolve — `requires_lab_ssh` checks `[lab_ssh]` in the config and the
  `LAB_SSH_*` environment, so a run cannot start with dead `malware_deploy`/`malware_persist`;
- the scope disagrees with the profile (two runs only compare on the same scope);
- the dashboard run has no node for `entry_host` — the emitter drops such events silently, which is
  how a run can be visibly busy and record nothing.

A server launched on another host (the pentest MCP is reached over `ssh`) cannot be enumerated from
here, so its tools are reported as *unconfirmed* (a `WARN`) rather than missing. Everything the
profile states is checked; everything it does not state stays `UNKNOWN` to the operator, who gets
the profile's briefing instead of a range layout carried over from the previous run. The report is
written next to the run trace, or under `~/.local/state/evilkimi/preflight/`.

## The lab run controls, from inside the session

A session that reports to the dashboard can also drive it. Configure the board first:

```toml
[dashboard]
url = "http://dashboard.example.test:8793"  # no default: an empty url attaches nothing
attach = true                        # declare the server on every kimi/qwen launch
auto = true                          # put this run on the board, take it off at exit
timeout = 5.0                        # seconds per control request
```

`evilkit kimi` / `evilkit qwen` then declare a `dashboard` MCP server, which gives the operator:

- `start_run` — the board's **Start run**: marks the newest prepared run as the one being tracked,
  so the board leaves the live-brain view. `keystone.run_control.start` refuses it while another run
  is being tracked ("a run is already being tracked"), and when no run has been prepared
  ("use bin/launch.sh to publish one first");
- `stop_run` — the board's **Stop**: marks the tracked run finished, so the live-brain view returns;
- `end_run` — makes no request at all: it writes `state = "finished"` into the bound run's
  `dashboard/status.json` plus a `kind = "control"` record in its `journal.jsonl`. It works whether
  or not the board is tracking that run, and the board keeps a finished run in view for ten minutes
  before retiring it;
- `run_status` — reads `/api/status` and reports which control is running and which registered
  scripts exist.

What these are: the board's own fixed, pre-registered scripts (`keystone-range/bin/start.sh` and
`bin/stop.sh`), and those scripts are **bookkeeping** — `keystone/run_control.py` says of itself that
it "does not start EvilKit or perform any security action", and stop's own comment is "it stops
tracking, not the range or the operator". None of the tools launches or tears down the range,
starts or stops an operator session, or puts traffic on a target. (`bin/reset.sh` is the heavy one —
it recreates containers and rotates flags — and is deliberately not exposed.)

One shared record deserves its own note: `dashboard/status.json` holds the run's identity and the
`started` anchor the board's run clock counts from — `#run-clock` is drawn from `status.started` and
falls back to `00:00:00` when it is absent. The range writes that anchor when it starts tracking, and
everything EvilKit writes into the file (the telemetry bridge and `end_run` both) **merges** into it
rather than replacing it, so an operator action can never blank the clock of the run it belongs to.

`--attach-dashboard` declares the server for one launch even when the config does not ask for it;
`--no-dashboard-mcp` suppresses the server *and* the automation for that launch. `--dry-run`,
`--no-write` and `write_mcp_json = false` report what would be attached without touching the file.

The entry is written to the file the engine actually reads: `<project>/.kimi-code/mcp.json`, else
`$KIMI_CODE_HOME/mcp.json` for the Kimi CLI — a plain `.mcp.json` is ignored, the same rule that
governs the recorded scope — and the project `.mcp.json` for the Qwen adapter.

### Automatic tracking (`auto`)

With `auto = true` the launcher manages the board's view of the run instead of leaving it to the
operator:

1. before the session starts it asks the board for its control state — if a run is already being
   tracked, or the board is busy with another control, the launch leaves it alone and says so;
2. otherwise it runs the Start control and waits for the board's verdict, so a refusal ("no matching
   prepared run") is reported rather than assumed to have worked;
3. when the session ends it runs the Stop control — **but only if this launch is what started the
   tracking**. A run someone else put on the board, or one you started by hand, is never taken off
   it by this session's exit.

Because the board's controls answer as soon as they have launched the script, the client waits
briefly (up to `timeout`) for the verdict, so a tool call reports "succeeded" or the script's own
failure message instead of a hopeful "running".

Two limits are stated rather than hidden. `--no-supervise` (and `--max-restarts 0`) replaces the
launcher with the CLI, so nothing survives to stop the tracking; the launch starts it anyway and
warns. And the board's run-control endpoints carry a same-origin check rather than authentication,
so anything able to reach that URL can start or stop tracking.

## Worked example: reading a run back

Two commands answer "what did this run actually do".

Classify the calls in any session log — EvilKit's own, the Kimi CLI wire, or a Qwen transcript:

```
$ evilkit calls classify ~/.local/state/evilkimi/sessions/session_8e2ba546-....jsonl
  calls: 67  distinct signatures: 67
  barren=18, unrecorded=49
```

Categories are `gate_refusal`, `schema_refusal`, `timeout`, `auth_failure`, `proven_finding`,
`productive`, `barren` and `unrecorded` (a call whose result the log never captured — not the same
finding as one that produced nothing). It also reports the refusals that were re-issued unchanged,
which is the number that has to be zero:

```
$ evilkit calls classify ~/.qwen/.../b1d80b25-....jsonl
  refusals re-issued unchanged: 1
    x4  mcp__mission__get_state {"arguments": {}}
```

Cross-check the three records a run leaves — its session log, the dashboard's events, and the
`journal.jsonl` the scorer reads:

```
$ evilkit calls verify-run ~/Projects/keystone-range/runs/<run-id>
  journal_records=0, dashboard_events=88, sessions_claiming_the_run=0
  PROBLEM: no journal.jsonl — the scorer reads this file, so the run scores zero on every
           agent-declared action however much work it did
  PROBLEM: no session log claims this run — the operator's own record cannot be tied to it
  inconsistent — score is provisional
```

Exit status is 0 only when the records agree; `--json` prints the report for a scorer or a dashboard.

## Scope syntax reference

A scope is a comma-separated list. Each entry may be:

| Kind | Example | Normalised to |
|---|---|---|
| IPv4 address | `10.0.0.5` | `10.0.0.5/32` |
| IPv4 network | `10.0.0.0/24` | `10.0.0.0/24` |
| IPv6 address | `2001:db8::1` | `2001:db8::1/128` |
| IPv6 network | `2001:db8::/32` | `2001:db8::/32` |
| Hostname | `APP.Example.COM.` | `app.example.com` |

Rules and limits:

- Duplicates are removed; the order of the rest is preserved.
- Entries are lowercased and a trailing dot is stripped, so `App.Example.COM.` and
  `app.example.com` are the same entry.
- An entry longer than 253 characters is rejected.
- These characters are rejected anywhere in an entry: whitespace, `"`, `'`, `` ` ``, `$`, `;`, `&`,
  `|`, `<`, `>`, `(`, `)`, `{`, `}`, `[`, `]`, `\`, `!`, `*`, `?`, `~`, `^`, `#`, and control
  characters.
- An entry made only of digits and dots has to be a valid IP address or network. `10.0.0.256`,
  `999.1.1.1`, `192.168.1.300` and `1.2.3.4.5` are rejected rather than read as hostnames.
- A network whose host bits are set is rejected, with the corrected form named in the message:
  `10.0.0.5/24` used to be rounded down and is now an error. A bare address is unaffected:
  `10.0.0.5` is still `10.0.0.5/32`.
- A prefix length of `0` is refused unless `--allow-any` is passed, because `0.0.0.0/0` and `::/0`
  authorise every address there is.
- Wildcards are not supported at all, in any position: `*.example.com` is an error.
- Legacy numeric address forms are refused: `0x7f000001`, `0x7f.1`, `127.1` and every other form
  `inet_aton` accepts, because resolvers read them as a host you did not type — those three all mean
  `127.0.0.1`.

The whole scope value also has a set of shortcuts: `solo`, `none`, `off`, or an empty string mean
`127.0.0.1/32`, in any case, with surrounding whitespace ignored. Those words are matched against
the whole value only. Inside a list they are ordinary hostnames:

```console
$ evilkit -s solo -n
evilkit: would record 127.0.0.1/32 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
$ evilkit -s '10.0.0.5,solo' -n
evilkit: would record 10.0.0.5/32,solo in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

The same syntax, limits and refusals apply to `--deny`, so a denied target is written in exactly the
form the same token would take as a scope entry. The one difference is the empty value: as a scope it
means the `solo` loopback default, and as a deny list it means "deny nothing".

Rejections look like this and exit `2`:

```console
$ evilkit -s '*.example.com' -y -n
evilkit: '*.example.com' uses wildcard matching, which the tool server cannot enforce
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
$ evilkit -s 10.0.0.5/24 -n
evilkit: '10.0.0.5/24' has host bits set; did you mean 10.0.0.0/24?
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
$ evilkit -s 0.0.0.0/0 -n
evilkit: '0.0.0.0/0' covers every address; pass --allow-any to confirm that is intended
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
$ evilkit -s 0x7f000001 -n
evilkit: '0x7f000001' is a legacy numeric address form that resolvers read as a different host; write it as a dotted-quad address instead
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
$ evilkit -s 10.0.0.256 -n
evilkit: '10.0.0.256' looks like an IP address but is not valid
evilkit: expected a comma-separated list of hosts, IPs or CIDRs, or 'solo'
```

```console
$ evilkit -s 10.20.30.0/24 --deny '*.example.com' -n
evilkit: '*.example.com' uses wildcard matching, which the tool server cannot enforce
evilkit: expected a comma-separated list of hosts, IPs or CIDRs for the deny list
$ echo $?
2
```

The second line names the list that was rejected, so it is clear which of the two values was at
fault. Nothing is written: both lists are validated before the file is touched.

Mixing kinds in one scope is fine:

```console
$ evilkit -s '10.0.0.5, APP.Example.COM., 2001:db8::/32' -n
evilkit: would record 10.0.0.5/32,app.example.com,2001:db8::/32 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

`--allow-any` exists so that a deliberate `0.0.0.0/0` is possible, not so that it is convenient:

```console
$ evilkit -s 0.0.0.0/0 -n --allow-any
evilkit: would record 0.0.0.0/0 in /srv/engagements/acme/.mcp.json
evilkit: would launch /home/you/.kimi-code/bin/kimi
```

## What gets written to `.mcp.json`

One value, plus the deny list when `--deny` asks for it:
`mcpServers.pentest.env.PENTEST_ALLOWED_TARGETS`, and `mcpServers.pentest.env.PENTEST_DENIED_TARGETS`.
Everything else in the file is read, re-serialised and written back unchanged. Concretely:

- The file is found by walking up from the working directory, or taken from `--mcp-json`.
- A file with no `mcpServers.pentest` entry is not modified, and the run stops with `exit 1` because
  the scope could not be recorded.
- A `<name>.lock` sidecar beside the target is locked for the read-modify-write, so two runs against
  the same project queue instead of interleaving. The lock file is created on the first write and
  stays there, which is why `.mcp.json.lock` appears in this repository's `.gitignore`.
- The new content is written to a staging file named `.mcp.json.<random>.new` and parsed back as JSON
  before it is swapped in with `os.replace`, so a half-written `.mcp.json` is not a state this tool
  can leave behind. The randomised name matters: with the old fixed name `.mcp.json.new`, a hostile
  repository could have committed a symlink at that path and evilkit would have written through it on
  to any file the user could write.
- The previous version is copied to `.mcp.json.<YYYYmmdd-HHMMSS>.bak` before the swap, so the target
  is never briefly missing. Two writes inside the same second do not collide: the second takes `-1`,
  the third `-2`, and so on.
- The target keeps its file mode. A `.mcp.json` at `0600` is still `0600` after a write, rather than
  being loosened to the umask on a file that may hold a `PENTEST_TOKEN`.
- Backups beyond `backup_keep` are deleted, oldest first, ordered by timestamp and then by that
  suffix, so the ones kept are genuinely the newest. `backup_keep = 0` skips both the backup and the
  pruning, so the swap is direct.
- When both values already equal what was asked for, the file is not written and no backup is made.
  A deny list that changed on its own is not that case: it is written and backed up like any other
  change.
- Input that cannot be parsed is reported as a message rather than a traceback: invalid UTF-8, invalid
  JSON, and JSON nested too deeply all produce a clean error and the fail-closed exit.
- The whole file is re-serialised with two-space indentation, so the first run after you hand-edit
  the file usually shows a reformatting diff. Existing keys keep their order; a missing `env` object
  is appended to the server entry.
- Under `--dry-run` all of the checks above are evaluated and nothing is written, so the answers match
  a real run, including the exit code. The one thing it does not do is create the staging file or take
  the lock, which is why it cannot report that the directory is unwritable.

The staging file, the backups and the lock are all written beside the target, which is why
`.gitignore` has to cover any `*.mcp.json` basename and not just `.mcp.json`.

## Recipes

Configure a default scope for a machine that is only ever used against one lab range, so the prompt
press-enter path is useful rather than a footgun:

```toml
# ~/.config/evilkit/config.toml
default_scope = "10.20.0.0/16"
```

Pin a specific CLI build, leaving the `PATH` lookup out of it:

```toml
kimi_bin = "~/.local/bin/kimi-1.2.3"
```

Turn a pivot flag on for every launch, in a project whose tool server reads the environment:

```toml
[extra_env]
PENTEST_ALLOW_PIVOT = "1"
```

An `[extra_env]` entry cannot set the scope. `PENTEST_ALLOWED_TARGETS` is dropped from the table and
reported as a config problem, because a config file must not be able to widen the scope behind a
banner that names the requested one. A key that TOML cannot express bare — one with a space, a colon,
or a dot — is written quoted, and control characters are escaped, so unusual keys and values survive
being saved and read back.

Scope a project you are not sitting in, and confirm it landed:

```bash
EVILKIT_KIMI_BIN=/bin/true \
  evilkit -s 10.20.30.0/24 --mcp-json /srv/engagements/acme/.mcp.json -y
evilkit scope show --mcp-json /srv/engagements/acme/.mcp.json
```

Reset a directory before handing it to someone else:

```bash
evilkit scope clear
rm -f .mcp.json.*.bak .mcp.json.lock
```

## Troubleshooting

**`evilkit: no .mcp.json found`** — `scope show` needs a file; the search walks up from the working
directory. Either `cd` into the project or pass `--mcp-json`.

**`evilkit: <path> declares no 'pentest' server; nothing to scope`** followed by **`nothing was
launched: the scope could not be recorded`** — the file exists but has no `mcpServers.pentest` entry,
so there was nowhere to record the scope and evilkit stopped rather than run under the scope already in
the file. Compare the file against `examples/.mcp.json.example`. The same three-line failure appears
for a missing `.mcp.json`, an unreadable file, and a write that failed.

**`evilkit: pass --allow-unscoped to launch anyway`** — that line is part of the failure above, and it
is the only way past it. Before you use it, read the scope already in the file with `evilkit scope
show`: that is the scope the session will actually run under, and it may be wider than the one you
asked for.

**`evilkit: cannot find the Kimi Code CLI ('kimi')`** — the binary is not on `PATH` and no path is
configured. Set `kimi_bin`, or export `EVILKIT_KIMI_BIN=/full/path/to/kimi`.

**`evilkit: could not open <path>.lock: ...`** or **`could not stage a new .mcp.json: ...`** — the
directory holding the target is not writable by you, so the scope could not be recorded and the run
stopped. Fix the permissions on the directory. A dry run will not show you this, because it takes no
lock and stages no file.

**`evilkit: could not read <file>: ...`**, **`unknown key 'x' ignored`**, or **`evilkit: extra_env
cannot set PENTEST_ALLOWED_TARGETS; the authorised scope is the one that is recorded`** — the config
file is malformed or has a setting evilkit will not accept. Every setting falls back to its default and
the run continues; a bad `default_scope` falls back to `127.0.0.1/32`, and an `[extra_env]` entry
naming the scope is dropped. `evilkit run` prints these warnings before it does anything else, and
`evilkit config show` and `evilkit doctor` print the same lines; the exit code stays `0`, because a
config problem is not a reason to refuse to launch. `evilkit config path` tells you which file is
being read, which matters when `EVILKIT_CONFIG` is set. `doctor` adds a state to its `config file`
line — `ok`, `absent (defaults)` when no file exists, or `unreadable (using defaults)` when one exists
but could not be parsed — so you can tell a missing config from a broken one.

**`evilkit: /path/.mcp.json already exists; leaving it alone`** (from `config init`) — expected;
delete the file first if you want a fresh default written.

**`evilkit: /path/.mcp.json is not valid JSON: ...`** or **`... is not valid UTF-8: ...`** or
**`... is nested too deeply to parse`** — evilkit will not parse a file it cannot read, and will not
write one either, so the run stops with `exit 1`. Fix the file by hand; the backups it made are valid
JSON, so the newest `.bak` is usually the fastest way back.

**The scope looks right in `.mcp.json` but the session still sees an old one** — check for a
`--no-write` or `write_mcp_json = false` in play, and check for a nearer `.mcp.json` than the one
you edited. Remember that the `.mcp.json` `env` block wins over the exported variable, so anything
reading the file needs the file updated.

**Everything looks right but the tool server still refuses targets** — evilkit has no visibility
into the tool server. It records one value; whether that value is what your server checks is outside
what this launcher can verify.

**A run in a script printed nothing** — check the exit code first: a run that never launched prints its
reason on stderr and exits `1` or `2`. When it does launch, the status lines are flushed before the
CLI takes over, so they do reach a pipe or a log file. This is the run's own output on the terminal,
not the launch log: read that back with `evilkit log`, and the scope recorded in `.mcp.json` with
`evilkit scope show`.

**A dry run was happy but the real run refused to write** — `--dry-run` takes no lock and creates no
staging file, so it cannot tell you the directory is read-only. The real run reports the lock or
staging failure, says `nothing was launched: the scope could not be recorded`, and exits `1`. Fix the
permissions on the directory, not the file.

**`evilkit theme install` refuses to touch my theme** — the installed file differs from the bundled
one, which is what the command believes a local edit looks like. Re-run with `--force` if you want the
bundled theme back, or leave it and keep your edit. If the destination is a symlink, the refusal is
unconditional and `--force` will not change it; remove the link first if you really meant to replace
it.
