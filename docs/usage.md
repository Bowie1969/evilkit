# evilkit usage

This page goes past the quick start in the [README](../README.md): how the scope is collected and
written, what each flag does in practice, and a set of worked sessions you can copy from.

- [The launch sequence](#the-launch-sequence)
- [Worked example: preparing an engagement](#worked-example-preparing-an-engagement)
- [Worked example: scripted and CI runs](#worked-example-scripted-and-ci-runs)
- [Worked example: several projects on one machine](#worked-example-several-projects-on-one-machine)
- [Worked example: deviating from a project's scope](#worked-example-deviating-from-a-projects-scope)
- [Worked example: inspecting and resetting the recorded scope](#worked-example-inspecting-and-resetting-the-recorded-scope)
- [Worked example: the theme and the doctor command](#worked-example-the-theme-and-the-doctor-command)
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
   `mcpServers.pentest.env.PENTEST_ALLOWED_TARGETS`. This is the step that fails closed: if there is
   no file, no `pentest` server in it, or the write itself fails, the run stops with `exit 1` and the
   CLI is never started.
6. Resolve the Kimi Code CLI binary. If it is not found, exit `1`.
7. Print `evilkit: authorized scope -> <scope>`, flush stdout and stderr, and `exec` the CLI,
   replacing the evilkit process. Its exit status becomes the session's exit status, and no evilkit
   code runs afterwards.

Because step 7 is an `exec`, the Kimi Code CLI is the process you Ctrl-C out of. evilkit does not run
alongside it, does not read its output, and does not clean up after it. The flush in that step is why
the status lines survive when stdout is a pipe or a log file rather than a terminal.

Step 7 prints `authorized scope -> <scope>` only when that scope is in force: recorded in the file, or
deliberately left unwritten because you asked for that with `--no-write` or
`write_mcp_json = false`. When `--allow-unscoped` lets a run continue after a failed step 5, the line
is different — `scope -> <scope> (NOT enforced; recorded scope is unchanged)` — and the session runs
under whatever scope the file already held.

With `--dry-run`, steps 4 and 5 run against the same target and report the same failures and the same
exit codes, and the write is replaced by a description of what it would have done. Adding
`--no-write` as well takes a shortcut instead: the run stops after step 3, checks no target, and
launches nothing.

The environment handed to the CLI is your environment, plus `PENTEST_ALLOWED_TARGETS` set to the
normalised scope, plus `KIMI_CODE_IDENTITY_NAME` and `KIMI_CODE_IDENTITY_SLUG` set to `evilkit`
unless they were already set, plus everything in `[extra_env]` from your config. The scope is applied
last, so no `[extra_env]` entry can override it.

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
`evilkit scope show`, which prints the value from the file and nothing else.

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

## Worked example: inspecting and resetting the recorded scope

```console
$ evilkit scope show
10.20.30.0/24,10.20.40.0/24

$ evilkit scope clear
evilkit: /srv/engagements/acme/.mcp.json reset to 127.0.0.1/32
```

`scope clear` writes the loopback default; it does not delete the key or the file. It is the right
last step before archiving an engagement directory, before sharing it, or before uninstalling
evilkit.

When there is nothing to read, both fail loudly rather than printing nothing:

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
```

Read it as: the binary resolved, the state of the config file, the file evilkit would write, the
scope currently recorded, and whether the theme file is present. The `config file` line reads
`ok` when the file loaded, `absent (defaults)` when there is no file, and
`unreadable (using defaults)` when a file is there but could not be parsed. A `MISSING` binary or an
unreadable scope makes it exit `1`. Note that "no `.mcp.json` in this directory tree" does not make
it exit `1`, so do not use `doctor` as a gate for that condition — use `evilkit scope show`, which
does fail.

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

Strictly one value: `mcpServers.pentest.env.PENTEST_ALLOWED_TARGETS`. Everything else in the file is
read, re-serialised and written back unchanged. Concretely:

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
- When the value already equals the scope, the file is not written and no backup is made.
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

**A run in a script logged nothing** — check the exit code first: a run that never launched prints its
reason on stderr and exits `1` or `2`. When it does launch, the status lines are flushed before the
CLI takes over, so they do reach a pipe or a log file. Read the recorded scope back with
`evilkit scope show` if you want it on its own.

**A dry run was happy but the real run refused to write** — `--dry-run` takes no lock and creates no
staging file, so it cannot tell you the directory is read-only. The real run reports the lock or
staging failure, says `nothing was launched: the scope could not be recorded`, and exits `1`. Fix the
permissions on the directory, not the file.

**`evilkit theme install` refuses to touch my theme** — the installed file differs from the bundled
one, which is what the command believes a local edit looks like. Re-run with `--force` if you want the
bundled theme back, or leave it and keep your edit. If the destination is a symlink, the refusal is
unconditional and `--force` will not change it; remove the link first if you really meant to replace
it.
