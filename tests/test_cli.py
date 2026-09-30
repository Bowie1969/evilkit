"""Tests for evilkit.cli — exit codes, the scope/config/doctor commands and the
launch path.

Paths that reach ``os.execvpe`` replace the interpreter, so those are exercised
in a subprocess against a stub binary (``_helpers.STUB_SCRIPT``) that reports the
argv and launch environment it received.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import DENY_ENV_KEY, SCOPE_ENV_KEY, EvilkitTestCase  # noqa: E402

from evilkit import __version__  # noqa: E402
from evilkit.cli import EXIT_ERROR, EXIT_OK, EXIT_USAGE  # noqa: E402


class CliTestCase(EvilkitTestCase):
    def scope_in(self, path):
        return json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["pentest"]["env"][
            SCOPE_ENV_KEY
        ]

    def deny_in(self, path):
        return json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["pentest"]["env"][
            DENY_ENV_KEY
        ]

    def backups(self):
        return sorted(p.name for p in self.tmp.glob(".mcp.json*.bak"))


class TestVersionAndHelp(CliTestCase):
    def test_version_subcommand(self):
        code, out, err = self.call_main(["version"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, f"evilkit {__version__}\n")
        self.assertEqual(err, "")

    def test_long_version_flag(self):
        code, out, _ = self.call_main(["--version"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn(__version__, out)

    def test_short_version_flag(self):
        code, out, _ = self.call_main(["-V"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn(__version__, out)

    def test_help_exits_zero(self):
        code, out, err = self.call_main(["--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("usage", out.lower())
        self.assertEqual(err, "")

    def test_unknown_command_is_a_usage_error(self):
        code, _, err = self.call_main(["frobnicate"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("usage", err.lower())


class TestRunDryRun(CliTestCase):
    def test_rejected_scope_exits_two_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()

        code, out, err = self.call_main(["-s", "10.0.0.0/24;rm -rf /", "-y", "-n"])

        self.assertEqual(code, EXIT_USAGE)
        self.assertEqual(out, "")
        self.assertTrue(err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_rejected_scope_exits_two_without_a_dry_run_too(self):
        code, _, err = self.call_main(["-s", "10.0.0.0/24;rm -rf /", "-y"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertTrue(err)

    def test_solo_scope_dry_run_succeeds(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, _ = self.call_main(["-s", "solo", "-y", "-n"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("127.0.0.1/32", out)

    def test_dry_run_never_writes(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()

        code, out, _ = self.call_main(["-s", "10.0.0.0/24", "-y", "-n"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("would record 10.0.0.0/24", out)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_dry_run_reports_the_launcher_it_would_use(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        _, out, _ = self.call_main(["-s", "solo", "-y", "-n"])
        self.assertIn(str(self.stub), out)

    def test_dry_run_without_a_fixture_previews_the_fatal_error(self):
        code, out, err = self.call_main(["-s", "solo", "-y", "-n"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("nothing to scope", err)
        self.assertIn("nothing was launched", err)
        self.assertNotIn("would launch", out)

    def test_dry_run_without_a_fixture_succeeds_with_allow_unscoped(self):
        code, out, err = self.call_main(["-s", "solo", "-y", "-n", "--allow-unscoped"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("may differ", err)
        self.assertIn("would not record 127.0.0.1/32", out)
        self.assertIn("would launch", out)

    def test_non_interactive_default_scope_is_used_with_yes(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, out, _ = self.call_main(["-y", "-n"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("127.0.0.1/32", out)
        self.assertEqual(path.read_bytes(), before)

    def test_missing_explicit_mcp_json_exits_one(self):
        code, _, err = self.call_main(["-s", "solo", "-y", "--mcp-json", str(self.tmp / "no.json")])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("does not exist", err)


class TestScopeCommand(CliTestCase):
    def test_show_prints_exactly_the_recorded_scope(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, err = self.call_main(["scope", "show"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "10.0.0.0/24\n")
        self.assertEqual(err, "")

    def test_show_is_the_default_action(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, _ = self.call_main(["scope"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "10.0.0.0/24\n")

    def test_show_accepts_an_explicit_path(self):
        path = self.write_mcp_json(self.pentest_fixture("10.8.0.0/16"), directory=self.tmp)
        code, out, _ = self.call_main(["scope", "show", "--mcp-json", str(path)])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "10.8.0.0/16\n")

    def test_show_finds_a_fixture_in_a_parent_directory(self):
        top = self.tmp / "project"
        top.mkdir()
        self.write_mcp_json(self.pentest_fixture("10.8.0.0/16"), directory=top)
        deep = top / "a" / "b"
        deep.mkdir(parents=True)
        old = os.getcwd()
        os.chdir(deep)
        try:
            code, out, _ = self.call_main(["scope", "show"])
        finally:
            os.chdir(old)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "10.8.0.0/16\n")

    def test_show_does_not_modify_the_file(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        self.call_main(["scope", "show"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_show_without_any_fixture_exits_one(self):
        code, out, err = self.call_main(["scope", "show"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("no .mcp.json", err)

    def test_show_without_a_pentest_server_exits_one(self):
        self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        code, _, err = self.call_main(["scope", "show"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no pentest server", err)

    def test_show_on_invalid_json_exits_one(self):
        (self.tmp / ".mcp.json").write_text("{not json", encoding="utf-8")
        code, _, err = self.call_main(["scope", "show"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not valid JSON", err)

    def test_show_reports_the_deny_list_when_one_is_recorded(self):
        self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        code, out, err = self.call_main(["scope", "show"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertEqual(out, "10.0.0.0/24\ndeny: 10.0.0.9/32\n")

    def test_show_prints_the_scope_alone_when_the_deny_list_is_empty(self):
        self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny=""))
        code, out, _ = self.call_main(["scope", "show"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "10.0.0.0/24\n")

    def test_clear_resets_the_scope_to_the_locked_down_default(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, err = self.call_main(["scope", "clear"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("127.0.0.1/32", out)
        self.assertEqual(self.scope_in(path), "127.0.0.1/32")
        self.assertEqual(len(self.backups()), 1)

    def test_clear_is_idempotent(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()
        code, out, _ = self.call_main(["scope", "clear"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("already", out)
        self.assertEqual(path.read_bytes(), before)

    def test_clear_without_a_pentest_server_exits_one(self):
        path = self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "clear"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("pentest", err)
        self.assertEqual(path.read_bytes(), before)


class TestScopeEdit(CliTestCase):
    """`scope set` / `add` / `remove` — changing the record without launching."""

    def test_set_replaces_the_recorded_scope(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, err = self.call_main(["scope", "set", "10.8.0.0/16"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("10.8.0.0/16", out)
        self.assertEqual(self.scope_in(path), "10.8.0.0/16")
        self.assertEqual(len(self.backups()), 1)

    def test_set_writes_the_normalised_form(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, _, _ = self.call_main(["scope", "set", "10.0.0.5, app.lan."])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "10.0.0.5/32,app.lan")

    def test_set_accepts_solo(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, _, _ = self.call_main(["scope", "set", "solo"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "127.0.0.1/32")

    def test_set_preserves_everything_else_in_the_file(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        self.call_main(["scope", "set", "10.8.0.0/16"])
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["mcpServers"]["pentest"]["env"]["OTHER_ENV"], "keep-me")
        self.assertEqual(data["mcpServers"]["pentest"]["env"]["NUMERIC"], 7)
        self.assertEqual(
            data["mcpServers"]["mission"]["env"][SCOPE_ENV_KEY], "not-the-pentest-server"
        )
        self.assertEqual(data["topLevel"]["nested"][2], {"flag": True})

    def test_set_rejects_host_bits_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "set", "10.0.0.5/24"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("did you mean 10.0.0.0/24", err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_set_refuses_a_zero_prefix_without_allow_any(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "set", "0.0.0.0/0"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("--allow-any", err)
        self.assertEqual(path.read_bytes(), before)

    def test_set_accepts_a_zero_prefix_with_allow_any(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, _, _ = self.call_main(["scope", "set", "0.0.0.0/0", "--allow-any"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "0.0.0.0/0")

    def test_set_dry_run_reports_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, out, _ = self.call_main(["scope", "set", "10.8.0.0/16", "--dry-run"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("would record", out)
        self.assertIn("10.8.0.0/16", out)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_set_on_the_same_scope_is_a_no_op(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, out, _ = self.call_main(["scope", "set", "10.0.0.0/24"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("already", out)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_set_accepts_an_explicit_path(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, _, _ = self.call_main(["scope", "set", "10.8.0.0/16", "--mcp-json", str(path)])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "10.8.0.0/16")

    def test_set_works_when_the_server_has_no_env_block_yet(self):
        path = self.write_mcp_json({"mcpServers": {"pentest": {"command": "x"}}})
        code, _, err = self.call_main(["scope", "set", "10.8.0.0/16"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertEqual(self.scope_in(path), "10.8.0.0/16")

    def test_set_without_a_pentest_server_exits_one(self):
        path = self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "set", "10.8.0.0/16"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("pentest", err)
        self.assertEqual(path.read_bytes(), before)

    def test_edit_without_any_fixture_exits_one(self):
        code, _, err = self.call_main(["scope", "add", "10.8.0.0/16"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no .mcp.json", err)

    def test_add_appends_without_dropping_what_was_recorded(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, _, _ = self.call_main(["scope", "add", "192.168.1.0/24,app.lan"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24,192.168.1.0/24,app.lan")

    def test_add_keeps_the_recorded_order_and_only_appends(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24,192.168.1.0/24"))
        code, _, _ = self.call_main(["scope", "add", "10.0.0.0/24,172.16.0.0/16"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24,192.168.1.0/24,172.16.0.0/16")

    def test_add_deduplicates_a_target_already_recorded(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24,192.168.1.0/24"))
        before = path.read_bytes()
        code, out, _ = self.call_main(["scope", "add", "10.0.0.0/24"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("already", out)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_add_rejects_a_bad_target_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "add", "*.example.com"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("wildcard", err)
        self.assertEqual(path.read_bytes(), before)

    def test_add_accepts_a_recorded_zero_scope(self):
        path = self.write_mcp_json(self.pentest_fixture("0.0.0.0/0"))
        code, _, err = self.call_main(["scope", "add", "10.8.0.0/16"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertEqual(self.scope_in(path), "0.0.0.0/0,10.8.0.0/16")

    def test_remove_drops_one_target_and_keeps_the_rest(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24,192.168.1.0/24,app.lan"))
        code, _, _ = self.call_main(["scope", "remove", "192.168.1.0/24"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24,app.lan")

    def test_remove_matches_a_normalised_form(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.5/32,10.0.0.0/24"))
        code, _, _ = self.call_main(["scope", "remove", "10.0.0.5"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24")

    def test_remove_of_an_absent_target_changes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, out, _ = self.call_main(["scope", "remove", "192.168.1.0/24"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("already", out)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_remove_refuses_to_leave_no_target_at_all(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "remove", "10.0.0.0/24"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("scope clear", err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_remove_with_nothing_recorded_exits_one(self):
        path = self.write_mcp_json({"mcpServers": {"pentest": {"command": "x"}}})
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "remove", "10.0.0.0/24"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("nothing to remove", err)
        self.assertEqual(path.read_bytes(), before)

    def test_remove_refuses_a_recorded_scope_it_cannot_parse(self):
        path = self.write_mcp_json(self.pentest_fixture("not a scope"))
        before = path.read_bytes()
        code, _, err = self.call_main(["scope", "remove", "10.0.0.0/24"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("scope set", err)
        self.assertEqual(path.read_bytes(), before)


class TestRunLaunches(CliTestCase):
    def test_scope_is_recorded_then_the_binary_runs(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24")
        self.assertEqual(len(self.backups()), 1)
        self.assertIn("identity:evilkit", proc.stdout)

    def test_child_receives_the_scope_and_identity_in_its_environment(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24,app.lan", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("scope:10.0.0.0/24,app.lan", proc.stdout)
        self.assertIn("identity:evilkit", proc.stdout)

    def test_arguments_after_a_standalone_double_dash_reach_the_child(self):
        proc = self.run_cli(["-s", "solo", "-y", "--no-write", "--", "-c"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual([line for line in proc.stdout.splitlines() if line.startswith("arg:")],
                         ["arg:-c"])

    def test_passthrough_arguments_keep_their_order(self):
        proc = self.run_cli(
            ["run", "-s", "solo", "-y", "--no-write", "--", "-c", "-p", "hello world"]
        )

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual([line for line in proc.stdout.splitlines() if line.startswith("arg:")],
                         ["arg:-c", "arg:-p", "arg:hello world"])

    def test_no_flag_scope_is_read_from_the_environment(self):
        proc = self.run_cli(
            ["-y", "--no-write"], env={SCOPE_ENV_KEY: "10.9.0.0/16"}
        )
        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("scope:10.9.0.0/16", proc.stdout)

    def test_no_write_leaves_the_file_byte_identical(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y", "--no-write"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_unchanged_scope_reports_already_and_creates_no_backup(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])
        self.assertIn("identity:evilkit", proc.stdout)

    def test_missing_kimi_binary_exits_one_before_launching(self):
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": str(self.tmp / "env" / "absent")}):
            code, _, err = self.call_main(["-s", "solo", "-y", "--no-write"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot find the Kimi Code CLI", err)

    def test_a_missing_binary_leaves_the_recorded_scope_unchanged(self):
        # The binary is checked before the scope is committed, so a launch that
        # cannot start must not rewrite (and here widen) the recorded scope.
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": str(self.tmp / "env" / "absent")}):
            code, _, err = self.call_main(["-s", "10.0.0.0/24", "-y"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("cannot find the Kimi Code CLI", err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_strict_without_a_pentest_server_exits_one_and_writes_nothing(self):
        path = self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        before = path.read_bytes()

        code, _, err = self.call_main(["-s", "solo", "-y", "--strict"])

        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("pentest", err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_strict_is_still_accepted_and_changes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y", "--strict"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24")

    def test_a_missing_pentest_server_fails_closed_by_default(self):
        path = self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        before = path.read_bytes()

        proc = self.run_cli(["-s", "solo", "-y"])

        self.assertEqual(proc.returncode, EXIT_ERROR, proc.stdout)
        self.assertIn("nothing to scope", proc.stderr)
        self.assertIn("nothing was launched", proc.stderr)
        self.assertNotIn("identity:", proc.stdout)
        self.assertEqual(path.read_bytes(), before)

    def test_a_missing_pentest_server_launches_with_allow_unscoped(self):
        path = self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})
        before = path.read_bytes()

        proc = self.run_cli(["-s", "solo", "-y", "--allow-unscoped"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("nothing to scope", proc.stderr)
        self.assertIn("may differ", proc.stderr)
        self.assertNotIn("authorized scope", proc.stdout)
        self.assertIn("scope:127.0.0.1/32", proc.stdout)
        self.assertIn("identity:evilkit", proc.stdout)
        self.assertEqual(path.read_bytes(), before)

    def test_an_unreadable_mcp_json_fails_closed_by_default(self):
        path = self.tmp / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")

        proc = self.run_cli(["-s", "solo", "-y"])

        self.assertEqual(proc.returncode, EXIT_ERROR, proc.stdout)
        self.assertIn("not valid JSON", proc.stderr)
        self.assertNotIn("identity:", proc.stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "{not json")

    def test_an_unreadable_mcp_json_launches_with_allow_unscoped(self):
        path = self.tmp / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")

        proc = self.run_cli(["-s", "solo", "-y", "--allow-unscoped"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("not valid JSON", proc.stderr)
        self.assertIn("may differ", proc.stderr)
        self.assertNotIn("authorized scope", proc.stdout)
        self.assertEqual(path.read_text(encoding="utf-8"), "{not json")

    def test_no_mcp_json_at_all_fails_closed(self):
        proc = self.run_cli(["-s", "solo", "-y"])

        self.assertEqual(proc.returncode, EXIT_ERROR, proc.stdout)
        self.assertIn("nothing to scope", proc.stderr)
        self.assertNotIn("identity:", proc.stdout)

    def test_the_banner_only_names_an_enforced_scope(self):
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        recorded = self.run_cli(["-s", "10.0.0.0/24", "-y"])
        self.assertIn("authorized scope -> 10.0.0.0/24", recorded.stdout)

        # A scope the operator declined to write is not in force: the file keeps
        # whatever it held, so the enforced banner would be a lie.
        target = self.tmp / ".mcp.json"
        before = target.read_bytes()

        unscoped = self.run_cli(["-s", "10.0.0.0/24", "-y", "--no-write"])

        self.assertNotIn("authorized scope", unscoped.stdout)
        self.assertIn("NOT enforced", unscoped.stdout)
        self.assertEqual(target.read_bytes(), before)

    def test_with_strict_an_unreadable_mcp_json_is_fatal(self):
        path = self.tmp / ".mcp.json"
        path.write_text("{not json", encoding="utf-8")

        code, _, err = self.call_main(["-s", "solo", "-y", "--strict"])

        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not valid JSON", err)


class TestAllowAny(CliTestCase):
    def test_a_zero_prefix_is_a_usage_error_without_the_flag(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()

        code, _, err = self.call_main(["-s", "0.0.0.0/0", "-y"])

        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("--allow-any", err)
        self.assertEqual(path.read_bytes(), before)

    def test_a_zero_prefix_is_recorded_with_the_flag(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "0.0.0.0/0", "-y", "--allow-any"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.scope_in(path), "0.0.0.0/0")
        self.assertIn("0.0.0.0/0", proc.stdout)


class TestHostBitsOnTheCommandLine(CliTestCase):
    def test_a_widening_network_is_a_usage_error_naming_the_fix(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        before = path.read_bytes()

        code, _, err = self.call_main(["-s", "10.0.0.5/24", "-y"])

        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("did you mean 10.0.0.0/24?", err)
        self.assertEqual(path.read_bytes(), before)


class TestDeny(CliTestCase):
    """`run --deny` — refusing targets that are inside the allowed scope."""

    def test_deny_is_written_alongside_the_scope(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "--deny", "10.0.0.9", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24")
        self.assertEqual(self.deny_in(path), "10.0.0.9/32")

    def test_deny_expands_a_range_token(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "--deny", "192.168.1.10-50", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(
            self.deny_in(path),
            "192.168.1.10/31,192.168.1.12/30,192.168.1.16/28,"
            "192.168.1.32/28,192.168.1.48/31,192.168.1.50/32",
        )

    def test_deny_is_normalised_like_an_allow_entry(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(
            ["-s", "10.0.0.0/24", "--deny", " APP.Example.COM. , 10.0.0.9 ", "-y"]
        )

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.deny_in(path), "app.example.com,10.0.0.9/32")

    def test_an_omitted_deny_is_preserved(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.deny_in(path), "10.0.0.9/32")
        self.assertEqual(self.backups(), [])

    def test_a_deny_only_change_writes_and_backs_up(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        before = path.read_bytes()

        proc = self.run_cli(["-s", "10.0.0.0/24", "--deny", "10.0.0.10/32", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertNotEqual(path.read_bytes(), before)
        self.assertEqual(self.deny_in(path), "10.0.0.10/32")
        self.assertEqual(len(self.backups()), 1)

    def test_the_same_deny_twice_is_a_no_op(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        before = path.read_bytes()

        proc = self.run_cli(["-s", "10.0.0.0/24", "--deny", "10.0.0.9/32", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("already", proc.stdout)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_an_empty_deny_recorded_earlier_can_be_cleared(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "--deny", "", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertEqual(self.deny_in(path), "")

    def test_an_empty_deny_never_denies_loopback(self):
        """Regression: parse_scope("") answers with the solo sentinel.

        An empty *allow* scope means "lock down to loopback". Routing an empty
        deny list through the same reading would have denied the operator their
        own loopback, which is not what "deny nothing" means.
        """
        for raw in ("", "   "):
            with self.subTest(deny=raw):
                path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))

                proc = self.run_cli(["-s", "10.0.0.0/24", "--deny", raw, "-y"])

                self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
                self.assertEqual(self.deny_in(path), "")
                self.assertNotEqual(self.deny_in(path), "127.0.0.1/32")

    def test_an_invalid_deny_token_exits_two_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()

        code, out, err = self.call_main(
            ["-s", "127.0.0.1/32", "--deny", "10.0.0.0/24;rm -rf /", "-y"]
        )

        self.assertEqual(code, EXIT_USAGE)
        self.assertEqual(out, "")
        self.assertTrue(err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_an_invalid_deny_token_leaves_the_deny_list_alone(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))
        before = path.read_bytes()

        code, _, err = self.call_main(["-s", "10.0.0.0/24", "--deny", "*.example.com", "-y"])

        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("wildcard", err)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_a_deny_token_with_host_bits_is_rejected(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()

        code, _, err = self.call_main(["-s", "10.0.0.0/24", "--deny", "10.0.0.5/24", "-y"])

        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("did you mean 10.0.0.0/24?", err)
        self.assertEqual(path.read_bytes(), before)

    def test_a_dry_run_reports_the_deny_list_and_writes_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()

        code, out, _ = self.call_main(["-s", "10.0.0.0/24", "--deny", "10.0.0.9", "-y", "-n"])

        self.assertEqual(code, EXIT_OK)
        self.assertIn("[deny: 10.0.0.9/32]", out)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])

    def test_a_dry_run_of_the_same_deny_would_change_nothing(self):
        self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))

        code, out, _ = self.call_main(
            ["-s", "10.0.0.0/24", "--deny", "10.0.0.9/32", "-y", "-n"]
        )

        self.assertEqual(code, EXIT_OK)
        self.assertIn("would leave", out)
        self.assertIn("[deny: 10.0.0.9/32]", out)

    def test_a_deny_list_survives_scope_set(self):
        path = self.write_mcp_json(self.deny_fixture("10.0.0.0/24", deny="10.0.0.9/32"))

        code, _, err = self.call_main(["scope", "set", "10.8.0.0/16"])

        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertEqual(self.scope_in(path), "10.8.0.0/16")
        self.assertEqual(self.deny_in(path), "10.0.0.9/32")

    def test_run_help_lists_the_deny_flag(self):
        code, out, _ = self.call_main(["run", "--help"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("--deny", out)


class TestExtraEnvCannotOverrideTheScope(CliTestCase):
    def test_a_scope_key_in_extra_env_is_dropped_and_reported(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(
            "[extra_env]\nPENTEST_ALLOWED_TARGETS = \"0.0.0.0/0\"\n", encoding="utf-8"
        )
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("PENTEST_ALLOWED_TARGETS", proc.stderr)
        self.assertIn("scope:10.0.0.0/24", proc.stdout)
        self.assertEqual(self.scope_in(path), "10.0.0.0/24")

    def test_the_launch_environment_is_scoped_even_if_a_config_is_hand_built(self):
        from evilkit import cli
        from evilkit.config import Config

        env = cli._launch_env(
            Config(extra_env={"PENTEST_ALLOWED_TARGETS": "0.0.0.0/0"}), "10.0.0.0/24"
        )

        self.assertEqual(env["PENTEST_ALLOWED_TARGETS"], "10.0.0.0/24")


class TestConfigCommand(CliTestCase):
    def test_path_prints_the_environment_override(self):
        code, out, err = self.call_main(["config", "path"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, f"{self.config_file}\n")
        self.assertEqual(err, "")

    def test_path_is_the_default_action(self):
        code, out, _ = self.call_main(["config"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("kimi_bin", out)

    def test_show_prints_the_effective_settings(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text('kimi_bin = "/opt/kimi"\nbackup_keep = 1\n', encoding="utf-8")
        code, out, err = self.call_main(["config", "show"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("/opt/kimi", out)
        self.assertIn("backup_keep     = 1", out)
        self.assertIn(str(self.config_file), out)

    def test_show_reports_problems_on_stderr_without_failing(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text('backup_keep = "many"\n', encoding="utf-8")
        code, _, err = self.call_main(["config", "show"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("backup_keep", err)

    def test_show_does_not_create_the_file(self):
        self.call_main(["config", "show"])
        self.assertFalse(self.config_file.exists())

    def test_init_writes_a_loadable_config(self):
        code, out, err = self.call_main(["config", "init"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn(str(self.config_file), out)
        self.assertTrue(self.config_file.is_file())

        from evilkit.config import load

        config, problems = load()
        self.assertEqual(problems, [])
        self.assertEqual(config.source, self.config_file)

    def test_init_refuses_to_clobber_an_existing_file(self):
        self.call_main(["config", "init"])
        self.config_file.write_text('kimi_bin = "mine"\n', encoding="utf-8")
        before = self.config_file.read_bytes()

        code, out, err = self.call_main(["config", "init"])

        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("already exists", err)
        self.assertEqual(self.config_file.read_bytes(), before)


class TestDoctor(CliTestCase):
    def test_exits_zero_when_the_binary_is_present(self):
        code, out, err = self.call_main(["doctor"])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(err, "")
        self.assertIn("kimi binary", out)
        self.assertIn("ok", out)

    def test_exits_one_when_the_binary_is_missing(self):
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": str(self.tmp / "env" / "absent")}):
            code, out, _ = self.call_main(["doctor"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("MISSING", out)

    def test_reports_the_config_path_and_theme_state(self):
        code, out, _ = self.call_main(["doctor"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn(str(self.config_file), out)
        self.assertIn("theme installed", out)
        self.assertIn(str(self.kimi_home), out)

    def test_reports_the_recorded_scope(self):
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        code, out, _ = self.call_main(["doctor"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("10.0.0.0/24", out)

    def test_reports_config_problems_without_failing(self):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text('backup_keep = "many"\n', encoding="utf-8")
        code, _, err = self.call_main(["doctor"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("backup_keep", err)

    def test_doctor_touches_nothing(self):
        path = self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))
        before = path.read_bytes()
        self.call_main(["doctor"])
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.backups(), [])


class TestFixedRegressions(CliTestCase):
    def test_the_banner_survives_a_pipe(self):
        """Regression: the pre-exec banner used to be lost on any non-tty stdout.

        _cmd_run printed with print() and then os.execvpe() replaced the process
        without flushing sys.stdout, so on a pipe or a redirect -- i.e. every
        scripted or logged run -- the line naming the enforced scope never
        appeared. Both streams are now flushed before the exec.
        """
        self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))

        proc = self.run_cli(["-s", "10.0.0.0/24", "-y"])

        self.assertEqual(proc.returncode, EXIT_OK, proc.stderr)
        self.assertIn("authorized scope -> 10.0.0.0/24", proc.stdout)

    def test_dry_run_strict_previews_the_fatal_error(self):
        """Regression: a dry run used to pass write=False into _apply_scope().

        The .mcp.json was therefore never inspected, so --dry-run --strict
        reported success and printed "would record ..." for an operation the
        real run refuses. The dry run now runs the same target checks.
        """
        self.write_mcp_json({"mcpServers": {"mission": {"command": "x"}}})

        code, out, _ = self.call_main(["-s", "solo", "-y", "-n", "--strict"])

        self.assertEqual(code, EXIT_ERROR, f"dry run should preview the fatal error, said: {out!r}")


if __name__ == "__main__":
    unittest.main()
