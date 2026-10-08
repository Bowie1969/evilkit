"""Tests for evilkit.tools — scope validation and executors."""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit.tools import (  # noqa: E402
    ExecutionError,
    ShellExecutor,
    SimulationExecutor,
    validate_command,
)


class TestCommandValidation(EvilkitTestCase):
    def test_empty_command_is_rejected(self):
        with self.assertRaises(ExecutionError):
            validate_command("", ["127.0.0.1/32"])

    def test_forbidden_shell_characters_are_rejected(self):
        with self.assertRaises(ExecutionError):
            validate_command("ping -c 1 127.0.0.1; rm -rf /", ["127.0.0.1/32"])

    def test_redirection_is_rejected(self):
        with self.assertRaises(ExecutionError):
            validate_command("ping -c 1 127.0.0.1 > /tmp/out", ["127.0.0.1/32"])

    def test_disallowed_binary_is_rejected(self):
        with self.assertRaises(ExecutionError):
            validate_command("bash -c 'echo hi'", ["127.0.0.1/32"])

    def test_out_of_scope_ip_is_rejected(self):
        with self.assertRaises(ExecutionError) as ctx:
            validate_command("ping -c 1 10.0.0.1", ["127.0.0.1/32"])
        self.assertIn("outside", str(ctx.exception))

    def test_in_scope_ip_is_allowed(self):
        validate_command("ping -c 1 127.0.0.1", ["127.0.0.1/32"])

    def test_in_scope_network_is_allowed(self):
        validate_command("nmap 10.0.0.5", ["10.0.0.0/24"])

    def test_hostname_outside_scope_is_rejected(self):
        with self.assertRaises(ExecutionError):
            validate_command("curl http://example.com", ["127.0.0.1/32"])


class TestSimulationExecutor(EvilkitTestCase):
    def test_ping_loopback_succeeds(self):
        exe = SimulationExecutor(["127.0.0.1/32"])
        result = exe.execute("ping -c 1 127.0.0.1")
        self.assertEqual(result.returncode, 0)
        self.assertIn("64 bytes", result.stdout)

    def test_ping_non_loopback_in_scope_fails_simulated(self):
        exe = SimulationExecutor(["10.0.0.0/24"])
        result = exe.execute("ping -c 1 10.0.0.5")
        self.assertNotEqual(result.returncode, 0)

    def test_ping_out_of_scope_is_rejected(self):
        exe = SimulationExecutor(["127.0.0.1/32"])
        result = exe.execute("ping -c 1 10.0.0.1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside", result.stderr)

    def test_nmap_loopback_returns_ports(self):
        exe = SimulationExecutor(["127.0.0.1/32"])
        result = exe.execute("nmap -sV 127.0.0.1")
        self.assertEqual(result.returncode, 0)
        self.assertIn("22/tcp open", result.stdout)

    def test_curl_loopback_returns_html(self):
        exe = SimulationExecutor(["127.0.0.1/32"])
        result = exe.execute("curl http://127.0.0.1")
        self.assertEqual(result.returncode, 0)
        self.assertIn("<html>", result.stdout)


class TestShellExecutor(EvilkitTestCase):
    def test_runs_allowed_command_in_scope(self):
        exe = ShellExecutor(["127.0.0.1/32"])
        with mock.patch("evilkit.tools.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                args=["ping"], returncode=0, stdout="pong", stderr=""
            )
            result = exe.execute("ping -c 1 127.0.0.1")
        # The command must reach the process as separate argv words, not as one
        # binary name with the arguments glued on.
        self.assertEqual(run.call_args.args[0], ["ping", "-c", "1", "127.0.0.1"])
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "pong")

    def test_missing_binary_reports_not_found(self):
        exe = ShellExecutor(["127.0.0.1/32"])
        with mock.patch("evilkit.tools.subprocess.run") as run:
            run.side_effect = FileNotFoundError(2, "No such file", "nmap")
            result = exe.execute("nmap 127.0.0.1")
        self.assertEqual(result.returncode, 127)
        self.assertIn("command not found", result.stderr)

    def test_rejects_out_of_scope_command(self):
        exe = ShellExecutor(["127.0.0.1/32"])
        with self.assertRaises(ExecutionError):
            exe.execute("ping -c 1 10.0.0.1")

    def test_rejects_disallowed_binary(self):
        exe = ShellExecutor(["127.0.0.1/32"])
        with self.assertRaises(ExecutionError):
            exe.execute("bash -c 'echo hi'")


if __name__ == "__main__":
    unittest.main()
