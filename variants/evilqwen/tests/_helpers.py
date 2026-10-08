"""Shared hermetic harness for the evilkit test suite.

Every test that touches disk runs inside its own ``tempfile.TemporaryDirectory``
with ``HOME``, ``XDG_CONFIG_HOME``, ``EVILKIT_CONFIG``, ``EVILKIT_KIMI_HOME`` and
``EVILKIT_KIMI_BIN`` all pointing into that directory, and with the process
working directory set to it. Nothing can therefore read or write the developer's
real ``~/.config``, ``~/.kimi-code``, or a real project ``.mcp.json``.

Not collected by ``unittest discover`` (the file is not named ``test*``).
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SCOPE_ENV_KEY = "PENTEST_ALLOWED_TARGETS"

#: Stand-in for the Kimi Code CLI. Prints its argv and the launch environment so
#: a test can prove what actually reached the child process.
STUB_SCRIPT = """#!/bin/sh
for a in "$@"; do printf 'arg:%s\\n' "$a"; done
printf 'scope:%s\\n' "${PENTEST_ALLOWED_TARGETS-unset}"
printf 'identity:%s\\n' "${KIMI_CODE_IDENTITY_NAME-unset}"
"""


class NotATty(io.StringIO):
    """Stdin stand-in that never claims to be a terminal."""

    def isatty(self) -> bool:
        return False


class EvilkitTestCase(unittest.TestCase):
    """Base class: temp dir, scrubbed environment, cwd inside the temp dir."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="evilkit-tests-")
        self.addCleanup(self._tmpdir.cleanup)
        self.tmp = pathlib.Path(self._tmpdir.name).resolve()

        self.home = self.tmp / "env" / "home"
        self.kimi_home = self.tmp / "env" / "kimi-home"
        self.config_file = self.tmp / "env" / "config" / "config.toml"
        self.stub = self.tmp / "env" / "kimi-stub"
        self.home.mkdir(parents=True, exist_ok=True)
        self.kimi_home.mkdir(parents=True, exist_ok=True)
        self.stub.parent.mkdir(parents=True, exist_ok=True)
        self.stub.write_text(STUB_SCRIPT, encoding="utf-8")
        self.stub.chmod(0o755)

        env = {
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.tmp / "xdg-config"),
            "EVILKIT_CONFIG": str(self.config_file),
            "EVILKIT_KIMI_HOME": str(self.kimi_home),
            "EVILKIT_KIMI_BIN": str(self.stub),
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        # _collect_scope() falls back to this variable, so a value exported in the
        # developer's shell must not leak into a test.
        os.environ.pop(SCOPE_ENV_KEY, None)
        # _launch_env() uses setdefault() for these, so they must be absent for the
        # child process to report the identity evilkit actually sets.
        os.environ.pop("KIMI_CODE_IDENTITY_NAME", None)
        os.environ.pop("KIMI_CODE_IDENTITY_SLUG", None)

        self._cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self._cwd)

    # -- filesystem fixtures -------------------------------------------------

    def write_mcp_json(self, data, directory=None, name=".mcp.json") -> pathlib.Path:
        path = pathlib.Path(directory or self.tmp) / name
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def pentest_fixture(self, scope: str = "10.0.0.0/24") -> dict:
        """A .mcp.json with a pentest server plus unrelated content to preserve."""
        return {
            "mcpServers": {
                "pentest": {
                    "command": "python3",
                    "args": ["-m", "pentest_tools_server"],
                    "env": {
                        SCOPE_ENV_KEY: scope,
                        "OTHER_ENV": "keep-me",
                        "NUMERIC": 7,
                    },
                },
                "mission": {
                    "command": "python3",
                    "args": ["-m", "mission_server"],
                    "env": {SCOPE_ENV_KEY: "not-the-pentest-server"},
                },
            },
            "topLevel": {"nested": [1, 2, {"flag": True}], "unicode": "héllo"},
        }

    # -- invocation helpers --------------------------------------------------

    def call_main(self, argv: list[str]):
        """Run ``cli.main`` in-process with stdout/stderr/stdin captured.

        Returns ``(exit_code, stdout, stderr)``. An argparse ``SystemExit`` is
        reported as its exit code so ``--version`` and usage errors can be
        asserted the same way as a returned code.

        Only safe for paths that return before ``os.execvpe`` (dry runs, errors
        and the non-launching commands).
        """
        from evilkit.cli import main

        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), mock.patch("sys.stdin", NotATty()):
            try:
                code = main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def run_cli(self, argv, *, cwd=None, env=None, stdin=subprocess.DEVNULL):
        """Run the real CLI in a subprocess (needed for the launching paths)."""
        child_env = dict(os.environ)
        child_env["PYTHONPATH"] = os.pathsep.join(
            [str(PROJECT_ROOT), child_env.get("PYTHONPATH", "")]
        ).strip(os.pathsep)
        for leak in (SCOPE_ENV_KEY, "KIMI_CODE_IDENTITY_NAME", "KIMI_CODE_IDENTITY_SLUG"):
            child_env.pop(leak, None)
        child_env.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "evilkit", *argv],
            cwd=str(cwd or self.tmp),
            env=child_env,
            capture_output=True,
            text=True,
            stdin=stdin,
            timeout=60,
        )
