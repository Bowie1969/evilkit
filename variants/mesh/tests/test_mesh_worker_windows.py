"""Portable tests for the standalone Windows worker protocol."""

from __future__ import annotations

import threading

from evilkit import mesh
from scripts import mesh_worker_windows as win
from tests._helpers import EvilkitTestCase


class WindowsWorkerTest(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.hub = mesh.Hub(None, "x" * 40, brief="In scope: app.launchdarkly.com\nOut of scope: support chat")
        self.server = mesh.MeshServer(("127.0.0.1", 0), mesh._handler(self.hub))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.token = self.tmp / "token"
        self.token.write_text("x" * 40)

    def test_worker_runs_kimi_with_complete_brief(self):
        self.stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$2\"\n")
        self.stub.chmod(0o755)
        self.hub.submit("inspect allowed host", None)
        code = win.main(["--leader", self.base, "--token-file", str(self.token), "--name", "laptop", "--project", str(self.tmp / "project"), "--kimi-bin", str(self.stub), "--once"])
        self.assertEqual(code, 0)
        output = "".join(e["text"] for e in self.hub.tail(0)["events"])
        self.assertIn("In scope: app.launchdarkly.com", output)
        self.assertIn("Out of scope: support chat", output)
        self.assertEqual(self.hub.state()["tasks"][0]["status"], "done")

    def test_rejects_scoped_hub(self):
        self.hub.mode = "recorded-scope"
        self.hub.scope = "app.launchdarkly.com"
        code = win.main(["--leader", self.base, "--token-file", str(self.token), "--name", "laptop", "--project", str(self.tmp / "project"), "--kimi-bin", str(self.stub), "--once"])
        self.assertEqual(code, 1)
        self.assertEqual(self.hub.state()["workers"], [])
