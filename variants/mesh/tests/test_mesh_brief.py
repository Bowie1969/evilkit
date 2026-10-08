"""Unscoped brief mode: the readable brief reaches leader and worker intact."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from unittest import mock

from evilkit import mesh
from evilkit.mesh_brief import BriefError, read_brief
from tests._helpers import EvilkitTestCase


BRIEF = """LaunchDarkly engagement
In scope: app.launchdarkly.com and events.launchdarkly.com.
Out of scope: support chat, other users' data, DoS.
All accounts must use a bugcrowdninja email address.
"""


class BriefTest(EvilkitTestCase):
    def _server(self):
        hub = mesh.Hub(None, "x" * 40, brief=BRIEF)
        server = mesh.MeshServer(("127.0.0.1", 0), mesh._handler(hub))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return hub, f"http://127.0.0.1:{server.server_port}"

    def _token_file(self):
        path = self.tmp / "token"
        path.write_text("x" * 40 + "\n")
        path.chmod(0o600)
        return path

    def test_text_pointer_and_html_keep_all_rules(self):
        html = self.tmp / "brief.html"
        html.write_text("<html><body><h1>LaunchDarkly</h1><p>In scope: app.launchdarkly.com</p><p>Out of scope: support chat</p><script>bad text</script></body></html>")
        pointer = self.tmp / "brief.txt"
        pointer.write_text(html.as_uri())
        text, digest = read_brief(pointer)
        self.assertIn("In scope: app.launchdarkly.com", text)
        self.assertIn("Out of scope: support chat", text)
        self.assertNotIn("bad text", text)
        self.assertEqual(len(digest), 64)

    def test_unscoped_worker_gets_full_brief_without_pentest_config(self):
        hub, base = self._server()
        token = self._token_file()
        self.stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$2\"\n")
        self.stub.chmod(0o755)
        hub.submit("inspect authorized app", None)
        code = mesh.main(["work", "--leader", base, "--token-file", str(token), "--name", "local-1", "--allow-unscoped", "--once"])
        self.assertEqual(code, 0)
        config = json.loads((self.tmp / ".kimi-code" / "mcp.json").read_text())
        self.assertEqual(list(config["mcpServers"]), ["evilkit-mesh"])
        output = "".join(e["text"] for e in hub.tail(0)["events"]).replace("\r\n", "\n")
        self.assertIn(BRIEF, output)
        self.assertEqual(hub.state()["tasks"][0]["status"], "done")

    def test_unscoped_hub_requires_explicit_worker_flag(self):
        hub, base = self._server()
        token = self._token_file()
        code = mesh.main(["work", "--leader", base, "--token-file", str(token), "--name", "local-1", "--once"])
        self.assertEqual(code, 1)
        self.assertEqual(hub.state()["workers"], [])

    def test_leader_agent_receives_full_brief(self):
        brief = self.tmp / "brief.txt"
        brief.write_text(BRIEF)
        token = self.tmp / "hub-token"
        captured = self.tmp / "agent.md"
        self.stub.write_text("#!/bin/sh\ncp \"$2\" \"$EVILKIT_TEST_AGENT_COPY\"\n")
        self.stub.chmod(0o755)
        with mock.patch.dict(os.environ, {"EVILKIT_TEST_AGENT_COPY": str(captured)}):
            code = mesh.main(["lead", "--brief", str(brief), "--allow-unscoped", "--bind", "127.0.0.1", "--port", "0", "--token-file", str(token), "--cockpit"])
        self.assertEqual(code, 0)
        self.assertIn(BRIEF, captured.read_text())

    def test_brief_cannot_be_combined_with_recorded_scope(self):
        brief = self.tmp / "brief.txt"
        brief.write_text(BRIEF)
        with mock.patch.object(mesh, "_start_tmux") as start:
            self.assertEqual(mesh.main(["start", "--brief", str(brief), "--scope", "app.launchdarkly.com", "--allow-unscoped"]), 1)
            start.assert_not_called()
