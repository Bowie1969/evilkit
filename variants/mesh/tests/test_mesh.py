"""Coordinator tests use loopback and a local fake Kimi process only."""

from __future__ import annotations

import json
import os
import threading
from unittest import mock

from evilkit import mesh, mesh_mcp
from tests._helpers import EvilkitTestCase


class MeshTest(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.hub = mesh.Hub("10.0.0.0/24", "x" * 40)
        self.server = mesh.MeshServer(("127.0.0.1", 0), mesh._handler(self.hub))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.token_file = self.tmp / "token"
        self.token_file.write_text("x" * 40 + "\n", encoding="ascii")
        self.token_file.chmod(0o600)

    def test_auth_and_task_ownership(self):
        with self.assertRaises(mesh.MeshError):
            mesh._request(self.base, "wrong", "/state")
        self.assertEqual(mesh._request(self.base, self.hub.token, "/register", {"name": "box1"})["scope"], "10.0.0.0/24")
        task = mesh._request(self.base, self.hub.token, "/task", {"prompt": "inspect host", "worker": "box1"})
        claimed = mesh._request(self.base, self.hub.token, "/claim", {"name": "box1"})["task"]
        self.assertEqual(claimed["id"], task["id"])
        with self.assertRaises(mesh.MeshError):
            mesh._request(self.base, self.hub.token, "/output", {"name": "other", "task": task["id"], "text": "fake"})
        mesh._request(self.base, self.hub.token, "/output", {"name": "box1", "task": task["id"], "text": "hello"})
        self.assertIn("hello", [e["text"] for e in self.hub.tail(0)["events"]])

    def test_worker_records_scope_and_streams_kimi_output(self):
        path = self.write_mcp_json(self.pentest_fixture("127.0.0.1/32"))
        self.stub.write_text("#!/bin/sh\nprintf 'worker output\\n'\n", encoding="utf-8")
        self.stub.chmod(0o755)
        self.hub.submit("check target", None)
        code = mesh.main(["work", "--leader", self.base, "--token-file", str(self.token_file), "--name", "box1", "--mcp-json", str(path), "--once"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(path.read_text())["mcpServers"]["pentest"]["env"]["PENTEST_ALLOWED_TARGETS"], "10.0.0.0/24")
        self.assertIn("evilkit-mesh", json.loads(path.read_text())["mcpServers"])
        self.assertEqual(self.hub.state()["tasks"][0]["status"], "done")
        self.assertIn("worker output", "".join(e["text"] for e in self.hub.tail(0)["events"]))

    def test_worker_fails_closed_without_pentest_server(self):
        path = self.write_mcp_json({"mcpServers": {"other": {"command": "x"}}})
        code = mesh.main(["work", "--leader", self.base, "--token-file", str(self.token_file), "--name", "box1", "--mcp-json", str(path), "--once"])
        self.assertEqual(code, 1)
        self.assertEqual(self.hub.state()["workers"], [])

    def test_remote_url_rejects_public_hosts(self):
        for value in ("http://8.8.8.8:8765", "http://example.com:8765", "https://100.101.1.1:8765"):
            with self.subTest(value=value), self.assertRaises(mesh.MeshError):
                mesh._url(value)

    def test_token_file_private(self):
        self.token_file.chmod(0o644)
        with self.assertRaises(mesh.MeshError):
            mesh._token(self.token_file)

    def test_mcp_install_preserves_existing_and_refuses_conflict(self):
        path = self.write_mcp_json(self.pentest_fixture())
        before = json.loads(path.read_text())
        mesh._install_mcp(path)
        after = json.loads(path.read_text())
        self.assertEqual(after["mcpServers"]["pentest"], before["mcpServers"]["pentest"])
        self.assertEqual(after["mcpServers"]["mission"], before["mcpServers"]["mission"])
        after["mcpServers"]["evilkit-mesh"] = {"command": "other"}
        path.write_text(json.dumps(after))
        with self.assertRaises(mesh.MeshError):
            mesh._install_mcp(path)

    def test_mcp_tools_use_hub_and_role(self):
        env = {"EVILKIT_MESH_LEADER": self.base, "EVILKIT_MESH_TOKEN_FILE": str(self.token_file)}
        with mock.patch.dict(os.environ, env):
            init = mesh_mcp._response({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
            self.assertEqual(init["result"]["serverInfo"]["name"], "evilkit-mesh")
            result = mesh_mcp._response({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "assign_task", "arguments": {"prompt": "inspect host"}}})
            self.assertFalse(result["result"].get("isError", False))
            task = json.loads(result["result"]["content"][0]["text"])
            self.hub.register("box1")
            self.hub.claim("box1")
            with mock.patch.dict(os.environ, {"EVILKIT_MESH_WORKER": "box1", "EVILKIT_MESH_TASK": task["id"]}):
                finding = mesh_mcp._response({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "report_finding", "arguments": {"title": "Issue", "detail": "Evidence"}}})
                self.assertFalse(finding["result"].get("isError", False))
            self.assertEqual(self.hub.state()["findings"][0]["title"], "Issue")

    def test_start_normalises_scope_before_launching_tmux(self):
        with mock.patch.object(mesh, "_start_tmux", return_value=0) as start:
            self.assertEqual(mesh.main(["start", "--scope", "10.0.0.5", "--no-attach"]), 0)
            self.assertEqual(start.call_args.args[0], "10.0.0.5/32")
            self.assertFalse(start.call_args.kwargs["attach"])
        with mock.patch.object(mesh, "_start_tmux") as start:
            self.assertEqual(mesh.main(["start", "--scope", "0.0.0.0/0"]), 1)
            start.assert_not_called()

    def test_kimi_binary_finds_existing_home_install(self):
        binary = self.home / ".kimi-code" / "bin" / "kimi"
        binary.parent.mkdir(parents=True)
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        with mock.patch.dict(os.environ, {"EVILKIT_KIMI_BIN": ""}), mock.patch.object(mesh.shutil, "which", return_value=None):
            self.assertEqual(mesh._kimi_binary(), str(binary))

    def test_scope_autodetects_current_kimi_mcp_file(self):
        path = self.tmp / ".kimi-code" / "mcp.json"
        path.parent.mkdir()
        path.write_text(json.dumps(self.pentest_fixture("127.0.0.1/32")))
        self.assertEqual(mesh._scope_record("10.0.0.0/24", None, 0), path)
        self.assertEqual(json.loads(path.read_text())["mcpServers"]["pentest"]["env"]["PENTEST_ALLOWED_TARGETS"], "10.0.0.0/24")

    def test_connection_file_is_local_default(self):
        mesh._write_connection(self.token_file, self.base)
        self.assertEqual(mesh._read_connection(self.token_file), self.base)
