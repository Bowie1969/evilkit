"""Tests for mesh node: sandboxed file ops, allowlisted commands, knowledge sharing, kill switch."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from evilkit import mesh, mesh_mcp, mesh_node
from tests._helpers import EvilkitTestCase


class MeshNodeTest(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.hub = mesh.Hub("10.0.0.0/24", "x" * 40)
        self.server = mesh.MeshServer(("127.0.0.1", 0), mesh._handler(self.hub))
        import threading
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.token_file = self.tmp / "token"
        self.token_file.write_text("x" * 40 + "\n", encoding="ascii")
        self.token_file.chmod(0o600)
        # Create sandbox with test files
        self.sandbox = self.tmp / "sandbox"
        self.sandbox.mkdir()
        (self.sandbox / "notes.txt").write_text("hello world\n", encoding="utf-8")
        (self.sandbox / "subdir").mkdir()
        (self.sandbox / "subdir" / "data.csv").write_text("a,b,c\n1,2,3\n", encoding="utf-8")


class NodeSandboxTest(MeshNodeTest):
    def test_list_files_returns_entries(self):
        entries = mesh_node.node_list_files(self.sandbox)
        names = [e["name"] for e in entries]
        self.assertIn("notes.txt", names)
        self.assertIn("subdir", names)

    def test_list_files_subdirectory(self):
        entries = mesh_node.node_list_files(self.sandbox, "subdir")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["name"], "data.csv")

    def test_read_file_returns_content(self):
        content = mesh_node.node_read_file(self.sandbox, "notes.txt")
        self.assertEqual(content.strip(), "hello world")

    def test_read_file_truncates_large_files(self):
        large = self.sandbox / "big.txt"
        large.write_text("A" * 1000, encoding="utf-8")
        content = mesh_node.node_read_file(self.sandbox, "big.txt", max_bytes=100)
        self.assertIn("truncated", content)
        self.assertEqual(len(content[:100]), 100)

    def test_file_hash_returns_sha256(self):
        h = mesh_node.node_file_hash(self.sandbox, "notes.txt")
        self.assertEqual(len(h), 64)  # hex SHA-256

    def test_path_escape_is_rejected(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node._resolve_sandbox_path(self.sandbox, "../../etc/passwd")

    def test_nonexistent_file_raises(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node.node_read_file(self.sandbox, "missing.txt")

    def test_directory_read_raises(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node.node_read_file(self.sandbox, "subdir")


class NodeCommandTest(MeshNodeTest):
    def test_allowlisted_command_runs(self):
        result = mesh_node.node_run_command("hostname", frozenset({"hostname"}))
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["stdout"].strip())

    def test_denied_command_is_rejected(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node.node_run_command("rm -rf /", frozenset({"rm"}))

    def test_non_allowlisted_is_rejected(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node.node_run_command("hostname", frozenset({"ls"}))

    def test_empty_command_is_rejected(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node.node_run_command("", frozenset({"hostname"}))

    def test_missing_binary_is_rejected(self):
        with self.assertRaises(mesh.MeshError):
            mesh_node.node_run_command("nonexistent_binary_xyz", frozenset({"nonexistent_binary_xyz"}))


class NodeHubTest(MeshNodeTest):
    def test_node_register(self):
        info = self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        self.assertEqual(info["privilege"], "root")
        self.assertIn("lab-1", self.hub.nodes)

    def test_node_register_rejects_killed(self):
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        self.hub.node_kill("lab-1")
        with self.assertRaises(mesh.MeshError):
            self.hub.node_register("lab-1", str(self.sandbox), 1235, "root")

    def test_node_claim_and_complete(self):
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "uid-1000")
        task = self.hub.node_submit("list_files", None, path=".")
        claimed = self.hub.node_claim("lab-1")
        self.assertEqual(claimed["task"]["id"], task["id"])
        self.hub.node_complete("lab-1", task["id"], {"files": ["notes.txt"]})
        self.assertEqual(self.hub.node_tasks[task["id"]]["status"], "done")

    def test_node_observe_and_knowledge(self):
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        obs = self.hub.node_observe("lab-1", "config", "ssh_port", "SSH on 2222")
        self.assertEqual(obs["category"], "config")
        items = self.hub.node_knowledge()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["subject"], "ssh_port")

    def test_node_knowledge_filter_by_category(self):
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        self.hub.node_observe("lab-1", "config", "ssh", "port 22")
        self.hub.node_observe("lab-1", "network", "dns", "8.8.8.8")
        config_items = self.hub.node_knowledge(category="config")
        self.assertEqual(len(config_items), 1)

    def test_node_kill_check(self):
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        self.assertFalse(self.hub.node_kill_check("lab-1")["killed"])
        self.hub.node_kill("lab-1")
        self.assertTrue(self.hub.node_kill_check("lab-1")["killed"])

    def test_node_status(self):
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        status = self.hub.node_status()
        self.assertEqual(len(status["nodes"]), 1)
        self.assertEqual(status["knowledge_count"], 0)


class NodeAPITest(MeshNodeTest):
    def test_node_register_via_http(self):
        result = mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        self.assertEqual(result["privilege"], "root")

    def test_node_task_and_claim_via_http(self):
        mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        task = mesh._request(self.base, self.hub.token, "/node/task", {"type": "list_files", "path": "."})
        self.assertIn("id", task)
        claimed = mesh._request(self.base, self.hub.token, "/node/claim", {"name": "lab-1"})
        self.assertEqual(claimed["task"]["id"], task["id"])

    def test_node_complete_via_http(self):
        mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        task = mesh._request(self.base, self.hub.token, "/node/task", {"type": "list_files", "path": "."})
        mesh._request(self.base, self.hub.token, "/node/claim", {"name": "lab-1"})
        result = mesh._request(self.base, self.hub.token, "/node/complete", {
            "name": "lab-1", "task": task["id"], "result": {"files": ["notes.txt"]},
        })
        self.assertTrue(result["ok"])

    def test_node_observe_via_http(self):
        mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        obs = mesh._request(self.base, self.hub.token, "/node/observe", {
            "name": "lab-1", "category": "config", "subject": "ssh", "detail": "port 22",
        })
        self.assertEqual(obs["category"], "config")

    def test_node_knowledge_via_http(self):
        mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        mesh._request(self.base, self.hub.token, "/node/observe", {
            "name": "lab-1", "category": "config", "subject": "ssh", "detail": "port 22",
        })
        items = mesh._request(self.base, self.hub.token, "/node/knowledge?limit=10")
        self.assertEqual(len(items), 1)

    def test_node_kill_via_http(self):
        mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        result = mesh._request(self.base, self.hub.token, "/node/kill", {"name": "lab-1"})
        self.assertTrue(result["killed"])
        check = mesh._request(self.base, self.hub.token, "/node/kill-check", {"name": "lab-1"})
        self.assertTrue(check["killed"])

    def test_node_status_via_http(self):
        mesh._request(self.base, self.hub.token, "/node/register", {
            "name": "lab-1", "sandbox": str(self.sandbox), "pid": 1234, "privilege": "root",
        })
        status = mesh._request(self.base, self.hub.token, "/node/status")
        self.assertEqual(len(status["nodes"]), 1)


class NodeMCPPTest(MeshNodeTest):
    def test_mcp_node_tools_exist(self):
        tool_names = [t["name"] for t in mesh_mcp.TOOLS]
        self.assertIn("list_nodes", tool_names)
        self.assertIn("node_task", tool_names)
        self.assertIn("node_knowledge", tool_names)
        self.assertIn("node_kill", tool_names)

    def test_mcp_list_nodes(self):
        env = {"EVILKIT_MESH_LEADER": self.base, "EVILKIT_MESH_TOKEN_FILE": str(self.token_file)}
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        with mock.patch.dict(os.environ, env):
            result = mesh_mcp._response({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "list_nodes", "arguments": {}},
            })
            content = result["result"]["content"][0]["text"]
            if result["result"].get("isError"):
                self.fail(f"MCP call failed: {content}")
            data = json.loads(content)
            self.assertEqual(len(data["nodes"]), 1)

    def test_mcp_node_task(self):
        env = {"EVILKIT_MESH_LEADER": self.base, "EVILKIT_MESH_TOKEN_FILE": str(self.token_file)}
        with mock.patch.dict(os.environ, env):
            result = mesh_mcp._response({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "node_task", "arguments": {"type": "list_files", "path": "."}},
            })
            content = result["result"]["content"][0]["text"]
            if result["result"].get("isError"):
                self.fail(f"MCP call failed: {content}")
            data = json.loads(content)
            self.assertIn("id", data)

    def test_mcp_node_knowledge(self):
        env = {"EVILKIT_MESH_LEADER": self.base, "EVILKIT_MESH_TOKEN_FILE": str(self.token_file)}
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        self.hub.node_observe("lab-1", "config", "ssh", "port 22")
        with mock.patch.dict(os.environ, env):
            result = mesh_mcp._response({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "node_knowledge", "arguments": {}},
            })
            content = result["result"]["content"][0]["text"]
            if result["result"].get("isError"):
                self.fail(f"MCP call failed: {content}")
            items = json.loads(content)
            self.assertEqual(len(items), 1)

    def test_mcp_node_kill(self):
        env = {"EVILKIT_MESH_LEADER": self.base, "EVILKIT_MESH_TOKEN_FILE": str(self.token_file)}
        self.hub.node_register("lab-1", str(self.sandbox), 1234, "root")
        with mock.patch.dict(os.environ, env):
            result = mesh_mcp._response({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "node_kill", "arguments": {"node_name": "lab-1"}},
            })
            content = result["result"]["content"][0]["text"]
            if result["result"].get("isError"):
                self.fail(f"MCP call failed: {content}")
            data = json.loads(content)
            self.assertTrue(data["killed"])
