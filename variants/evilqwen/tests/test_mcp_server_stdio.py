"""Regression tests for the MCP stdio server hardening.

Run-12 postmortem: lib modules printed to stdout (poisoning the JSON-RPC
stream), long handlers blocked the single-threaded loop past the client's
patience, and the client killed + restarted the server for the rest of the
run. These tests pin the three fixes:

- every byte on the stdout wire is JSON-RPC, even for tools whose libs print
- a handler past CALL_BUDGET_SECONDS gets -32002 and the server keeps answering
- a scan_range CIDR is capped to MAX_SCAN_HOSTS before probing

They spawn mcp-malware-generator.py as a subprocess and drive it over stdio,
exactly like qwen does. No cage/range tools are called.
"""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(REPO_ROOT, "mcp-malware-generator.py")


class McpServerCase(unittest.TestCase):
    def setUp(self):
        self._procs = []

    def tearDown(self):
        for proc in self._procs:
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

    def _spawn(self, extra_env=None, budget=None, max_scan_hosts=None):
        env = dict(os.environ)
        for key in ("LAB_SSH_USER", "LAB_SSH_PASS", "LAB_SSH_KEY"):
            env.pop(key, None)
        env.pop("EVILKIT_MISSION_CONTRACT", None)
        env.pop("EVILKIT_MISSION_STATE", None)
        if budget is not None:
            env["EVILKIT_MCP_CALL_BUDGET"] = str(budget)
        if max_scan_hosts is not None:
            env["EVILKIT_MCP_MAX_SCAN_HOSTS"] = str(max_scan_hosts)
        env.update(extra_env or {})
        proc = subprocess.Popen(
            [sys.executable, SERVER],
            cwd=REPO_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(proc)
        return proc

    def _rpc(self, proc, method, params=None, req_id=0, timeout=15.0):
        """Send one request; return (status, elapsed, response_dict).

        status is 'ok', 'garbage-line' (non-JSON byte on the wire — the
        run-12 poison), 'timeout', or 'child-exited'.
        """
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        if proc.poll() is not None:
            return ("child-exited", 0.0, None)
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        t0 = time.time()
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        while True:
            if proc.poll() is not None:
                return ("child-exited", time.time() - t0, None)
            remaining = timeout - (time.time() - t0)
            if remaining <= 0:
                return ("timeout", timeout, None)
            events = sel.select(timeout=min(0.25, remaining))
            if not events:
                continue
            line = proc.stdout.readline()
            if not line:
                return ("child-exited", time.time() - t0, None)
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                return ("garbage-line", time.time() - t0, line[:200])
            if resp.get("id") == req_id:
                return ("ok", time.time() - t0, resp)

    def _init(self, proc):
        status, _, resp = self._rpc(proc, "initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        }, req_id=1)
        self.assertEqual(status, "ok", "initialize failed")
        self._rpc(proc, "notifications/initialized", req_id=2)

    def test_wire_stays_json_across_tool_battery(self):
        """No tool may put a non-JSON-RPC byte on stdout (run-12 poison)."""
        proc = self._spawn()
        self._init(proc)
        calls = [
            ("tools/list", {}),
            ("mission_contract", {}),
            ("mission_status", {}),
            ("malware_harvest", {"host": "localhost"}),
            ("malware_map_trust", {"scan_range": "127.0.0.0/30", "json_output": True}),
            ("no_such_tool", {}),
        ]
        for i, (tool, args) in enumerate(calls, start=10):
            timeout = 90.0 if tool == "malware_map_trust" else 15.0
            status, elapsed, resp = self._rpc(proc, "tools/call", {
                "name": tool, "arguments": args,
            }, req_id=i, timeout=timeout)
            self.assertNotEqual(status, "garbage-line",
                                f"{tool} wrote a non-JSON line to the protocol stream")
            self.assertNotEqual(status, "child-exited",
                                f"server died during {tool}")
            self.assertEqual(status, "ok", f"{tool}: {status}")
        self.assertIsNone(proc.poll(), "server must still be alive after the battery")

    def test_slow_tool_gets_budget_error_and_server_stays_responsive(self):
        """A handler past the budget returns -32002; the loop keeps answering."""
        proc = self._spawn(budget=1)
        self._init(proc)
        # Unreachable hosts keep the reachability scanner busy with probe
        # timeouts. Self-calibrating: skip when this box answers them fast.
        t_probe = time.time()
        subprocess.run(["ping", "-c", "1", "-W", "2", "10.99.50.250"],
                       capture_output=True, timeout=10)
        if time.time() - t_probe < 0.8:
            self.skipTest("10.99.50.250 is answered or refused fast on this box")
        status, elapsed, resp = self._rpc(proc, "tools/call", {
            "name": "malware_map_trust",
            "arguments": {
                "known_hosts": "10.99.50.250,10.99.50.251,10.99.50.252",
                "json_output": True,
            },
        }, req_id=10, timeout=20)
        self.assertEqual(status, "ok", f"expected a budget error response, got {status}")
        self.assertEqual(resp["error"]["code"], -32002, resp)
        # The straggler must not block the loop: a cheap call answers fast.
        status, elapsed, _ = self._rpc(proc, "tools/call", {
            "name": "mission_status", "arguments": {},
        }, req_id=11, timeout=10)
        self.assertEqual(status, "ok", "server unresponsive after budget error")
        self.assertLess(elapsed, 10, "mission_status queued behind straggler")
        self.assertIsNone(proc.poll(), "server must survive a budget overflow")

    def test_scan_range_capped_to_max_hosts(self):
        proc = self._spawn(budget=90, max_scan_hosts=4)
        self._init(proc)
        status, _, resp = self._rpc(proc, "tools/call", {
            "name": "malware_map_trust",
            "arguments": {"scan_range": "10.99.50.0/24", "json_output": True},
        }, req_id=10, timeout=150)
        self.assertEqual(status, "ok", f"{status}")
        self.assertNotIn("error", resp, resp.get("error"))
        text = resp["result"]["content"][0]["text"]
        self.assertIn("capped to the first 4", text)

    def test_shadow_scanner_accepts_home_argument(self):
        """Regression: _scan_shadow_file takes (home, host) like every scanner."""
        sys.path.insert(0, os.path.join(REPO_ROOT, "lib"))
        try:
            import credential_harvester  # noqa: E402
        finally:
            sys.path.remove(os.path.join(REPO_ROOT, "lib"))
        creds = credential_harvester._scan_shadow_file("/nonexistent-home", "host")
        self.assertIsInstance(creds, list)


if __name__ == "__main__":
    unittest.main()
