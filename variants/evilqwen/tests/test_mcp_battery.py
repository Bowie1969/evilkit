"""Per-tool battery for the malware-scripting MCP.

Every tool this server exposes is called over the real stdio wire and must come
back with either a real result or the *specific* refusal its precondition
implies — never a fabricated success, never a hang, never a dead server, and
never a local result wearing a remote host's name.

The battery is the acceptance test for the "make every malware tool work" pass:
a tool that silently degrades to a stub, mislabels the operator box as a guest,
or dies on a missing credential fails here. The two layers are tested
separately on purpose:

- unconfigured (no ``LAB_SSH_*``, no provider key, real contract, fresh state):
  every ssh/provider-backed tool must refuse with its documented reason, and the
  four declaration-gated tools must refuse with ``-31002``.
- configured (a probe contract with no prerequisites, objectives declared):
  the same tools must actually run, with local work labelled ``LOCAL ONLY``.

Run: ``cd variants/evilqwen && python3 -m unittest tests.test_mcp_battery -v``
"""

from __future__ import annotations

import itertools
import json
import os
import subprocess
import tempfile
import unittest
from collections import namedtuple

from tests._helpers import PROJECT_ROOT, McpWireHarness

CONTRACT = os.path.join(str(PROJECT_ROOT), "contracts", "mission.json")
#: Override to point the same battery at another copy of the server (the
#: installed/mounted one, say) and prove that copy is healthy too:
#: ``EVILKIT_BATTERY_SERVER=/path/to/mcp-malware-generator.py``
SERVER = os.environ.get(
    "EVILKIT_BATTERY_SERVER", os.path.join(str(PROJECT_ROOT), "mcp-malware-generator.py")
)

LOCAL_ONLY = "LOCAL ONLY — NOT HOST EVIDENCE"

#: The 21 tools the server advertises. Anything missing from this list, or extra
#: in ``tools/list``, is a battery failure — the list is the contract.
ALL_TOOLS = (
    "malware_c2",
    "malware_classify",
    "malware_deploy",
    "malware_evasion",
    "malware_generate",
    "malware_get_logs",
    "malware_harvest",
    "malware_lotl",
    "malware_map_trust",
    "malware_persist",
    "malware_polymorph",
    "malware_range",
    "malware_stage",
    "malware_test",
    "malware_vuln_research",
    "malware_worm",
    "mission_contract",
    "mission_declare",
    "mission_status",
    "mission_verify",
    "rea_range",
)

#: Tools the contract gates behind a declaration for a named objective.
GATED = {
    "malware_persist": "persistence",
    "malware_c2": "c2_resilience",
    "malware_worm": "propagation",
    "malware_classify": "crown_objective",
}

Result = namedtuple("Result", "code message text")

PROBE_C = '#include <stdio.h>\nint main(void){printf("probe\\n");return 0;}\n'

#: A probe contract whose objectives are all already "ready": no prerequisites,
#: one witness each. It lets the battery reach past the declaration gate to the
#: tools themselves without inventing mission evidence against the real contract.
PROBE_CONTRACT = {
    "campaign": "battery-probe",
    "notes": "probe contract for the MCP battery — not an engagement",
    "scope": ["127.0.0.0/8"],
    "sink": "127.0.0.1:14444",
    "max_actions": 50,
    "verification_reserve": 5,
    "stop_condition": "probe complete",
    "objectives": [
        {
            "id": objective,
            "title": f"probe {objective}",
            "points": 1,
            "requires": [],
            "sensitive": True,
            "witnesses": [{"name": f"{objective}_probe", "description": "probe"}],
        }
        for objective in ("persistence", "c2_resilience", "propagation", "crown_objective")
    ],
}


class BatteryCase(McpWireHarness, unittest.TestCase):
    """One spawned server per test, plus a call helper that keeps the wire honest."""

    SERVER_PATH = SERVER
    SERVER_CWD = str(PROJECT_ROOT)

    def setUp(self):
        super().setUp()
        self._ids = itertools.count(100)
        self.workdir = tempfile.TemporaryDirectory(prefix="evilkit-battery-")
        self.addCleanup(self.workdir.cleanup)

    def path(self, name: str) -> str:
        return os.path.join(self.workdir.name, name)

    def write_probe_source(self) -> str:
        path = self.path("probe.c")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(PROBE_C)
        return path

    def probe_contract_file(self) -> str:
        path = self.path("probe-contract.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(PROBE_CONTRACT, handle)
        return path

    def spawn_unconfigured(self, **env):
        """Real contract, fresh state, no guest credentials, no provider key."""
        extra = {
            "EVILKIT_MISSION_CONTRACT": CONTRACT,
            "EVILKIT_MISSION_STATE": self.path("state.json"),
        }
        extra.update(env)
        proc = self._spawn(extra_env=extra)
        self._init(proc)
        return proc

    def spawn_probe_contract(self):
        """Probe contract (nothing to wait for), still no guest credentials."""
        proc = self._spawn(extra_env={
            "EVILKIT_MISSION_CONTRACT": self.probe_contract_file(),
            "EVILKIT_MISSION_STATE": self.path("probe-state.json"),
        })
        self._init(proc)
        return proc

    def declare(self, proc, objective):
        result = self.call(proc, "mission_declare", {
            "objective": objective,
            "action": f"battery probe for {objective}",
            "rationale": "exercise the tool through its gate in a test",
        })
        self.assertIsNone(result.code, f"declaration for {objective} was refused: {result.message}")
        return result

    def call(self, proc, tool, args=None, timeout=60.0):
        """Call one tool. Returns Result(code, message, text) — code None on success."""
        status, elapsed, resp = self._rpc(
            proc,
            "tools/call",
            {"name": tool, "arguments": args or {}},
            req_id=next(self._ids),
            timeout=timeout,
        )
        self.assertNotEqual(status, "garbage-line",
                            f"{tool} wrote a non-JSON line to the protocol stream")
        self.assertNotEqual(status, "child-exited", f"the server died during {tool}")
        self.assertEqual(status, "ok", f"{tool} did not answer within {timeout:.0f}s ({status})")
        if "error" in resp:
            return Result(resp["error"].get("code"), resp["error"].get("message", ""), "")
        text = resp["result"]["content"][0]["text"]
        return Result(None, "", text)

    def assert_ok(self, result, *needles):
        self.assertIsNone(result.code, f"expected success, got {result.code}: {result.message}")
        for needle in needles:
            self.assertIn(needle, result.text)

    def assert_refused(self, result, *needles):
        self.assertEqual(result.code, -31000, f"expected a tool refusal, got {result.code}: "
                         f"{result.message or result.text[:200]}")
        for needle in needles:
            self.assertIn(needle, result.message)


class TestInventory(BatteryCase):
    def test_all_twenty_one_tools_are_advertised(self):
        proc = self.spawn_unconfigured()
        status, _, resp = self._rpc(proc, "tools/list", {}, req_id=next(self._ids))
        self.assertEqual(status, "ok")
        names = sorted(tool["name"] for tool in resp["result"]["tools"])
        self.assertEqual(names, sorted(ALL_TOOLS))
        for tool in resp["result"]["tools"]:
            self.assertTrue(tool.get("description"), f"{tool['name']} has no description")
            self.assertEqual(tool["inputSchema"]["type"], "object",
                             f"{tool['name']} has no input schema")

    def test_every_tool_answers_without_killing_the_server(self):
        """One cheap call per tool; the loop must survive all 21."""
        proc = self.spawn_unconfigured()
        args = {
            "malware_deploy": {"payload_path": self.path("missing-payload")},
            "malware_test": {"target_vm": "10.99.50.41"},
            "malware_generate": {"output_dir": self.path("gen")},
            "malware_get_logs": {"run_dir": self.workdir.name},
            "malware_polymorph": {"source_path": self.path("missing.c")},
            "malware_stage": {"source_path": self.path("missing.c")},
            "malware_harvest": {"host": "10.99.50.41"},
            "malware_map_trust": {"host": "10.99.50.41"},
            "malware_vuln_research": {},
            "malware_lotl": {"action": "recon", "host": "10.99.50.41", "dry_run": False},
            "malware_classify": {"host": "10.99.50.41"},
            "malware_evasion": {},
            "malware_worm": {"cidr": "127.0.0.0/30"},
            "malware_persist": {"host": "10.99.50.41"},
            "malware_c2": {"test_failover": False},
            "malware_range": {"action": "path"},
        }
        for tool in ALL_TOOLS:
            self.call(proc, tool, args.get(tool, {}))
        self.assertIsNone(proc.poll(), "the server must still be alive after every tool")


class TestRefusalsWhenUnconfigured(BatteryCase):
    """No guest credentials and no provider key: every gate must say why."""

    def test_generate_without_a_provider_key(self):
        proc = self.spawn_unconfigured()
        result = self.call(proc, "malware_generate", {
            "c2_addr": "127.0.0.1:14444", "targets": "127.0.0.1",
            "output_dir": self.path("gen"),
        })
        self.assert_refused(result, "no frontier provider credential", "OPENROUTER_API_KEY")

    def test_generate_refuses_a_local_model_unless_opted_in(self):
        """Scripting is a hosted-model job; a local endpoint needs an explicit opt-in."""
        proc = self.spawn_unconfigured(EVILKIT_OPERATOR_URL="http://127.0.0.1:11434/v1")
        result = self.call(proc, "malware_generate", {
            "c2_addr": "127.0.0.1:14444", "targets": "127.0.0.1",
            "output_dir": self.path("gen"),
        })
        self.assert_refused(result, "refusing to script payloads with a local model",
                            "EVILKIT_ALLOW_LOCAL_SCRIPTING")

    def test_deploy_without_guest_credentials(self):
        proc = self.spawn_unconfigured()
        payload = self.path("payload")
        open(payload, "w").close()
        result = self.call(proc, "malware_deploy", {
            "payload_path": payload, "target_vms": ["10.99.50.41"],
        })
        self.assert_refused(result, "LAB_SSH_USER")

    def test_deploy_reports_a_missing_payload_before_credentials(self):
        proc = self.spawn_unconfigured()
        result = self.call(proc, "malware_deploy", {
            "payload_path": self.path("nope"), "target_vms": ["10.99.50.41"],
        })
        self.assert_refused(result, "Payload not found")

    def test_test_requires_a_named_guest(self):
        proc = self.spawn_unconfigured()
        result = self.call(proc, "malware_test", {})
        self.assert_refused(result, "target_vm is required", "will not run it locally")

    def test_test_without_credentials_never_runs_locally(self):
        proc = self.spawn_unconfigured()
        result = self.call(proc, "malware_test", {"target_vm": "10.99.50.41", "test_command": "id"})
        self.assert_refused(result, "LAB_SSH_USER")

    def test_gated_tools_refuse_without_a_declaration(self):
        proc = self.spawn_unconfigured()
        calls = {
            "malware_persist": {"host": "10.99.50.41"},
            "malware_c2": {"test_failover": False},
            "malware_worm": {"cidr": "127.0.0.0/30", "scope": "127.0.0.0/8"},
            "malware_classify": {"host": "localhost"},
        }
        for tool, args in calls.items():
            with self.subTest(tool=tool):
                result = self.call(proc, tool, args)
                self.assertEqual(result.code, -31002, f"{tool}: {result.code} {result.message}")
                self.assertIn("DECLARATION REQUIRED", result.message)
                self.assertEqual(GATED[tool], self._objective_named_in(result.message))

    @staticmethod
    def _objective_named_in(message: str) -> str:
        for objective in GATED.values():
            if objective in message:
                return objective
        return ""

    def test_remote_hosts_are_refused_by_the_local_scrapers(self):
        proc = self.spawn_unconfigured()
        cases = [
            ("malware_harvest", {"host": "10.99.50.41"}, "refusing to harvest credentials for"),
            ("malware_map_trust", {"host": "10.99.50.41"}, "refusing to map trust from"),
            ("malware_lotl", {"action": "recon", "host": "10.99.50.41", "dry_run": False},
             "refusing to run the recon workflow on"),
        ]
        for tool, args, needle in cases:
            with self.subTest(tool=tool):
                self.assert_refused(self.call(proc, tool, args), needle, "not the target")

    def test_vuln_research_requires_a_target(self):
        proc = self.spawn_unconfigured()
        self.assert_refused(self.call(proc, "malware_vuln_research", {}),
                            "host and port are required")

    def test_polymorph_and_stage_say_what_is_missing(self):
        proc = self.spawn_unconfigured()
        self.assert_refused(self.call(proc, "malware_polymorph", {"source_path": self.path("nope.c")}),
                            "Source not found")
        self.assert_refused(self.call(proc, "malware_stage", {"source_path": self.path("nope.c")}),
                            "Source not found")

    def test_range_guards(self):
        proc = self.spawn_unconfigured()
        self.assert_refused(self.call(proc, "malware_range", {"action": "teleport"}),
                            "unknown range action")
        self.assert_refused(self.call(proc, "malware_range", {"action": "path"}),
                            "run_id is required for path action")
        self.assert_refused(
            self.call(proc, "malware_range", {"action": "prepare", "range_root": self.path("no-such-range")}),
            "range root does not exist")

    def test_rea_range_refuses_sensibly_when_not_prepared(self):
        """No estate and no REA contract: honest refusals, server stays alive."""
        proc = self.spawn_unconfigured(REA_RANGE_ROOT=self.path("no-such-estate"))
        self.assert_refused(self.call(proc, "rea_range", {"action": "status"}),
                            "not prepared")
        self.assert_refused(self.call(proc, "rea_range", {"action": "score"}),
                            "rea-control-plane")
        self.assertIsNone(proc.poll(), "the server must still be alive after the refusals")

    def test_mission_tools_refuse_without_a_contract(self):
        proc = self._spawn(extra_env={"EVILKIT_MISSION_CONTRACT": self.path("none.json"),
                                      "EVILKIT_MISSION_STATE": self.path("state.json")})
        self._init(proc)
        for tool, args, needle in (
            ("mission_contract", {"path": self.path("none.json")}, "no mission contract"),
            ("mission_declare", {"objective": "x", "action": "y", "rationale": "z"},
             "no mission contract"),
            ("mission_status", {}, "no mission contract"),
            ("mission_verify", {"objective": "x", "witness": "y"}, "no mission contract"),
        ):
            with self.subTest(tool=tool):
                self.assert_refused(self.call(proc, tool, args), needle)

    def test_mission_declare_needs_a_concrete_action(self):
        proc = self.spawn_unconfigured()
        self.assert_refused(self.call(proc, "mission_declare", {"objective": "delivery"}),
                            "objective, action and rationale are all required")


class TestLocalPaths(BatteryCase):
    """The tools that legitimately work on this box must work, and say so."""

    def test_get_logs_is_a_clean_no_op_without_logs(self):
        proc = self.spawn_unconfigured()
        self.assert_ok(self.call(proc, "malware_get_logs",
                                 {"run_dir": self.workdir.name, "log_type": "c2"}), "log")

    def test_harvest_labels_local_results(self):
        proc = self.spawn_unconfigured()
        self.assert_ok(self.call(proc, "malware_harvest", {"host": "localhost"}), LOCAL_ONLY)

    def test_map_trust_labels_local_results(self):
        proc = self.spawn_unconfigured()
        self.assert_ok(self.call(proc, "malware_map_trust",
                                 {"known_hosts": "127.0.0.1", "json_output": True}), LOCAL_ONLY)

    def test_evasion_labels_local_results(self):
        proc = self.spawn_unconfigured()
        self.assert_ok(self.call(proc, "malware_evasion", {}), LOCAL_ONLY)

    def test_lotl_dry_run_is_labelled_a_plan(self):
        proc = self.spawn_unconfigured()
        self.assert_ok(self.call(proc, "malware_lotl", {"action": "recon", "host": "localhost"}),
                       "DRY RUN")

    def test_polymorph_produces_variants(self):
        proc = self.spawn_unconfigured()
        source = self.write_probe_source()
        result = self.call(proc, "malware_polymorph",
                           {"source_path": source, "count": 2, "compile": True}, timeout=180.0)
        self.assert_ok(result)

    def test_stage_builds_a_chain(self):
        proc = self.spawn_unconfigured()
        source = self.write_probe_source()
        result = self.call(proc, "malware_stage",
                           {"source_path": source, "c2_addr": "127.0.0.1:14444"}, timeout=180.0)
        self.assert_ok(result)

    def test_mission_contract_status_declare_verify(self):
        proc = self.spawn_unconfigured()
        self.assert_ok(self.call(proc, "mission_contract", {}), "CONTRACT LOADED")
        self.assert_ok(self.call(proc, "mission_status", {}), "delivery")
        self.declare(proc, "delivery")
        refused = self.call(proc, "mission_verify",
                            {"objective": "delivery", "witness": "not_a_witness"})
        self.assert_refused(refused, "not a witness of")
        self.assert_ok(self.call(proc, "mission_verify", {
            "objective": "delivery",
            "witness": "foothold_execution",
            "evidence": "battery: witness ledger round-trip",
        }))

    def test_gated_tools_run_once_declared(self):
        """Past the gate, each tool does its real local work and labels it."""
        proc = self.spawn_probe_contract()
        self.declare(proc, "crown_objective")

        classify = self.call(proc, "malware_classify",
                             {"host": "localhost", "scan_root": self.workdir.name, "max_files": 5})
        self.assert_ok(classify, LOCAL_ONLY, "files classified")

        remote = self.call(proc, "malware_classify", {"host": "10.99.50.41"})
        self.assert_refused(remote, "refusing to classify", "mission_verify")

        self.declare(proc, "persistence")
        persist = self.call(proc, "malware_persist", {"host": "localhost"})
        self.assert_ok(persist, "LOCAL ONLY")

        self.declare(proc, "c2_resilience")
        c2 = self.call(proc, "malware_c2", {"test_failover": False}, timeout=120.0)
        self.assert_ok(c2)

        self.declare(proc, "propagation")
        self.assert_refused(self.call(proc, "malware_worm", {}), "cidr is required")
        self.assert_refused(self.call(proc, "malware_worm", {"cidr": "127.0.0.0/30"}),
                            "scope is required")
        self.assert_refused(
            self.call(proc, "malware_worm", {"cidr": "10.99.50.0/24", "scope": "127.0.0.0/8"}),
            "refusing to propagate into")


if __name__ == "__main__":
    unittest.main()
