"""Tests for the mission contract, declaration gate, proof ledger and lifecycle.

Covers lib/mission_contract.py, lib/persistence_lifecycle.py and the MCP wiring
that gates sensitive tools and makes malware_persist prove its outcome.

Nothing here touches the network or the developer's machine: transport is always
injected, and the only LocalTransport assertion is a flag read.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

import lib.persistence_lifecycle as pl  # noqa: E402
from lib.mission_contract import (  # noqa: E402
    C2_WITNESSES,
    CROWN_CHAIN_WITNESSES,
    PERSISTENCE_WITNESSES,
    MissionContract,
    MissionTracker,
    ObjectiveSpec,
    ObjectiveState,
    VerificationBudget,
    load_contract,
)
from lib.persistence_lifecycle import (  # noqa: E402
    LocalTransport,
    PersistenceOutcome,
    lifecycle_for,
    transport_for,
)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = PROJECT_ROOT / "contracts" / "mission.json"
MCP_SCRIPT = PROJECT_ROOT / "mcp-malware-generator.py"


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeTransport:
    """A scriptable host. ``script`` entries match once, in order."""

    local_only = False

    def __init__(self, host: str = "10.99.50.11", script=None, reachable: bool = True) -> None:
        self.host = host
        self.script = list(script or [])
        self.reachable = reachable
        self.commands: list[str] = []
        self.closed = False

    def run(self, command: str, timeout: float = 20.0):
        self.commands.append(command)
        for index, (needle, result) in enumerate(self.script):
            if needle in command:
                self.script.pop(index)
                return result
        if not self.reachable:
            return (1, "", "unreachable")
        if command == "true":
            return (0, "", "")
        if "PRESENT" in command:
            return (0, "PRESENT", "")
        if "is-active" in command:
            return (0, "active", "")
        return (0, "", "")

    def put(self, local_path: str, remote_path: str) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FakeLocalTransport(FakeTransport):
    """Local-only variant; never runs a real command."""

    local_only = True


def _load_mcp():
    """Load the MCP server script as a module (it is not a package)."""
    spec = importlib.util.spec_from_file_location("mcp_malware_generator", MCP_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _small_contract() -> MissionContract:
    return MissionContract(
        campaign="test",
        objectives=(
            ObjectiveSpec(id="persistence", title="P", points=20, sensitive=True,
                          witnesses=PERSISTENCE_WITNESSES),
            ObjectiveSpec(id="c2_resilience", title="C", points=10, sensitive=True,
                          witnesses=C2_WITNESSES),
            ObjectiveSpec(
                id="crown_objective", title="X", points=30, sensitive=True,
                requires=("persistence",), witnesses=CROWN_CHAIN_WITNESSES,
            ),
        ),
        max_actions=20,
        verification_reserve=5,
    )


# ---------------------------------------------------------------------------
# Contract model
# ---------------------------------------------------------------------------

class TestContract(EvilkitTestCase):
    def test_shipped_contract_loads_with_expected_shape(self):
        contract = MissionContract.load(CONTRACT)
        self.assertEqual(contract.sink, "192.168.0.10:14444")
        ids = [o.id for o in contract.objectives]
        self.assertEqual(
            ids,
            ["delivery", "staged_loader", "persistence", "c2_resilience", "propagation", "crown_objective"],
        )
        self.assertEqual(contract.by_id("persistence").required_witnesses,
                         tuple(w.name for w in PERSISTENCE_WITNESSES))
        self.assertTrue(contract.by_id("crown_objective").requires_any)

    def test_contract_round_trips_through_dict(self):
        contract = _small_contract()
        again = MissionContract.from_dict(json.loads(json.dumps(contract.to_dict())))
        self.assertEqual(again.to_dict(), contract.to_dict())


# ---------------------------------------------------------------------------
# Declaration gate (rec 2)
# ---------------------------------------------------------------------------

class TestDeclarationGate(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json",
                                      now=lambda: "2026-01-01T00:00:00Z")

    def test_sensitive_objective_refused_without_declaration(self):
        message = self.tracker.check_gate("persistence")
        self.assertIn("DECLARATION REQUIRED", message)
        self.assertIn("mission_declare", message)

    def test_declaration_opens_the_gate(self):
        self.tracker.declare("persistence", "install systemd unit", "survive reboot")
        self.assertEqual(self.tracker.check_gate("persistence"), "")

    def test_declaration_is_ordered_and_durable(self):
        first = self.tracker.declare("persistence", "a", "because")
        second = self.tracker.declare("persistence", "b", "also")
        self.assertEqual(first.seq, 1)
        self.assertEqual(second.seq, 2)
        reloaded = MissionTracker.load(self.tmp / "state.json")
        self.assertEqual([d.action for d in reloaded.declarations], ["a", "b"])
        self.assertEqual(reloaded.declaration_for("persistence").action, "b")

    def test_unknown_objective_is_refused(self):
        self.assertEqual(self.tracker.check_gate("nope"), "unknown objective 'nope'")
        with self.assertRaises(KeyError):
            self.tracker.declare("nope", "a", "b")

    def test_tool_gate_maps_sensitive_tools(self):
        self.assertIn("DECLARATION REQUIRED", self.tracker.gate_tool("malware_persist"))
        self.assertIn("DECLARATION REQUIRED", self.tracker.gate_tool("malware_classify"))
        self.assertEqual(self.tracker.gate_tool("malware_deploy"), "")

    def test_dependent_objective_blocked_until_prerequisite_verified(self):
        self.tracker.declare("crown_objective", "read crown01 records", "exfil proof")
        message = self.tracker.check_gate("crown_objective")
        self.assertIn("OBJECTIVE BLOCKED", message)
        self.assertIn("persistence", message)

    def test_dependent_objective_opens_once_prerequisite_is_witnessed(self):
        self.tracker.declare("persistence", "install", "reason")
        for witness in PERSISTENCE_WITNESSES:
            self.tracker.observe("persistence", witness.name, "observed")
        self.assertEqual(self.tracker.progress("persistence").state, ObjectiveState.VERIFIED)
        self.tracker.declare("crown_objective", "read", "reason")
        self.assertEqual(self.tracker.check_gate("crown_objective"), "")


# ---------------------------------------------------------------------------
# Objective state machine and proof ledger (recs 3, 4, 8)
# ---------------------------------------------------------------------------

class TestStateMachine(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json")
        self.tracker.declare("persistence", "install", "reason")

    def test_state_progresses_ready_attempted_partial_verified(self):
        self.assertEqual(self.tracker.progress("persistence").state, ObjectiveState.READY)
        self.tracker.begin("persistence", "install systemd unit")
        self.assertEqual(self.tracker.progress("persistence").state, ObjectiveState.ATTEMPTED)
        self.tracker.observe("persistence", "persistence_installed", "unit file present")
        self.assertEqual(self.tracker.progress("persistence").state, ObjectiveState.PARTIAL)
        for name in ("persistence_activated", "persistence_callback", "persistence_survived_restart"):
            self.tracker.observe("persistence", name, "observed")
        self.assertEqual(self.tracker.progress("persistence").state, ObjectiveState.VERIFIED)

    def test_install_alone_is_partial_not_verified(self):
        self.tracker.observe("persistence", "persistence_installed", "unit file present")
        progress = self.tracker.progress("persistence")
        self.assertEqual(progress.state, ObjectiveState.PARTIAL)
        self.assertIn("persistence_callback", progress.missing)
        self.assertIn("persistence_survived_restart", progress.missing)

    def test_unknown_witness_is_rejected(self):
        with self.assertRaises(KeyError):
            self.tracker.observe("persistence", "made_up_witness", "x")

    def test_witnesses_are_not_double_counted(self):
        self.tracker.observe("persistence", "persistence_installed", "a")
        self.tracker.observe("persistence", "persistence_installed", "b")
        self.assertEqual(len(self.tracker.witnesses["persistence"]), 1)
        self.assertEqual(self.tracker.budget.verification_used, 1)

    def test_state_survives_reload(self):
        self.tracker.observe("persistence", "persistence_installed", "unit file present")
        reloaded = MissionTracker.load(self.tmp / "state.json")
        progress = reloaded.progress("persistence")
        self.assertEqual(progress.state, ObjectiveState.PARTIAL)
        self.assertIn("persistence_installed", progress.witnesses)


# ---------------------------------------------------------------------------
# Failure classification and re-planning (rec 6)
# ---------------------------------------------------------------------------

class TestFailureClassification(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json")
        self.tracker.declare("persistence", "install", "reason")

    def test_second_equivalent_failure_stops_the_branch(self):
        first = self.tracker.record_outcome("persistence", "systemd install", False,
                                            signature="systemd user unit on 10.99.50.11")
        self.assertIn("EQUIVALENT FAILURE", first)
        second = self.tracker.record_outcome("persistence", "systemd install", False,
                                             signature="systemd user unit on 10.99.50.11")
        self.assertIn("BRANCH STOPPED", second)
        self.assertEqual(self.tracker.progress("persistence").state, ObjectiveState.FAILED)
        self.assertIn("BRANCH STOPPED", self.tracker.gate_tool("malware_persist"))

    def test_distinct_failures_do_not_stop_the_branch(self):
        self.tracker.record_outcome("persistence", "a", False, signature="systemd")
        message = self.tracker.record_outcome("persistence", "b", False, signature="cron")
        self.assertNotIn("BRANCH STOPPED", message)
        self.assertFalse(self.tracker.classifier.stopped_for("persistence"))

    def test_classifier_survives_reload(self):
        self.tracker.record_outcome("persistence", "a", False, signature="s")
        self.tracker.record_outcome("persistence", "a", False, signature="s")
        reloaded = MissionTracker.load(self.tmp / "state.json")
        self.assertTrue(reloaded.classifier.stopped_for("persistence"))
        self.assertIn("BRANCH STOPPED", reloaded.gate_tool("malware_persist"))


# ---------------------------------------------------------------------------
# Verification budget (rec 12)
# ---------------------------------------------------------------------------

class TestVerificationBudget(EvilkitTestCase):
    def test_reserve_is_held_back_from_exploitation(self):
        budget = VerificationBudget(max_actions=20, reserve=5)
        self.assertEqual(budget.exploitation_ceiling, 15)
        self.assertEqual(budget.remaining("exploitation"), 15)
        self.assertEqual(budget.remaining("verification"), 5)

    def test_warning_fires_when_access_spends_the_ceiling(self):
        budget = VerificationBudget(max_actions=20, reserve=5)
        budget.consume("exploitation", 15)
        self.assertIn("VERIFICATION RESERVE REACHED", budget.warning())
        self.assertEqual(budget.remaining("exploitation"), 0)
        self.assertEqual(budget.remaining("verification"), 5)

    def test_verify_work_consumes_the_reserve_not_the_ceiling(self):
        tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json")
        tracker.declare("persistence", "install", "reason")
        tracker.begin("persistence", "install")
        tracker.observe("persistence", "persistence_installed", "e")
        self.assertEqual(tracker.budget.exploitation_used, 1)
        self.assertEqual(tracker.budget.verification_used, 1)


# ---------------------------------------------------------------------------
# Reconciliation (rec 11)
# ---------------------------------------------------------------------------

class TestReconciliation(EvilkitTestCase):
    def test_gaps_name_the_missing_witnesses(self):
        tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json")
        tracker.declare("persistence", "install", "reason")
        tracker.observe("persistence", "persistence_installed", "e")
        gaps = tracker.gaps()
        self.assertTrue(any("persistence_activated" in gap for gap in gaps))
        self.assertTrue(any("c2_resilience" in gap and "not started" in gap for gap in gaps))

    def test_reconcile_reports_proven_and_unproven(self):
        tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json")
        tracker.declare("persistence", "install", "reason")
        for witness in PERSISTENCE_WITNESSES:
            tracker.observe("persistence", witness.name, "observed")
        text = tracker.reconcile()
        self.assertIn("Verified: 1/3 objectives", text)
        self.assertIn("Unproven:", text)

    def test_status_counts_points_only_for_verified(self):
        tracker = MissionTracker(_small_contract(), path=self.tmp / "state.json")
        tracker.declare("persistence", "install", "reason")
        tracker.observe("persistence", "persistence_installed", "e")
        status = tracker.status()
        self.assertEqual(status["points_verified"], 0)
        self.assertEqual(status["points_available"], 60)


# ---------------------------------------------------------------------------
# Persistence lifecycle (rec 8)
# ---------------------------------------------------------------------------

class TestPersistenceLifecycle(EvilkitTestCase):
    def test_systemd_lifecycle_proves_three_facts_but_not_the_callback(self):
        outcome = lifecycle_for("10.99.50.11", "/tmp/.cache", "systemd", FakeTransport())
        self.assertIsInstance(outcome, PersistenceOutcome)
        self.assertTrue(outcome.deployed)
        self.assertIn("persistence_installed", outcome.witnesses)
        self.assertIn("persistence_activated", outcome.witnesses)
        self.assertIn("persistence_survived_restart", outcome.witnesses)
        self.assertIn("persistence_callback", outcome.missing)
        self.assertTrue(outcome.partial)
        self.assertIn("PARTIAL", outcome.summary())

    def test_service_that_does_not_return_after_restart_is_not_survival(self):
        script = [("systemctl --user restart", (1, "", "failed"))]
        outcome = lifecycle_for("10.99.50.11", "/tmp/.cache", "systemd", FakeTransport(script=script))
        self.assertIn("persistence_activated", outcome.witnesses)
        self.assertIn("persistence_survived_restart", outcome.missing)

    def test_cron_installs_but_defers_activation_to_the_clock(self):
        outcome = lifecycle_for("10.99.50.11", "/tmp/.cache", "cron", FakeTransport())
        self.assertIn("persistence_installed", outcome.witnesses)
        self.assertIn("persistence_activated", outcome.missing)
        self.assertTrue(any("clock is the witness" in line for line in outcome.detail))

    def test_unknown_mechanism_is_reported_not_silently_skipped(self):
        outcome = lifecycle_for("10.99.50.11", "/tmp/.cache", "ld_preload", FakeTransport())
        self.assertFalse(outcome.deployed)
        self.assertIn("unknown mechanism", outcome.error)
        self.assertEqual(
            sorted(outcome.missing),
            ["persistence_activated", "persistence_callback",
             "persistence_installed", "persistence_survived_restart"],
        )

    def test_unreachable_host_fails_loudly(self):
        outcome = lifecycle_for("10.99.50.11", "/tmp/.cache", "systemd",
                                FakeTransport(reachable=False))
        self.assertFalse(outcome.deployed)
        self.assertIn("did not answer", outcome.error)

    def test_local_only_outcome_is_flagged_and_never_evidence(self):
        outcome = lifecycle_for("localhost", "/tmp/.cache", "cron", FakeLocalTransport())
        self.assertTrue(outcome.local_only)
        self.assertIn("LOCAL ONLY", outcome.summary())
        self.assertIn("proves nothing about the estate", outcome.summary())

    def test_local_transport_class_declares_itself_local(self):
        self.assertTrue(LocalTransport("localhost").local_only)

    def test_transport_selection_requires_credentials_for_ssh(self):
        self.assertTrue(transport_for("10.99.50.11").local_only)
        with mock.patch.object(pl, "ParamikoTransport") as fake_cls:
            fake_cls.return_value.local_only = False
            chosen = transport_for("10.99.50.11", user="svc", password="x")
        fake_cls.assert_called_once()
        self.assertIs(chosen, fake_cls.return_value)


# ---------------------------------------------------------------------------
# MCP wiring
# ---------------------------------------------------------------------------

class TestMcpWiring(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.state = self.tmp / "mission-state.json"
        env = {
            "EVILKIT_MISSION_CONTRACT": str(CONTRACT),
            "EVILKIT_MISSION_STATE": str(self.state),
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("LAB_SSH_USER", "LAB_SSH_PASS", "LAB_SSH_KEY"):
            os.environ.pop(name, None)
        self.mcp = _load_mcp()

    def call(self, name, arguments=None):
        return self.mcp.handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        })

    def text(self, response):
        return response["result"]["content"][0]["text"]

    def declare_persistence(self):
        """Clear delivery, then declare persistence.

        The shipped contract makes persistence depend on delivery, so the
        delivery witnesses are recorded first -- the same order the state
        machine enforces on the agent.
        """
        for witness in ("foothold_execution", "delivery_route_evidenced"):
            self.call("mission_verify", {
                "objective": "delivery", "witness": witness, "evidence": "observed",
            })
        return self.call("mission_declare", {
            "objective": "persistence", "action": "install systemd unit", "rationale": "survive reboot",
        })

    def test_new_tools_are_advertised(self):
        listed = self.mcp.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = [t["name"] for t in listed["result"]["tools"]]
        for tool in ("mission_contract", "mission_declare", "mission_status", "mission_verify"):
            self.assertIn(tool, names)

    def test_sensitive_tool_refused_before_declaration(self):
        response = self.call("malware_worm", {"cidr": "10.99.50.0/24"})
        self.assertIn("error", response)
        self.assertIn("DECLARATION REQUIRED", response["error"]["message"])

    def test_declare_then_sensitive_tool_passes_the_gate(self):
        self.assertIn("DECLARED #1", self.text(self.declare_persistence()))
        response = self.call("malware_persist", {"host": "10.99.50.11"})
        message = response.get("error", {}).get("message", "")
        # The gate is passed; the tool then refuses for its own reason.
        self.assertNotIn("DECLARATION REQUIRED", message)
        self.assertIn("refusing to persist", message)

    def test_persist_refuses_to_install_on_the_mcp_host_without_credentials(self):
        self.declare_persistence()
        response = self.call("malware_persist", {"host": "10.99.50.11"})
        self.assertIn("refusing to persist", response["error"]["message"])

    def test_persist_records_only_proven_witnesses(self):
        self.declare_persistence()
        with mock.patch.dict(os.environ, {"LAB_SSH_USER": "svc", "LAB_SSH_PASS": "x"}), \
                mock.patch.object(self.mcp, "transport_for", return_value=FakeTransport()):
            response = self.call("malware_persist", {"host": "10.99.50.11", "mechanisms": "systemd"})
        body = self.text(response)
        self.assertIn("persistence_installed", body)
        self.assertIn("Still unproven", body)
        self.assertIn("persistence_callback", body)
        status = json.loads(self.text(self.call("mission_status")))
        row = next(r for r in status["objectives"] if r["id"] == "persistence")
        self.assertEqual(row["state"], "partial")
        self.assertIn("persistence_activated", row["witnesses"])

    def test_persist_local_only_records_no_witness(self):
        self.declare_persistence()
        with mock.patch.dict(os.environ, {"LAB_SSH_USER": "svc", "LAB_SSH_PASS": "x"}), \
                mock.patch.object(self.mcp, "transport_for", return_value=FakeLocalTransport()):
            self.call("malware_persist", {"host": "10.99.50.11", "mechanisms": "cron"})
        status = json.loads(self.text(self.call("mission_status")))
        row = next(r for r in status["objectives"] if r["id"] == "persistence")
        self.assertEqual(row["witnesses"], [])

    def test_verify_then_status_reaches_verified(self):
        self.declare_persistence()
        for witness in ("persistence_installed", "persistence_activated",
                        "persistence_callback", "persistence_survived_restart"):
            self.call("mission_verify", {
                "objective": "persistence", "witness": witness, "evidence": "observed",
            })
        status = json.loads(self.text(self.call("mission_status")))
        row = next(r for r in status["objectives"] if r["id"] == "persistence")
        self.assertEqual(row["state"], "verified")

    def test_declare_requires_action_and_rationale(self):
        response = self.call("mission_declare", {"objective": "persistence", "action": "install"})
        self.assertIn("error", response)
        self.assertIn("rationale", response["error"]["message"])

    def test_classify_refuses_to_scan_the_mcp_host_as_the_target(self):
        # Declare the prerequisite chain so the refusal comes from the tool, not
        # from the declaration gate.
        self.declare_persistence()
        for witness in ("persistence_installed", "persistence_activated",
                        "persistence_callback", "persistence_survived_restart"):
            self.call("mission_verify", {"objective": "persistence", "witness": witness,
                                         "evidence": "observed"})
        self.call("mission_declare", {"objective": "crown_objective", "action": "read /clients.csv",
                                      "rationale": "scored asset"})
        response = self.call("malware_classify", {"host": "crown01", "exfil": True})
        self.assertIn("refusing to classify", response["error"]["message"])

    def test_contract_tool_reports_prerequisites_and_sink(self):
        body = self.text(self.call("mission_contract"))
        self.assertIn("192.168.0.10:14444", body)
        self.assertIn("requires: delivery", body)


# ---------------------------------------------------------------------------
# Loader behaviour
# ---------------------------------------------------------------------------

class TestLoader(EvilkitTestCase):
    def test_contract_path_honours_env(self):
        with mock.patch.dict(os.environ, {"EVILKIT_MISSION_CONTRACT": str(CONTRACT)}):
            self.assertEqual(load_contract().campaign, MissionContract.load(CONTRACT).campaign)

    def test_missing_contract_returns_none(self):
        with mock.patch.dict(os.environ, {"EVILKIT_MISSION_CONTRACT": str(self.tmp / "nope.json")}):
            self.assertIsNone(load_contract())


if __name__ == "__main__":
    unittest.main()
