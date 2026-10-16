"""Tests for evilkit.brain — the operator-auditor controller loop."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit.brain import Controller, RunOptions  # noqa: E402
from evilkit.models import ChatCompletionClient  # noqa: E402
from evilkit.tools import SimulationExecutor  # noqa: E402


class TestControllerWithDryRunModels(EvilkitTestCase):
    def test_simulation_loop_runs_without_api_keys(self):
        operator = ChatCompletionClient("", "op", dry_run=True)
        auditor = ChatCompletionClient("", "audit", dry_run=True)
        executor = SimulationExecutor(["127.0.0.1/32"])
        controller = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=2),
        )
        result = controller.run()
        self.assertEqual(len(result.state.evidence), 2)
        self.assertIn("127.0.0.1", result.state.hosts)

    def test_loop_stops_at_max_turns(self):
        operator = ChatCompletionClient("", "op", dry_run=True)
        auditor = ChatCompletionClient("", "audit", dry_run=True)
        executor = SimulationExecutor(["127.0.0.1/32"])
        controller = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=3),
        )
        result = controller.run()
        self.assertIn("max_turns", result.state.completion_reason)

    def test_state_is_saved_to_disk(self):
        state_path = self.tmp / "state.json"
        operator = ChatCompletionClient("", "op", dry_run=True)
        auditor = ChatCompletionClient("", "audit", dry_run=True)
        executor = SimulationExecutor(["127.0.0.1/32"])
        controller = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=1, state_path=str(state_path)),
        )
        controller.run()
        self.assertTrue(state_path.is_file())

    def test_state_is_loaded_from_disk(self):
        state_path = self.tmp / "state.json"
        operator = ChatCompletionClient("", "op", dry_run=True)
        auditor = ChatCompletionClient("", "audit", dry_run=True)
        executor = SimulationExecutor(["127.0.0.1/32"])

        first = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=1, state_path=str(state_path)),
        )
        first.run()

        second = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=2, state_path=str(state_path)),
        )
        result = second.run()
        self.assertEqual(result.state.turns, 1)


class TestControllerWithMockedModels(EvilkitTestCase):
    def _fixed_operator(self, responses: list[dict]):
        class FakeClient:
            def __init__(self):
                self._responses = iter(responses)

            def complete(self, request):
                return json.dumps(next(self._responses, {"command": ""}))

        return FakeClient()

    def _fixed_auditor(self, responses: list[dict]):
        class FakeClient:
            def __init__(self):
                self._responses = iter(responses)

            def complete(self, request):
                return json.dumps(next(self._responses, {"verdict": "CONTINUE"}))

        return FakeClient()

    def test_challenge_verdict_prevents_completion(self):
        operator = self._fixed_operator([
            {"goal": "ping host", "command": "ping -c 1 127.0.0.1", "expected_result": "ok"},
        ])
        auditor = self._fixed_auditor([
            {"verdict": "CHALLENGE", "reason": "no proof host is in scope", "required_test": "traceroute 127.0.0.1"},
        ])
        executor = SimulationExecutor(["127.0.0.1/32"])
        controller = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=1),
        )
        result = controller.run()
        self.assertFalse(result.state.completed)
        self.assertEqual(len(result.state.evidence), 1)

    def test_pause_verdict_stops_the_loop(self):
        operator = self._fixed_operator([
            {"goal": "ping host", "command": "ping -c 1 127.0.0.1", "expected_result": "ok"},
        ])
        auditor = self._fixed_auditor([
            {"verdict": "PAUSE", "reason": "possible scope issue"},
        ])
        executor = SimulationExecutor(["127.0.0.1/32"])
        controller = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=3),
        )
        result = controller.run()
        self.assertTrue(result.state.paused)
        self.assertIn("scope issue", result.state.completion_reason)

    def test_advise_verdict_is_non_blocking(self):
        operator = self._fixed_operator([
            {"goal": "ping host", "command": "ping -c 1 127.0.0.1", "expected_result": "ok"},
        ])
        auditor = self._fixed_auditor([
            {"verdict": "ADVISE", "reason": "try rustscan instead"},
        ])
        executor = SimulationExecutor(["127.0.0.1/32"])
        controller = Controller(
            operator,
            auditor,
            executor,
            ["127.0.0.1/32"],
            RunOptions(max_turns=1),
        )
        result = controller.run()
        self.assertFalse(result.state.paused)
        self.assertFalse(result.state.completed)


if __name__ == "__main__":
    unittest.main()
