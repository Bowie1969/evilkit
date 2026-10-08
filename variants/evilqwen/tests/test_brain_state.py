"""Tests for evilkit.brain_state — ledger, topology, coverage and serialization."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit.brain_state import (  # noqa: E402
    AttackPath,
    Coverage,
    Credential,
    EvidenceEntry,
    Finding,
    Host,
    MissionState,
    Service,
    add_attack_path,
    add_credential,
    add_finding,
    add_host,
    add_service,
    classify_evidence,
    detect_thrashing,
    record_evidence,
    state_from_json,
    state_to_json,
    update_coverage,
)


class TestEvidenceLedger(EvilkitTestCase):
    def test_record_evidence_appends_with_unverified_classification(self):
        state = MissionState(scope=["127.0.0.1/32"])
        record_evidence(state, "host is up", "ping -c 1 127.0.0.1", "64 bytes", "tool")
        self.assertEqual(len(state.evidence), 1)
        self.assertEqual(state.evidence[0].classification, "unverified")
        self.assertEqual(state.evidence[0].turn, 0)

    def test_classify_evidence_changes_classification(self):
        state = MissionState(scope=["127.0.0.1/32"])
        record_evidence(state, "host is up", "ping", "ok", "tool")
        classify_evidence(state, 0, "confirmed")
        self.assertEqual(state.evidence[0].classification, "confirmed")

    def test_invalid_classification_is_rejected(self):
        state = MissionState(scope=["127.0.0.1/32"])
        record_evidence(state, "x", "y", "z", "tool")
        with self.assertRaises(ValueError):
            classify_evidence(state, 0, "maybe")


class TestTopology(EvilkitTestCase):
    def test_add_host_deduplicates_by_address(self):
        state = MissionState(scope=["127.0.0.1/32"])
        h1 = add_host(state, "127.0.0.1", hostname="loopback")
        h2 = add_host(state, "127.0.0.1")
        self.assertIs(h1, h2)
        self.assertEqual(h1.hostname, "loopback")
        self.assertEqual(len(state.hosts), 1)

    def test_add_service_deduplicates_by_port_and_protocol(self):
        state = MissionState(scope=["127.0.0.1/32"])
        s1 = add_service(state, "127.0.0.1", 22, name="ssh")
        s2 = add_service(state, "127.0.0.1", 22, banner="OpenSSH")
        self.assertIs(s1, s2)
        self.assertEqual(s1.name, "ssh")
        self.assertEqual(s1.banner, "OpenSSH")

    def test_add_service_creates_host_when_missing(self):
        state = MissionState(scope=["127.0.0.1/32"])
        add_service(state, "10.0.0.5", 80, name="http")
        self.assertIn("10.0.0.5", state.hosts)


class TestCredentialsAndFindings(EvilkitTestCase):
    def test_add_credential_redacts_by_default(self):
        state = MissionState(scope=["127.0.0.1/32"])
        cred = add_credential(state, "password123", "password", "enum")
        self.assertIn("***", cred.display_value())
        self.assertNotIn("password123", cred.display_value())

    def test_add_finding_requires_valid_severity(self):
        state = MissionState(scope=["127.0.0.1/32"])
        with self.assertRaises(ValueError):
            add_finding(state, "x", "urgent", "desc")
        finding = add_finding(state, "x", "high", "desc")
        self.assertEqual(finding.severity, "high")


class TestAttackPathsAndCoverage(EvilkitTestCase):
    def test_add_attack_path(self):
        state = MissionState(scope=["127.0.0.1/32"])
        path = add_attack_path(state, "foothold", "127.0.0.1", "ssh-credential-reuse")
        self.assertIn(path, state.attack_paths)

    def test_update_coverage_tracks_phases_per_service(self):
        state = MissionState(scope=["127.0.0.1/32"])
        update_coverage(state, "127.0.0.1", "22/tcp", "recon")
        update_coverage(state, "127.0.0.1", "22/tcp", "enumeration")
        self.assertEqual(
            state.coverage.by_host["127.0.0.1"]["22/tcp"],
            {"enumeration", "recon"},
        )


class TestThrashingDetection(EvilkitTestCase):
    def test_repeated_identical_command_is_flagged(self):
        state = MissionState(scope=["127.0.0.1/32"])
        for _ in range(4):
            record_evidence(state, "x", "same", "output", "tool")
        warnings = detect_thrashing(state, window=4)
        self.assertTrue(any("identical" in w for w in warnings))

    def test_high_failure_rate_is_flagged(self):
        state = MissionState(scope=["127.0.0.1/32"])
        for _ in range(4):
            record_evidence(state, "x", f"cmd", "error: failed", "tool")
        warnings = detect_thrashing(state, window=4)
        self.assertTrue(any("failure" in w for w in warnings))


class TestSerialization(EvilkitTestCase):
    def test_round_trip_preserves_state(self):
        state = MissionState(scope=["127.0.0.1/32"])
        record_evidence(state, "host up", "ping", "ok", "tool")
        classify_evidence(state, 0, "confirmed")
        add_host(state, "127.0.0.1", hostname="loopback", evidence_ref=0)
        add_service(state, "127.0.0.1", 22, name="ssh", evidence_ref=0)
        add_credential(state, "secret", "password", "loot", evidence_ref=0)
        add_finding(state, "ssh exposed", "medium", "port 22 open", evidence_ref=0)
        add_attack_path(state, "foothold", "127.0.0.1", "ssh", completed=True)
        update_coverage(state, "127.0.0.1", "22/tcp", "recon")

        text = state_to_json(state)
        restored = state_from_json(text)

        self.assertEqual(restored.scope, state.scope)
        self.assertEqual(len(restored.evidence), 1)
        self.assertEqual(restored.evidence[0].classification, "confirmed")
        self.assertEqual(restored.hosts["127.0.0.1"].hostname, "loopback")
        self.assertEqual(restored.hosts["127.0.0.1"].services[0].name, "ssh")
        self.assertEqual(restored.credentials[0].value, "secret")
        self.assertEqual(restored.findings[0].severity, "medium")
        self.assertTrue(restored.attack_paths[0].completed)
        self.assertEqual(
            restored.coverage.by_host["127.0.0.1"]["22/tcp"],
            {"recon"},
        )


if __name__ == "__main__":
    unittest.main()
