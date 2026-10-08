"""L3 graduation: per-(host, credential) circuit breaker.

Prevents the 227× svc/svc123 brute-force seen in run evilkit-20261004-1511.
"""

from __future__ import annotations

import unittest

from evilkit.harness import (
    AttemptBudget,
    HarnessState,
    _extract_credential,
)


class TestCredentialExtraction(unittest.TestCase):

    def test_sshpass(self) -> None:
        self.assertEqual(
            _extract_credential("sshpass -p 'svc123' ssh svc@10.99.50.21"),
            "svc:svc123",
        )

    def test_ssh_user_only(self) -> None:
        self.assertEqual(_extract_credential("ssh svc@10.99.50.21"), "svc")

    def test_netexec(self) -> None:
        self.assertEqual(
            _extract_credential("nxc smb 10.0.0.5 -u admin -p Pass1!"),
            "admin:Pass1!",
        )

    def test_curl_basic_auth(self) -> None:
        self.assertEqual(
            _extract_credential("curl -u admin:hunter2 http://x/"),
            "admin:hunter2",
        )

    def test_hydra(self) -> None:
        self.assertEqual(
            _extract_credential("hydra -l root -p toor ssh://10.0.0.5"),
            "root:toor",
        )

    def test_smbclient(self) -> None:
        self.assertEqual(
            _extract_credential("smbclient //10.0.0.5/share -U admin%hunter2"),
            "admin:hunter2",
        )

    def test_no_cred_in_scan(self) -> None:
        self.assertEqual(_extract_credential("nmap -sV 10.0.0.5"), "")


class TestCredLock(unittest.TestCase):

    def test_cred_lock_after_cap(self) -> None:
        b = AttemptBudget(max_per_cred_per_host=3)
        self.assertIsNone(b.record_auth_attempt("10.0.0.5", credential="u:p"))
        self.assertIsNone(b.record_auth_attempt("10.0.0.5", credential="u:p"))
        msg = b.record_auth_attempt("10.0.0.5", credential="u:p")
        self.assertIsNotNone(msg)
        self.assertIn("CRED LOCK", msg)
        self.assertTrue(b.is_cred_locked("10.0.0.5", "u:p"))

    def test_other_cred_on_same_host_still_open(self) -> None:
        b = AttemptBudget(max_per_cred_per_host=2)
        b.record_auth_attempt("10.0.0.5", credential="u:p")
        b.record_auth_attempt("10.0.0.5", credential="u:p")
        self.assertTrue(b.is_cred_locked("10.0.0.5", "u:p"))
        self.assertFalse(b.is_cred_locked("10.0.0.5", "root:toor"))
        self.assertIsNone(b.record_auth_attempt("10.0.0.5", credential="root:toor"))

    def test_227_attempts_capped(self) -> None:
        """The run-20261004 regression: same cred, same host, 227 attempts."""
        b = AttemptBudget(max_per_cred_per_host=3)
        locks = 0
        for _ in range(227):
            if b.record_auth_attempt("10.99.50.21", credential="svc:svc123") is not None:
                locks += 1
                break  # a disciplined operator stops here
        self.assertEqual(locks, 1)
        self.assertLess(b.cred_attempts["10.99.50.21|svc:svc123"], 227)


class TestHarnessL3EndToEnd(unittest.TestCase):

    def test_failed_auth_locks_cred(self) -> None:
        h = HarnessState()
        h.budget.max_per_cred_per_host = 3
        cmd = "sshpass -p 'svc123' ssh svc@10.99.50.21"
        warnings: list[str] = []
        for _ in range(3):
            warnings = h.record_action(1, cmd, "", "Permission denied", 255)
        self.assertTrue(any("CRED LOCK" in w for w in warnings), warnings)

    def test_successful_auth_does_not_lock(self) -> None:
        h = HarnessState()
        h.budget.max_per_cred_per_host = 2
        cmd = "sshpass -p 'root' ssh root@10.0.0.9"
        warnings: list[str] = []
        for _ in range(5):
            warnings = h.record_action(1, cmd, "Last login: Mon", "", 0)
        self.assertFalse(any("CRED LOCK" in w for w in warnings), warnings)

    def test_pre_action_check_blocks_locked_cred(self) -> None:
        h = HarnessState()
        h.budget.max_per_cred_per_host = 2
        cmd = "sshpass -p 'svc123' ssh svc@10.99.50.21"
        for _ in range(2):
            h.record_action(1, cmd, "", "Permission denied", 255)
        blocked = h.pre_action_check(host="10.99.50.21", credential="svc:svc123")
        self.assertIsNotNone(blocked)
        self.assertIn("cred-locked", blocked)
        # Different credential against the same host is still allowed.
        self.assertIsNone(h.pre_action_check(host="10.99.50.21", credential="root:toor"))


if __name__ == "__main__":
    unittest.main()
