"""Hermetic tests for lib/rea_range.py — the synthetic REA teaching range.

Everything runs against a tempfile estate over real loopback sockets with
ephemeral ports (the module supports port 0 and reports the bound ports).
No sleeps beyond the module's join timeouts; nothing touches the network
or the developer's machine.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

import lib.rea_range as rea  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REA_CONTRACT_PATH = os.path.join(PROJECT_ROOT, "contracts", "rea-mission.json")
REA_CVE_CONTRACT_PATH = os.path.join(PROJECT_ROOT, "contracts", "rea-cve-mission.json")

FLAG_RE = re.compile(r"REA\{[0-9a-f]{16}\}")

EPHEMERAL_PORTS = {"dns": 0, "idp": 0, "kms": 0, "shush": 0, "credulous": 0, "objects": 0}

SHELLSHOCK_ENV = {"SHELLSHOCK_TEST": "() { :; }; echo CVE-2014-6271-injected"}
SHELLSHOCK_MARKER = "[emulated CVE-2014-6271 env-function injection"


def dns_query(name: str, qtype: int = 16) -> bytes:
    """A minimal single-question DNS query packet."""
    packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        packet += bytes([len(label)]) + label.encode("ascii")
    packet += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    return packet


def http_request(port: int, method: str, path: str, payload=None, headers=None):
    """One loopback HTTP round-trip; returns (status, raw body bytes)."""
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10.0)
    try:
        request_headers = {"Content-Type": "application/json"} if body else {}
        request_headers.update(headers or {})
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def openssl_decrypt(ciphertext: str, password: str, salt_hex: str) -> str:
    """Decrypt a base64 AES-256-CBC/PBKDF2 blob the same way the module wraps it."""
    completed = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000",
            "-S", salt_hex, "-pass", f"pass:{password}", "-a", "-A",
        ],
        input=ciphertext.encode("ascii"),
        capture_output=True,
        timeout=15,
        check=True,
    )
    return completed.stdout.decode("utf-8").strip()


class ReaRangeTestCase(EvilkitTestCase):
    """Prepare an estate under the hermetic tmp dir; stop it on the way out."""

    def prepare_estate(self):
        result = rea.prepare(self.estate_root)
        self.assertTrue(result.ok, f"prepare failed: {result.error}")
        return result

    def start_estate(self, ports=None):
        result = rea.start(self.estate_root, ports)
        self.assertTrue(result.ok, f"start failed: {result.error}")
        return result

    def setUp(self):
        super().setUp()
        self.estate_root = self.tmp / "estate"
        self._started = False

    def tearDown(self):
        if self._started:
            stopped = rea.stop(self.estate_root)
            if not stopped.ok:
                raise AssertionError(f"cleanup stop failed: {stopped.error}")
        super().tearDown()


class ReaRangeLayoutTests(ReaRangeTestCase):
    def test_prepare_creates_the_estate_layout(self):
        self.prepare_estate()
        root = self.estate_root
        for relative in (
            "ca/ca_key", "ca/ca_key.pub",
            "kms/master.key",
            "apps/billing/app.json",
            "apps/prod-api/app.json", "apps/prod-api/flag.txt",
            "objects/idp_credentials.json", "objects/ca_key",
            "stacks/billing.json", "stacks/prod-api.json",
            "workstation/id_ed25519", "workstation/id_ed25519.pub",
            "workstation/iam_keys.enc",
            "dns/zone.txt", "prepared.json", "evidence.jsonl",
        ):
            self.assertTrue((root / relative).is_file(), f"missing {relative}")

        self.assertEqual((root / "kms" / "master.key").stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            (root / "objects" / "ca_key").read_bytes(),
            (root / "ca" / "ca_key").read_bytes(),
            "the object-store ca_key must be a copy of the parked CA key",
        )
        self.assertEqual((root / "objects" / "ca_key").stat().st_mode & 0o777, 0o644)
        self.assertRegex(
            (root / "apps" / "prod-api" / "flag.txt").read_text(encoding="utf-8").strip(),
            FLAG_RE,
        )
        zone = (root / "dns" / "zone.txt").read_text(encoding="utf-8")
        self.assertIn("_ssh-ca.evilkit.rea.", zone)
        self.assertIn("IN TXT", zone)
        self.assertIn("SHA256:", zone)

        billing = json.loads((root / "apps" / "billing" / "app.json").read_text(encoding="utf-8"))
        envelope = billing["env"]["BILLING_DB_PASSWORD_ENCRYPTED"]
        for key in ("key_id", "context", "nonce", "ct", "wrapped_key"):
            self.assertIn(key, envelope, f"envelope missing {key}")
        self.assertEqual(envelope["context"], {"app": "billing", "var": "BILLING_DB_PASSWORD"})
        self.assertEqual(len(bytes.fromhex(envelope["nonce"])), 8)
        for key in ("nonce", "ct"):
            self.assertIn(key, envelope["wrapped_key"])

        # The plaintext must appear nowhere on disk — the only route is unwrap+decrypt.
        master = (root / "kms" / "master.key").read_text(encoding="utf-8").strip()
        data_key = openssl_decrypt(
            envelope["wrapped_key"]["ct"], master, envelope["wrapped_key"]["nonce"]
        )
        plaintext = openssl_decrypt(envelope["ct"], data_key, envelope["nonce"])
        self.assertTrue(plaintext.startswith("billing-"))
        for path in root.rglob("*"):
            if not path.is_file() or path.name == "evidence.jsonl":
                continue
            self.assertNotIn(
                plaintext.encode("utf-8"), path.read_bytes(), f"plaintext planted at {path}"
            )

    def test_prepare_refuses_to_rebuild_an_existing_estate(self):
        self.prepare_estate()
        again = rea.prepare(self.estate_root)
        self.assertFalse(again.ok)
        self.assertIn("already prepared", again.error)

    def test_status_and_stop_refuse_before_prepare(self):
        status = rea.status(self.estate_root)
        self.assertFalse(status.ok)
        self.assertIn("not prepared", status.error)
        stopped = rea.stop(self.estate_root)
        self.assertFalse(stopped.ok)
        self.assertIn("not running", stopped.error)
        started = rea.start(self.estate_root)
        self.assertFalse(started.ok)
        self.assertIn("not prepared", started.error)


class ReaRangeTeachingPathTests(ReaRangeTestCase):
    """The full teaching path over real loopback sockets, then a journal-only score."""

    def setUp(self):
        super().setUp()
        self.prepare_estate()
        start = self.start_estate(ports={
            "dns": 0, "idp": 0, "kms": 0, "shush": 0, "credulous": 0, "objects": 0,
        })
        self._started = True
        self.ports = start.data["ports"]
        for name in ("dns", "idp", "kms", "shush", "credulous", "objects"):
            self.assertGreater(self.ports[name], 0, f"{name} did not bind an ephemeral port")
        self.root = self.estate_root
        self.flag_token = (self.root / "apps" / "prod-api" / "flag.txt").read_text(
            encoding="utf-8"
        ).strip()

    def run_teaching_path(self):
        root = self.root
        # 1. DNS TXT query.
        zone = (root / "dns" / "zone.txt").read_text(encoding="utf-8").strip()
        fingerprint = zone.split('"', 2)[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10.0)
        try:
            sock.sendto(dns_query("_ssh-ca.evilkit.rea"), ("127.0.0.1", self.ports["dns"]))
            response, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        self.assertIn(fingerprint.encode("ascii"), response)

        # 2. /sso with the wrong credential, then the planted one.
        creds = json.loads((root / "objects" / "idp_credentials.json").read_text(encoding="utf-8"))
        status, _ = http_request(self.ports["idp"], "POST", "/sso",
                                 {"user": creds["user"], "password": "wrong-password"})
        self.assertEqual(status, 403)
        status, body = http_request(self.ports["idp"], "POST", "/sso", creds)
        self.assertEqual(status, 200)
        assertion = json.loads(body)["assertion"]
        self.assertEqual(len(assertion), 32)

        # 3. /cert: exchange the assertion for a CA-signed cert.
        pubkey = (root / "workstation" / "id_ed25519.pub").read_text(encoding="utf-8").strip()
        status, body = http_request(self.ports["idp"], "POST", "/cert",
                                    {"assertion": assertion, "pubkey": pubkey})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["principal"], "root")
        self.assertIn("ssh-ed25519-cert-v01@openssh.com", payload["cert"])

        # 4. Object store: read the CA key; refuse traversal.
        status, body = http_request(self.ports["objects"], "GET", "/objects/ca_key")
        self.assertEqual(status, 200)
        self.assertEqual(body, (root / "ca" / "ca_key").read_bytes())
        status, _ = http_request(self.ports["objects"], "GET", "/objects/../ca/ca_key")
        self.assertEqual(status, 400)

        # 5. KMS unwrap: anonymous caller gets the billing data key.
        billing = json.loads((root / "apps" / "billing" / "app.json").read_text(encoding="utf-8"))
        envelope = billing["env"]["BILLING_DB_PASSWORD_ENCRYPTED"]
        status, body = http_request(
            self.ports["kms"], "POST", "/unwrap", {"wrapped_key": envelope["wrapped_key"]}
        )
        self.assertEqual(status, 200)
        data_key = json.loads(body)["data_key"]
        self.assertRegex(data_key, r"^[0-9a-f]{64}$")

        # 6. Decrypt the billing secret with the data key, independently of the module.
        plaintext = openssl_decrypt(envelope["ct"], data_key, envelope["nonce"])
        self.assertTrue(plaintext.startswith("billing-"))

        # 7. shush: app list, then exec on billing proves the same secret decrypts.
        status, body = http_request(self.ports["shush"], "GET", "/apps")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["apps"], ["billing", "prod-api"])
        status, body = http_request(self.ports["shush"], "POST", "/exec",
                                    {"app": "billing", "command": "echo $BILLING_DB_PASSWORD"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["stdout"].strip(), plaintext)

        # 8. credulous: the SSH-key-wrapped IAM keys unlock.
        status, body = http_request(self.ports["credulous"], "POST", "/exec",
                                    {"command": "echo $AWS_ACCESS_KEY_ID"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["stdout"].strip().startswith("AKIA"))

        # 9. Crown: shush exec on prod-api reads the flag.
        status, body = http_request(self.ports["shush"], "POST", "/exec",
                                    {"app": "prod-api", "command": "cat flag.txt"})
        self.assertEqual(status, 200)
        self.assertIn(self.flag_token, json.loads(body)["stdout"])

    def test_full_teaching_path_then_score(self):
        self.run_teaching_path()

        with open(REA_CONTRACT_PATH, encoding="utf-8") as handle:
            contract = json.load(handle)
        result = rea.score(self.estate_root, contract)
        self.assertTrue(result.ok, f"score failed: {result.error}")

        proven = {frozenset(entry[:2]): entry[2] for entry in result.data["proven"]}
        expected = {
            ("recon_trust_root", "dns_txt_requested"),
            ("recon_trust_root", "object_store_listed"),
            ("saml_assertion", "assertion_issued"),
            ("saml_assertion", "signed_cert_issued"),
            ("ca_compromise", "ca_key_read"),
            ("envelope_bypass", "unwrap_without_context"),
            ("envelope_bypass", "secret_decrypted"),
            ("iam_unlock", "iam_exec_called"),
            ("crown_objective", "crown_exec"),
        }
        for objective, witness in expected:
            key = frozenset((objective, witness))
            self.assertIn(key, proven, f"missing witness {objective}/{witness}")
            evidence = proven[key]
            self.assertIn('"event"', evidence, "evidence must be the literal journal line")
        self.assertEqual(result.data["unproven"], [])
        self.assertEqual(result.data["crown_flag"], self.flag_token)
        self.assertIn("dns_query", result.data["estate_events"])
        self.assertIn("object_read", result.data["estate_events"])
        self.assertIn("unwrap_called", result.data["estate_events"])
        self.assertIn("exec_called", result.data["estate_events"])
        self.assertIn("iam_exec_called", result.data["estate_events"])

        # Every evidence line really came from the journal.
        journal_text = (self.estate_root / "evidence.jsonl").read_text(encoding="utf-8")
        for _, _, evidence in result.data["proven"]:
            self.assertIn(evidence.strip(), journal_text)

    def test_score_refuses_a_non_rea_contract(self):
        result = rea.score(self.estate_root, {"campaign": "chainbreaker", "objectives": []})
        self.assertFalse(result.ok)
        self.assertIn("rea-control-plane", result.error)

    def test_stop_shuts_the_services(self):
        status, _ = http_request(self.ports["idp"], "POST", "/sso", {})
        self.assertEqual(status, 400)
        stopped = rea.stop(self.estate_root)
        self.assertTrue(stopped.ok, f"stop failed: {stopped.error}")
        self._started = False
        self.assertFalse((self.estate_root / "running.json").exists())
        with self.assertRaises(ConnectionRefusedError):
            http_request(self.ports["idp"], "POST", "/sso", {})
        # A second stop is an honest refusal, not a lie.
        again = rea.stop(self.estate_root)
        self.assertFalse(again.ok)
        self.assertIn("not running", again.error)

    def test_journal_never_records_a_fabricated_witness(self):
        """A fresh estate's score proves nothing except what really happened."""
        with open(REA_CONTRACT_PATH, encoding="utf-8") as handle:
            contract = json.load(handle)
        result = rea.score(self.estate_root, contract)
        self.assertTrue(result.ok)
        self.assertEqual(result.data["proven"], [])
        self.assertEqual(result.data["crown_flag"], None)
        self.assertEqual(
            [entry["witness"] for entry in result.data["unproven"]],
            [
                "dns_txt_requested", "object_store_listed", "assertion_issued",
                "signed_cert_issued", "ca_key_read", "unwrap_without_context",
                "secret_decrypted", "iam_exec_called", "crown_exec",
            ],
        )


class ReaRangeCveTests(ReaRangeTestCase):
    """The CVE variant: fixed confused deputy, Shellshock-shaped /exec, padding oracle crown."""

    def setUp(self):
        super().setUp()
        result = rea.prepare(self.estate_root, variant="cve")
        self.assertTrue(result.ok, f"prepare failed: {result.error}")
        start = self.start_estate(ports=EPHEMERAL_PORTS)
        self._started = True
        self.ports = start.data["ports"]
        self.root = self.estate_root
        self.envelope = json.loads(
            (self.root / "crown_envelope.json").read_text(encoding="utf-8")
        )

    def journal_entries(self):
        entries = []
        for line in (self.root / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(json.loads(line))
        return entries

    def crown_decrypt_block(self, ciphertext):
        """Decrypt one block with the estate's master key and crown IV (test-side)."""
        master = (self.root / "kms" / "master.key").read_text(encoding="utf-8").strip()
        completed = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-K", master,
             "-iv", self.envelope["iv"], "-nopad"],
            input=ciphertext, capture_output=True, timeout=15, check=True,
        )
        return completed.stdout

    def oracle_valid(self, ct_hex):
        status, _ = http_request(self.ports["kms"], "POST", "/oracle", {"ct_hex": ct_hex})
        return status == 200

    def test_cve_layout(self):
        root = self.root
        self.assertEqual((root / "variant.txt").read_text(encoding="utf-8").strip(), "cve")
        self.assertTrue((root / "crown_envelope.json").is_file())
        self.assertFalse((root / "apps" / "prod-api" / "flag.txt").exists(),
                         "the CVE crown must not exist in plaintext")
        self.assertEqual(len(bytes.fromhex(self.envelope["iv"])), 16)
        self.assertEqual(len(bytes.fromhex(self.envelope["ct"])), 16)
        readme = (root / "README.txt").read_text(encoding="utf-8")
        self.assertIn("CVE-2014-6271", readme)
        self.assertIn("CVE-2016-2107", readme)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2014-6271", readme)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2016-2107", readme)
        self.assertIn("behavioral stand-ins, not the real vulnerable software", readme)
        self.assertIn("exists only as ciphertext", readme)
        billing = json.loads((root / "apps" / "billing" / "app.json").read_text(encoding="utf-8"))
        self.assertRegex(billing["token"], r"^[0-9a-f]{32}$")

        # The crown block really is 4 printable hex bytes + 0x0b PKCS#7 padding,
        # and the token plaintext appears nowhere on disk.
        block = self.crown_decrypt_block(bytes.fromhex(self.envelope["ct"]))
        self.assertEqual(len(block), 16)
        self.assertRegex(block[:4].decode("ascii"), r"^[0-9a-f]{4}$")
        self.assertEqual(block[4:], b"\x0b" * 12)
        for path in root.rglob("*"):
            if not path.is_file() or path.name == "evidence.jsonl":
                continue
            self.assertNotIn(
                block[:4], path.read_bytes(), f"crown token planted at {path}"
            )

        # GET /crown_envelope serves the envelope and journals the read.
        status, body = http_request(self.ports["kms"], "GET", "/crown_envelope")
        self.assertEqual(status, 200)
        served = json.loads(body)
        self.assertEqual(served["ct"], self.envelope["ct"])
        self.assertEqual(served["iv"], self.envelope["iv"])
        self.assertIn("crown_envelope_read",
                      [e.get("event") for e in self.journal_entries()])

    def test_exec_env_function_injection(self):
        status, body = http_request(self.ports["shush"], "POST", "/exec",
                                    {"app": "billing", "command": "echo base",
                                     "env": SHELLSHOCK_ENV})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIn(SHELLSHOCK_MARKER, payload["stdout"],
                      "the emulated injection must carry its honesty label")
        self.assertIn("CVE-2014-6271-injected", payload["stdout"])
        self.assertIn("base", payload["stdout"])
        entries = [e for e in self.journal_entries() if e.get("event") == "env_function_injection"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["app"], "billing")
        self.assertIn("echo CVE-2014-6271-injected", entries[0]["payload"])

        # A non-Shellshock-shaped env value is never treated as a function.
        status, body = http_request(self.ports["shush"], "POST", "/exec",
                                    {"app": "billing", "command": "echo base",
                                     "env": {"PLAIN": "hello"}})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertNotIn(SHELLSHOCK_MARKER, payload["stdout"])
        self.assertNotIn("CVE-2014-6271-injected", payload["stdout"])

    def test_rea_variant_ignores_the_env_field(self):
        rea_root = self.tmp / "rea-estate"
        prepared = rea.prepare(rea_root, variant="rea")
        self.assertTrue(prepared.ok, f"prepare failed: {prepared.error}")
        started = rea.start(rea_root, ports=EPHEMERAL_PORTS)
        self.assertTrue(started.ok, f"start failed: {started.error}")
        try:
            status, body = http_request(started.data["ports"]["shush"], "POST", "/exec",
                                        {"app": "billing", "command": "echo base",
                                         "env": SHELLSHOCK_ENV})
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertNotIn("CVE-2014-6271-injected", payload["stdout"])
            self.assertNotIn(SHELLSHOCK_MARKER, payload["stdout"])
            entries = [
                json.loads(line)
                for line in (rea_root / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip() and "env_function_injection" in line
            ]
            self.assertEqual(entries, [])
        finally:
            stopped = rea.stop(rea_root)
            self.assertTrue(stopped.ok, f"stop failed: {stopped.error}")

    def test_unwrap_refuses_without_app_token(self):
        billing = json.loads((self.root / "apps" / "billing" / "app.json").read_text(encoding="utf-8"))
        envelope = billing["env"]["BILLING_DB_PASSWORD_ENCRYPTED"]
        body = {"wrapped_key": envelope["wrapped_key"], "key_id": "kms-billing",
                "context": {"app": "billing", "var": "BILLING_DB_PASSWORD"}}
        status, _ = http_request(self.ports["kms"], "POST", "/unwrap", body)
        self.assertEqual(status, 403, "the confused deputy must be fixed in the CVE variant")
        status, _ = http_request(self.ports["kms"], "POST", "/unwrap", body,
                                 headers={"X-App-Token": "wrong-token"})
        self.assertEqual(status, 403)
        entries = [e for e in self.journal_entries() if e.get("event") == "unwrap_denied_context"]
        self.assertGreaterEqual(len(entries), 2)

    def test_unwrap_with_app_token_works(self):
        billing = json.loads((self.root / "apps" / "billing" / "app.json").read_text(encoding="utf-8"))
        envelope = billing["env"]["BILLING_DB_PASSWORD_ENCRYPTED"]
        status, body = http_request(
            self.ports["kms"], "POST", "/unwrap",
            {"wrapped_key": envelope["wrapped_key"], "key_id": "kms-billing",
             "context": {"app": "billing", "var": "BILLING_DB_PASSWORD"}},
            headers={"X-App-Token": billing["token"]},
        )
        self.assertEqual(status, 200)
        self.assertRegex(json.loads(body)["data_key"], r"^[0-9a-f]{64}$")

    def test_oracle_reports_padding_valid_and_invalid(self):
        # The crown block itself has valid 0x0b padding.
        status, body = http_request(self.ports["kms"], "POST", "/oracle",
                                    {"ct_hex": self.envelope["ct"]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"padding": "valid"})

        # A block we encrypt ourselves with an invalid last byte (0x00) is
        # deterministically invalid — no flake risk from corrupting one bit.
        master = (self.root / "kms" / "master.key").read_text(encoding="utf-8").strip()
        bad_ct = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-K", master, "-iv",
             self.envelope["iv"], "-nopad"],
            input=b"\x00" * 16, capture_output=True, timeout=15, check=True,
        ).stdout
        status, body = http_request(self.ports["kms"], "POST", "/oracle",
                                    {"ct_hex": bad_ct.hex()})
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "padding invalid"})

        entries = self.journal_entries()
        events = [e.get("event") for e in entries]
        self.assertIn("oracle_padding_valid", events)
        self.assertIn("oracle_padding_invalid", events)

    def test_crown_token_recovery_via_oracle_then_score(self):
        """Byte-at-a-time CBC padding-oracle recovery of the 4-byte crown token.

        The estate discloses the envelope shape (one block: 4 unknown bytes +
        0x0b PKCS#7 padding), so only the 4 token bytes are brute-forced —
        4 bytes x <=256 oracle queries, all loopback.
        """
        iv = bytes.fromhex(self.envelope["iv"])
        crown_ct = bytes.fromhex(self.envelope["ct"])
        known = bytearray(16)
        known[4:] = b"\x0b" * 12
        queries = 0
        for index in range(3, -1, -1):
            pad = 16 - index
            block = bytearray(16)
            for i in range(index + 1, 16):
                block[i] = known[i] ^ iv[i] ^ pad
            found = None
            for candidate in range(256):
                block[index] = candidate
                queries += 1
                if self.oracle_valid(block.hex() + crown_ct.hex()):
                    found = candidate
                    break
            self.assertIsNotNone(found, f"no candidate produced valid padding for byte {index}")
            known[index] = found ^ iv[index] ^ pad
        token = bytes(known[:4]).decode("ascii")
        self.assertRegex(token, r"^[0-9a-f]{4}$", f"recovered {token!r} is not 4 hex chars")
        self.assertEqual(token.encode("ascii"), self.crown_decrypt_block(crown_ct)[:4])

        # /verify_crown: the wrong token is refused, the recovered one accepted.
        wrong = "ffff" if token != "ffff" else "fffe"
        status, _ = http_request(self.ports["kms"], "POST", "/verify_crown", {"token": wrong})
        self.assertEqual(status, 403)
        status, body = http_request(self.ports["kms"], "POST", "/verify_crown", {"token": token})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["verified"], True)

        with open(REA_CVE_CONTRACT_PATH, encoding="utf-8") as handle:
            cve_contract = json.load(handle)
        result = rea.score(self.estate_root, cve_contract, variant="cve")
        self.assertTrue(result.ok, f"score failed: {result.error}")
        proven = {(objective, witness) for objective, witness, _ in result.data["proven"]}
        self.assertIn(("envelope_bypass", "oracle_queried"), proven,
                      "oracle queries must prove envelope_bypass")
        self.assertIn(("crown_objective", "crown_verified"), proven)
        self.assertEqual(result.data["crown_flag"], token,
                         "the crown token must be attached as crown_flag")
        for objective, witness, evidence in result.data["proven"]:
            self.assertIn('"event"', evidence, "evidence must be the literal journal line")

        # The journal really has both oracle events and the verified token.
        entries = self.journal_entries()
        events = [e.get("event") for e in entries]
        self.assertIn("oracle_padding_invalid", events)
        self.assertIn("oracle_padding_valid", events)
        self.assertIn("crown_verified", entries[-1].get("event", ""))
        self.assertIn(token, (self.root / "evidence.jsonl").read_text(encoding="utf-8"))
        self.assertLessEqual(queries, 1024, "recovery must stay within 4 bytes x 256 queries")

        # Scoring the CVE estate against the wrong (rea) contract refuses.
        with open(REA_CONTRACT_PATH, encoding="utf-8") as handle:
            rea_contract = json.load(handle)
        refused = rea.score(self.estate_root, rea_contract, variant="cve")
        self.assertFalse(refused.ok)
        self.assertIn("rea-control-plane-cve", refused.error)
        # And a variant argument disagreeing with the estate on disk refuses.
        refused = rea.score(self.estate_root, cve_contract, variant="rea")
        self.assertFalse(refused.ok)
        self.assertIn("source of truth", refused.error)

    def test_score_and_start_require_variant_txt(self):
        with open(REA_CVE_CONTRACT_PATH, encoding="utf-8") as handle:
            cve_contract = json.load(handle)
        (self.root / "variant.txt").unlink()
        result = rea.score(self.root, cve_contract, variant="cve")
        self.assertFalse(result.ok)
        self.assertIn("variant.txt", result.error)
        stopped = rea.stop(self.root)
        self.assertTrue(stopped.ok, f"stop failed: {stopped.error}")
        self._started = False
        started = rea.start(self.root)
        self.assertFalse(started.ok)
        self.assertIn("variant.txt", started.error)

    def test_cve_teaching_surface_still_serves_the_other_planes(self):
        """DNS, IdP, object store and credulous behave identically in the CVE variant."""
        zone = (self.root / "dns" / "zone.txt").read_text(encoding="utf-8").strip()
        fingerprint = zone.split('"', 2)[1]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10.0)
        try:
            sock.sendto(dns_query("_ssh-ca.evilkit.rea"), ("127.0.0.1", self.ports["dns"]))
            response, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        self.assertIn(fingerprint.encode("ascii"), response)
        status, body = http_request(self.ports["objects"], "GET", "/objects/ca_key")
        self.assertEqual(status, 200)
        status, body = http_request(self.ports["credulous"], "POST", "/exec",
                                    {"command": "echo $AWS_ACCESS_KEY_ID"})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["stdout"].strip().startswith("AKIA"))


if __name__ == "__main__":
    unittest.main()
