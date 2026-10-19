"""Tests for the evilkit orchestration layer (phases 1-5)."""

from __future__ import annotations

import base64
import http.client
import io
import json
import os
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
from contextlib import closing
from pathlib import Path
from unittest import mock

from evilkit import _ed25519, mesh, mesh_mcp
from evilkit.orchestration import (
    Board,
    BoardError,
    canonical_request,
    DEFAULT_MSG_TTL,
    MAX_PENDING_PER_PEER,
    OBJECTIVE_STATUSES,
)
from evilkit.instance_daemon import InstanceDaemon, SPOOL_FILE, read_spool


# --- helpers -----------------------------------------------------------------


def _temp_board(tmpdir: Path, *, scope: str | None = "10.10.10.0/24,example.com", clock=None) -> Board:
    journal = tmpdir / "journal.jsonl"
    return Board(engagement_scope=scope, journal_path=journal,
                 clock=clock or time.time)


def _enroll(board: Board, name: str) -> tuple[bytes, bytes]:
    sk, pk = _ed25519.keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")
    board.enroll_pubkey(name=name, pubkey_b64=pk_b64)
    board.register_instance(name=name, pubkey_b64=pk_b64, role="operator",
                            capabilities=["nmap"], position=["10.10.10.0/24"])
    return sk, pk


# --- Phase 1: broker core ----------------------------------------------------


class JournalReplayTests(unittest.TestCase):
    """A hub restart rebuilds board state and pending inboxes from the journal."""

    def test_messages_claims_objectives_survive_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            board = _temp_board(tmp_path)
            sk_a, pk_a = _enroll(board, "alpha")
            sk_b, pk_b = _enroll(board, "bravo")
            board.send_message(from_name="alpha", to_name="bravo",
                               subject="hello", body="world")
            board.acquire_claim(owner="alpha", asset="10.10.10.5:445")
            board.upsert_objective(from_name="alpha", id=None,
                                   title="enum SMB", status="in_progress")
            seq_before = board.seq
            # Rebuild
            board2 = Board(engagement_scope=board.engagement_scope,
                           journal_path=tmp_path / "journal.jsonl")
            board2.replay()
            self.assertGreaterEqual(board2.seq, seq_before)
            self.assertEqual(sorted(board2.instances.keys()), ["alpha", "bravo"])
            inbox = board2.read_inbox("bravo")
            self.assertEqual(len(inbox["messages"]), 1)
            self.assertEqual(inbox["messages"][0]["subject"], "hello")
            self.assertEqual([c["asset"] for c in board2.list_claims()], ["10.10.10.5:445"])
            self.assertEqual([o["title"] for o in board2.list_objectives()], ["enum SMB"])


class MessagingTests(unittest.TestCase):
    def test_directed_delivery_and_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            for i in range(5):
                board.send_message(from_name="a", to_name="b",
                                   subject=f"m{i}", body={"i": i})
            inbox = board.read_inbox("b")
            self.assertEqual([m["subject"] for m in inbox["messages"]],
                             ["m0", "m1", "m2", "m3", "m4"])
            # per-inbox seq is monotonic
            self.assertEqual([m["seq"] for m in inbox["messages"]], [1, 2, 3, 4, 5])

    def test_ack_removes_and_returns_acked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            board.send_message(from_name="a", to_name="b", subject="s", body="x")
            msgs = board.read_inbox("b")["messages"]
            result = board.ack_messages("b", [m["id"] for m in msgs])
            self.assertEqual(result["acked"], [msgs[0]["id"]])
            self.assertEqual(board.read_inbox("b")["messages"], [])

    def test_ttl_expiry_drops_old_messages(self) -> None:
        now = [1000.0]
        clock = lambda: now[0]
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp), clock=clock)
            _enroll(board, "a")
            _enroll(board, "b")
            board.send_message(from_name="a", to_name="b",
                               subject="hi", body="x", ttl=10)
            self.assertEqual(len(board.read_inbox("b")["messages"]), 1)
            now[0] += 60
            self.assertEqual(board.read_inbox("b")["messages"], [])

    def test_inbox_cap_drops_oldest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            for i in range(MAX_PENDING_PER_PEER + 5):
                board.send_message(from_name="a", to_name="b",
                                   subject=f"m{i}", body="x")
            msgs = board.read_inbox("b")["messages"]
            self.assertEqual(len(msgs), MAX_PENDING_PER_PEER)
            # oldest were dropped
            self.assertEqual(msgs[0]["subject"], "m5")

    def test_oversized_body_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            huge = "x" * (16 * 1024 + 1)
            with self.assertRaises(BoardError):
                board.send_message(from_name="a", to_name="b",
                                   subject="big", body=huge)

    def test_subject_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            with self.assertRaises(BoardError):
                board.send_message(from_name="a", to_name="b",
                                   subject="s" * 300, body="x")


class ChannelTests(unittest.TestCase):
    def test_publish_delivers_to_subscribers_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "pub")
            _enroll(board, "sub1")
            _enroll(board, "sub2")
            _enroll(board, "silent")
            board.subscribe("sub1", "ops")
            board.subscribe("sub2", "ops")
            board.publish_channel(from_name="pub", channel="ops", body="go")
            self.assertEqual(len(board.read_inbox("sub1")["messages"]), 1)
            self.assertEqual(len(board.read_inbox("sub2")["messages"]), 1)
            self.assertEqual(board.read_inbox("silent")["messages"], [])

    def test_unsubscribe_stops_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "pub")
            _enroll(board, "sub")
            board.subscribe("sub", "ops")
            board.subscribe("sub", "ops", active=False)
            board.publish_channel(from_name="pub", channel="ops", body="go")
            self.assertEqual(board.read_inbox("sub")["messages"], [])


# --- Phase 2: coordination board --------------------------------------------


class ClaimTests(unittest.TestCase):
    def test_first_writer_wins_and_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            r = board.acquire_claim(owner="a", asset="10.10.10.5:445")
            self.assertTrue(r["ok"])
            r2 = board.acquire_claim(owner="b", asset="10.10.10.5:445")
            self.assertFalse(r2["ok"])
            self.assertEqual(r2["owner"], "a")
            # re-claim by same owner is idempotent OK
            r3 = board.acquire_claim(owner="a", asset="10.10.10.5:445")
            self.assertTrue(r3["ok"])
            # release and re-claim
            board.release_claim(owner="a", asset="10.10.10.5:445")
            self.assertTrue(board.acquire_claim(owner="b", asset="10.10.10.5:445")["ok"])

    def test_off_scope_asset_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            with self.assertRaises(BoardError):
                board.acquire_claim(owner="a", asset="8.8.8.8:53")

    def test_credential_shaped_asset_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            with self.assertRaises(BoardError):
                board.acquire_claim(owner="a", asset="password=hunter2")

    def test_ttl_auto_release(self) -> None:
        now = [1000.0]
        clock = lambda: now[0]
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp), clock=clock)
            _enroll(board, "a")
            _enroll(board, "b")
            board.acquire_claim(owner="a", asset="10.10.10.5", ttl=10)
            now[0] += 60
            # second owner can claim after expiry
            r = board.acquire_claim(owner="b", asset="10.10.10.5")
            self.assertTrue(r["ok"])


class ObjectiveTests(unittest.TestCase):
    def test_upsert_and_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            o = board.upsert_objective(from_name="a", id="O1",
                                        title="enum SMB", status="queued")
            self.assertEqual(o["id"], "O1")
            # update status
            board.upsert_objective(from_name="a", id="O1",
                                   title="enum SMB", status="done")
            objs = board.list_objectives()
            self.assertEqual(objs[0]["status"], "done")

    def test_invalid_status_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            with self.assertRaises(BoardError):
                board.upsert_objective(from_name="a", id=None,
                                        title="x", status="whatever")

    def test_credential_shaped_evidence_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            with self.assertRaises(BoardError):
                board.upsert_objective(from_name="a", id=None,
                                        title="x", status="done",
                                        evidence="password=hunter2")


class PositionScopeTests(unittest.TestCase):
    def test_position_rejected_when_outside_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp), scope="10.10.10.0/24")
            sk, pk = _ed25519.keypair()
            pk_b64 = base64.b64encode(pk).decode("ascii")
            board.enroll_pubkey(name="pi", pubkey_b64=pk_b64)
            r = board.register_instance(
                name="pi", pubkey_b64=pk_b64, role="drop",
                capabilities=[],
                position=["10.10.10.0/26", "8.8.8.8/32"],
            )
            self.assertIn("10.10.10.0/26", r["accepted"])
            self.assertIn("8.8.8.8/32", r["rejected"])

    def test_peers_reaching(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp), scope="10.10.10.0/24,10.20.20.0/24")
            for name, pos in [("ops", ["10.10.10.0/24"]), ("pi", ["10.20.20.0/24"])]:
                sk, pk = _ed25519.keypair()
                pk_b64 = base64.b64encode(pk).decode("ascii")
                board.enroll_pubkey(name=name, pubkey_b64=pk_b64)
                board.register_instance(name=name, pubkey_b64=pk_b64,
                                        role="", capabilities=[], position=pos)
            self.assertEqual(board.peers_reaching("10.20.20.5"), ["pi"])
            self.assertEqual(board.peers_reaching("10.10.10.5"), ["ops"])


# --- Phase 4: security hardening ---------------------------------------------


class ReplayWindowTests(unittest.TestCase):
    def test_stale_timestamp_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            with self.assertRaises(BoardError):
                board.check_nonce("a", "abcdef1234567890", time.time() - 10_000)

    def test_replayed_nonce_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            now = time.time()
            board.check_nonce("a", "abcdef1234567890", now)
            with self.assertRaises(BoardError):
                board.check_nonce("a", "abcdef1234567890", now)


class RevokeTests(unittest.TestCase):
    def test_revoked_name_cannot_reregister(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            board.revoke("a")
            sk, pk = _ed25519.keypair()
            pk_b64 = base64.b64encode(pk).decode("ascii")
            with self.assertRaises(BoardError):
                board.register_instance(name="a", pubkey_b64=pk_b64,
                                         role="", capabilities=[], position=[])


class SecretMessageTests(unittest.TestCase):
    def test_secret_flag_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            board = _temp_board(Path(tmp))
            _enroll(board, "a")
            _enroll(board, "b")
            board.send_message(from_name="a", to_name="b", subject="s",
                                body="x", secret=True)
            msg = board.read_inbox("b")["messages"][0]
            self.assertTrue(msg["secret"])


# --- HTTP integration (end-to-end with Hub) ----------------------------------


class HttpIntegrationTests(unittest.TestCase):
    """Spin up a real mesh.Hub over HTTP and talk to it over the signed protocol."""

    def _free_port(self) -> int:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="evilkit-orch-")
        self.addCleanup(self.tmp.cleanup)
        self.journal = Path(self.tmp.name) / "journal.jsonl"
        self.token_file = Path(self.tmp.name) / "token"
        self.token_file.write_text("t" * 48, encoding="ascii")
        self.token_file.chmod(0o600)
        self.token = (self.token_file.read_text(encoding="ascii")).strip()
        self.port = self._free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.hub = mesh.Hub(
            scope="10.10.10.0/24,10.20.20.0/24",
            token=self.token,
            journal_path=self.journal,
        )
        self.server = mesh.MeshServer(("127.0.0.1", self.port), mesh._handler(self.hub))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._shutdown)

    def _shutdown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _enroll_instance(self, name: str, position=None) -> tuple[bytes, bytes]:
        sk, pk = _ed25519.keypair()
        pk_b64 = base64.b64encode(pk).decode("ascii")
        mesh._request(self.base, self.token, "/instance/enroll",
                      {"name": name, "pubkey": pk_b64})
        mesh._signed_request(self.base, name=name, sk=sk, pk=pk,
                              method="POST", path="/instance/register",
                              data={"pubkey": pk_b64, "role": "op",
                                    "capabilities": ["nmap"],
                                    "position": list(position or ["10.10.10.0/24"])})
        return sk, pk

    def test_signed_register_and_message_round_trip(self) -> None:
        sk_a, pk_a = self._enroll_instance("alpha")
        sk_b, pk_b = self._enroll_instance("bravo")
        send = mesh._signed_request(
            self.base, name="alpha", sk=sk_a, pk=pk_a,
            method="POST", path="/msg",
            data={"to": "bravo", "subject": "hi", "body": "world"},
        )
        self.assertIn(send["delivered_to"], (["bravo"],))
        inbox = mesh._signed_request(
            self.base, name="bravo", sk=sk_b, pk=pk_b,
            method="GET", path="/inbox?after=0",
        )
        self.assertEqual(inbox["messages"][0]["subject"], "hi")

    def test_forged_signature_refused(self) -> None:
        self._enroll_instance("alpha")
        wrong_sk, wrong_pk = _ed25519.keypair()
        # The signature from a wrong key must be rejected under the enrolled name.
        with self.assertRaises(mesh.MeshError) as cm:
            mesh._signed_request(
                self.base, name="alpha", sk=wrong_sk, pk=wrong_pk,
                method="POST", path="/instance/heartbeat", data={},
            )
        self.assertIn("401", str(cm.exception))

    def test_unenrolled_name_refused(self) -> None:
        sk, pk = _ed25519.keypair()
        with self.assertRaises(mesh.MeshError):
            mesh._signed_request(
                self.base, name="never-enrolled", sk=sk, pk=pk,
                method="POST", path="/instance/heartbeat", data={},
            )

    def test_replayed_signature_refused(self) -> None:
        sk, pk = self._enroll_instance("alpha")
        # Build one request manually to replay the same body+nonce+ts twice.
        import urllib.request
        import urllib.error
        body = b"{}"
        ts = f"{time.time():.6f}"
        nonce = "replayed-nonce-123"
        sig = _ed25519.sign(canonical_request("POST", "/instance/heartbeat", body, ts, nonce), sk, pk)
        headers = {
            "X-Evilkit-Node": "alpha",
            "X-Evilkit-Ts": ts,
            "X-Evilkit-Nonce": nonce,
            "X-Evilkit-Sig": base64.b64encode(sig).decode("ascii"),
            "Content-Type": "application/json",
        }

        def _call() -> int:
            req = urllib.request.Request(
                self.base + "/instance/heartbeat", data=body, headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                return exc.code

        self.assertEqual(_call(), 200)
        self.assertEqual(_call(), 401)

    def test_revoked_instance_refused(self) -> None:
        sk, pk = self._enroll_instance("alpha")
        mesh._request(self.base, self.token, "/instance/revoke", {"name": "alpha"})
        with self.assertRaises(mesh.MeshError):
            mesh._signed_request(
                self.base, name="alpha", sk=sk, pk=pk,
                method="POST", path="/instance/heartbeat", data={},
            )

    def test_off_scope_claim_refused(self) -> None:
        sk, pk = self._enroll_instance("alpha")
        with self.assertRaises(mesh.MeshError):
            mesh._signed_request(
                self.base, name="alpha", sk=sk, pk=pk,
                method="POST", path="/claim",
                data={"asset": "8.8.8.8:53", "ttl": 60},
            )

    def test_claim_conflict_round_trip(self) -> None:
        sk_a, pk_a = self._enroll_instance("alpha")
        sk_b, pk_b = self._enroll_instance("bravo")
        r1 = mesh._signed_request(self.base, name="alpha", sk=sk_a, pk=pk_a,
                                   method="POST", path="/claim",
                                   data={"asset": "10.10.10.5:445"})
        self.assertTrue(r1["ok"])
        r2 = mesh._signed_request(self.base, name="bravo", sk=sk_b, pk=pk_b,
                                   method="POST", path="/claim",
                                   data={"asset": "10.10.10.5:445"})
        self.assertFalse(r2["ok"])
        self.assertEqual(r2["owner"], "alpha")

    def test_oversized_body_refused_over_http(self) -> None:
        sk, pk = self._enroll_instance("alpha")
        self._enroll_instance("bravo")
        huge = "x" * (17 * 1024)
        with self.assertRaises(mesh.MeshError):
            mesh._signed_request(
                self.base, name="alpha", sk=sk, pk=pk,
                method="POST", path="/msg",
                data={"to": "bravo", "subject": "big", "body": huge},
            )

    def test_hub_restart_restores_board(self) -> None:
        """Phase 5 acceptance: restart rebuilds the board from the journal."""
        sk_a, pk_a = self._enroll_instance("alpha")
        sk_b, pk_b = self._enroll_instance("bravo")
        mesh._signed_request(self.base, name="alpha", sk=sk_a, pk=pk_a,
                              method="POST", path="/msg",
                              data={"to": "bravo", "subject": "pre-restart", "body": "x"})
        mesh._signed_request(self.base, name="alpha", sk=sk_a, pk=pk_a,
                              method="POST", path="/claim",
                              data={"asset": "10.10.10.5:22"})
        # Shut down and start a new hub on the same journal file.
        self._shutdown()
        port = self._free_port()
        hub2 = mesh.Hub(scope=self.hub.scope, token=self.token,
                        journal_path=self.journal)
        server2 = mesh.MeshServer(("127.0.0.1", port), mesh._handler(hub2))
        thread2 = threading.Thread(target=server2.serve_forever, daemon=True)
        thread2.start()
        try:
            base2 = f"http://127.0.0.1:{port}"
            inbox = mesh._signed_request(base2, name="bravo", sk=sk_b, pk=pk_b,
                                          method="GET", path="/inbox?after=0")
            self.assertEqual(inbox["messages"][0]["subject"], "pre-restart")
            claims = mesh._signed_request(base2, name="alpha", sk=sk_a, pk=pk_a,
                                           method="GET", path="/claims")
            self.assertEqual(claims["claims"][0]["asset"], "10.10.10.5:22")
        finally:
            server2.shutdown()
            server2.server_close()


# --- Instance daemon + MCP ---------------------------------------------------


class InstanceDaemonTests(unittest.TestCase):
    def _free_port(self) -> int:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_once_mode_mirrors_inbox_to_spool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            journal = tmp_path / "journal.jsonl"
            token = "t" * 48
            hub = mesh.Hub(scope="10.10.10.0/24", token=token, journal_path=journal)
            port = self._free_port()
            server = mesh.MeshServer(("127.0.0.1", port), mesh._handler(hub))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{port}"
                # pre-enroll alpha via operator token
                sk_a, pk_a = _ed25519.keypair()
                pk_a_b64 = base64.b64encode(pk_a).decode("ascii")
                mesh._request(base, token, "/instance/enroll",
                              {"name": "alpha", "pubkey": pk_a_b64})
                # pre-enroll + register bravo
                sk_b, pk_b = _ed25519.keypair()
                pk_b_b64 = base64.b64encode(pk_b).decode("ascii")
                mesh._request(base, token, "/instance/enroll",
                              {"name": "bravo", "pubkey": pk_b_b64})
                mesh._signed_request(base, name="bravo", sk=sk_b, pk=pk_b,
                                      method="POST", path="/instance/register",
                                      data={"pubkey": pk_b_b64, "role": "",
                                            "capabilities": [], "position": []})
                # alpha spool + daemon
                spool = tmp_path / "spool-alpha"
                daemon = InstanceDaemon(
                    name="alpha", leader=base, sk=sk_a, pk=pk_a,
                    spool=spool, role="op", capabilities=[], position=[],
                )
                daemon.register()
                # bravo sends alpha a message
                mesh._signed_request(base, name="bravo", sk=sk_b, pk=pk_b,
                                      method="POST", path="/msg",
                                      data={"to": "alpha", "subject": "ping", "body": "x"})
                daemon.pull_inbox()
                # spool now has the message
                msgs = read_spool(spool)
                self.assertEqual([m["subject"] for m in msgs], ["ping"])
                self.assertEqual(daemon._after, 1)
            finally:
                server.shutdown()
                server.server_close()


class McpInstanceToolsTests(unittest.TestCase):
    """The mesh MCP bridge gates instance tools on identity and signs its requests."""

    def test_instance_tool_requires_identity(self) -> None:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("EVILKIT_MESH_INSTANCE_")}
        with mock.patch.dict(os.environ, env, clear=True):
            os.environ["EVILKIT_MESH_LEADER"] = "http://127.0.0.1:65535"
            os.environ["EVILKIT_MESH_TOKEN_FILE"] = ""
            with self.assertRaises(mesh.MeshError):
                mesh_mcp._call("send_message",
                               {"to": "x", "subject": "y", "body": "z"})

    def test_instance_tool_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            journal = tmp_path / "journal.jsonl"
            token = "t" * 48
            hub = mesh.Hub(scope="10.10.10.0/24", token=token, journal_path=journal)
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            server = mesh.MeshServer(("127.0.0.1", port), mesh._handler(hub))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f"http://127.0.0.1:{port}"
                sk_a, pk_a = _ed25519.keypair()
                pk_a_b64 = base64.b64encode(pk_a).decode("ascii")
                mesh._request(base, token, "/instance/enroll",
                              {"name": "alpha", "pubkey": pk_a_b64})
                mesh._signed_request(base, name="alpha", sk=sk_a, pk=pk_a,
                                      method="POST", path="/instance/register",
                                      data={"pubkey": pk_a_b64, "role": "",
                                            "capabilities": [], "position": []})
                sk_b, pk_b = _ed25519.keypair()
                pk_b_b64 = base64.b64encode(pk_b).decode("ascii")
                mesh._request(base, token, "/instance/enroll",
                              {"name": "bravo", "pubkey": pk_b_b64})
                mesh._signed_request(base, name="bravo", sk=sk_b, pk=pk_b,
                                      method="POST", path="/instance/register",
                                      data={"pubkey": pk_b_b64, "role": "",
                                            "capabilities": [], "position": []})
                key_path = tmp_path / "alpha.sk"
                _ed25519.save_sk(key_path, sk_a)
                env = {
                    "EVILKIT_MESH_LEADER": base,
                    "EVILKIT_MESH_TOKEN_FILE": "",
                    "EVILKIT_MESH_INSTANCE_NAME": "alpha",
                    "EVILKIT_MESH_INSTANCE_KEY": str(key_path),
                }
                with mock.patch.dict(os.environ, env, clear=True):
                    mesh_mcp._call("send_message",
                                   {"to": "bravo", "subject": "hello", "body": "world"})
                    # Switch identity to bravo and read bravo's inbox.
                    key_b_path = tmp_path / "bravo.sk"
                    _ed25519.save_sk(key_b_path, sk_b)
                    os.environ["EVILKIT_MESH_INSTANCE_NAME"] = "bravo"
                    os.environ["EVILKIT_MESH_INSTANCE_KEY"] = str(key_b_path)
                    inbox = mesh_mcp._call("read_inbox", {"ack": False})
                    self.assertEqual(inbox["messages"][0]["subject"], "hello")
            finally:
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
