"""Unit tests for the companion server and scope gate.

Run from the mobile/companion directory:
    python3 -m unittest test_server -v
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import server as server_mod


class CompanionAPITestCase(unittest.TestCase):
    """Spin up the server on a random port and exercise the HTTP API."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.token = "test-token"
        cls.data_dir = Path("/tmp/evilkit-companion-test-py")
        cls.data_dir.mkdir(parents=True, exist_ok=True)
        cls.store = server_mod.Store(data_dir=cls.data_dir, token=cls.token)
        cls.handler = server_mod._build_handler(cls.store)
        cls.server = server_mod.ThreadingHTTPServer(("127.0.0.1", 0), cls.handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def _request(
        self, path: str, method: str = "GET", data: dict | None = None, auth: bool = True
    ) -> tuple[int, dict]:
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = Request(
            self._url(path),
            data=body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        if auth:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urlopen(req, timeout=30) as resp:  # noqa: S310
                code = resp.getcode()
                payload = json.loads(resp.read().decode("utf-8"))
                return code, payload
        except HTTPError as exc:
            payload = json.loads(exc.read().decode("utf-8")) if exc.fp else {}
            return exc.code, payload

    def test_health_is_public(self) -> None:
        code, body = self._request("/api/v1/health", auth=False)
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "ok")

    def test_tools_is_public(self) -> None:
        code, body = self._request("/api/v1/tools", auth=False)
        self.assertEqual(code, 200)
        self.assertIn("verify_http", [t["name"] for t in body["tools"]])

    def test_unauthorized_post_rejected(self) -> None:
        code, body = self._request(
            "/api/v1/sessions", method="POST", data={"scope": "127.0.0.1/32"}, auth=False
        )
        self.assertEqual(code, 401)

    def test_session_creation_requires_scope(self) -> None:
        code, body = self._request("/api/v1/sessions", method="POST", data={})
        self.assertEqual(code, 400)
        self.assertIn("scope is required", body["error"])

    def test_session_creation_validates_scope(self) -> None:
        code, body = self._request("/api/v1/sessions", method="POST", data={"scope": "10.0.0.256"})
        self.assertEqual(code, 400)
        self.assertIn("invalid scope", body["error"])

    def test_verify_http_respects_scope(self) -> None:
        code, session = self._request(
            "/api/v1/sessions", method="POST", data={"scope": "127.0.0.1/32"}
        )
        self.assertEqual(code, 201)
        sid = session["id"]

        # Out-of-scope request must be refused before execution.
        code, body = self._request(
            f"/api/v1/sessions/{sid}/run",
            method="POST",
            data={"tool": "verify_http", "args": {"url": "http://example.com", "timeout": 5}},
        )
        self.assertEqual(code, 403)
        self.assertIn("outside the authorised scope", body["error"])

    def test_port_scan_respects_deny_list(self) -> None:
        code, session = self._request(
            "/api/v1/sessions",
            method="POST",
            data={"scope": "127.0.0.0/24", "deny": "127.0.0.1"},
        )
        self.assertEqual(code, 201)
        sid = session["id"]

        code, body = self._request(
            f"/api/v1/sessions/{sid}/run",
            method="POST",
            data={"tool": "port_scan", "args": {"target": "127.0.0.1", "ports": "80", "timeout": 10}},
        )
        self.assertEqual(code, 403)

    def test_job_stream_and_retrieval(self) -> None:
        code, session = self._request(
            "/api/v1/sessions", method="POST", data={"scope": "127.0.0.1/32"}
        )
        sid = session["id"]

        code, body = self._request(
            f"/api/v1/sessions/{sid}/run",
            method="POST",
            data={"tool": "verify_http", "args": {"url": f"http://127.0.0.1:{self.port}/api/v1/health", "timeout": 5}},
        )
        self.assertEqual(code, 200)
        job_id = body["id"]
        self.assertEqual(body["state"], "done")
        self.assertEqual(body["returncode"], 0)

        # Retrieve job again.
        code, body = self._request(f"/api/v1/sessions/{sid}/jobs/{job_id}")
        self.assertEqual(code, 200)
        self.assertEqual(body["id"], job_id)


class ScopeGateTestCase(unittest.TestCase):
    """Direct tests for the scope gate helpers."""

    def test_host_in_scope_for_hostname(self) -> None:
        allowed, denied = server_mod._parse_scope("example.com", "")
        self.assertTrue(server_mod._host_in_scope("example.com", allowed, denied))
        self.assertFalse(server_mod._host_in_scope("other.com", allowed, denied))

    def test_host_in_scope_for_cidr(self) -> None:
        allowed, denied = server_mod._parse_scope("10.0.0.0/24", "")
        self.assertTrue(server_mod._host_in_scope("10.0.0.5", allowed, denied))
        self.assertFalse(server_mod._host_in_scope("10.0.1.5", allowed, denied))

    def test_deny_list_overrides_allow(self) -> None:
        allowed, denied = server_mod._parse_scope("10.0.0.0/24", "10.0.0.5")
        self.assertFalse(server_mod._host_in_scope("10.0.0.5", allowed, denied))
        self.assertTrue(server_mod._host_in_scope("10.0.0.6", allowed, denied))


if __name__ == "__main__":
    unittest.main()
