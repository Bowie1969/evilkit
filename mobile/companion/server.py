"""Scope-gated companion server for the mobile evilkit runtime.

The companion runs on a small Linux device tethered to an iPhone. It exposes a
small HTTP API that the iOS app uses to run pentest tools. Every target in a
tool call is checked against the session's allowed/denied scope before execution.

This server is intentionally lightweight: only the Python standard library is
required, plus the vendored evilkit_core modules.
"""

from __future__ import annotations

import argparse
import dataclasses
import io
import json
import logging
import os
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from evilkit_core import audit as audit_mod, scope as scope_mod

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8787
DEFAULT_DATA_DIR = "/var/lib/evilkit-companion"
SCOPE_ENV_KEY = "PENTEST_ALLOWED_TARGETS"
DENY_ENV_KEY = "PENTEST_DENIED_TARGETS"

_log = logging.getLogger("evilkit-companion")


@dataclasses.dataclass
class Session:
    id: str
    scope: str
    deny: str
    created_at: float
    log_path: Path


@dataclasses.dataclass
class Job:
    id: str
    session_id: str
    tool: str
    args: dict[str, Any]
    state: str = "pending"  # pending, running, done, error
    returncode: int | None = None
    output: list[str] = dataclasses.field(default_factory=list)
    queue: queue.Queue[str | None] = dataclasses.field(default_factory=queue.Queue)
    thread: threading.Thread | None = None
    started_at: float | None = None
    finished_at: float | None = None


class Store:
    """In-memory session and job store with append-only audit logging."""

    def __init__(self, data_dir: Path, token: str) -> None:
        self.data_dir = data_dir
        self.token = token
        self.sessions: dict[str, Session] = {}
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        data_dir.mkdir(parents=True, exist_ok=True)

    def create_session(self, scope: str, deny: str = "") -> Session:
        session_id = secrets.token_urlsafe(16)
        log_path = self.data_dir / f"{session_id}.jsonl"
        session = Session(
            id=session_id,
            scope=scope,
            deny=deny,
            created_at=time.time(),
            log_path=log_path,
        )
        with self.lock:
            self.sessions[session_id] = session
        self._audit(session, "session_created", {"scope": scope, "deny": deny})
        return session

    def get_session(self, session_id: str) -> Session | None:
        with self.lock:
            return self.sessions.get(session_id)

    def create_job(self, session_id: str, tool: str, args: dict[str, Any]) -> Job:
        job_id = secrets.token_urlsafe(16)
        job = Job(id=job_id, session_id=session_id, tool=tool, args=args)
        with self.lock:
            self.jobs[job_id] = job
        return job

    def get_job(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def _audit(self, session: Session, event: str, payload: dict[str, Any]) -> None:
        entry = {
            "v": audit_mod.ENTRY_VERSION,
            "at": audit_mod._timestamp(),
            "event": event,
            "session": session.id,
            **payload,
        }
        try:
            audit_mod.record(session.log_path, entry)
        except audit_mod.LogError as exc:
            _log.warning("could not write audit log: %s", exc)

    def record_tool_call(self, session: Session, job_id: str, tool: str, args: dict[str, Any]) -> None:
        self._audit(session, "tool_call", {"job": job_id, "tool": tool, "args": args})

    def record_tool_result(self, session: Session, job_id: str, returncode: int) -> None:
        self._audit(session, "tool_result", {"job": job_id, "returncode": returncode})


class ScopeGateError(Exception):
    """Raised when a tool target is outside the authorised scope."""


@dataclasses.dataclass
class Tool:
    name: str
    description: str
    schema: dict[str, Any]
    handler: Any


def _host_in_scope(host: str, allowed: list[str], denied: list[str]) -> bool:
    """Check whether a host is inside allowed and not inside denied.

    Hostnames are matched literally. IPs and networks are matched with CIDR
    containment.
    """
    host_lower = host.lower().rstrip(".")

    def _contains(token: str, target: str) -> bool:
        token = token.lower()
        if "/" in token:
            try:
                network = scope_mod.ipaddress.ip_network(token, strict=True)
            except ValueError:
                return token == target
            try:
                address = scope_mod.ipaddress.ip_address(target)
            except ValueError:
                return False
            return address in network
        return token == target

    if any(_contains(d, host_lower) for d in denied):
        return False
    return any(_contains(a, host_lower) for a in allowed)


def _parse_scope(scope: str, deny: str) -> tuple[list[str], list[str]]:
    allowed = scope_mod.parse_scope(scope, allow_any=True)
    denied = scope_mod.parse_scope(deny, allow_any=True) if deny.strip() else []
    return allowed, denied


def _validate_target(target: str, allowed: list[str], denied: list[str]) -> None:
    """Refuse a target that is outside the session scope."""
    parsed = urlparse(target)
    host = parsed.hostname or target
    if host is None:
        raise ScopeGateError(f"could not determine host from {target!r}")
    if not _host_in_scope(host, allowed, denied):
        raise ScopeGateError(f"target {host!r} is outside the authorised scope")


def _run_stream(cmd: list[str], job: Job, timeout: int | None = None) -> None:
    """Worker that runs a command and streams stdout/stderr into the job queue."""
    job.state = "running"
    job.started_at = time.time()
    _log.info("[%s] running: %s", job.id, shlex.join(cmd))
    proc: subprocess.Popen[str] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            stripped = line.rstrip("\n")
            job.output.append(stripped)
            job.queue.put(stripped)
        proc.wait(timeout=timeout)
        job.returncode = proc.returncode
        job.state = "done" if proc.returncode == 0 else "error"
    except subprocess.TimeoutExpired:
        if proc is not None:
            proc.kill()
        job.returncode = 124
        job.state = "error"
        job.queue.put("[evilkit-companion: command timed out]")
    except FileNotFoundError as exc:
        job.returncode = 127
        job.state = "error"
        job.queue.put(f"[evilkit-companion: command not found: {exc}]")
    except Exception as exc:  # noqa: BLE001
        job.returncode = 1
        job.state = "error"
        job.queue.put(f"[evilkit-companion: execution error: {exc}]")
    finally:
        if proc is not None and proc.stdout is not None:
            proc.stdout.close()
        job.finished_at = time.time()
        job.queue.put(None)
        _log.info("[%s] finished with rc=%s", job.id, job.returncode)


def _spawn_stream(cmd: list[str], job: Job, timeout: int | None = None) -> None:
    """Start a background thread to run ``cmd`` and stream its output."""
    job.thread = threading.Thread(target=_run_stream, args=(cmd, job, timeout), daemon=True)
    job.thread.start()


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _tool_verify_http(session: Session, args: dict[str, Any], job: Job) -> list[str]:
    url = str(args.get("url", "")).strip()
    method = str(args.get("method", "GET")).upper()
    headers = args.get("headers", {}) or {}
    follow_redirects = bool(args.get("follow_redirects", True))
    timeout = int(args.get("timeout", 30))

    if not url:
        raise ScopeGateError("url is required")

    allowed, denied = _parse_scope(session.scope, session.deny)
    _validate_target(url, allowed, denied)

    cmd = ["curl", "-sSL" if follow_redirects else "-sS", "-D", "-", "-o", "-"]
    if method != "GET":
        cmd += ["-X", method]
    for key, value in headers.items():
        cmd += ["-H", f"{key}: {value}"]
    cmd += ["--max-time", str(timeout), "--", url]
    _spawn_stream(cmd, job, timeout=timeout + 5)
    return cmd


def _tool_port_scan(session: Session, args: dict[str, Any], job: Job) -> list[str]:
    target = str(args.get("target", "")).strip()
    ports = str(args.get("ports", "top-1000")).strip()
    timeout = int(args.get("timeout", 300))

    if not target:
        raise ScopeGateError("target is required")

    allowed, denied = _parse_scope(session.scope, session.deny)
    _validate_target(target, allowed, denied)

    cmd = ["rustscan", "-a", target]
    if ports == "top-1000":
        cmd.append("--top")
    elif ports:
        cmd.append("-p")
        cmd.append(ports)
    _spawn_stream(cmd, job, timeout=timeout + 10)
    return cmd


TOOLS: dict[str, Tool] = {
    "verify_http": Tool(
        name="verify_http",
        description="Make an HTTP/HTTPS request to a target URL using curl.",
        schema={
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Full URL to request"},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object", "default": {}},
                "follow_redirects": {"type": "boolean", "default": True},
                "timeout": {"type": "integer", "default": 30},
            },
        },
        handler=_tool_verify_http,
    ),
    "port_scan": Tool(
        name="port_scan",
        description="Run a rustscan TCP port scan against a target host.",
        schema={
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": {"type": "string", "description": "Host or IP to scan"},
                "ports": {"type": "string", "default": "top-1000", "description": "Ports or 'top-1000'"},
                "timeout": {"type": "integer", "default": 300},
            },
        },
        handler=_tool_port_scan,
    ),
}


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


def _json_response(handler: BaseHTTPRequestHandler, status: int, body: Any) -> None:
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _error(handler: BaseHTTPRequestHandler, status: int, message: str) -> None:
    _json_response(handler, status, {"error": message})


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8")
    return json.loads(raw)


def _check_auth(handler: BaseHTTPRequestHandler, store: Store) -> bool:
    auth = handler.headers.get("Authorization", "")
    expected = f"Bearer {store.token}"
    # Constant-time compare is overkill for a local device token, but harmless.
    return secrets.compare_digest(auth, expected)


class Handler(BaseHTTPRequestHandler):
    store: Store

    def log_message(self, format: str, *args: Any) -> None:
        _log.info("%s - %s", self.address_string(), format % args)

    def _path_match(self, pattern: str) -> re.Match[str] | None:
        return re.fullmatch(pattern, self.path)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/v1/health":
            self._handle_health()
            return
        if self.path == "/api/v1/tools":
            self._handle_tools()
            return
        m = self._path_match(r"/api/v1/sessions/([^/]+)")
        if m:
            self._handle_get_session(m.group(1))
            return
        m = self._path_match(r"/api/v1/sessions/([^/]+)/jobs/([^/]+)")
        if m:
            self._handle_get_job(m.group(1), m.group(2))
            return
        _error(self, 404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        if not _check_auth(self, self.store):
            _error(self, 401, "unauthorized")
            return
        if self.path == "/api/v1/sessions":
            self._handle_create_session()
            return
        m = self._path_match(r"/api/v1/sessions/([^/]+)/run")
        if m:
            self._handle_run(m.group(1))
            return
        _error(self, 404, "not found")

    def _handle_health(self) -> None:
        _json_response(
            self,
            200,
            {
                "status": "ok",
                "version": "0.1.0",
                "sessions": len(self.store.sessions),
                "jobs": len(self.store.jobs),
            },
        )

    def _handle_tools(self) -> None:
        tools = [
            {"name": t.name, "description": t.description, "schema": t.schema}
            for t in TOOLS.values()
        ]
        _json_response(self, 200, {"tools": tools})

    def _handle_create_session(self) -> None:
        try:
            body = _read_json(self)
        except json.JSONDecodeError as exc:
            _error(self, 400, f"invalid JSON: {exc}")
            return

        scope = str(body.get("scope", "")).strip()
        if not scope:
            _error(self, 400, "scope is required")
            return
        try:
            scope_mod.normalise_scope(scope, allow_any=False)
        except scope_mod.ScopeError as exc:
            _error(self, 400, f"invalid scope: {exc}")
            return

        deny = str(body.get("deny", "")).strip()
        if deny:
            try:
                scope_mod.normalise_scope(deny, allow_any=False)
            except scope_mod.ScopeError as exc:
                _error(self, 400, f"invalid deny list: {exc}")
                return

        session = self.store.create_session(scope, deny)
        _json_response(self, 201, {
            "id": session.id,
            "scope": session.scope,
            "deny": session.deny,
            "created_at": session.created_at,
        })

    def _handle_get_session(self, session_id: str) -> None:
        session = self.store.get_session(session_id)
        if session is None:
            _error(self, 404, "session not found")
            return
        _json_response(self, 200, {
            "id": session.id,
            "scope": session.scope,
            "deny": session.deny,
            "created_at": session.created_at,
        })

    def _handle_get_job(self, session_id: str, job_id: str) -> None:
        job = self.store.get_job(job_id)
        if job is None or job.session_id != session_id:
            _error(self, 404, "job not found")
            return
        _json_response(self, 200, {
            "id": job.id,
            "tool": job.tool,
            "args": job.args,
            "state": job.state,
            "returncode": job.returncode,
            "output": job.output,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
        })

    def _handle_run(self, session_id: str) -> None:
        session = self.store.get_session(session_id)
        if session is None:
            _error(self, 404, "session not found")
            return

        try:
            body = _read_json(self)
        except json.JSONDecodeError as exc:
            _error(self, 400, f"invalid JSON: {exc}")
            return

        tool_name = str(body.get("tool", "")).strip()
        args = body.get("args", {}) or {}
        if not isinstance(args, dict):
            _error(self, 400, "args must be an object")
            return

        tool = TOOLS.get(tool_name)
        if tool is None:
            _error(self, 400, f"unknown tool: {tool_name}")
            return

        job = self.store.create_job(session_id, tool_name, args)
        self.store.record_tool_call(session, job.id, tool_name, args)

        try:
            tool.handler(session, args, job)
        except ScopeGateError as exc:
            job.state = "error"
            job.returncode = 403
            job.output.append(str(exc))
            job.queue.put(str(exc))
            job.queue.put(None)

        accept = self.headers.get("Accept", "")
        if "text/event-stream" in accept:
            self._stream_job(job)
        else:
            # Block until finished.
            if job.thread is not None:
                job.thread.join()
            if job.returncode == 403:
                _error(self, 403, "\n".join(job.output))
                return
            _json_response(self, 200, {
                "id": job.id,
                "state": job.state,
                "returncode": job.returncode,
                "output": job.output,
            })

    def _stream_job(self, job: Job) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        def _send_event(event: str, data: str) -> None:
            payload = f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8")
            self.wfile.write(payload)
            self.wfile.flush()

        _send_event("job", json.dumps({"id": job.id, "state": job.state}))

        while True:
            try:
                line = job.queue.get(timeout=300)
            except queue.Empty:
                break
            if line is None:
                break
            _send_event("output", line)

        if job.thread is not None:
            job.thread.join()
        _send_event(
            "done",
            json.dumps({"id": job.id, "state": job.state, "returncode": job.returncode}),
        )


def _build_handler(store: Store) -> type[BaseHTTPRequestHandler]:
    class BoundHandler(Handler):
        pass

    BoundHandler.store = store  # type: ignore[attr-defined]
    return BoundHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="evilkit mobile companion server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="bind port")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="session/log directory")
    parser.add_argument("--token", help="bearer token (auto-generated if omitted)")
    parser.add_argument("--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    data_dir = Path(args.data_dir)
    token = args.token or secrets.token_urlsafe(32)
    store = Store(data_dir=data_dir, token=token)

    handler_cls = _build_handler(store)
    server = ThreadingHTTPServer((args.host, args.port), handler_cls)
    _log.info("evilkit companion server listening on http://%s:%s", args.host, args.port)
    _log.info("authorization token: %s", token)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log.info("shutting down")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
