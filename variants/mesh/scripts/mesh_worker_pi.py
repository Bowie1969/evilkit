"""Standalone Raspberry Pi worker for a brief-based Evilkit mesh.

Runs on the Pi (arm64 Raspberry Pi OS Lite), joins the mesh hub running on
Parrot, and pulls work from it. This is the third worker type alongside the
Windows and WSL workers; it speaks the same token-authenticated HTTP protocol
(register / claim / output / complete / finding / update / state / tail).

Two things are different from the Windows worker, because the Pi is a remote
node reached over a WireGuard tunnel rather than a box on the same LAN:

  * it reconnects. A dropped tunnel is expected, not fatal. The loop backs off
    and rejoins the hub, re-registering when the hub has forgotten it (the hub
    keeps workers in memory, so a hub restart means the Pi must re-register).
  * it spools. Output produced while the tunnel is down is written to a local
    spool file and flushed to the hub on reconnect, so a task's evidence is not
    lost to a transient network drop.

It deliberately accepts only a brief-unscoped hub and never edits target scope,
exactly like the Windows worker. Uses only the Python standard library and the
user's existing Kimi Code install.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class WorkerError(Exception):
    pass


# The hub binds to loopback or a numeric Tailscale IP. On the Pi the hub is
# reached across a WireGuard tunnel, so accept the WireGuard subnet as well as
# loopback and the Tailscale CGNAT range.
_WG_NETWORK = ipaddress.ip_network("10.66.0.0/24")
_TS_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def _leader(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise WorkerError("leader must use a numeric loopback, WireGuard, or Tailscale IPv4 address") from exc
    allowed = (
        address.version == 4
        and (address.is_loopback or address in _WG_NETWORK or address in _TS_NETWORK)
    )
    if (
        parsed.scheme != "http"
        or port is None
        or not allowed
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise WorkerError("leader must be an http://loopback-or-tunnel-ip:port URL")
    return value.rstrip("/")


def _request(leader: str, token: str, path: str, body: dict | None = None, *, timeout: int = 20) -> dict:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        leader + path,
        data=payload,
        method="GET" if body is None else "POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise WorkerError(f"hub returned {exc.code}: {exc.read(300).decode('utf-8', 'replace')}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise WorkerError(f"hub unavailable: {exc}") from exc


class Spool:
    """Append-only local buffer for hub-bound messages while the tunnel is down.

    Each line is a JSON object: {"path": ..., "body": {...}}. On reconnect the
    spool is replayed in order and truncated only once the hub has accepted
    every line, so a crash mid-flush loses nothing.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, path: str, body: dict) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"path": path, "body": body}) + "\n")

    def pending(self) -> list[dict]:
        if not self.path.is_file():
            return []
        entries = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue
        return entries

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)


def _send(leader: str, token: str, spool: Spool, path: str, body: dict) -> None:
    """Send to the hub, spooling on failure so nothing is lost to a tunnel drop."""
    try:
        _request(leader, token, path, body)
    except WorkerError:
        spool.add(path, body)
        raise


def _flush_spool(leader: str, token: str, spool: Spool) -> None:
    entries = spool.pending()
    if not entries:
        return
    for entry in entries:
        _request(leader, token, entry["path"], entry["body"])
    spool.clear()


def _kimi_command(explicit: str | None) -> list[str]:
    if explicit:
        return [explicit]
    kimi = shutil.which("kimi")
    if not kimi:
        raise WorkerError("Kimi Code CLI not found on PATH (pass --kimi-bin)")
    return [kimi]


def _run_task(leader: str, token: str, spool: Spool, name: str, task: dict, brief: str, kimi: list[str], project: Path) -> None:
    task_id = task["id"]
    prompt = (
        "The complete readable engagement brief follows. Follow its in-scope targets, "
        "out-of-scope exclusions, and testing restrictions exactly. Stop if a task "
        "would exceed them. No pentest MCP target scope was recorded.\n\n"
        "<engagement_brief>\n" + brief + "\n</engagement_brief>\n\n"
        "Assigned task: " + task["prompt"] + "\n"
        "State your evidence and findings clearly in the final answer."
    )
    env = dict(os.environ)
    env.pop("PENTEST_ALLOWED_TARGETS", None)
    env.update(EVILKIT_MESH_LEADER=leader, EVILKIT_MESH_WORKER=name, EVILKIT_MESH_TASK=task_id)
    code = 1
    child = None
    try:
        child = subprocess.Popen(
            [*kimi, "-p", prompt],
            cwd=project,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        assert child.stdout is not None
        with child.stdout:
            for line in child.stdout:
                for offset in range(0, len(line), 10000):
                    chunk = line[offset:offset + 10000]
                    try:
                        _send(leader, token, spool, "/output", {"name": name, "task": task_id, "text": chunk})
                    except WorkerError:
                        # Tunnel down: keep reading the child and spooling.
                        pass
        code = child.wait()
    except Exception as exc:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        try:
            _send(leader, token, spool, "/output", {"name": name, "task": task_id, "text": f"\nPi worker error: {exc}\n"})
        except WorkerError:
            pass
    try:
        _send(leader, token, spool, "/complete", {"name": name, "task": task_id, "code": code})
    except WorkerError:
        pass


def _join(leader: str, token: str, spool: Spool, name: str, digest: str) -> str:
    """Register with the hub and return the brief text. Raises on any mismatch."""
    state = _request(leader, token, "/state")
    if state.get("mode") != "brief-unscoped" or state.get("scope") is not None:
        raise WorkerError("hub is not in brief-based unscoped mode")
    brief_data = _request(leader, token, "/brief")
    brief = brief_data["text"]
    local = hashlib.sha256(brief.encode("utf-8")).hexdigest()
    if local != state["brief_sha256"] or local != brief_data["sha256"] or local != digest:
        raise WorkerError("engagement brief changed during download")
    registered = _request(leader, token, "/register", {"name": name})
    if registered.get("brief_sha256") != digest:
        raise WorkerError("engagement brief changed during registration")
    _flush_spool(leader, token, spool)
    return brief


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Kimi as a Raspberry Pi worker for an unscoped brief-based mesh")
    parser.add_argument("--leader", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--kimi-bin", help="test or custom Kimi executable")
    parser.add_argument("--spool", type=Path, default=Path("~/.local/state/evilk-cmesh/spool.jsonl"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--max-backoff", type=float, default=60.0)
    args = parser.parse_args(argv)

    try:
        leader = _leader(args.leader)
        token = args.token_file.read_text(encoding="ascii").strip()
        if len(token) < 32:
            raise WorkerError("token file is empty or too short")
        kimi = _kimi_command(args.kimi_bin)
        project = args.project.expanduser().resolve()
        project.mkdir(parents=True, exist_ok=True)
        spool = Spool(args.spool.expanduser())

        # Fetch the brief once, up front, so we can pin its digest. Everything
        # after this is a reconnect loop: if the tunnel drops we back off and
        # rejoin rather than exiting, because the Pi is expected to be remote.
        state = _request(leader, token, "/state")
        if state.get("mode") != "brief-unscoped" or state.get("scope") is not None:
            raise WorkerError("hub is not in brief-based unscoped mode")
        brief_data = _request(leader, token, "/brief")
        brief = brief_data["text"]
        digest = hashlib.sha256(brief.encode("utf-8")).hexdigest()
        if digest != state["brief_sha256"] or digest != brief_data["sha256"]:
            raise WorkerError("engagement brief changed during download")

        backoff = 2.0
        joined = False
        while True:
            if not joined:
                try:
                    brief = _join(leader, token, spool, args.name, digest)
                    print(f"Pi mesh worker {args.name}: connected, brief {digest[:12]}", flush=True)
                    joined = True
                    backoff = 2.0
                except WorkerError as exc:
                    print(f"Pi mesh worker: waiting to join ({exc})", file=sys.stderr, flush=True)
                    time.sleep(backoff)
                    backoff = min(backoff * 2, args.max_backoff)
                    continue
            try:
                claim = _request(leader, token, "/claim", {"name": args.name})
                if claim.get("mode") != "brief-unscoped" or claim.get("brief_sha256") != digest:
                    raise WorkerError("engagement brief changed; refusing task")
                if claim["task"] is not None:
                    _run_task(leader, token, spool, args.name, claim["task"], brief, kimi, project)
                    if args.once:
                        return 0
                elif args.once:
                    return 0
                else:
                    time.sleep(2)
            except WorkerError as exc:
                # Tunnel dropped or hub restarted: rejoin on the next pass.
                print(f"Pi mesh worker: reconnecting ({exc})", file=sys.stderr, flush=True)
                joined = False
                time.sleep(backoff)
                backoff = min(backoff * 2, args.max_backoff)
    except (WorkerError, OSError, KeyError, TypeError) as exc:
        print(f"Pi mesh worker: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
