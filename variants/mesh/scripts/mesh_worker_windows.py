"""Standalone Windows Kimi worker for a brief-based Evilkit mesh.

Uses only Python's standard library and the user's existing Kimi Code install.
It deliberately accepts only a brief-unscoped hub and never edits target scope.
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


def _leader(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise WorkerError("leader must use a numeric loopback or Tailscale IPv4 address") from exc
    if parsed.scheme != "http" or port is None or address.version != 4 or not (address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10")) or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise WorkerError("leader must be an http://loopback-or-tailnet-ip:port URL")
    return value.rstrip("/")


def _request(leader: str, token: str, path: str, body: dict | None = None) -> dict:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        leader + path,
        data=payload,
        method="GET" if body is None else "POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise WorkerError(f"hub returned {exc.code}: {exc.read(300).decode('utf-8', 'replace')}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise WorkerError(f"hub unavailable: {exc}") from exc


def _kimi_command(explicit: str | None) -> list[str]:
    if explicit:
        return [explicit]
    appdata = os.environ.get("APPDATA")
    node = shutil.which("node")
    if not appdata or not node:
        raise WorkerError("Windows Kimi installation not found (APPDATA or node missing)")
    main = Path(appdata) / "npm" / "node_modules" / "@moonshot-ai" / "kimi-code" / "dist" / "main.mjs"
    if not main.is_file():
        raise WorkerError(f"Kimi JavaScript entry point not found: {main}")
    return [node, str(main)]


def _run_task(leader: str, token: str, name: str, task: dict, brief: str, kimi: list[str], project: Path) -> None:
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
                    _request(leader, token, "/output", {"name": name, "task": task_id, "text": chunk})
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
            _request(leader, token, "/output", {"name": name, "task": task_id, "text": f"\nWindows worker error: {exc}\n"})
        except WorkerError:
            pass
    _request(leader, token, "/complete", {"name": name, "task": task_id, "code": code})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Kimi as a Windows worker for an unscoped brief-based mesh")
    parser.add_argument("--leader", required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--kimi-bin", help="test or custom Kimi executable")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    try:
        leader = _leader(args.leader)
        token = args.token_file.read_text(encoding="ascii").strip()
        if len(token) < 32:
            raise WorkerError("token file is empty or too short")
        kimi = _kimi_command(args.kimi_bin)
        project = args.project.expanduser().resolve()
        project.mkdir(parents=True, exist_ok=True)
        state = _request(leader, token, "/state")
        if state.get("mode") != "brief-unscoped" or state.get("scope") is not None:
            raise WorkerError("hub is not in brief-based unscoped mode")
        brief_data = _request(leader, token, "/brief")
        brief = brief_data["text"]
        digest = hashlib.sha256(brief.encode("utf-8")).hexdigest()
        if digest != state["brief_sha256"] or digest != brief_data["sha256"]:
            raise WorkerError("engagement brief changed during download")
        registered = _request(leader, token, "/register", {"name": args.name})
        if registered.get("brief_sha256") != digest:
            raise WorkerError("engagement brief changed during registration")
        print(f"Windows mesh worker {args.name}: connected, brief {digest[:12]}", flush=True)
        while True:
            claim = _request(leader, token, "/claim", {"name": args.name})
            if claim.get("mode") != "brief-unscoped" or claim.get("brief_sha256") != digest:
                raise WorkerError("engagement brief changed; refusing task")
            if claim["task"] is not None:
                _run_task(leader, token, args.name, claim["task"], brief, kimi, project)
                if args.once:
                    return 0
            elif args.once:
                return 0
            else:
                time.sleep(2)
    except (WorkerError, OSError, KeyError, TypeError) as exc:
        print(f"Windows mesh worker: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
