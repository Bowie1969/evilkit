"""Instance-side daemon: register, heartbeat, and mirror the inbox to a spool.

Each evilkit instance that participates in the orchestration layer runs one
of these daemons. It talks to the hub over the signed instance protocol
(ed25519) and mirrors the hub's view of this peer's inbox into a local JSONL
spool. The agent process on this device reads the spool through the
``evilkit-mesh`` MCP tools, so inbox reads stay instant even when the hub is
briefly unreachable.

The daemon never acts on message content; it only transports it. Every
action the agent takes on receipt still runs behind that device's own
scope gate. The hub is a messenger, not an authority.
"""

from __future__ import annotations

import base64
import json
import os
import signal
import tempfile
import threading
import time
from pathlib import Path

from . import _ed25519
from .mesh import MeshError, _signed_request, _url


DEFAULT_HEARTBEAT = 30.0
DEFAULT_POLL = 2.0
SPOOL_FILE = "inbox.jsonl"
STATUS_FILE = "status.json"


class InstanceDaemon:
    def __init__(
        self,
        *,
        name: str,
        leader: str,
        sk: bytes,
        pk: bytes,
        spool: Path,
        role: str = "",
        capabilities: list[str] | None = None,
        position: list[str] | None = None,
        channels: list[str] | None = None,
        poll_interval: float = DEFAULT_POLL,
        heartbeat_interval: float = DEFAULT_HEARTBEAT,
    ):
        self.name = name
        self.base = _url(leader)
        self.sk = sk
        self.pk = pk
        self.pk_b64 = base64.b64encode(pk).decode("ascii")
        self.role = role
        self.capabilities = list(capabilities or [])
        self.position = list(position or [])
        self.channels = list(channels or [])
        self.spool = Path(spool).expanduser()
        self.poll_interval = float(poll_interval)
        self.heartbeat_interval = float(heartbeat_interval)
        self._stop = threading.Event()
        self._after = 0
        self.spool.mkdir(parents=True, exist_ok=True)

    def _spool_path(self) -> Path:
        return self.spool / SPOOL_FILE

    def _status_path(self) -> Path:
        return self.spool / STATUS_FILE

    def _write_status(self, extra: dict) -> None:
        path = self._status_path()
        record = {
            "name": self.name,
            "leader": self.base,
            "after": self._after,
            "updated": time.time(),
            **extra,
        }
        tmp_fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".new")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                json.dump(record, handle, sort_keys=True)
                handle.write("\n")
            os.replace(tmp_name, path)
        finally:
            Path(tmp_name).unlink(missing_ok=True)

    def _append_messages(self, msgs: list[dict]) -> None:
        if not msgs:
            return
        path = self._spool_path()
        with open(path, "a", encoding="utf-8") as handle:
            for msg in msgs:
                handle.write(json.dumps(msg, sort_keys=True) + "\n")
                handle.flush()
            os.fsync(handle.fileno())

    def register(self) -> dict:
        return _signed_request(
            self.base, name=self.name, sk=self.sk, pk=self.pk,
            method="POST", path="/instance/register",
            data={
                "pubkey": self.pk_b64,
                "role": self.role,
                "capabilities": self.capabilities,
                "position": self.position,
            },
        )

    def subscribe_channels(self) -> list[dict]:
        results = []
        for channel in self.channels:
            results.append(_signed_request(
                self.base, name=self.name, sk=self.sk, pk=self.pk,
                method="POST", path="/channel/subscribe",
                data={"channel": channel, "active": True},
            ))
        return results

    def heartbeat(self) -> dict:
        return _signed_request(
            self.base, name=self.name, sk=self.sk, pk=self.pk,
            method="POST", path="/instance/heartbeat", data={},
        )

    def pull_inbox(self) -> dict:
        res = _signed_request(
            self.base, name=self.name, sk=self.sk, pk=self.pk,
            method="GET", path=f"/inbox?after={self._after}",
        )
        msgs = res.get("messages") or []
        if msgs:
            self._append_messages(msgs)
            self._after = max(self._after, max(m["seq"] for m in msgs))
        return res

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> int:
        """Register, subscribe, then poll inbox and heartbeat until stop()."""
        self.register()
        self.subscribe_channels()
        self._write_status({"status": "running"})
        last_heartbeat = 0.0
        while not self._stop.is_set():
            now = time.time()
            try:
                self.pull_inbox()
            except MeshError as exc:
                self._write_status({"status": "degraded", "error": str(exc)})
            else:
                self._write_status({"status": "running"})
            if now - last_heartbeat >= self.heartbeat_interval:
                try:
                    self.heartbeat()
                    last_heartbeat = now
                except MeshError as exc:
                    self._write_status({"status": "degraded", "error": str(exc)})
            self._stop.wait(self.poll_interval)
        self._write_status({"status": "stopped"})
        return 0


def read_spool(spool: Path, *, after: int = 0) -> list[dict]:
    """Agent-side helper: read mirrored messages whose seq > after."""
    path = Path(spool).expanduser() / SPOOL_FILE
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("seq", 0) > after:
            out.append(record)
    return sorted(out, key=lambda m: m["seq"])


def install_signal_handlers(daemon: InstanceDaemon) -> None:
    def _handler(signum, frame):  # pragma: no cover
        daemon.stop()
    try:
        signal.signal(signal.SIGTERM, _handler)
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError):
        pass
