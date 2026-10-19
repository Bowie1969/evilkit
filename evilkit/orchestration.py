"""Peer orchestration layer on top of the mesh hub.

The mesh was a one-way dispatcher: hub queues prompt tasks, workers run them.
This layer adds peer-to-peer coordination so multiple evilkit instances on
different devices can message each other, divide targets, share intel, hand
off tasks, and report progress — while every action on every device still
runs behind that device's own fail-closed scope gate.

The Board is a pure data layer with no HTTP of its own. The mesh.Hub owns an
instance and exposes its operations through signed instance endpoints. The
Board writes every state transition to an append-only JSONL journal and can
rebuild itself from that journal on restart.

Scope invariants:
- A ``position`` entry must be a subset of the hub's engagement scope. Any
  entry that fails validation is dropped and reported; nothing it contains
  can ever widen a device's own scope.
- A ``claim`` is refused when its asset host is outside the engagement scope.
- Messages carry data, never authority. The hub never writes scope into any
  device's .mcp.json.
- Credentials are not stored on the board. A message flagged ``secret=true``
  is journaled and warned, never echoed in plaintext in state(); plaintext
  credential-shaped payloads in claims/objectives are refused.
"""

from __future__ import annotations

import base64
import collections
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from . import scope as scope_mod


class BoardError(Exception):
    """Raised for every orchestration-level failure (routed to HTTP 400)."""


# --- caps and defaults --------------------------------------------------------

MAX_BODY_BYTES = 16 * 1024
MAX_SUBJECT_CHARS = 200
MAX_PENDING_PER_PEER = 200
DEFAULT_MSG_TTL = 6 * 3600
MAX_MSG_TTL = 7 * 24 * 3600
NONCE_WINDOW = 300  # seconds
NONCE_LRU = 4096
MAX_POSITIONS = 64
MAX_CAPABILITIES = 32
MAX_CHANNELS_PER_PEER = 32
MAX_CHANNEL_NAME = 64
MAX_OBJECTIVE_TITLE = 200
MAX_OBJECTIVE_EVIDENCE = 4096
MAX_OBJECTIVES = 1000

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_CHANNEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

OBJECTIVE_STATUSES = frozenset({"queued", "in_progress", "blocked", "done", "abandoned"})

# Patterns that look like credentials and must never land in persistent board
# state. Each pattern targets a plausible operator mistake; the goal is to
# refuse the entry rather than silently store it.
_CRED_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"(?i)\bpassw(?:or)?d\s*[:=]"),
    re.compile(r"(?i)\bpass\s*[:=]"),
    re.compile(r"(?i)\bsecret\s*[:=]"),
    re.compile(r"(?i)\btoken\s*[:=]"),
    re.compile(r"(?i)\bapi[_-]?key\s*[:=]"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    # NTLM hash or raw hex-ish long string that looks like a credential.
    re.compile(r"(?i)\bNTLM:[A-Fa-f0-9]{32,}"),
    re.compile(r"(?i):[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}"),
)


def _validate_name(name: str, *, label: str = "name") -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise BoardError(f"{label} must use letters, digits, - or _ (1-64 chars)")
    return name


def _validate_channel(name: str) -> str:
    if not isinstance(name, str) or not _CHANNEL_RE.match(name):
        raise BoardError("channel must use letters, digits, ., - or _ (1-64 chars)")
    return name


def _refuse_credentials(text: str, *, label: str) -> None:
    for pattern in _CRED_PATTERNS:
        if pattern.search(text):
            raise BoardError(
                f"{label} looks like it carries a credential; use secret messaging instead"
            )


def _asset_host(asset: str) -> str:
    """Return the host part of an ``asset`` string (host or host:port)."""
    if not isinstance(asset, str) or not asset.strip():
        raise BoardError("asset must be a non-empty string")
    if len(asset) > 256:
        raise BoardError("asset is too long (256 chars max)")
    # Strip optional service prefix like "http://" if someone passes a URL by mistake.
    if "://" in asset:
        raise BoardError("asset must be host or host:port, not a URL")
    host = asset.strip()
    if host.startswith("["):
        # bracketed IPv6
        end = host.find("]")
        if end == -1:
            raise BoardError("invalid IPv6 asset")
        return host[1:end]
    if host.count(":") == 1:
        host, _, _port = host.rpartition(":")
    return host


def _position_in_scope(entry: str, engagement_scope: str | None) -> bool:
    """Whether a per-instance reachable CIDR is a subset of the engagement scope.

    In brief-unscoped mode the hub has no recorded scope, so positions are
    accepted as self-declared (and still never grant authority on a receiving
    device, which has its own gate). In recorded-scope mode, each position
    entry must be contained by some engagement-scope network of the same
    family. A hostname entry is allowed only when it appears literally in the
    engagement scope.
    """
    if engagement_scope is None:
        return True
    try:
        pos_net = ipaddress.ip_network(entry, strict=False)
    except (ValueError, TypeError):
        # treat as hostname: must appear verbatim in the engagement list
        tokens = {t.strip().lower() for t in engagement_scope.split(",") if t.strip()}
        return entry.strip().lower() in tokens
    for raw in engagement_scope.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            engagement_net = ipaddress.ip_network(raw, strict=False)
        except (ValueError, TypeError):
            continue
        if (
            pos_net.version == engagement_net.version
            and pos_net.subnet_of(engagement_net)
        ):
            return True
    return False


# --- journal ------------------------------------------------------------------


class Journal:
    """Append-only JSONL event log with crash-safe rotation.

    One line per event: ``{"seq": N, "ts": T, "kind": K, "payload": {...}}``.
    The journal is the Board's durability contract; everything that mutates
    board state goes through ``append`` and is replayed on boot.
    """

    def __init__(self, path: Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Make sure the file exists so later appends never race on create.
        if not self.path.exists():
            self.path.touch(mode=0o600)
        self._lock = threading.Lock()

    def append(self, kind: str, payload: dict[str, Any], *, seq: int, ts: float) -> None:
        record = {"seq": seq, "ts": ts, "kind": kind, "payload": payload}
        line = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())

    def read(self) -> list[dict]:
        """Return every record in order, skipping blanks and corrupt lines."""
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        out: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and "seq" in record and "kind" in record:
                out.append(record)
        return out


# --- board --------------------------------------------------------------------


class Board:
    """In-memory coordination state, journaled.

    This class owns the instances, their inboxes, channel subscriptions, the
    claim register, the objective board, findings extensions, and the nonce
    replay window. Every state-mutating operation writes a journal entry and
    emits an event callback for downstream telemetry.

    ``on_event(kind, payload)`` is called synchronously under the lock, so
    callbacks must stay cheap; the mesh.Hub uses it to feed the dashboard and
    the existing tail/watch deque.
    """

    def __init__(
        self,
        *,
        engagement_scope: str | None,
        journal_path: Path | None = None,
        on_event: Callable[[str, dict], None] | None = None,
        clock: Callable[[], float] = time.time,
    ):
        self.engagement_scope = engagement_scope
        self.journal = Journal(journal_path) if journal_path is not None else None
        self.on_event = on_event or (lambda kind, payload: None)
        self.clock = clock
        self.lock = threading.RLock()
        # Instance records: name -> {name, pubkey (b64), role, capabilities,
        # position, seen, enrolled, revoked, next_seq}
        self.instances: dict[str, dict] = {}
        # Pending inbox messages, newest-last: name -> deque of records.
        self.inboxes: dict[str, collections.deque[dict]] = {}
        # Channel subscriptions: channel -> set of peer names.
        self.subscriptions: dict[str, set[str]] = {}
        # Claims: asset -> {owner, acquired, expires}.
        self.claims: dict[str, dict] = {}
        # Objectives: id -> record.
        self.objectives: dict[str, dict] = {}
        # Monotonic sequence used for inbox IDs and journal order.
        self.seq = 0
        # Nonce replay window: (name, nonce) -> expiry_ts, bounded by LRU.
        self._nonces: collections.OrderedDict[tuple[str, str], float] = collections.OrderedDict()

    # --- plumbing ---------------------------------------------------------

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _journal(self, kind: str, payload: dict, *, seq: int, ts: float) -> None:
        if self.journal is not None:
            self.journal.append(kind, payload, seq=seq, ts=ts)
        try:
            self.on_event(kind, {"seq": seq, "ts": ts, **payload})
        except Exception:
            pass

    # --- replay -----------------------------------------------------------

    def replay(self) -> None:
        """Rebuild the board state from a persisted journal."""
        if self.journal is None:
            return
        with self.lock:
            # Reset so a second replay is deterministic.
            self.instances.clear()
            self.inboxes.clear()
            self.subscriptions.clear()
            self.claims.clear()
            self.objectives.clear()
            self.seq = 0
            for record in self.journal.read():
                kind = record.get("kind", "")
                payload = record.get("payload") or {}
                seq = int(record.get("seq") or 0)
                if seq > self.seq:
                    self.seq = seq
                self._apply(kind, payload, seq=seq, ts=float(record.get("ts") or 0.0))
            # Expire anything whose TTL already passed.
            self._expire_locked(self.clock())

    def _apply(self, kind: str, payload: dict, *, seq: int, ts: float) -> None:
        """Pure state-transition apply used by replay. No journaling, no events."""
        if kind == "instance_register":
            name = payload.get("name")
            if not name:
                return
            self.instances[name] = {
                "name": name,
                "pubkey": payload.get("pubkey", ""),
                "role": payload.get("role", ""),
                "capabilities": list(payload.get("capabilities") or []),
                "position": list(payload.get("position") or []),
                "position_rejected": list(payload.get("position_rejected") or []),
                "enrolled": ts,
                "seen": ts,
                "revoked": False,
                "next_seq": 0,
            }
            self.inboxes.setdefault(name, collections.deque())
        elif kind == "instance_update":
            inst = self.instances.get(payload.get("name"))
            if inst is None:
                return
            for key in ("role", "capabilities", "position", "position_rejected"):
                if key in payload:
                    inst[key] = payload[key] if not isinstance(payload[key], tuple) else list(payload[key])
            inst["seen"] = ts
        elif kind == "instance_heartbeat":
            inst = self.instances.get(payload.get("name"))
            if inst is not None:
                inst["seen"] = ts
        elif kind == "instance_revoke":
            inst = self.instances.get(payload.get("name"))
            if inst is not None:
                inst["revoked"] = True
        elif kind == "msg_send":
            self._deliver_locked(payload, seq=seq, ts=ts, from_replay=True)
        elif kind == "msg_acked":
            name = payload.get("to")
            ids = set(payload.get("ids") or [])
            if name in self.inboxes and ids:
                self.inboxes[name] = collections.deque(
                    m for m in self.inboxes[name] if m["id"] not in ids
                )
        elif kind == "channel_subscribe":
            channel = payload.get("channel")
            name = payload.get("name")
            if channel and name:
                self.subscriptions.setdefault(channel, set()).add(name)
        elif kind == "channel_unsubscribe":
            channel = payload.get("channel")
            name = payload.get("name")
            if channel in self.subscriptions and name:
                self.subscriptions[channel].discard(name)
                if not self.subscriptions[channel]:
                    del self.subscriptions[channel]
        elif kind == "claim_acquire":
            self.claims[payload["asset"]] = {
                "asset": payload["asset"],
                "owner": payload["owner"],
                "acquired": ts,
                "expires": float(payload["expires"]),
            }
        elif kind == "claim_release":
            self.claims.pop(payload.get("asset"), None)
        elif kind == "objective_upsert":
            oid = payload["id"]
            self.objectives[oid] = {
                "id": oid,
                "title": payload.get("title", ""),
                "status": payload.get("status", "queued"),
                "owner": payload.get("owner"),
                "requires": list(payload.get("requires") or []),
                "evidence": payload.get("evidence", ""),
                "updated": ts,
            }

    # --- instances --------------------------------------------------------

    def register_instance(
        self,
        *,
        name: str,
        pubkey_b64: str,
        role: str,
        capabilities: list[str],
        position: list[str],
    ) -> dict:
        _validate_name(name, label="instance name")
        try:
            pubkey_bytes = base64.b64decode(pubkey_b64, validate=True)
        except ValueError as exc:
            raise BoardError("pubkey must be base64-encoded 32 bytes") from exc
        if len(pubkey_bytes) != 32:
            raise BoardError("pubkey must decode to exactly 32 bytes")
        if not isinstance(role, str) or len(role) > 64:
            raise BoardError("role must be a string of 0-64 characters")
        caps = list(capabilities or [])
        if len(caps) > MAX_CAPABILITIES:
            raise BoardError(f"capabilities exceed {MAX_CAPABILITIES} entries")
        for cap in caps:
            if not isinstance(cap, str) or not cap or len(cap) > 64:
                raise BoardError("each capability must be a 1-64 char string")
        pos_entries = list(position or [])
        if len(pos_entries) > MAX_POSITIONS:
            raise BoardError(f"position exceeds {MAX_POSITIONS} entries")
        accepted: list[str] = []
        rejected: list[str] = []
        for entry in pos_entries:
            if not isinstance(entry, str) or not entry.strip():
                rejected.append(str(entry))
                continue
            entry = entry.strip()
            if _position_in_scope(entry, self.engagement_scope):
                accepted.append(entry)
            else:
                rejected.append(entry)
        with self.lock:
            existing = self.instances.get(name)
            if existing is not None:
                if existing.get("revoked"):
                    raise BoardError(f"instance {name} has been revoked and cannot re-register")
                stored_pk = existing.get("pubkey")
                if stored_pk and stored_pk != pubkey_b64:
                    raise BoardError(f"instance {name} is enrolled with a different key")
            ts = self.clock()
            seq = self._next_seq()
            payload = {
                "name": name,
                "pubkey": pubkey_b64,
                "role": role,
                "capabilities": caps,
                "position": accepted,
                "position_rejected": rejected,
            }
            self._apply("instance_register", payload, seq=seq, ts=ts)
            self._journal("instance_register", payload, seq=seq, ts=ts)
            result = {
                "name": name,
                "accepted": accepted,
                "rejected": rejected,
                "engagement_scope": self.engagement_scope,
            }
        return result

    def enroll_pubkey(self, *, name: str, pubkey_b64: str, role: str = "") -> dict:
        """Operator-side pre-enrollment: record the pubkey before any traffic."""
        _validate_name(name, label="instance name")
        try:
            pubkey_bytes = base64.b64decode(pubkey_b64, validate=True)
        except ValueError as exc:
            raise BoardError("pubkey must be base64-encoded 32 bytes") from exc
        if len(pubkey_bytes) != 32:
            raise BoardError("pubkey must decode to exactly 32 bytes")
        with self.lock:
            existing = self.instances.get(name)
            if existing is not None and existing.get("pubkey") and existing["pubkey"] != pubkey_b64:
                raise BoardError(f"instance {name} already has a different key")
            if existing is not None and existing.get("revoked"):
                raise BoardError(f"instance {name} is revoked")
            ts = self.clock()
            seq = self._next_seq()
            payload = {
                "name": name,
                "pubkey": pubkey_b64,
                "role": role or (existing.get("role", "") if existing else ""),
                "capabilities": list((existing.get("capabilities", []) if existing else [])),
                "position": list((existing.get("position", []) if existing else [])),
                "position_rejected": list((existing.get("position_rejected", []) if existing else [])),
            }
            self._apply("instance_register", payload, seq=seq, ts=ts)
            self._journal("instance_register", payload, seq=seq, ts=ts)
            return {"name": name, "enrolled": True}

    def heartbeat(self, name: str) -> dict:
        with self.lock:
            inst = self.instances.get(name)
            if inst is None:
                raise BoardError("instance is not registered")
            if inst.get("revoked"):
                raise BoardError("instance is revoked")
            ts = self.clock()
            seq = self._next_seq()
            payload = {"name": name}
            self._apply("instance_heartbeat", payload, seq=seq, ts=ts)
            self._journal("instance_heartbeat", payload, seq=seq, ts=ts)
            return {"name": name, "seen": ts}

    def revoke(self, name: str) -> dict:
        with self.lock:
            inst = self.instances.get(name)
            if inst is None:
                raise BoardError(f"unknown instance: {name}")
            ts = self.clock()
            seq = self._next_seq()
            payload = {"name": name}
            self._apply("instance_revoke", payload, seq=seq, ts=ts)
            self._journal("instance_revoke", payload, seq=seq, ts=ts)
            return {"name": name, "revoked": True}

    def get_pubkey(self, name: str) -> str | None:
        with self.lock:
            inst = self.instances.get(name)
            if inst is None or inst.get("revoked"):
                return None
            key = inst.get("pubkey")
            return key or None

    def is_revoked(self, name: str) -> bool:
        with self.lock:
            inst = self.instances.get(name)
            return bool(inst and inst.get("revoked"))

    # --- replay protection ------------------------------------------------

    def check_nonce(self, name: str, nonce: str, ts: float) -> None:
        """Reject stale timestamps and reused nonces inside the window."""
        now = self.clock()
        if abs(now - ts) > NONCE_WINDOW:
            raise BoardError("request timestamp is outside the replay window")
        if not isinstance(nonce, str) or not (8 <= len(nonce) <= 128):
            raise BoardError("nonce must be an 8-128 char token")
        key = (name, nonce)
        with self.lock:
            # Expire old nonces.
            expired = [k for k, exp in self._nonces.items() if exp < now - NONCE_WINDOW]
            for k in expired:
                self._nonces.pop(k, None)
            if key in self._nonces:
                raise BoardError("nonce has been used recently")
            self._nonces[key] = now
            self._nonces.move_to_end(key)
            while len(self._nonces) > NONCE_LRU:
                self._nonces.popitem(last=False)

    # --- messaging --------------------------------------------------------

    def _validate_message_envelope(
        self,
        *,
        from_name: str,
        subject: str,
        body: Any,
        reply_to: str | None,
        ttl: int | None,
        secret: bool,
    ) -> dict:
        if from_name not in self.instances:
            raise BoardError("sending instance is not registered")
        if self.instances[from_name].get("revoked"):
            raise BoardError("sending instance is revoked")
        if not isinstance(subject, str) or not subject.strip():
            raise BoardError("subject is required")
        if len(subject) > MAX_SUBJECT_CHARS:
            raise BoardError(f"subject exceeds {MAX_SUBJECT_CHARS} characters")
        try:
            body_json = json.dumps(body) if not isinstance(body, str) else body
        except (TypeError, ValueError) as exc:
            raise BoardError("message body is not JSON-serialisable") from exc
        if len(body_json.encode("utf-8")) > MAX_BODY_BYTES:
            raise BoardError(f"message body exceeds {MAX_BODY_BYTES} bytes")
        if reply_to is not None and (not isinstance(reply_to, str) or len(reply_to) > 64):
            raise BoardError("reply_to must be an id string under 64 chars")
        if ttl is None:
            ttl = DEFAULT_MSG_TTL
        if not isinstance(ttl, int) or ttl < 1 or ttl > MAX_MSG_TTL:
            raise BoardError(f"ttl must be an int in [1, {MAX_MSG_TTL}]")
        return {"subject": subject, "body": body_json, "reply_to": reply_to, "ttl": ttl, "secret": bool(secret)}

    def send_message(
        self,
        *,
        from_name: str,
        to_name: str,
        subject: str,
        body: Any,
        reply_to: str | None = None,
        ttl: int | None = None,
        secret: bool = False,
    ) -> dict:
        envelope = self._validate_message_envelope(
            from_name=from_name, subject=subject, body=body,
            reply_to=reply_to, ttl=ttl, secret=secret,
        )
        with self.lock:
            if to_name not in self.instances:
                raise BoardError(f"unknown recipient: {to_name}")
            if self.instances[to_name].get("revoked"):
                raise BoardError(f"recipient {to_name} is revoked")
            self._expire_locked(self.clock())
            ts = self.clock()
            seq = self._next_seq()
            msg_id = uuid.uuid4().hex[:16]
            payload = {
                "id": msg_id, "from": from_name, "to": to_name, "channel": None,
                "subject": envelope["subject"], "body": envelope["body"],
                "reply_to": envelope["reply_to"], "ttl": envelope["ttl"],
                "secret": envelope["secret"],
            }
            self._apply("msg_send", payload, seq=seq, ts=ts)
            self._journal("msg_send", payload, seq=seq, ts=ts)
            return {"id": msg_id, "seq": seq, "delivered_to": [to_name]}

    def publish_channel(
        self,
        *,
        from_name: str,
        channel: str,
        body: Any,
        subject: str = "",
        ttl: int | None = None,
        secret: bool = False,
    ) -> dict:
        _validate_channel(channel)
        envelope = self._validate_message_envelope(
            from_name=from_name, subject=subject or f"channel:{channel}", body=body,
            reply_to=None, ttl=ttl, secret=secret,
        )
        with self.lock:
            self._expire_locked(self.clock())
            targets = sorted(
                name for name in self.subscriptions.get(channel, set())
                if name in self.instances and not self.instances[name].get("revoked")
            )
            ts = self.clock()
            seq = self._next_seq()
            msg_id = uuid.uuid4().hex[:16]
            delivered: list[str] = []
            for name in targets:
                if name == from_name:
                    continue
                payload = {
                    "id": uuid.uuid4().hex[:16], "from": from_name, "to": name,
                    "channel": channel, "subject": envelope["subject"],
                    "body": envelope["body"], "reply_to": None,
                    "ttl": envelope["ttl"], "secret": envelope["secret"],
                    "group_id": msg_id,
                }
                sub_seq = self._next_seq()
                self._apply("msg_send", payload, seq=sub_seq, ts=ts)
                self._journal("msg_send", payload, seq=sub_seq, ts=ts)
                delivered.append(name)
            return {"id": msg_id, "channel": channel, "seq": seq, "delivered_to": delivered}

    def _deliver_locked(self, payload: dict, *, seq: int, ts: float, from_replay: bool = False) -> None:
        to = payload.get("to")
        if not to or to not in self.instances:
            return
        box = self.inboxes.setdefault(to, collections.deque())
        inst = self.instances[to]
        inst_seq = int(inst.get("next_seq") or 0) + 1
        inst["next_seq"] = inst_seq
        record = {
            "id": payload["id"],
            "seq": inst_seq,
            "from": payload["from"],
            "to": to,
            "channel": payload.get("channel"),
            "subject": payload.get("subject", ""),
            "body": payload.get("body", ""),
            "reply_to": payload.get("reply_to"),
            "secret": bool(payload.get("secret")),
            "ts": ts,
            "expires": ts + float(payload.get("ttl", DEFAULT_MSG_TTL)),
            "group_id": payload.get("group_id"),
            "hub_seq": seq,
        }
        box.append(record)
        while len(box) > MAX_PENDING_PER_PEER:
            dropped = box.popleft()
            # Only emit the drop event live, not during replay.
            if not from_replay:
                drop_seq = self._next_seq()
                self._journal("msg_dropped", {"to": to, "id": dropped["id"], "reason": "inbox_cap"},
                              seq=drop_seq, ts=self.clock())

    def read_inbox(self, name: str, *, after: int = 0) -> dict:
        with self.lock:
            if name not in self.instances:
                raise BoardError("instance is not registered")
            self._expire_locked(self.clock())
            box = self.inboxes.get(name) or collections.deque()
            msgs = [dict(m) for m in box if m["seq"] > after]
            return {"name": name, "messages": msgs, "has_more": False}

    def ack_messages(self, name: str, ids: list[str]) -> dict:
        with self.lock:
            if name not in self.instances:
                raise BoardError("instance is not registered")
            if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                raise BoardError("ids must be a list of strings")
            ids_set = set(ids)
            box = self.inboxes.get(name)
            if not box:
                return {"acked": [], "remaining": 0}
            acked = [m["id"] for m in box if m["id"] in ids_set]
            if acked:
                self.inboxes[name] = collections.deque(m for m in box if m["id"] not in ids_set)
                ts = self.clock()
                seq = self._next_seq()
                payload = {"to": name, "ids": acked}
                self._journal("msg_acked", payload, seq=seq, ts=ts)
            return {"acked": acked, "remaining": len(self.inboxes.get(name, []))}

    def _expire_locked(self, now: float) -> None:
        # TTL on inboxes.
        for name, box in list(self.inboxes.items()):
            if not box:
                continue
            kept = collections.deque(m for m in box if m["expires"] > now)
            if len(kept) != len(box):
                for m in box:
                    if m["expires"] <= now:
                        seq = self._next_seq()
                        self._journal(
                            "msg_expired",
                            {"to": name, "id": m["id"]},
                            seq=seq, ts=now,
                        )
                self.inboxes[name] = kept
        # TTL on claims.
        for asset, claim in list(self.claims.items()):
            if claim["expires"] <= now:
                seq = self._next_seq()
                self._apply("claim_release", {"asset": asset}, seq=seq, ts=now)
                self._journal("claim_release", {"asset": asset, "reason": "expired"},
                              seq=seq, ts=now)

    # --- channels ---------------------------------------------------------

    def subscribe(self, name: str, channel: str, *, active: bool = True) -> dict:
        _validate_channel(channel)
        with self.lock:
            if name not in self.instances:
                raise BoardError("instance is not registered")
            if self.instances[name].get("revoked"):
                raise BoardError("instance is revoked")
            current = {c for c, members in self.subscriptions.items() if name in members}
            ts = self.clock()
            seq = self._next_seq()
            if active:
                if channel in current:
                    return {"channel": channel, "subscribed": True}
                if len(current) >= MAX_CHANNELS_PER_PEER:
                    raise BoardError(f"{name} already subscribes to the max of {MAX_CHANNELS_PER_PEER} channels")
                payload = {"channel": channel, "name": name}
                self._apply("channel_subscribe", payload, seq=seq, ts=ts)
                self._journal("channel_subscribe", payload, seq=seq, ts=ts)
                return {"channel": channel, "subscribed": True}
            payload = {"channel": channel, "name": name}
            self._apply("channel_unsubscribe", payload, seq=seq, ts=ts)
            self._journal("channel_unsubscribe", payload, seq=seq, ts=ts)
            return {"channel": channel, "subscribed": False}

    def list_channels(self, *, name: str | None = None) -> dict:
        with self.lock:
            if name is None:
                return {
                    "channels": {c: sorted(members) for c, members in self.subscriptions.items()}
                }
            if name not in self.instances:
                raise BoardError("instance is not registered")
            return {
                "name": name,
                "channels": sorted(
                    c for c, members in self.subscriptions.items() if name in members
                ),
            }

    # --- claims -----------------------------------------------------------

    def acquire_claim(self, *, owner: str, asset: str, ttl: int | None = None) -> dict:
        if owner not in self.instances:
            raise BoardError("claiming instance is not registered")
        if self.instances[owner].get("revoked"):
            raise BoardError("claiming instance is revoked")
        if not isinstance(asset, str) or not asset.strip():
            raise BoardError("asset is required")
        asset = asset.strip()
        _refuse_credentials(asset, label="asset")
        host = _asset_host(asset)
        if self.engagement_scope is not None and not scope_mod.target_in_scope(
            host, self.engagement_scope
        ):
            raise BoardError(f"asset {asset!r} is outside the engagement scope")
        if ttl is None:
            ttl = 1800
        if not isinstance(ttl, int) or ttl < 1 or ttl > 24 * 3600:
            raise BoardError("ttl must be an int in [1, 86400]")
        with self.lock:
            self._expire_locked(self.clock())
            existing = self.claims.get(asset)
            if existing is not None and existing["owner"] != owner:
                return {
                    "ok": False,
                    "asset": asset,
                    "owner": existing["owner"],
                    "expires": existing["expires"],
                    "conflict": True,
                }
            ts = self.clock()
            seq = self._next_seq()
            expires = ts + ttl
            payload = {"asset": asset, "owner": owner, "expires": expires}
            self._apply("claim_acquire", payload, seq=seq, ts=ts)
            self._journal("claim_acquire", payload, seq=seq, ts=ts)
            return {"ok": True, "asset": asset, "owner": owner, "expires": expires}

    def release_claim(self, *, owner: str, asset: str) -> dict:
        with self.lock:
            self._expire_locked(self.clock())
            claim = self.claims.get(asset)
            if claim is None:
                return {"ok": False, "asset": asset, "reason": "not_claimed"}
            if claim["owner"] != owner:
                raise BoardError(f"{asset} is held by {claim['owner']}, not {owner}")
            ts = self.clock()
            seq = self._next_seq()
            payload = {"asset": asset}
            self._apply("claim_release", payload, seq=seq, ts=ts)
            self._journal("claim_release", {"asset": asset, "reason": "released"},
                          seq=seq, ts=ts)
            return {"ok": True, "asset": asset}

    def list_claims(self) -> list[dict]:
        with self.lock:
            self._expire_locked(self.clock())
            return [dict(c) for c in sorted(self.claims.values(), key=lambda x: x["acquired"])]

    # --- objectives -------------------------------------------------------

    def upsert_objective(
        self,
        *,
        from_name: str | None,
        id: str | None,
        title: str,
        status: str,
        owner: str | None = None,
        requires: list[str] | None = None,
        evidence: str = "",
    ) -> dict:
        if not isinstance(title, str) or not title.strip():
            raise BoardError("objective title is required")
        if len(title) > MAX_OBJECTIVE_TITLE:
            raise BoardError(f"title exceeds {MAX_OBJECTIVE_TITLE} characters")
        if status not in OBJECTIVE_STATUSES:
            raise BoardError(f"status must be one of: {sorted(OBJECTIVE_STATUSES)}")
        if not isinstance(evidence, str) or len(evidence) > MAX_OBJECTIVE_EVIDENCE:
            raise BoardError(f"evidence must be a string under {MAX_OBJECTIVE_EVIDENCE} chars")
        _refuse_credentials(evidence, label="objective evidence")
        _refuse_credentials(title, label="objective title")
        requires_list = list(requires or [])
        for req in requires_list:
            if not isinstance(req, str) or not req:
                raise BoardError("each requires entry must be a non-empty string")
        with self.lock:
            if owner is not None and owner not in self.instances:
                raise BoardError(f"unknown owner: {owner}")
            if from_name is not None and from_name not in self.instances:
                raise BoardError("sending instance is not registered")
            if id is None:
                id = uuid.uuid4().hex[:12]
            else:
                if not isinstance(id, str) or not id or len(id) > 64:
                    raise BoardError("id must be a 1-64 char string")
            for req in requires_list:
                if req not in self.objectives and req != id:
                    # Allow forward declaration but note it; return remains OK.
                    pass
            if len(self.objectives) >= MAX_OBJECTIVES and id not in self.objectives:
                raise BoardError(f"objective board is full ({MAX_OBJECTIVES})")
            ts = self.clock()
            seq = self._next_seq()
            payload = {
                "id": id, "title": title, "status": status,
                "owner": owner, "requires": requires_list, "evidence": evidence,
            }
            self._apply("objective_upsert", payload, seq=seq, ts=ts)
            self._journal("objective_upsert", payload, seq=seq, ts=ts)
            return dict(self.objectives[id])

    def list_objectives(self) -> list[dict]:
        with self.lock:
            return [dict(o) for o in sorted(self.objectives.values(), key=lambda x: x["id"])]

    # --- read-only summaries ---------------------------------------------

    def summary(self) -> dict:
        with self.lock:
            self._expire_locked(self.clock())
            peers = []
            now = self.clock()
            for inst in self.instances.values():
                peers.append({
                    "name": inst["name"],
                    "role": inst.get("role", ""),
                    "capabilities": list(inst.get("capabilities") or []),
                    "position": list(inst.get("position") or []),
                    "position_rejected": list(inst.get("position_rejected") or []),
                    "seen": inst.get("seen"),
                    "online": (now - (inst.get("seen") or 0)) < 90,
                    "enrolled": inst.get("enrolled"),
                    "revoked": bool(inst.get("revoked")),
                    "pending": len(self.inboxes.get(inst["name"], ())),
                })
            return {
                "engagement_scope": self.engagement_scope,
                "peers": sorted(peers, key=lambda p: p["name"]),
                "claims": self.list_claims(),
                "objectives": self.list_objectives(),
                "channels": {c: sorted(m) for c, m in self.subscriptions.items()},
                "seq": self.seq,
            }

    def peers_reaching(self, host: str) -> list[str]:
        """Return instance names whose position covers ``host``."""
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        results: list[str] = []
        with self.lock:
            for inst in self.instances.values():
                if inst.get("revoked"):
                    continue
                for entry in inst.get("position") or []:
                    if addr is not None:
                        try:
                            net = ipaddress.ip_network(entry, strict=False)
                        except ValueError:
                            if entry.lower() == host.lower():
                                results.append(inst["name"])
                                break
                            continue
                        if addr.version == net.version and addr in net:
                            results.append(inst["name"])
                            break
                    else:
                        if entry.lower() == host.lower():
                            results.append(inst["name"])
                            break
        return sorted(results)


# --- signing contract ---------------------------------------------------------

def canonical_request(method: str, path: str, body: bytes, ts: str, nonce: str) -> bytes:
    """Bytes a request's signature covers. METHOD\\nPATH\\nsha256(body)\\nTS\\nNONCE."""
    import hashlib
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), path, body_hash, ts, nonce]).encode("utf-8")


__all__ = [
    "Board",
    "BoardError",
    "Journal",
    "canonical_request",
    "DEFAULT_MSG_TTL",
    "MAX_BODY_BYTES",
    "MAX_SUBJECT_CHARS",
    "MAX_PENDING_PER_PEER",
    "NONCE_WINDOW",
    "OBJECTIVE_STATUSES",
]
