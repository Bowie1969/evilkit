"""Synthetic REA control-plane teaching range (stdlib only).

Emulates the *shape* of REA's published control plane on a loopback-only
estate: a SAML assertion -> SSH-CA trust chain (sshephalopod), KMS
envelope-wrapped secrets with an emulated confused-deputy unwrap bug
(shush), IAM credentials wrapped to an SSH private key (credulous), and
stack manifests as the delivery mechanism (stackup).

Every request to every service appends one JSON line to the estate's
evidence journal (``<root>/evidence.jsonl``). Scoring reads that journal
and nothing else — witness over testimony.

The estate has two variants, chosen at prepare time and recorded in
``<root>/variant.txt`` (the estate on disk is the source of truth):

- ``rea`` (default): the synthetic confused-deputy KMS unwrap.
- ``cve``: the confused deputy is FIXED; instead the estate teaches two
  disclosed bug shapes as honest behavioral stand-ins — CVE-2014-6271
  (Shellshock) env-function injection on shush /exec, and a CVE-2016-2107
  (OpenSSL AES-NI CBC padding oracle) class byte-at-a-time oracle on the
  KMS crown envelope. The estate emulates the observable vulnerable
  behavior; it never runs the real vulnerable software.

Nothing here binds a non-loopback interface, and nothing authenticates
anything real.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HOST = "127.0.0.1"
DEFAULT_ROOT = Path(os.environ.get("REA_RANGE_ROOT", "/tmp/rea-estate")).expanduser()
DEFAULT_PORTS = {
    "dns": 25353,
    "idp": 28080,
    "kms": 28081,
    "shush": 28082,
    "credulous": 28083,
    "objects": 28084,
}
SERVICE_NAMES = ("dns", "idp", "kms", "shush", "credulous", "objects")

#: Estate variants; prepare() writes the chosen one into <root>/variant.txt.
VARIANT_NAMES = ("rea", "cve")
#: The contract campaign each variant scores against.
VARIANT_CAMPAIGNS = {"rea": "rea-control-plane", "cve": "rea-control-plane-cve"}

#: CVE-2014-6271 (Shellshock) shape: a bash-function-definition prefix.
SHELLSHOCK_RE = re.compile(r"^\(\s*\)\s*\{\s*[^}]*\}\s*;\s*(.*)$")
#: Honesty label prepended to any emulated injection output.
SHELLSHOCK_MARKER = (
    "[emulated CVE-2014-6271 env-function injection — "
    "behavioral stand-in, not real vulnerable bash]"
)
CVE_SHELLSHOCK_REF = "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
CVE_PADDING_ORACLE_REF = "https://nvd.nist.gov/vuln/detail/CVE-2016-2107"
#: Ceiling for a Shellshock-shaped injected payload.
INJECT_TIMEOUT = 5.0
#: The crown envelope is one AES block: 4 printable hex bytes + PKCS#7 to 16.
CROWN_BLOCK_BYTES = 16
CROWN_TOKEN_BYTES = 4
CROWN_PAD_BYTE = 0x0B

#: Hard ceiling for every ssh-keygen/openssl subprocess.
SUB_TIMEOUT = 15.0
#: Ceiling for a user-supplied exec command.
EXEC_TIMEOUT = 10.0
#: How long stop() waits for a service thread before reporting it as stuck.
JOIN_TIMEOUT = 3.0
MAX_BODY_BYTES = 1_000_000


@dataclass
class ReaResult:
    """One estate operation, including structured output or a safe error."""

    ok: bool
    operation: str = ""
    data: dict = field(default_factory=dict)
    error: str = ""

    @property
    def success(self) -> bool:
        return self.ok


@dataclass
class _EstateRuntime:
    """The live handles of one running estate (registry entry)."""

    root: Path
    ports: dict
    stop_event: threading.Event
    threads: list = field(default_factory=list)
    http_servers: list = field(default_factory=list)
    udp_sockets: list = field(default_factory=list)


#: Singleton registry keyed by resolved estate root, so start/stop across
#: tool calls in one process agree about who owns which estate.
_ESTATES: dict[str, _EstateRuntime] = {}
_ESTATES_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Journal — the ONLY scoring input
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def journal(root: Path, service: str, event: str, **fields: object) -> str:
    """Append one JSON line to the estate's evidence journal; return the line."""
    entry: dict[str, object] = {"ts": _now_iso(), "service": service, "event": event}
    entry.update(fields)
    line = json.dumps(entry, sort_keys=True)
    with open(root / "evidence.jsonl", "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
    return line


def variant_of(root: str | Path = DEFAULT_ROOT) -> str | None:
    """The estate's variant as recorded in <root>/variant.txt on disk.

    Returns the stripped file contents (or None when missing/unreadable).
    The estate on disk is the source of truth; callers validate the value
    against VARIANT_NAMES.
    """
    path = Path(root).expanduser().resolve() / "variant.txt"
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


# ---------------------------------------------------------------------------
# Subprocess helpers — argv lists only, timeout, honest errors
# ---------------------------------------------------------------------------

def _require_binary(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"{name} is required for the REA range but was not found on PATH")
    return path


def _run_binary(
    operation: str,
    argv: list[str],
    *,
    input_bytes: bytes | None = None,
    text: bool = False,
) -> subprocess.CompletedProcess:
    """Run ssh-keygen/openssl by argv list (never a shell), bounded and checked."""
    try:
        completed = subprocess.run(
            argv,
            input=input_bytes,
            capture_output=True,
            text=text,
            timeout=SUB_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"{argv[0]} not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{operation} timed out after {SUB_TIMEOUT:g} seconds") from exc
    except OSError as exc:
        raise RuntimeError(f"could not run {argv[0]}: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode("utf-8", "replace")
        raise RuntimeError(f"{operation} failed: {stderr.strip()[:400]}")
    return completed


def _openssl_encrypt(plaintext: bytes, password: str, salt_hex: str) -> str:
    """AES-256-CBC with PBKDF2 (10000 iterations) and a fixed salt; base64 out.

    The salt (8 bytes / 16 hex chars) is passed explicitly so the caller's
    envelope ``nonce`` field IS the salt and decrypt can reuse it verbatim.
    """
    completed = _run_binary(
        "openssl enc",
        [
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "10000",
            "-S", salt_hex, "-pass", f"pass:{password}", "-a", "-A",
        ],
        input_bytes=plaintext,
    )
    return completed.stdout.decode("ascii").strip()


def _openssl_decrypt(ciphertext: str, password: str, salt_hex: str) -> str:
    completed = _run_binary(
        "openssl enc -d",
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000",
            "-S", salt_hex, "-pass", f"pass:{password}", "-a", "-A",
        ],
        input_bytes=ciphertext.encode("ascii"),
    )
    return completed.stdout.decode("utf-8", "replace").strip()


# ---------------------------------------------------------------------------
# prepare — build the estate layout
# ---------------------------------------------------------------------------

def prepare(
    root: str | Path = DEFAULT_ROOT,
    ports: dict | None = None,
    variant: str = "rea",
) -> ReaResult:
    """Create the estate layout under ``root``. Honest refusal if already built.

    ``variant`` is "rea" (the synthetic confused-deputy estate) or "cve"
    (confused deputy fixed; Shellshock-shaped shush exec and a CBC padding
    oracle gating the crown instead). The choice is recorded in
    ``<root>/variant.txt`` — the estate on disk is the source of truth.
    """
    if variant not in VARIANT_NAMES:
        return ReaResult(
            False, "prepare",
            error=f"unknown variant {variant!r} — expected one of {', '.join(VARIANT_NAMES)}",
        )
    estate = Path(root).expanduser().resolve()
    prepared = estate / "prepared.json"
    if prepared.is_file():
        return ReaResult(
            False, "prepare",
            error=f"estate at {estate} is already prepared — stop it and remove the directory to rebuild",
        )
    if estate.exists() and not estate.is_dir():
        return ReaResult(False, "prepare", error=f"estate root {estate} exists and is not a directory")

    try:
        _require_binary("ssh-keygen")
        _require_binary("openssl")
    except FileNotFoundError as exc:
        return ReaResult(False, "prepare", error=str(exc))

    resolved = dict(DEFAULT_PORTS)
    if ports:
        resolved.update(ports)

    try:
        for sub in (
            "ca", "kms", "objects", "apps/billing", "apps/prod-api",
            "stacks", "workstation", "dns", "idp-scratch",
        ):
            (estate / sub).mkdir(parents=True, exist_ok=True)

        # CA keypair — parked at the estate root (the emulated sshephalopod S3 mistake).
        _run_binary("ssh-keygen (CA keypair)", [
            "ssh-keygen", "-t", "ed25519", "-N", "",
            "-f", str(estate / "ca" / "ca_key"), "-C", "rea-teaching-ca",
        ])

        # Workstation key — the "stolen" operator-side identity credulous derives from.
        _run_binary("ssh-keygen (workstation key)", [
            "ssh-keygen", "-t", "ed25519", "-N", "",
            "-f", str(estate / "workstation" / "id_ed25519"), "-C", "rea-workstation",
        ])

        # Master KMS key, 0600.
        master_key = secrets.token_bytes(32).hex()
        master_path = estate / "kms" / "master.key"
        master_path.write_text(master_key + "\n", encoding="utf-8")
        master_path.chmod(0o600)

        # Envelope-wrapped app secrets. The plaintext is planted NOWHERE:
        # the only route to it is KMS unwrap + openssl decrypt.
        plaintexts = {
            "billing": {"BILLING_DB_PASSWORD": "billing-" + secrets.token_hex(12)},
            "prod-api": {"PROD_API_TOKEN": "prod-" + secrets.token_hex(12)},
        }
        for app, app_secrets in plaintexts.items():
            data_key = secrets.token_bytes(32).hex()
            env: dict[str, object] = {}
            for var, plaintext in app_secrets.items():
                salt = secrets.token_hex(8)
                wrap_salt = secrets.token_hex(8)
                ct = _openssl_encrypt(plaintext.encode("utf-8"), data_key, salt)
                wrap_ct = _openssl_encrypt(data_key.encode("ascii"), master_key, wrap_salt)
                env[var + "_ENCRYPTED"] = {
                    "key_id": f"kms-{app}",
                    "context": {"app": app, "var": var},
                    "nonce": salt,
                    "ct": ct,
                    "wrapped_key": {"nonce": wrap_salt, "ct": wrap_ct},
                }
            manifest: dict[str, object] = {"app": app, "env": env}
            if variant == "cve":
                # Per-app token the fixed KMS /unwrap checks against X-App-Token.
                manifest["token"] = secrets.token_hex(16)
            (estate / "apps" / app / "app.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )

        if variant == "cve":
            # Crown: a 4-hex-char token, PKCS#7-padded to one AES block,
            # encrypted with the master key (-K/-iv, no salt). The plaintext
            # is planted NOWHERE — the token exists only as ciphertext and the
            # only route to it is the KMS padding oracle.
            crown_token = secrets.token_hex(CROWN_TOKEN_BYTES // 2)
            crown_plain = (
                crown_token.encode("ascii") + bytes([CROWN_PAD_BYTE]) * (CROWN_BLOCK_BYTES - CROWN_TOKEN_BYTES)
            )
            # 16-byte IV (32 hex chars). The spec's "-iv <16 hex chars>" would
            # make openssl zero-pad a short IV (warning on stderr); a full-size
            # IV is well-formed on every openssl.
            crown_iv = secrets.token_hex(16)
            crown_ct = _run_binary(
                "openssl enc (crown envelope)",
                ["openssl", "enc", "-aes-256-cbc", "-K", master_key, "-iv", crown_iv, "-nopad"],
                input_bytes=crown_plain,
            ).stdout
            if len(crown_ct) != CROWN_BLOCK_BYTES:
                raise RuntimeError(f"crown envelope is {len(crown_ct)} bytes, expected {CROWN_BLOCK_BYTES}")
            (estate / "crown_envelope.json").write_text(
                json.dumps({"iv": crown_iv, "ct": crown_ct.hex()}, indent=2) + "\n",
                encoding="utf-8",
            )
            (estate / "README.txt").write_text(
                "REA teaching estate — CVE variant\n"
                "emulated CVE behavior: (a) CVE-2014-6271 class — caller env parsed "
                "as function definitions; (b) CVE-2016-2107 class — CBC padding oracle "
                "on the crown envelope; behavioral stand-ins, not the real vulnerable "
                "software; the 4-byte crown token exists only as ciphertext.\n"
                f"CVE-2014-6271: {CVE_SHELLSHOCK_REF}\n"
                f"CVE-2016-2107: {CVE_PADDING_ORACLE_REF}\n",
                encoding="utf-8",
            )
        else:
            # Crown flag — reachable only through shush /exec with decrypted env.
            flag_token = "REA{" + secrets.token_hex(8) + "}"
            (estate / "apps" / "prod-api" / "flag.txt").write_text(flag_token + "\n", encoding="utf-8")

        # Planted IdP credential, 0644 (the config-hygiene teaching point).
        idp_creds = {"user": "svc-" + secrets.token_hex(4), "password": secrets.token_hex(12)}
        (estate / "objects" / "idp_credentials.json").write_text(
            json.dumps(idp_creds, indent=2) + "\n", encoding="utf-8"
        )

        # The CA private key is ALSO reachable via the object store, 0644 —
        # the emulated sshephalopod S3 mistake.
        ca_copy = estate / "objects" / "ca_key"
        shutil.copyfile(estate / "ca" / "ca_key", ca_copy)
        ca_copy.chmod(0o644)

        # Fake IAM creds wrapped to the workstation private key (credulous shape).
        iam = {
            "AWS_ACCESS_KEY_ID": (
                "AKIA" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                                 for _ in range(16))
            ),
            "AWS_SECRET_ACCESS_KEY": secrets.token_hex(20),
        }
        iam_pass = hashlib.sha256(
            (estate / "workstation" / "id_ed25519").read_bytes()
        ).hexdigest()
        iam_salt = secrets.token_hex(8)
        iam_ct = _openssl_encrypt(json.dumps(iam).encode("utf-8"), iam_pass, iam_salt)
        (estate / "workstation" / "iam_keys.enc").write_text(
            json.dumps({"nonce": iam_salt, "ct": iam_ct}) + "\n", encoding="utf-8"
        )

        # Stackup-style manifests.
        for app, app_secrets in plaintexts.items():
            (estate / "stacks" / f"{app}.json").write_text(
                json.dumps(
                    {
                        "app": app,
                        "delivery": "stackup",
                        "env": sorted(f"{var}_ENCRYPTED" for var in app_secrets),
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

        # DNS zone: the CA public-key fingerprint.
        fingerprint = _run_binary(
            "ssh-keygen -lf (CA fingerprint)",
            ["ssh-keygen", "-lf", str(estate / "ca" / "ca_key.pub")],
            text=True,
        ).stdout.strip().split()[1]
        (estate / "dns" / "zone.txt").write_text(
            f'_ssh-ca.evilkit.rea. IN TXT "{fingerprint}"\n', encoding="utf-8"
        )

        # The variant on disk — the estate is the source of truth for start/score.
        (estate / "variant.txt").write_text(variant + "\n", encoding="utf-8")

        # Empty evidence journal — the ONLY scoring input.
        (estate / "evidence.jsonl").write_text("", encoding="utf-8")
    except (OSError, RuntimeError, ValueError) as exc:
        return ReaResult(False, "prepare", error=f"prepare failed: {exc}")

    prepared.write_text(
        json.dumps(
            {"root": str(estate), "created_at": _now_iso(), "ports": resolved, "variant": variant},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    journal(estate, "estate", "prepared", ports=resolved, variant=variant)
    return ReaResult(True, "prepare", data={"root": str(estate), "ports": resolved, "variant": variant})


# ---------------------------------------------------------------------------
# DNS (UDP) — the _ssh-ca TXT record
# ---------------------------------------------------------------------------

def _read_qname(packet: bytes, offset: int) -> tuple[str, int]:
    """Minimal label walk; compression pointers are not needed for the teaching query."""
    labels: list[str] = []
    pos = offset
    while True:
        if pos >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            pos += 2  # compression pointer — unexpected here; stop at the jump
            break
        pos += 1
        labels.append(packet[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), pos


def _dns_reply(query: bytes, zone_value: str) -> bytes | None:
    """Answer a TXT question with the zone value; anything else gets an empty answer."""
    if len(query) < 12:
        return None
    try:
        _, question_end = _read_qname(query, 12)
    except ValueError:
        return None
    if question_end + 4 > len(query):
        return None
    qtype = int.from_bytes(query[question_end:question_end + 2], "big")
    answers = 1 if qtype == 16 else 0
    response = query[:2] + b"\x81\x80\x00\x01" + answers.to_bytes(2, "big") + b"\x00\x00\x00\x00"
    response += query[12:question_end + 4]
    if qtype == 16:
        txt = zone_value.encode("utf-8")
        rdata = bytes([len(txt)]) + txt
        response += (
            b"\xc0\x0c\x00\x10\x00\x01"
            + (300).to_bytes(4, "big")
            + len(rdata).to_bytes(2, "big")
            + rdata
        )
    return response


def _zone_value(root: Path) -> str:
    """The TXT payload of dns/zone.txt (the text between the quotes)."""
    line = (root / "dns" / "zone.txt").read_text(encoding="utf-8").strip()
    if '"' in line:
        return line.split('"', 2)[1]
    return line


def _dns_loop(runtime: _EstateRuntime, sock: socket.socket) -> None:
    root = runtime.root
    zone = _zone_value(root)
    while not runtime.stop_event.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(data) < 12:
            continue
        name = ""
        try:
            name, _ = _read_qname(data, 12)
        except ValueError:
            pass
        journal(root, "dns", "dns_query", name=name)
        reply = _dns_reply(data, zone)
        if reply:
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# HTTP services — one shared handler, per-service routes
# ---------------------------------------------------------------------------

class _ReaHTTPHandler(BaseHTTPRequestHandler):
    """Requests are journaled by the route handlers, so the access log is silent."""

    service = ""
    root: Path | None = None
    state: dict | None = None
    on_get = None
    on_post = None

    def log_message(self, format, *args):  # noqa: A002 — deliberately quiet
        return

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("missing request body")
        if length > MAX_BODY_BYTES:
            raise ValueError("request body too large")
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        return payload

    def _send(self, status: int, payload: object) -> None:
        if isinstance(payload, bytes):
            data, content_type = payload, "text/plain"
        else:
            data = json.dumps(payload).encode("utf-8")
            content_type = "application/json"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _safe(self, fn, *args) -> tuple[int, object]:
        try:
            return fn(*args)
        except Exception as exc:  # honest 500, never a silent drop
            return 500, {"error": f"internal error: {exc}"}

    def do_GET(self) -> None:
        status, payload = self._safe(self.on_get, self)
        self._send(status, payload)

    def do_POST(self) -> None:
        try:
            body = self._json_body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": f"invalid JSON body: {exc}"})
            return
        status, payload = self._safe(self.on_post, self, body)
        self._send(status, payload)


def _service_factory(
    service: str, root: Path, state: dict, on_get, on_post
) -> type[_ReaHTTPHandler]:
    return type(
        f"Rea{service.capitalize()}Handler",
        (_ReaHTTPHandler,),
        {
            "service": service,
            "root": root,
            "state": state,
            "on_get": staticmethod(on_get),
            "on_post": staticmethod(on_post),
        },
    )


def _endpoint(handler: _ReaHTTPHandler) -> str:
    return handler.path.split("?", 1)[0].strip("/")


def _method_refused(handler: _ReaHTTPHandler, verbs: str) -> tuple[int, object]:
    return 405, {"error": f"this service speaks {verbs} only"}


def _unknown_endpoint(handler: _ReaHTTPHandler) -> tuple[int, object]:
    return 404, {"error": f"unknown endpoint {handler.path!r}"}


# -- IdP --------------------------------------------------------------------

def _idp_sso(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    try:
        creds = json.loads((root / "objects" / "idp_credentials.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return 500, {"error": f"could not read the IdP credential store: {exc}"}
    user = str(body.get("user", ""))
    password = str(body.get("password", ""))
    if not user or not password:
        journal(root, "idp", "sso_denied", user=user, reason="user and password are required")
        return 400, {"error": "user and password are required"}
    if user == creds["user"] and password == creds["password"]:
        token = secrets.token_hex(16)
        handler.state["assertions"][token] = {"principal": "root", "subject": user}
        journal(root, "idp", "assertion_issued", user=user, principal="root")
        return 200, {"assertion": token}
    journal(root, "idp", "sso_denied", user=user)
    return 403, {"error": "invalid credentials"}


def _idp_cert(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    state = handler.state
    assertion = str(body.get("assertion", ""))
    pubkey = str(body.get("pubkey", "")).strip()
    if not assertion or not pubkey:
        journal(root, "idp", "cert_denied", reason="assertion and pubkey are required")
        return 400, {"error": "assertion and pubkey are required"}
    record = state["assertions"].get(assertion)
    if record is None:
        journal(root, "idp", "cert_denied", reason="unknown assertion")
        return 403, {"error": "unknown or expired assertion"}
    serial = state["serial"]
    state["serial"] += 1
    scratch = root / "idp-scratch"
    scratch.mkdir(exist_ok=True)
    stem = f"req-{serial}-{secrets.token_hex(4)}"
    pub_path = scratch / f"{stem}.pub"
    pub_path.write_text(pubkey if pubkey.endswith("\n") else pubkey + "\n", encoding="utf-8")
    cert_path = scratch / f"{stem}-cert.pub"
    try:
        _run_binary("ssh-keygen -s (IdP cert sign)", [
            "ssh-keygen", "-s", str(root / "ca" / "ca_key"),
            "-I", record["subject"], "-n", record["principal"],
            "-V", "+1h", "-z", str(serial), str(pub_path),
        ])
        cert_text = cert_path.read_text(encoding="utf-8")
    except (OSError, RuntimeError) as exc:
        journal(root, "idp", "cert_denied", reason=f"signing failed: {exc}"[:500])
        return 500, {"error": f"certificate signing failed: {exc}"[:400]}
    journal(
        root, "idp", "signed_cert_issued",
        principal=record["principal"], subject=record["subject"], serial=serial,
    )
    return 200, {"cert": cert_text, "principal": record["principal"]}


def _idp_get(handler: _ReaHTTPHandler) -> tuple[int, object]:
    return _method_refused(handler, "POST")


def _idp_post(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    endpoint = _endpoint(handler)
    if endpoint == "sso":
        return _idp_sso(handler, body)
    if endpoint == "cert":
        return _idp_cert(handler, body)
    return _unknown_endpoint(handler)


# -- KMS --------------------------------------------------------------------

def _kms_variant(handler: _ReaHTTPHandler) -> str:
    return str((handler.state or {}).get("variant", "rea"))


def _app_token(root: Path, app: str) -> str:
    """The per-app token from its app.json ("" when missing — never a match)."""
    try:
        manifest = json.loads((root / "apps" / app / "app.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    return str(manifest.get("token", ""))


def _envelope_app(body: dict) -> str:
    """The app an unwrap envelope belongs to: its context, else its key_id prefix."""
    context = body.get("context")
    if isinstance(context, dict) and context.get("app"):
        return str(context["app"])
    key_id = str(body.get("key_id", ""))
    if key_id.startswith("kms-"):
        return key_id[len("kms-"):]
    return ""


def _kms_unwrap(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    wrapped = body.get("wrapped_key")
    if not isinstance(wrapped, dict) or "nonce" not in wrapped or "ct" not in wrapped:
        journal(root, "kms", "unwrap_failed", caller="anonymous",
                reason="wrapped_key with nonce and ct is required")
        return 400, {"error": "wrapped_key with nonce and ct is required"}
    try:
        master = (root / "kms" / "master.key").read_text(encoding="utf-8").strip()
        data_key = _openssl_decrypt(str(wrapped["ct"]), master, str(wrapped["nonce"]))
    except Exception as exc:
        journal(root, "kms", "unwrap_failed", caller="anonymous", reason=str(exc)[:500])
        return 500, {"error": f"unwrap failed: {exc}"[:400]}
    if _kms_variant(handler) == "cve":
        # CVE variant: the confused deputy is FIXED. The caller must present the
        # app's own token (X-App-Token header) matching the envelope's context.
        app = _envelope_app(body)
        if not handler.headers.get("X-App-Token") or (
            handler.headers.get("X-App-Token", "") != _app_token(root, app)
        ):
            journal(
                root, "kms", "unwrap_denied_context", caller="anonymous",
                key_id=str(body.get("key_id", "")), context=body.get("context"),
            )
            return 403, {"error": "caller token does not match the envelope's encryption context"}
    else:
        # Rea variant — emulated confused deputy (documented, intentional): the
        # caller's identity is never checked against the envelope's context.
        pass
    journal(
        root, "kms", "unwrap_called", caller="anonymous",
        key_id=str(body.get("key_id", "")), context=body.get("context"),
    )
    return 200, {"data_key": data_key}


def _crown_envelope(root: Path) -> dict:
    return json.loads((root / "crown_envelope.json").read_text(encoding="utf-8"))


def _crown_decrypt_block(root: Path, ciphertext: bytes) -> bytes:
    """AES-256-CBC decrypt with the master key and the crown IV, -nopad.

    Real openssl AES; the padding check is done in Python so the service
    only ever reports padding validity — that reporting IS the emulated
    CVE-2016-2107-class oracle.
    """
    master = (root / "kms" / "master.key").read_text(encoding="utf-8").strip()
    envelope = _crown_envelope(root)
    completed = _run_binary(
        "openssl enc -d (crown)",
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", master, "-iv", str(envelope["iv"]), "-nopad"],
        input_bytes=ciphertext,
    )
    return completed.stdout


def _pkcs7_valid(plaintext: bytes) -> bool:
    """Strict PKCS#7 padding check on the final block (1..16 bytes)."""
    if not plaintext:
        return False
    pad = plaintext[-1]
    if not 1 <= pad <= 16 or pad > len(plaintext):
        return False
    return plaintext[-pad:] == bytes([pad]) * pad


def _kms_crown_envelope(handler: _ReaHTTPHandler) -> tuple[int, object]:
    root = handler.root
    try:
        data = (root / "crown_envelope.json").read_bytes()
    except OSError as exc:
        return 500, {"error": f"crown envelope missing: {exc}"}
    journal(root, "kms", "crown_envelope_read")
    return 200, data


def _kms_oracle(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    ct_hex = str(body.get("ct_hex", ""))
    try:
        ciphertext = bytes.fromhex(ct_hex)
    except ValueError:
        return 400, {"error": "ct_hex must be hex-encoded"}
    if not ciphertext or len(ciphertext) % CROWN_BLOCK_BYTES != 0:
        return 400, {"error": f"ciphertext must be a whole number of {CROWN_BLOCK_BYTES}-byte blocks"}
    try:
        plaintext = _crown_decrypt_block(root, ciphertext)
    except Exception as exc:
        journal(root, "kms", "oracle_failed", reason=str(exc)[:500])
        return 500, {"error": f"oracle failed: {exc}"[:400]}
    if _pkcs7_valid(plaintext):
        journal(root, "kms", "oracle_padding_valid")
        return 200, {"padding": "valid"}
    journal(root, "kms", "oracle_padding_invalid")
    return 400, {"error": "padding invalid"}


def _kms_verify_crown(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    token = str(body.get("token", "")).strip()
    try:
        plaintext = _crown_decrypt_block(root, bytes.fromhex(_crown_envelope(root)["ct"]))
    except Exception as exc:
        journal(root, "kms", "crown_verify_failed", reason=str(exc)[:500])
        return 500, {"error": f"could not read the crown: {exc}"[:400]}
    crown_token = plaintext[:CROWN_TOKEN_BYTES].decode("ascii", "replace")
    if token and token == crown_token:
        journal(root, "kms", "crown_verified", token=token)
        return 200, {"verified": True, "token": token}
    journal(root, "kms", "crown_verify_denied", token=token)
    return 403, {"error": "token does not match the crown"}


def _kms_get(handler: _ReaHTTPHandler) -> tuple[int, object]:
    if _kms_variant(handler) == "cve":
        if _endpoint(handler) == "crown_envelope":
            return _kms_crown_envelope(handler)
        return _unknown_endpoint(handler)
    return _method_refused(handler, "POST")


def _kms_post(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    endpoint = _endpoint(handler)
    if endpoint == "unwrap":
        return _kms_unwrap(handler, body)
    if _kms_variant(handler) == "cve":
        if endpoint == "oracle":
            return _kms_oracle(handler, body)
        if endpoint == "verify_crown":
            return _kms_verify_crown(handler, body)
    return _unknown_endpoint(handler)


# -- shush ------------------------------------------------------------------

def _shellshock_injection(env: dict | None) -> tuple[str, str] | None:
    """The first Shellshock-shaped env value's payload and its bash output.

    Returns None when no value matches. The payload runs with real bash so
    the emulated behavior is observable — the output is labelled, never
    presented as genuine bash parsing.
    """
    for value in (env or {}).values():
        match = SHELLSHOCK_RE.match(str(value))
        if not match:
            continue
        payload = match.group(1)
        try:
            completed = subprocess.run(
                ["bash", "-c", payload],
                capture_output=True, text=True, timeout=INJECT_TIMEOUT, check=False,
            )
            output = completed.stdout
        except subprocess.TimeoutExpired:
            output = ""
        return payload, output
    return None


def _decrypt_app_env(root: Path, manifest: dict) -> dict[str, str]:
    """Unwrap the app's data key with the master key, then decrypt every secret."""
    master = (root / "kms" / "master.key").read_text(encoding="utf-8").strip()
    out: dict[str, str] = {}
    for name, envelope in (manifest.get("env") or {}).items():
        if not isinstance(envelope, dict) or not name.endswith("_ENCRYPTED"):
            continue
        wrapped = envelope.get("wrapped_key")
        if not isinstance(wrapped, dict):
            raise ValueError(f"envelope for {name!r} has no wrapped_key")
        data_key = _openssl_decrypt(str(wrapped["ct"]), master, str(wrapped["nonce"]))
        out[name[: -len("_ENCRYPTED")]] = _openssl_decrypt(
            str(envelope["ct"]), data_key, str(envelope["nonce"])
        )
    return out


def _shush_apps(handler: _ReaHTTPHandler) -> tuple[int, object]:
    root = handler.root
    apps = sorted(
        d.name for d in (root / "apps").iterdir()
        if d.is_dir() and (d / "app.json").is_file()
    )
    journal(root, "shush", "apps_listed", apps=apps)
    return 200, {"apps": apps}


def _shush_exec(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    app = str(body.get("app", ""))
    command = body.get("command")
    if not app:
        return 400, {"error": "app is required"}
    app_dir = root / "apps" / app
    if not (app_dir / "app.json").is_file():
        journal(root, "shush", "exec_denied", app=app, reason="unknown app")
        return 404, {"error": f"unknown app {app!r}"}
    if not isinstance(command, str) or not command.strip():
        journal(root, "shush", "exec_denied", app=app, reason="command must be a non-empty string")
        return 400, {"error": "command must be a non-empty string"}
    injection = None
    if str((handler.state or {}).get("variant", "rea")) == "cve":
        env_field = body.get("env")
        if isinstance(env_field, dict):
            injection = _shellshock_injection(env_field)
            if injection is not None:
                payload, _ = injection
                journal(root, "shush", "env_function_injection", app=app, payload=payload)
    try:
        manifest = json.loads((app_dir / "app.json").read_text(encoding="utf-8"))
        env_vars = _decrypt_app_env(root, manifest)
    except (OSError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        journal(root, "shush", "exec_failed", app=app, reason=str(exc)[:500])
        return 500, {"error": f"could not decrypt secrets for {app!r}: {exc}"[:400]}
    run_env = dict(os.environ)
    run_env.update(env_vars)
    try:
        completed = subprocess.run(
            command, shell=True, cwd=str(app_dir), env=run_env,
            capture_output=True, text=True, timeout=EXEC_TIMEOUT, check=False,
        )
    except subprocess.TimeoutExpired:
        journal(root, "shush", "exec_failed", app=app, reason=f"timed out after {EXEC_TIMEOUT:g}s")
        return 504, {"error": f"command timed out after {EXEC_TIMEOUT:g} seconds"}
    journal(
        root, "shush", "exec_called", app=app, command=command,
        returncode=completed.returncode,
        stdout=completed.stdout, stderr=completed.stderr,
    )
    stdout = completed.stdout
    if injection is not None:
        _, injected_output = injection
        stdout = f"{SHELLSHOCK_MARKER}\n{injected_output}{stdout}"
    return 200, {
        "app": app,
        "stdout": stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
    }


def _shush_get(handler: _ReaHTTPHandler) -> tuple[int, object]:
    if _endpoint(handler) == "apps":
        return _shush_apps(handler)
    return _unknown_endpoint(handler)


def _shush_post(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    if _endpoint(handler) == "exec":
        return _shush_exec(handler, body)
    return _unknown_endpoint(handler)


# -- credulous --------------------------------------------------------------

def _credulous_exec(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    root = handler.root
    command = body.get("command")
    if not isinstance(command, str) or not command.strip():
        return 400, {"error": "command must be a non-empty string"}
    key_path = root / "workstation" / "id_ed25519"
    enc_path = root / "workstation" / "iam_keys.enc"
    if not key_path.is_file() or not enc_path.is_file():
        journal(root, "credulous", "iam_exec_failed", reason="workstation key or iam_keys.enc missing")
        return 500, {"error": "workstation key or iam_keys.enc is missing"}
    try:
        password = hashlib.sha256(key_path.read_bytes()).hexdigest()
        envelope = json.loads(enc_path.read_text(encoding="utf-8"))
        plaintext = _openssl_decrypt(
            str(envelope["ct"]), password, str(envelope["nonce"])
        )
        creds = json.loads(plaintext)
    except Exception as exc:
        journal(root, "credulous", "iam_exec_failed", reason=str(exc)[:500])
        return 500, {"error": f"could not unlock IAM keys: {exc}"[:400]}
    run_env = dict(os.environ)
    run_env.update({str(key): str(value) for key, value in creds.items()})
    try:
        completed = subprocess.run(
            command, shell=True, cwd=str(root / "workstation"), env=run_env,
            capture_output=True, text=True, timeout=EXEC_TIMEOUT, check=False,
        )
    except subprocess.TimeoutExpired:
        journal(root, "credulous", "iam_exec_failed", reason=f"timed out after {EXEC_TIMEOUT:g}s")
        return 504, {"error": f"command timed out after {EXEC_TIMEOUT:g} seconds"}
    journal(
        root, "credulous", "iam_exec_called", command=command,
        returncode=completed.returncode,
        stdout=completed.stdout, stderr=completed.stderr,
    )
    return 200, {
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
    }


def _credulous_get(handler: _ReaHTTPHandler) -> tuple[int, object]:
    return _method_refused(handler, "POST")


def _credulous_post(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    if _endpoint(handler) == "exec":
        return _credulous_exec(handler, body)
    return _unknown_endpoint(handler)


# -- object store -----------------------------------------------------------

def _objects_read(handler: _ReaHTTPHandler, name: str) -> tuple[int, object]:
    root = handler.root
    objects_dir = (root / "objects").resolve()
    if not name or "/" in name or "\\" in name or ".." in name:
        journal(root, "objects", "object_read_denied", name=name, reason="invalid object name")
        return 400, {"error": "invalid object name"}
    path = (root / "objects" / name).resolve()
    if not str(path).startswith(str(objects_dir) + os.sep):
        journal(root, "objects", "object_read_denied", name=name, reason="path traversal refused")
        return 400, {"error": "path traversal refused"}
    if not path.is_file():
        journal(root, "objects", "object_read_missing", name=name)
        return 404, {"error": f"no object {name!r}"}
    journal(root, "objects", "object_read", name=name)
    return 200, path.read_bytes()


def _objects_get(handler: _ReaHTTPHandler) -> tuple[int, object]:
    prefix = "/objects/"
    if not handler.path.startswith(prefix):
        return _unknown_endpoint(handler)
    return _objects_read(handler, handler.path[len(prefix):])


def _objects_post(handler: _ReaHTTPHandler, body: dict) -> tuple[int, object]:
    return _method_refused(handler, "GET")


# ---------------------------------------------------------------------------
# start / stop / status
# ---------------------------------------------------------------------------

def _resolved_ports(estate: Path, ports: dict | None) -> dict:
    resolved = dict(DEFAULT_PORTS)
    prepared_file = estate / "prepared.json"
    if prepared_file.is_file():
        try:
            saved = json.loads(prepared_file.read_text(encoding="utf-8")).get("ports")
            if isinstance(saved, dict):
                resolved.update(saved)
        except (OSError, json.JSONDecodeError):
            pass
    if ports:
        resolved.update(ports)
    return resolved


def _serve_forever(server: HTTPServer) -> None:
    server.serve_forever(poll_interval=0.2)


def start(root: str | Path = DEFAULT_ROOT, ports: dict | None = None) -> ReaResult:
    """Bind every loopback service (port 0 = ephemeral) and start its thread.

    The variant is read from the estate's variant.txt on disk — the estate
    is the source of truth, never a caller parameter.
    """
    estate = Path(root).expanduser().resolve()
    with _ESTATES_LOCK:
        if str(estate) in _ESTATES:
            return ReaResult(False, "start", error=f"estate at {estate} is already running — stop it first")
    if not (estate / "prepared.json").is_file():
        return ReaResult(False, "start", error=f"estate not prepared at {estate} — run prepare first")
    variant = variant_of(estate)
    if variant not in VARIANT_NAMES:
        return ReaResult(
            False, "start",
            error=f"estate at {estate} has no valid variant.txt (expected one of {', '.join(VARIANT_NAMES)}) — run prepare first",
        )
    try:
        _require_binary("ssh-keygen")
        _require_binary("openssl")
    except FileNotFoundError as exc:
        return ReaResult(False, "start", error=str(exc))

    resolved = _resolved_ports(estate, ports)
    bound_socks: list[socket.socket] = []
    bound_servers: list[HTTPServer] = []
    actual: dict[str, int] = {}

    def _bind_udp(service_name: str) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((HOST, int(resolved[service_name])))
        except OSError as exc:
            sock.close()
            raise RuntimeError(
                f"could not bind {service_name} on {HOST}:{resolved[service_name]}: {exc}"
            ) from exc
        sock.settimeout(0.5)
        bound_socks.append(sock)
        actual[service_name] = sock.getsockname()[1]
        return sock

    def _bind_http(service_name: str, state: dict, on_get, on_post) -> HTTPServer:
        handler_class = _service_factory(service_name, estate, state, on_get, on_post)
        try:
            server = HTTPServer((HOST, int(resolved[service_name])), handler_class)
        except OSError as exc:
            raise RuntimeError(
                f"could not bind {service_name} on {HOST}:{resolved[service_name]}: {exc}"
            ) from exc
        bound_servers.append(server)
        actual[service_name] = server.server_address[1]
        return server

    try:
        dns_sock = _bind_udp("dns")
        idp_server = _bind_http("idp", {"assertions": {}, "serial": 1}, _idp_get, _idp_post)
        kms_server = _bind_http("kms", {"variant": variant}, _kms_get, _kms_post)
        shush_server = _bind_http("shush", {"variant": variant}, _shush_get, _shush_post)
        credulous_server = _bind_http("credulous", {}, _credulous_get, _credulous_post)
        objects_server = _bind_http("objects", {}, _objects_get, _objects_post)
    except RuntimeError as exc:
        for server in bound_servers:
            try:
                server.server_close()
            except Exception:
                pass
        for sock in bound_socks:
            try:
                sock.close()
            except OSError:
                pass
        return ReaResult(False, "start", error=str(exc))

    runtime = _EstateRuntime(root=estate, ports=dict(actual), stop_event=threading.Event())
    runtime.udp_sockets.append(dns_sock)
    runtime.http_servers.extend(
        [idp_server, kms_server, shush_server, credulous_server, objects_server]
    )
    targets = [
        ("dns", lambda: _dns_loop(runtime, dns_sock)),
        ("idp", lambda: _serve_forever(idp_server)),
        ("kms", lambda: _serve_forever(kms_server)),
        ("shush", lambda: _serve_forever(shush_server)),
        ("credulous", lambda: _serve_forever(credulous_server)),
        ("objects", lambda: _serve_forever(objects_server)),
    ]
    for name, target in targets:
        thread = threading.Thread(target=target, name=f"rea-{name}", daemon=True)
        thread.start()
        runtime.threads.append(thread)

    with _ESTATES_LOCK:
        _ESTATES[str(estate)] = runtime
    (estate / "running.json").write_text(
        json.dumps(
            {"ports": dict(actual), "pid": os.getpid(), "started_at": _now_iso()}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    journal(estate, "estate", "started", ports=dict(actual), variant=variant)
    return ReaResult(
        True, "start",
        data={"root": str(estate), "ports": dict(actual), "pid": os.getpid(), "variant": variant},
    )


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stop(root: str | Path = DEFAULT_ROOT) -> ReaResult:
    """Stop the estate's services and remove running.json."""
    estate = Path(root).expanduser().resolve()
    with _ESTATES_LOCK:
        runtime = _ESTATES.pop(str(estate), None)
    if runtime is None:
        running_file = estate / "running.json"
        if running_file.is_file():
            pid = None
            try:
                pid = json.loads(running_file.read_text(encoding="utf-8")).get("pid")
            except (OSError, json.JSONDecodeError):
                pass
            if isinstance(pid, int) and _pid_alive(pid):
                return ReaResult(
                    False, "stop",
                    error=f"estate at {estate} is running in another process (pid {pid}) — stop it there",
                )
            running_file.unlink(missing_ok=True)
            return ReaResult(True, "stop", data={"stopped": True, "note": "removed stale running.json"})
        return ReaResult(False, "stop", error=f"estate at {estate} is not running")

    runtime.stop_event.set()
    for server in runtime.http_servers:
        try:
            server.shutdown()
        except Exception:
            pass
    for thread in runtime.threads:
        thread.join(timeout=JOIN_TIMEOUT)
    for server in runtime.http_servers:
        server.server_close()
    for sock in runtime.udp_sockets:
        try:
            sock.close()
        except OSError:
            pass
    (estate / "running.json").unlink(missing_ok=True)
    journal(estate, "estate", "stopped")
    still_alive = [thread.name for thread in runtime.threads if thread.is_alive()]
    return ReaResult(True, "stop", data={"stopped": True, "threads_still_alive": still_alive})


def status(root: str | Path = DEFAULT_ROOT) -> ReaResult:
    """Prepared/running state plus a journal summary."""
    estate = Path(root).expanduser().resolve()
    if not (estate / "prepared.json").is_file():
        return ReaResult(False, "status", error=f"estate not prepared at {estate} — run prepare first")
    with _ESTATES_LOCK:
        running = str(estate) in _ESTATES
    running_file = estate / "running.json"
    if not running and running_file.is_file():
        try:
            pid = json.loads(running_file.read_text(encoding="utf-8")).get("pid")
            running = isinstance(pid, int) and _pid_alive(pid)
        except (OSError, json.JSONDecodeError):
            pass
    journal_path = estate / "evidence.jsonl"
    entries: list[dict] = []
    if journal_path.is_file():
        for line in journal_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return ReaResult(True, "status", data={
        "root": str(estate),
        "prepared": True,
        "running": running,
        "variant": variant_of(estate),
        "journal_lines": len(entries),
        "last_journal": entries[-5:],
    })


# ---------------------------------------------------------------------------
# score — the evidence journal is the ONLY input
# ---------------------------------------------------------------------------

def _witness_match(witness: str, entry: dict, flag_token: str, variant: str) -> bool:
    service = entry.get("service", "")
    event = entry.get("event", "")
    if variant == "cve":
        # CVE-variant witnesses (contracts/rea-cve-mission.json).
        if witness == "oracle_queried":
            return event in ("oracle_padding_invalid", "oracle_padding_valid")
        if witness == "crown_verified":
            return event == "crown_verified"
    if witness == "dns_txt_requested":
        return service == "dns" and event == "dns_query"
    if witness == "object_store_listed":
        return event == "object_read"
    if witness == "assertion_issued":
        return event == "assertion_issued"
    if witness == "signed_cert_issued":
        return event == "signed_cert_issued"
    if witness == "ca_key_read":
        return event == "object_read" and entry.get("name") == "ca_key"
    if witness == "unwrap_without_context":
        return event == "unwrap_called"
    if witness == "secret_decrypted":
        return service == "shush" and event == "exec_called"
    if witness == "iam_exec_called":
        return event == "iam_exec_called"
    if witness == "crown_exec":
        if service != "shush" or event != "exec_called" or entry.get("app") != "prod-api":
            return False
        if "flag" in str(entry.get("command", "")).lower():
            return True
        return bool(flag_token) and flag_token in str(entry.get("stdout", ""))
    return False


def _witness_evidence(
    witness: str, journal_lines: list[tuple[str, dict]], flag_token: str, variant: str
) -> str | None:
    for line, entry in journal_lines:
        if _witness_match(witness, entry, flag_token, variant):
            return line
    return None


def _crown_output_has_flag(
    journal_lines: list[tuple[str, dict]], flag_token: str
) -> bool:
    if not flag_token:
        return False
    return any(
        entry.get("service") == "shush"
        and entry.get("event") == "exec_called"
        and entry.get("app") == "prod-api"
        and flag_token in str(entry.get("stdout", ""))
        for _, entry in journal_lines
    )


def score(
    root: str | Path = DEFAULT_ROOT,
    contract: dict | None = None,
    variant: str = "rea",
) -> ReaResult:
    """Score the estate against the REA contract, using evidence.jsonl only.

    The variant is read from the estate's variant.txt on disk (error if
    missing); the ``variant`` argument must agree with it — the estate is
    the source of truth. The contract campaign must match the variant:
    "rea-control-plane" for "rea", "rea-control-plane-cve" for "cve".
    """
    estate = Path(root).expanduser().resolve()
    estate_variant = variant_of(estate)
    if estate_variant not in VARIANT_NAMES:
        return ReaResult(
            False, "score",
            error=(
                f"estate at {estate} has no valid variant.txt "
                f"(expected one of {', '.join(VARIANT_NAMES)}) — run prepare first"
            ),
        )
    if variant not in VARIANT_NAMES:
        return ReaResult(
            False, "score",
            error=f"unknown variant {variant!r} — expected one of {', '.join(VARIANT_NAMES)}",
        )
    if variant != estate_variant:
        return ReaResult(
            False, "score",
            error=(
                f"variant mismatch: the estate on disk is {estate_variant!r} but scoring "
                f"was requested for variant {variant!r} — the estate is the source of truth"
            ),
        )
    expected_campaign = VARIANT_CAMPAIGNS[variant]
    if not isinstance(contract, dict) or contract.get("campaign") != expected_campaign:
        return ReaResult(
            False, "score",
            error=(
                f"rea_range scoring requires the REA contract for variant {variant!r} "
                f"(campaign {expected_campaign!r})"
            ),
        )
    if not (estate / "prepared.json").is_file():
        return ReaResult(False, "score", error=f"estate not prepared at {estate} — run prepare first")
    journal_path = estate / "evidence.jsonl"
    if not journal_path.is_file():
        return ReaResult(False, "score", error=f"no evidence journal at {journal_path} — run prepare first")

    journal_lines: list[tuple[str, dict]] = []
    for line in journal_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            journal_lines.append((line, json.loads(line)))
        except json.JSONDecodeError:
            continue

    flag_path = estate / "apps" / "prod-api" / "flag.txt"
    flag_token = flag_path.read_text(encoding="utf-8").strip() if flag_path.is_file() else ""

    proven: list[tuple[str, str, str]] = []
    unproven: list[dict[str, str]] = []
    for objective in contract.get("objectives") or []:
        objective_id = str(objective.get("id", ""))
        for witness in objective.get("witnesses") or []:
            name = witness.get("name") if isinstance(witness, dict) else str(witness)
            evidence = _witness_evidence(name, journal_lines, flag_token, variant)
            if evidence is not None:
                proven.append((objective_id, name, evidence))
            else:
                unproven.append({"objective": objective_id, "witness": name})

    counts: dict[str, int] = {}
    for _, entry in journal_lines:
        key = entry.get("event", "")
        counts[key] = counts.get(key, 0) + 1

    if variant == "cve":
        # The crown token is attached only from the journal's crown_verified line.
        crown_flag = None
        for _, entry in journal_lines:
            if entry.get("event") == "crown_verified":
                crown_flag = str(entry.get("token", ""))
    else:
        crown_flag = flag_token if _crown_output_has_flag(journal_lines, flag_token) else None

    return ReaResult(True, "score", data={
        "proven": proven,
        "unproven": unproven,
        "estate_events": counts,
        "crown_flag": crown_flag,
        "variant": variant,
    })
