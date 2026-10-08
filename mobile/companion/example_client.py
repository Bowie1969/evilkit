"""Example Python client for the evilkit companion server.

This shows the request/response shape the iOS app will need to implement in
Swift. Run the companion server first, then:

    python3 example_client.py http://127.0.0.1:8787 demo-token 10.0.0.0/24 10.0.0.5
"""

from __future__ import annotations

import json
import sys
import urllib.request
from urllib.error import HTTPError


def request(base: str, token: str, method: str, path: str, data: dict | None = None) -> dict:
    url = base.rstrip("/") + path
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(  # noqa: S310
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return {"code": resp.getcode(), "body": json.loads(resp.read().decode("utf-8"))}
    except HTTPError as exc:
        body = json.loads(exc.read().decode("utf-8")) if exc.fp else {}
        return {"code": exc.code, "body": body, "error": exc.reason}


def main() -> int:
    if len(sys.argv) < 5:
        print(f"usage: {sys.argv[0]} <base-url> <token> <scope> <target>")
        return 2

    base, token, scope, target = sys.argv[1:5]

    # Create a session.
    result = request(base, token, "POST", "/api/v1/sessions", {"scope": scope})
    print(f"create session: {result['code']} {result['body']}")
    if result["code"] != 201:
        return 1
    session_id = result["body"]["id"]

    # Run a port scan.
    result = request(
        base,
        token,
        "POST",
        f"/api/v1/sessions/{session_id}/run",
        {"tool": "port_scan", "args": {"target": target, "ports": "top-1000", "timeout": 300}},
    )
    print(f"port_scan: {result['code']}")
    for line in result["body"].get("output", []):
        print("  ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
