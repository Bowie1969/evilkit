# evilkit Mobile

This directory contains the mobile version of evilkit. The approved architecture
is an **iOS app + local Linux companion**: the iPhone is the operator UI, scope
authority, and audit record; a small Linux device (Raspberry Pi Zero 2 W, travel
router, etc.) tethered to the iPhone runs the actual pentest tools. Traffic
leaves through the iPhone's connection, so targets see the phone's source IP.

## Why a companion device?

iOS cannot spawn arbitrary binaries like `nmap` or `nuclei`, and its network
sandbox blocks raw sockets. A companion device is the only iOS-friendly way to
keep a real "full toolset" without jailbreak.

## Layout

```
mobile/
├── companion/          # Linux companion server and image build
│   ├── server.py       # scope-gated HTTP API server
│   ├── evilkit_core/   # vendored scope.py and audit.py
│   ├── install-tools.sh
│   ├── Dockerfile
│   ├── build-image.sh
│   └── test_server.py
├── ios/                # Swift/SwiftUI iOS app (future)
├── tool-bundle/        # ARM64 tool build scripts
└── docs/               # API and pairing documentation
```

## Quick start — test the companion locally

```bash
cd mobile/companion
python3 server.py --host 127.0.0.1 --port 8787 \
  --data-dir /tmp/evilkit-companion --token demo-token

# In another terminal:
curl -s http://127.0.0.1:8787/api/v1/health
curl -s -X POST -H 'Authorization: Bearer demo-token' \
  -H 'Content-Type: application/json' \
  -d '{"scope":"127.0.0.1/32"}' \
  http://127.0.0.1:8787/api/v1/sessions
```

See `docs/companion-api.md` for the full API.

## Build the companion image

```bash
cd mobile/companion
./build-image.sh
```

For a Raspberry Pi, flash Raspberry Pi OS Lite ARM64, then load and run the
container. Detailed steps are in `docs/ios-pairing.md`.
