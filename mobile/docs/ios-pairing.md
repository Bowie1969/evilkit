# iOS Pairing Guide

This document describes how to pair an iPhone with the evilkit companion
device so that the companion's traffic carries the iPhone's source IP.

## Hardware options

- **Raspberry Pi Zero 2 W** — small, cheap, runs the companion Docker image well.
- **Travel router** with OpenWrt or a small Linux chroot.
- **Second phone** running Termux or a Linux container.

## Network topology

```
[iPhone] <-- USB tethering / Personal Hotspot --> [Companion]
   ^
   |
[Target]  sees the iPhone's cellular/Wi-Fi IP
```

The companion's **default gateway must be the iPhone**. Two easy ways to achieve
this:

1. **Personal Hotspot** — iPhone creates a Wi-Fi network; companion joins it.
   The companion gets an RFC 1918 address and routes all traffic through the
   phone. Targets see the phone's public IP.

2. **USB tethering (recommended)** — iPhone plugged into the companion via USB
   shares its connection. More reliable than Wi-Fi hotspot, lower latency, and
   the companion can power itself from the phone if needed.

## Companion setup (Raspberry Pi Zero 2 W)

1. Flash Raspberry Pi OS Lite (64-bit) to a microSD card.
2. Boot the Pi and enable SSH.
3. Install Docker:

   ```bash
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker $USER
   ```

4. Build or load the companion image:

   ```bash
   # From a Mac/PC with Docker:
   cd evilkit/mobile/companion
   ./build-image.sh --export=container
   scp ../../dist/evilkit-companion-latest.tar.gz pi@<pi-ip>:/tmp

   # On the Pi:
   docker load < /tmp/evilkit-companion-latest.tar.gz
   ```

5. Run the companion container:

   ```bash
   docker run -d --rm --name evilkit-companion \
     --network host \
     -v /var/lib/evilkit-companion:/var/lib/evilkit-companion \
     -e COMPANION_TOKEN="choose-a-long-random-token" \
     evilkit-companion:latest
   ```

6. Verify the Pi's default gateway is the iPhone. On the Pi:

   ```bash
   ip route | grep default
   curl -s https://ipinfo.io/ip
   ```

   The IP shown should match the iPhone's public IP, not the Pi's home network.

## iOS app pairing flow

1. The iOS app scans the local network (or uses Bluetooth LE) to discover the
   companion.
2. The user enters the token shown during companion setup.
3. The app creates a session with `--scope` and starts running tools.
4. All tool traffic is emitted by the companion but routed through the iPhone.

## Security notes

- The companion HTTP API should not be exposed to untrusted networks. Bind it to
  the iPhone-tether interface or a private companion-to-phone link.
- Rotate the Bearer token per engagement.
- The companion device itself is a high-trust component: protect it like any
  other pentest laptop.

## Troubleshooting

- **Cannot reach companion from iPhone** — ensure both are on the same network
  segment. Personal Hotspot puts the companion in the `172.20.10.0/28` range by
  default.
- **Traffic does not show iPhone IP** — check the companion's default route with
  `ip route`. The iPhone-tether interface must be the default gateway.
- **Companion port 8787 not reachable** — if not using `--network host`, publish
  the port explicitly: `-p 8787:8787`.
