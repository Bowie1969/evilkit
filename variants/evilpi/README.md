# evilpi — the evilkit Raspberry Pi distro

A flashable Raspberry Pi image that boots into Kali Linux ARM64 with evilkit,
the mobile companion server, and a first-boot scope prompt pre-installed.

This variant is **not** a from-source rebuild of Kali. It downloads the
official Kali Raspberry Pi ARM64 image, mounts it, chroots in with
`qemu-user-static`, injects the evilpi overlay, and repackages the result.
Builds take minutes rather than the hours that `kali-arm/build.sh` needs,
and the base image is still Kali's: same kernel, same packages, same
signatures until the moment the overlay runs.

## What goes in the overlay

- **evilkit** (installed from the enclosing repo via `pipx` into the rootfs).
- **mobile companion server** (`server.py` + `evilkit_core/`) at
  `/opt/evilkit-companion/`, exposed via a `evilkit-companion.service`
  systemd unit on port `8787`.
- **evilkit-first-boot** oneshot: regenerates SSH host keys, prompts the
  operator on the console for an authorized scope, mints a companion API
  token, and writes both into `/etc/evilkit/scope.conf` and
  `/boot/firmware/evilkit-token` so an iPhone can pair without ever
  typing credentials.
- **motd** that prints the current scope on login, and a bashrc hook that
  refuses `evilkit` launches when `/etc/evilkit/scope.conf` is missing —
  the same "fails closed" invariant as core evilkit.

## What is **not** in the overlay

- No pre-shipped exploit payloads, no C2 beacons, no credentials, no
  wordlists beyond Kali's own `/usr/share/wordlists` symlinks. If you want
  those, bring them on a second SD partition or `scp` them in after
  first boot. The image is a stock Kali + scope guard, nothing more.
- No pre-authorised scope. The first-boot prompt refuses to continue
  until the operator types one.

## Build

Needs a Linux host with `losetup`, `qemu-user-static`, `kpartx`, `xz` and
root (or `sudo`). The sandbox check in `build.sh` fails fast with a list
of what is missing — nothing is attempted when any one of them is absent.

```bash
cd variants/evilpi
sudo ./build.sh \
  --kali-image kali-linux-2024.4-raspberry-pi-arm64.img.xz \
  --out dist/evilpi-$(date +%Y%m%d).img.xz
```

Pass `--download` to fetch the latest Kali Pi image into `./dist/kali/`
with its signature verified against the Kali signing key before the
overlay runs; pass a local path to use an image you already have.

Pass `--dry-run` to validate the overlay layout and the preflight checks
without touching a loop device. This is what CI runs; it needs no root.

## Flash and first boot

1. Flash `dist/evilpi-*.img.xz` to an SD card with Raspberry Pi Imager or
   `dd`. Standard Kali Pi flashing applies — no special steps.
2. Boot. On the console you will see:
   ```
   evilpi: no authorized scope on this device.
   evilpi: type the scope you are authorized to test, in CIDR form.
   scope>
   ```
3. Type the scope (`10.20.30.0/24`, or a comma-separated list). The
   first-boot unit writes it to `/etc/evilkit/scope.conf`, regenerates
   SSH host keys, mints a 128-bit companion token, and reboots once.
4. On the second boot the companion server is up on `:8787`. Pair the
   iOS app by scanning the QR code printed on the console (the token
   is also at `/boot/firmware/evilkit-token` for recovery).

## Threat model

evilpi inherits Kali's threat model with one addition: a first-boot
operator is trusted. The scope prompt is on the console, so the person
holding the SD card decides what the device is allowed to touch. The
companion server will refuse any session whose target falls outside
`/etc/evilkit/scope.conf`.

The scope guard is a typo guard, not a security boundary — the same
caveat as core evilkit. Real enforcement is in the pentest MCP server
the companion launches; this just makes sure that server never starts
with yesterday's scope.
