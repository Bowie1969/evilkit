# Dropper hook

Your Pi is already a dropper. Because netboot replaces the whole OS image, that
software has to live in this image too — otherwise the freshly provisioned root
won't do what the device does today.

Drop your existing dropper's installer here as `install.sh` (make it
executable). `chroot-provision.sh` runs it **inside the arm64 chroot**, after
the companion and tools are in place, so it can:

- `apt-get install` extra packages,
- copy payload files into the root,
- install and `systemctl enable` its own units.

It runs under qemu-arm64 emulation, so avoid steps that need real hardware
(e.g. probing `/dev` devices that don't exist in the chroot); defer those to a
oneshot systemd unit that runs on the real device at boot.

Keep any secrets your dropper needs out of git — read them from `../secrets/`
the same way the companion provisioning does, or have `install.sh` pull them
from your boot server at provision time.

If you leave this directory without an `install.sh`, the hook is simply skipped.

## Coexistence notes

- The companion binds to the WireGuard address only and the firewall
  (`/etc/nftables.conf`) default-drops inbound on the target-facing interface.
  If your dropper needs to listen on the target LAN, add an explicit `accept`
  rule for its port — scoped to the right `iifname` — rather than loosening the
  policy.
- `net.ipv4.ip_forward` is **off** by default (see `99-evilkit-hardening.conf`).
  Turn it on only if your dropper genuinely needs to route/pivot.
