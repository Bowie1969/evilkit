# evilkit drop device — Pi 4 netboot provisioning

Custom, scripted build for a **Raspberry Pi 4 Model B (4GB), no SD card**, that
boots over the network and comes up running the evilkit companion
(scope-gated pentest API) reachable only over a WireGuard tunnel — while still
carrying your existing dropper role.

This toolkit builds the image on **your boot server**; it does not ship a
pre-baked image. WireGuard keys and the companion token are generated on that
server and never touch git.

> **Authorized use only.** The companion enforces scope the same way desktop
> evilkit does: every tool target is checked against the session's
> allow/deny list before a packet is sent, and every session and call is
> written to an append-only audit log. Point it only at systems you are
> authorized to test.

---

## How the pieces fit

```
  control node (WireGuard server, you)
        ^  wg0: 10.9.0.1
        |        tunnel (Pi dials out, keepalive holds NAT open)
        |  wg0: 10.9.0.2  -- companion API bound HERE only (:8787)
   +----+-----------------------------------+
   |  Pi 4 (diskless)                        |  eth0: target LAN (firewall default-drop)
   |  kernel ip=dhcp -> mounts / over        |
   |  NFS from the boot server               |
   +-----------------------------------------+
        | TFTP (firmware) + NFS (rootfs)
        v
  boot server (NFS + TFTP + DHCP)  <- the audit log + tool bundle live here
```

Because the root filesystem is on the boot server's NFS export, **persistence --
including the audit JSONL -- lives on the boot server, not the Pi.** That neatly
answers "no SD card = where does state go": it goes in `NFS_ROOT`.

### The netboot trade-off (read this)

A diskless netboot Pi needs its **TFTP + NFS server reachable every time it
powers on**. That fits:

- a bench/lab where you provision and run the Pi on a network you control, or
- an engagement where your boot server sits on the same LAN as the drop.

It does **not** give you a device that can be dropped on a far-away network and
survive a power cycle on its own — with no local disk, a reboot with the boot
server unreachable leaves it with nothing to boot. If you need "drop it and
forget it across reboots anywhere", put the root on the USB SSD instead
(bare-metal install) and keep everything else in this toolkit. Say the word and
the USB-SSD variant of steps 10–30 can be added.

---

## Boot server prerequisites

A Linux boot server with:

- `nfs-kernel-server`, a TFTP daemon (dnsmasq's built-in TFTP is easiest), and
  DHCP (or dnsmasq proxy-DHCP) that tells the Pi where TFTP is.
- `qemu-user-static` + `binfmt-support` (to chroot into the arm64 root from an
  x86_64 host), `wireguard-tools`, `rsync`, `xz-utils`, `curl`, `unzip`.

Example dnsmasq (TFTP + proxy-DHCP) on `192.168.50.1`:

```
interface=eth0
dhcp-range=192.168.50.0,proxy
enable-tftp
tftp-root=/srv/tftp
pxe-service=0,"Raspberry Pi Boot"
```

NFS export (`/etc/exports`):

```
/srv/nfs/evilkit-pi *(rw,sync,no_subtree_check,no_root_squash)
```

Then `sudo exportfs -ra`.

---

## Build steps

All on the boot server, from this directory:

```bash
cp deploy.conf.example deploy.conf
$EDITOR deploy.conf                 # fill in IPs, WireGuard endpoint, serial…

./gen-secrets.sh                    # WireGuard keypair + companion token -> ./secrets/
# add the printed Pi public key as a [Peer] on your control node

sudo ./10-build-nfsroot.sh          # download Pi OS Lite arm64 -> NFS_ROOT
sudo ./20-provision-root.sh         # chroot: user, tools, companion, WG, units
sudo ./30-configure-netboot.sh      # publish firmware to TFTP + NFS cmdline
```

Then set the Pi 4 EEPROM boot order (once per device) per
[`40-eeprom-bootorder.md`](40-eeprom-bootorder.md), remove any temporary SD,
and power it on.

### Your existing dropper

Netboot replaces the whole OS, so your current dropper software must be baked
in too. Put its installer at `files/dropper/install.sh` before step 20 — see
[`files/dropper/README.md`](files/dropper/README.md). Without it the device
boots as companion-only.

---

## First boot — what happens

1. EEPROM -> TFTP: bootloader fetches `start4.elf`, the DTB, `kernel8.img`.
2. Kernel brings up `eth0` via DHCP and mounts `/` from NFS.
3. `evilkit-firstboot` gives the device a unique machine-id + SSH host keys.
4. `wg-quick@wg0` dials your control node; the tunnel comes up.
5. `evilkit-companion` binds to the tunnel address `10.9.0.2:8787` and starts.
   `nftables` drops anything inbound on the target LAN except established replies.

## Reach it

From your control node, over the tunnel:

```bash
TOKEN=$(cat secrets/companion.token)      # the token you generated
curl -s http://10.9.0.2:8787/api/v1/health
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"10.0.0.0/24","deny":"10.0.0.1"}' \
  http://10.9.0.2:8787/api/v1/sessions
```

See [`../docs/companion-api.md`](../../docs/companion-api.md) for the full API
and [`../example_client.py`](../example_client.py) for a client.

## Verify / debug

- Serial console (USB-UART, 115200) shows the whole boot; `enable_uart=1` is set.
- On the boot server: `journalctl` lives in `NFS_ROOT/var/log`; the audit log is
  at `NFS_ROOT/<COMPANION_DATA_DIR>`.
- `sudo wg show` on the control node confirms the Pi's handshake.
- Re-run any step; `20-provision-root.sh` is safe to re-run, and
  `10-build-nfsroot.sh --fresh` rebuilds the root from scratch.

## Rotate / revoke

- Rotate the token: `./gen-secrets.sh --force` then re-run step 20 (or just
  re-render `/etc/evilkit/companion.env` in `NFS_ROOT`) and restart the service.
- Kill access fast: remove the Pi's `[Peer]` from the control node — the tunnel
  drops, the companion's bind address disappears, and the service fails closed.

## Teardown

Power off, remove the `[Peer]` from the control node, and archive or wipe
`NFS_ROOT` (it holds the audit log — keep it if you need the record).

---

## Files

| path | purpose |
|------|---------|
| `deploy.conf.example` | all environment-specific parameters |
| `gen-secrets.sh` | generate WireGuard keypair + companion token (-> `secrets/`) |
| `10-build-nfsroot.sh` | fetch Pi OS Lite arm64, lay it into `NFS_ROOT` |
| `20-provision-root.sh` | chroot provisioning driver (qemu-arm64) |
| `30-configure-netboot.sh` | publish firmware to TFTP, write NFS `cmdline.txt` |
| `40-eeprom-bootorder.md` | one-time EEPROM network-boot setup |
| `files/chroot-provision.sh` | the in-chroot provisioning (renders config, installs, enables) |
| `files/*.tmpl`, `files/*.service`, `files/*.conf` | systemd units, WireGuard, firewall, sysctl |
| `files/dropper/` | hook for your existing dropper payload |
