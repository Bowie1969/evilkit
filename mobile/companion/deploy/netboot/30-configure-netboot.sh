#!/bin/sh
# 30-configure-netboot.sh -- publish firmware to TFTP and point the Pi at NFS.
#
# Run on the boot server as root, after 20-provision-root.sh. Copies the
# staged boot firmware into the TFTP tree (under the Pi's serial directory by
# default) and writes cmdline.txt / config.txt so the Pi 4 mounts NFS_ROOT as /.

set -eu

cd "$(dirname "$0")"
[ -f deploy.conf ] || { echo "error: deploy.conf missing"; exit 1; }
. ./deploy.conf
[ "$(id -u)" -eq 0 ] || { echo "error: run as root"; exit 1; }

FW="$NFS_ROOT/boot/firmware"
[ -d "$FW" ] || { echo "error: $FW missing -- run 10/20 first"; exit 1; }

# Target directory inside the TFTP root.
if [ "${TFTP_SERIAL_DIR:-1}" = "1" ]; then
    [ "$PI_SERIAL" != "00000000" ] || echo "warn: PI_SERIAL is still the placeholder; the Pi will request a different dir"
    DEST="$TFTP_ROOT/$PI_SERIAL"
else
    DEST="$TFTP_ROOT"
fi
mkdir -p "$DEST"

echo "publish firmware -> $DEST"
# Everything the GPU bootloader + kernel need: start4.elf, fixup4.dat, the
# bcm2711 dtb, overlays/, kernel8.img, etc.
cp -a "$FW"/. "$DEST"/

# --- cmdline.txt: root over NFS --------------------------------------------
CMDLINE="console=serial0,115200 console=tty1 root=/dev/nfs nfsroot=${BOOT_SERVER_IP}:${NFS_ROOT},vers=${NFS_VERS},tcp,nolock ip=dhcp rootfstype=nfs rw rootwait net.ifnames=0 fsck.repair=no"
printf '%s\n' "$CMDLINE" > "$DEST/cmdline.txt"
echo "wrote $DEST/cmdline.txt"

# --- config.txt: make sure NFS-root netboot is sane ------------------------
CFG="$DEST/config.txt"
touch "$CFG"
add_cfg() { grep -qxF "$1" "$CFG" 2>/dev/null || printf '%s\n' "$1" >> "$CFG"; }
add_cfg ""
add_cfg "# --- evilkit netboot ---"
# Serial console for recovery over UART.
add_cfg "enable_uart=1"
# Do not fall back to reading an (absent) SD on every boot stall.
add_cfg "boot_delay=0"
echo "patched $CFG"

cat <<EOF

TFTP tree ready at: $DEST
NFS root exported from: $NFS_ROOT (as ${BOOT_SERVER_IP}:${NFS_ROOT})

Remaining boot-server wiring (see README.md "Boot server prerequisites"):
  * NFS export line in /etc/exports:
      ${NFS_ROOT} *(rw,sync,no_subtree_check,no_root_squash)
    then: exportfs -ra
  * TFTP service (e.g. dnsmasq --enable-tftp --tftp-root=${TFTP_ROOT})
  * DHCP/proxyDHCP telling the Pi where TFTP is.

Then set the Pi 4 EEPROM boot order per 40-eeprom-bootorder.md and power it on.
EOF
