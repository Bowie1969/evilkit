#!/bin/sh
# 10-build-nfsroot.sh -- download Pi OS Lite arm64 and lay it into the NFS root.
#
# Run on the boot server as root. Idempotent-ish: it refuses to clobber a
# populated NFS_ROOT unless you pass --fresh (which wipes and rebuilds it).
#
# Result: NFS_ROOT contains the full Pi OS root filesystem, with the firmware
# boot partition staged at NFS_ROOT/boot/firmware for step 30 to push to TFTP.

set -eu

cd "$(dirname "$0")"
[ -f deploy.conf ] || { echo "error: deploy.conf missing (copy deploy.conf.example)"; exit 1; }
. ./deploy.conf

[ "$(id -u)" -eq 0 ] || { echo "error: run as root"; exit 1; }

FRESH=0
[ "${1:-}" = "--fresh" ] && FRESH=1

for t in xz losetup mount rsync curl; do
    command -v "$t" >/dev/null 2>&1 || { echo "error: '$t' not found"; exit 1; }
done

mkdir -p "$IMG_CACHE_DIR"
IMG_XZ="$IMG_CACHE_DIR/$(basename "$PIOS_IMG_URL")"
IMG="${IMG_XZ%.xz}"

# --- fetch ------------------------------------------------------------------
if [ ! -f "$IMG_XZ" ]; then
    echo "fetch $PIOS_IMG_URL"
    curl -fL --retry 4 -o "$IMG_XZ.part" "$PIOS_IMG_URL"
    mv "$IMG_XZ.part" "$IMG_XZ"
fi
if [ -n "${PIOS_IMG_SHA256:-}" ]; then
    echo "$PIOS_IMG_SHA256  $IMG_XZ" | sha256sum -c - || {
        echo "error: sha256 mismatch on $IMG_XZ"; exit 1; }
else
    echo "warn: PIOS_IMG_SHA256 is blank -- image integrity not verified"
fi

# --- decompress -------------------------------------------------------------
if [ ! -f "$IMG" ]; then
    echo "decompress -> $IMG"
    xz -dk "$IMG_XZ"
fi

# --- guard the target -------------------------------------------------------
if [ -d "$NFS_ROOT" ] && [ -n "$(ls -A "$NFS_ROOT" 2>/dev/null || true)" ]; then
    if [ "$FRESH" -eq 1 ]; then
        echo "wipe $NFS_ROOT (--fresh)"
        rm -rf "${NFS_ROOT:?}/"* "${NFS_ROOT:?}/".[!.]* 2>/dev/null || true
    else
        echo "error: $NFS_ROOT is not empty. Pass --fresh to rebuild." ; exit 1
    fi
fi
mkdir -p "$NFS_ROOT"

# --- loop-mount the image partitions ---------------------------------------
LOOP="$(losetup --show -fP "$IMG")"
echo "loop $LOOP"
cleanup() {
    sync || true
    for mp in /mnt/evilkit-root /mnt/evilkit-boot; do
        mountpoint -q "$mp" && umount "$mp" || true
    done
    [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p /mnt/evilkit-boot /mnt/evilkit-root
# p1 = boot firmware (FAT), p2 = root (ext4)
mount "${LOOP}p2" /mnt/evilkit-root
mount "${LOOP}p1" /mnt/evilkit-boot

echo "copy rootfs -> $NFS_ROOT"
rsync -aHAX --numeric-ids /mnt/evilkit-root/ "$NFS_ROOT/"

echo "stage boot firmware -> $NFS_ROOT/boot/firmware"
mkdir -p "$NFS_ROOT/boot/firmware"
rsync -aHAX /mnt/evilkit-boot/ "$NFS_ROOT/boot/firmware/"

echo "done. Next: sudo ./20-provision-root.sh"
