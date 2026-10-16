#!/usr/bin/env bash
# evilpi build: overlay the official Kali Raspberry Pi ARM64 image with the
# evilkit mobile companion and the first-boot scope prompt, then repackage
# as a flashable .img.xz.
#
# Needs: losetup, kpartx, qemu-user-static, xz, mount, chroot, root.
# Run on a Linux host. Fails fast when any prerequisite is missing.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
OVERLAY_DIR="$SCRIPT_DIR/pi-overlay"
COMPANION_DIR="$REPO_ROOT/mobile/companion"
DIST_DIR="$SCRIPT_DIR/dist"

KALI_IMAGE=""
OUT=""
DRY_RUN=0
DOWNLOAD=0

# Pinned image for reproducibility. Override with --kali-image or --download.
KALI_URL="https://kali.download/arm-images/kali-2024.4/kali-linux-2024.4-raspberry-pi-arm64.img.xz"
KALI_SHA256_URL="${KALI_URL}.sha256sum"

info() { printf 'evilpi: %s\n' "$*"; }
fail() { printf 'evilpi: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $0 [options]

  --kali-image PATH   Use this Kali Pi ARM64 image (.img or .img.xz).
  --download          Download the pinned Kali Pi image into ./dist/kali/.
  --out PATH          Write the finished image to PATH (default: dist/evilpi-<date>.img.xz).
  --dry-run           Validate overlay layout and preflight; touch no loop device.
  -h, --help          Show this message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kali-image) KALI_IMAGE="${2:?}"; shift 2;;
        --download)   DOWNLOAD=1; shift;;
        --out)        OUT="${2:?}"; shift 2;;
        --dry-run)    DRY_RUN=1; shift;;
        -h|--help)    usage; exit 0;;
        *)            fail "unknown argument: $1";;
    esac
done

: "${OUT:=$DIST_DIR/evilpi-$(date -u +%Y%m%d).img.xz}"

preflight_overlay() {
    [[ -d "$OVERLAY_DIR" ]] || fail "overlay directory missing: $OVERLAY_DIR"
    [[ -f "$OVERLAY_DIR/usr/local/bin/evilkit-first-boot" ]] \
        || fail "overlay missing first-boot script"
    [[ -f "$OVERLAY_DIR/etc/systemd/system/evilkit-first-boot.service" ]] \
        || fail "overlay missing first-boot unit"
    [[ -f "$OVERLAY_DIR/etc/systemd/system/evilkit-companion.service" ]] \
        || fail "overlay missing companion unit"
    [[ -d "$COMPANION_DIR" ]] \
        || fail "mobile/companion/ not found at $COMPANION_DIR"
    [[ -f "$COMPANION_DIR/server.py" ]] \
        || fail "companion server.py not found"
}

preflight_host() {
    local missing=()
    for tool in losetup kpartx mount umount chroot xz unxz sha256sum; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    # qemu-user-static ships as qemu-aarch64-static when installed as a package;
    # the binfmt handler is what actually matters at chroot time.
    command -v qemu-aarch64-static >/dev/null 2>&1 \
        || missing+=("qemu-aarch64-static (apt install qemu-user-static)")
    [[ -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]] \
        || missing+=("binfmt_misc handler for aarch64 (apt install binfmt-support)")
    if (( ${#missing[@]} )); then
        printf 'evilpi: missing on host:\n' >&2
        printf '  - %s\n' "${missing[@]}" >&2
        exit 1
    fi
    [[ $EUID -eq 0 ]] || fail "root required (losetup, mount, chroot); re-run with sudo"
}

download_kali() {
    mkdir -p "$DIST_DIR/kali"
    local base
    base="$(basename "$KALI_URL")"
    local target="$DIST_DIR/kali/$base"
    local sig="$DIST_DIR/kali/${base}.sha256sum"
    if [[ ! -f "$target" ]]; then
        info "downloading $KALI_URL"
        curl -fL --proto '=https' --tlsv1.2 -o "$target" "$KALI_URL"
    fi
    if [[ ! -f "$sig" ]]; then
        info "downloading checksum"
        curl -fL --proto '=https' --tlsv1.2 -o "$sig" "$KALI_SHA256_URL"
    fi
    info "verifying checksum"
    ( cd "$DIST_DIR/kali" && sha256sum --check --strict "$(basename "$sig")" )
    KALI_IMAGE="$target"
}

prepare_image_copy() {
    # Work on a copy; never touch the downloaded original.
    local work
    work="$DIST_DIR/work/evilpi.img"
    mkdir -p "$(dirname "$work")"
    rm -f "$work"
    if [[ "$KALI_IMAGE" == *.xz ]]; then
        info "decompressing $KALI_IMAGE -> $work"
        xz -dc "$KALI_IMAGE" > "$work"
    else
        info "copying $KALI_IMAGE -> $work"
        cp --sparse=always "$KALI_IMAGE" "$work"
    fi
    # Grow by 1 GiB to make room for apt installs and the companion payload.
    info "growing image by 1 GiB"
    truncate -s +1G "$work"
    printf '%s\n' "$work"
}

overlay_in_chroot() {
    local work="$1"
    local loop mnt_root mnt_boot
    loop="$(losetup --show --find --partscan "$work")"
    trap 'cleanup_loop "$loop" "$mnt_root" "$mnt_boot"' EXIT

    # Resize the second partition to use the extra 1 GiB.
    info "resizing root partition on $loop"
    parted --script "$loop" resizepart 2 100%
    e2fsck -fy "${loop}p2" >/dev/null
    resize2fs "${loop}p2" >/dev/null

    mnt_root="$(mktemp -d)"
    mnt_boot="$(mktemp -d)"
    mount "${loop}p2" "$mnt_root"
    mount "${loop}p1" "$mnt_boot"

    info "copying evilkit source into chroot"
    mkdir -p "$mnt_root/opt/evilkit-src"
    rsync -a --delete \
        --exclude '.git' --exclude 'dist' --exclude 'variants/evilpi/dist' \
        --exclude '**/__pycache__' --exclude '*.egg-info' \
        "$REPO_ROOT/" "$mnt_root/opt/evilkit-src/"

    info "copying companion server into chroot"
    mkdir -p "$mnt_root/opt/evilkit-companion"
    rsync -a "$COMPANION_DIR/server.py" "$COMPANION_DIR/evilkit_core" \
        "$COMPANION_DIR/requirements.txt" "$mnt_root/opt/evilkit-companion/"

    info "applying pi-overlay files"
    rsync -a "$OVERLAY_DIR/" "$mnt_root/"

    # Make the first-boot script executable; rsync preserves mode but belt-and-braces.
    chmod 0755 "$mnt_root/usr/local/bin/evilkit-first-boot"
    chmod 0755 "$mnt_root/usr/local/bin/evilkit-scope-prompt"

    info "setting up chroot (qemu, resolv.conf, bind mounts)"
    cp "$(command -v qemu-aarch64-static)" "$mnt_root/usr/bin/"
    mount --bind /dev "$mnt_root/dev"
    mount --bind /proc "$mnt_root/proc"
    mount --bind /sys "$mnt_root/sys"
    cp /etc/resolv.conf "$mnt_root/etc/resolv.conf"

    info "running in-chroot provisioning"
    chroot "$mnt_root" /bin/bash -eux <<'CHROOT'
export DEBIAN_FRONTEND=noninteractive
# evilkit needs pipx; qrencode is for the pairing QR on first boot.
apt-get update
apt-get install -y --no-install-recommends pipx python3-venv qrencode
# Install evilkit from the source we copied in. --system installs for root/all
# users; the companion unit runs as root so this is what we want.
pipx install --system /opt/evilkit-src || pipx install --global /opt/evilkit-src
systemctl enable evilkit-first-boot.service
systemctl enable evilkit-companion.service
rm -rf /var/lib/apt/lists/*
CHROOT

    sync

    umount "$mnt_root/sys" "$mnt_root/proc" "$mnt_root/dev"
    umount "$mnt_boot"
    umount "$mnt_root"
    losetup -d "$loop"
    trap - EXIT
}

cleanup_loop() {
    local loop="$1" mnt_root="${2:-}" mnt_boot="${3:-}"
    [[ -n "$mnt_root" && -d "$mnt_root" ]] && umount -R "$mnt_root" 2>/dev/null || true
    [[ -n "$mnt_boot" && -d "$mnt_boot" ]] && umount "$mnt_boot" 2>/dev/null || true
    [[ -n "$loop" ]] && losetup -d "$loop" 2>/dev/null || true
}

repackage() {
    local work="$1"
    mkdir -p "$(dirname "$OUT")"
    info "compressing -> $OUT"
    xz -T0 -9e --stdout "$work" > "$OUT"
    sha256sum "$OUT" > "${OUT}.sha256sum"
    info "wrote $OUT"
    info "wrote ${OUT}.sha256sum"
}

main() {
    preflight_overlay
    if (( DRY_RUN )); then
        info "dry-run: overlay layout OK"
        info "would download: $DOWNLOAD"
        info "would use image: ${KALI_IMAGE:-<none; pass --kali-image or --download>}"
        info "would write: $OUT"
        exit 0
    fi
    preflight_host
    if (( DOWNLOAD )); then
        download_kali
    fi
    [[ -n "$KALI_IMAGE" ]] || fail "no --kali-image given and --download not set"
    [[ -f "$KALI_IMAGE" ]] || fail "image not found: $KALI_IMAGE"
    local work
    work="$(prepare_image_copy)"
    overlay_in_chroot "$work"
    repackage "$work"
    rm -f "$work"
    info "done"
}

main "$@"
