#!/bin/sh
# 20-provision-root.sh -- provision the NFS root via an arm64 chroot.
#
# Run on the boot server as root, after 10-build-nfsroot.sh. Uses
# qemu-aarch64-static + binfmt_misc so an x86_64 host can chroot into the arm64
# root. Copies the companion, installs tools + deps, creates the operator user,
# lays down WireGuard + systemd units, and bakes in the secrets from ./secrets/.

set -eu

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
[ -f deploy.conf ] || { echo "error: deploy.conf missing"; exit 1; }
. ./deploy.conf
[ "$(id -u)" -eq 0 ] || { echo "error: run as root"; exit 1; }
[ -d "$NFS_ROOT" ] || { echo "error: $NFS_ROOT missing -- run 10-build-nfsroot.sh"; exit 1; }

COMPANION_SRC="$SCRIPT_DIR/../.."   # mobile/companion

# --- required secrets -------------------------------------------------------
for f in secrets/companion.token secrets/wg_pi_private.key; do
    [ -s "$f" ] || { echo "error: $f missing -- run ./gen-secrets.sh"; exit 1; }
done
AUTH_KEY="${SSH_AUTHORIZED_KEY_FILE:-./secrets/operator_ed25519.pub}"
[ -s "$AUTH_KEY" ] || { echo "error: SSH public key $AUTH_KEY missing"; exit 1; }

# --- qemu static for arm64 chroot ------------------------------------------
QEMU="$(command -v qemu-aarch64-static || true)"
[ -n "$QEMU" ] || { echo "error: qemu-aarch64-static not found (apt-get install qemu-user-static binfmt-support)"; exit 1; }
cp "$QEMU" "$NFS_ROOT/usr/bin/"

# --- vendor evilkit_core if needed -----------------------------------------
if [ ! -d "$COMPANION_SRC/evilkit_core" ]; then
    echo "vendor evilkit_core"
    ( cd "$COMPANION_SRC" && sh ./sync-evilkit-core.sh )
fi

# --- stage payload into the root -------------------------------------------
PAYLOAD="$NFS_ROOT/opt/evilkit-companion"
mkdir -p "$PAYLOAD"
cp -a "$COMPANION_SRC/server.py" "$PAYLOAD/"
cp -a "$COMPANION_SRC/evilkit_core" "$PAYLOAD/"
[ -f "$COMPANION_SRC/requirements.txt" ] && cp -a "$COMPANION_SRC/requirements.txt" "$PAYLOAD/"
cp -a "$COMPANION_SRC/install-tools.sh" "$PAYLOAD/"

# provisioning assets + secrets (secrets removed again after the chroot run)
PROV="$NFS_ROOT/opt/evilkit-provision"
mkdir -p "$PROV/secrets"
cp -a "$SCRIPT_DIR/files/." "$PROV/"
cp -a secrets/companion.token "$PROV/secrets/"
cp -a secrets/wg_pi_private.key "$PROV/secrets/"
cp -a "$AUTH_KEY" "$PROV/secrets/operator.pub"

# export the resolved config for the inner script
cat > "$PROV/deploy.env" <<EOF
PI_HOSTNAME='$PI_HOSTNAME'
BOOT_SERVER_IP='$BOOT_SERVER_IP'
COMPANION_PORT='$COMPANION_PORT'
COMPANION_BIND='$COMPANION_BIND'
COMPANION_DATA_DIR='$COMPANION_DATA_DIR'
COMPANION_DEFAULT_SCOPE='$COMPANION_DEFAULT_SCOPE'
WG_IFACE='$WG_IFACE'
WG_PI_ADDRESS='$WG_PI_ADDRESS'
WG_ALLOWED_IPS='$WG_ALLOWED_IPS'
WG_ENDPOINT_HOST='$WG_ENDPOINT_HOST'
WG_ENDPOINT_PORT='$WG_ENDPOINT_PORT'
WG_PEER_PUBLIC_KEY='$WG_PEER_PUBLIC_KEY'
WG_KEEPALIVE='$WG_KEEPALIVE'
WG_DNS='$WG_DNS'
NUCLEI_VERSION='$NUCLEI_VERSION'
FFUF_VERSION='$FFUF_VERSION'
TESTSSL_VERSION='$TESTSSL_VERSION'
EOF

# --- bind mounts for the chroot --------------------------------------------
for d in proc sys dev dev/pts; do mkdir -p "$NFS_ROOT/$d"; done
mount -t proc  proc  "$NFS_ROOT/proc"
mount -t sysfs sys   "$NFS_ROOT/sys"
mount --bind  /dev    "$NFS_ROOT/dev"
mount --bind  /dev/pts "$NFS_ROOT/dev/pts"
cleanup() {
    sync || true
    for mp in dev/pts dev sys proc; do
        mountpoint -q "$NFS_ROOT/$mp" && umount "$NFS_ROOT/$mp" || true
    done
    rm -f "$NFS_ROOT/usr/bin/qemu-aarch64-static" 2>/dev/null || true
    rm -rf "$PROV" 2>/dev/null || true   # scrub secrets copied in
}
trap cleanup EXIT INT TERM

echo "chroot provisioning..."
chroot "$NFS_ROOT" /bin/bash /opt/evilkit-provision/chroot-provision.sh

echo "done. Next: sudo ./30-configure-netboot.sh"
