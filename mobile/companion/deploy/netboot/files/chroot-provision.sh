#!/bin/bash
# chroot-provision.sh -- runs INSIDE the arm64 chroot (invoked by 20-provision-root.sh).
# Renders config from deploy.env + secrets, installs the tool bundle, creates
# the operator user, and enables the systemd units. Safe to re-run.
set -eu

PROV=/opt/evilkit-provision
APP=/opt/evilkit-companion
. "$PROV/deploy.env"
export DEBIAN_FRONTEND=noninteractive

TOKEN="$(cat "$PROV/secrets/companion.token")"
WG_PRIV="$(cat "$PROV/secrets/wg_pi_private.key")"

# sed-escape for values going into templates.
esc() { printf '%s' "$1" | sed -e 's/[&/\]/\\&/g'; }

render() {  # render <template> <dest> ; pairs of @@KEY@@=value follow via env
    local tmpl="$1" dest="$2"; shift 2
    local tmp; tmp="$(mktemp)"
    cp "$tmpl" "$tmp"
    while [ "$#" -gt 0 ]; do
        local key="${1%%=*}" val="${1#*=}"; shift
        sed -i "s/@@${key}@@/$(esc "$val")/g" "$tmp"
    done
    install -m 0644 "$tmp" "$dest"
    rm -f "$tmp"
}

# --- temporary working DNS for apt/curl inside the chroot ------------------
if [ -L /etc/resolv.conf ] || [ ! -s /etc/resolv.conf ]; then
    RESOLV_BAK="$(mktemp)"; cp -a /etc/resolv.conf "$RESOLV_BAK" 2>/dev/null || true
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
    RESTORE_RESOLV=1
else
    RESTORE_RESOLV=0
fi

# --- base packages ----------------------------------------------------------
apt-get update
apt-get install -y --no-install-recommends \
    python3 python3-venv curl ca-certificates unzip \
    nmap ncat openssl dnsutils \
    wireguard-tools nftables \
    bash coreutils openssh-server

# --- operator / service user -----------------------------------------------
if ! id evilkit >/dev/null 2>&1; then
    useradd --create-home --home-dir /home/evilkit --shell /bin/bash evilkit
fi
install -d -m 0750 -o evilkit -g evilkit "$COMPANION_DATA_DIR"

# --- SSH: key-only operator login ------------------------------------------
install -d -m 0700 -o evilkit -g evilkit /home/evilkit/.ssh
install -m 0600 -o evilkit -g evilkit "$PROV/secrets/operator.pub" /home/evilkit/.ssh/authorized_keys
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-evilkit.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers evilkit
EOF

# --- companion env + units --------------------------------------------------
install -d -m 0755 /etc/evilkit
render "$PROV/evilkit-companion.env.tmpl" /etc/evilkit/companion.env \
    "COMPANION_TOKEN=$TOKEN" \
    "COMPANION_BIND=$COMPANION_BIND" \
    "COMPANION_PORT=$COMPANION_PORT" \
    "COMPANION_DATA_DIR=$COMPANION_DATA_DIR"
chown evilkit:evilkit /etc/evilkit/companion.env
chmod 0600 /etc/evilkit/companion.env

render "$PROV/evilkit-companion.service.tmpl" /etc/systemd/system/evilkit-companion.service \
    "WG_IFACE=$WG_IFACE" \
    "COMPANION_DATA_DIR=$COMPANION_DATA_DIR"

install -m 0644 "$PROV/evilkit-firstboot.service" /etc/systemd/system/evilkit-firstboot.service
install -m 0755 "$PROV/firstboot.sh" "$APP/firstboot.sh"

# --- WireGuard call-home ----------------------------------------------------
install -d -m 0700 /etc/wireguard
if [ -n "${WG_DNS:-}" ]; then WG_DNS_LINE="DNS = ${WG_DNS}"; else WG_DNS_LINE=""; fi
render "$PROV/wg0.conf.tmpl" "/etc/wireguard/${WG_IFACE}.conf" \
    "WG_IFACE=$WG_IFACE" \
    "WG_PI_ADDRESS=$WG_PI_ADDRESS" \
    "WG_PI_PRIVATE_KEY=$WG_PRIV" \
    "WG_PEER_PUBLIC_KEY=$WG_PEER_PUBLIC_KEY" \
    "WG_ENDPOINT_HOST=$WG_ENDPOINT_HOST" \
    "WG_ENDPOINT_PORT=$WG_ENDPOINT_PORT" \
    "WG_ALLOWED_IPS=$WG_ALLOWED_IPS" \
    "WG_KEEPALIVE=$WG_KEEPALIVE" \
    "WG_DNS_LINE=$WG_DNS_LINE"
chmod 0600 "/etc/wireguard/${WG_IFACE}.conf"

# --- firewall + sysctl ------------------------------------------------------
render "$PROV/evilkit-nftables.conf.tmpl" /etc/nftables.conf \
    "WG_IFACE=$WG_IFACE" \
    "COMPANION_PORT=$COMPANION_PORT"
install -m 0644 "$PROV/99-evilkit-hardening.conf" /etc/sysctl.d/99-evilkit-hardening.conf

# --- keep NetworkManager off the NFS-root interface ------------------------
# The kernel configured eth0 via ip=dhcp to mount root; if NM re-DHCPs it the
# NFS mount can stall. Leave it to the kernel.
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/10-evilkit-nfsroot.conf <<'EOF'
[keyfile]
unmanaged-devices=interface-name:eth0
EOF

# --- identity ---------------------------------------------------------------
echo "$PI_HOSTNAME" > /etc/hostname
if grep -q '^127.0.1.1' /etc/hosts; then
    sed -i "s/^127.0.1.1.*/127.0.1.1\t$PI_HOSTNAME/" /etc/hosts
else
    printf '127.0.1.1\t%s\n' "$PI_HOSTNAME" >> /etc/hosts
fi

# --- tool bundle (ARM64) ----------------------------------------------------
ARCH=aarch64 INSTALL_DIR=/opt/evilkit-tools \
    NUCLEI_VERSION="$NUCLEI_VERSION" FFUF_VERSION="$FFUF_VERSION" TESTSSL_VERSION="$TESTSSL_VERSION" \
    sh "$APP/install-tools.sh" || echo "warn: tool bundle install reported errors (check network/versions)"

# --- optional: your existing dropper payload --------------------------------
# Drop your current dropper's installer at files/dropper/install.sh and it runs
# here, inside the image, so the device keeps doing what it does now.
if [ -x "$PROV/dropper/install.sh" ]; then
    echo "running dropper hook"
    sh "$PROV/dropper/install.sh"
fi

# --- enable services --------------------------------------------------------
systemctl enable ssh "wg-quick@${WG_IFACE}" nftables evilkit-firstboot evilkit-companion 2>/dev/null || {
    echo "systemctl enable unavailable in chroot; linking manually"
    ln -sf /etc/systemd/system/evilkit-companion.service \
        /etc/systemd/system/multi-user.target.wants/evilkit-companion.service 2>/dev/null || true
}

# --- lock down --------------------------------------------------------------
passwd -l root || true

# --- restore chroot DNS -----------------------------------------------------
if [ "$RESTORE_RESOLV" -eq 1 ]; then
    rm -f /etc/resolv.conf
    cp -a "$RESOLV_BAK" /etc/resolv.conf 2>/dev/null || ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    rm -f "$RESOLV_BAK"
fi
apt-get clean

echo "chroot provisioning complete."
