#!/bin/sh
# firstboot.sh -- give a freshly provisioned netboot image a unique identity.
# Idempotent: drops a sentinel and the oneshot unit skips it thereafter.
set -eu

STAMP=/var/lib/evilkit-firstboot.done
[ -f "$STAMP" ] && exit 0

# Unique machine-id (the golden root ships none / a stale one).
rm -f /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
systemd-machine-id-setup || true
[ -d /var/lib/dbus ] && cp -f /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true

# Fresh SSH host keys if absent.
if [ -z "$(ls /etc/ssh/ssh_host_* 2>/dev/null || true)" ]; then
    ssh-keygen -A || true
fi

mkdir -p "$(dirname "$STAMP")"
date -u +%FT%TZ > "$STAMP"
exit 0
