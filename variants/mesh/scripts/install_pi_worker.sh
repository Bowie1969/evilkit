#!/usr/bin/env bash
# Install the Evilkit mesh Pi worker on a Raspberry Pi OS Lite box.
#
# Run this ON THE PI, as root, after the WireGuard tunnel to Parrot is up and
# after you have copied the mesh token file across out of band.
#
#   sudo ./install_pi_worker.sh \
#     --leader http://10.66.0.1:8765 \
#     --token-file /etc/evilk-mesh/token \
#     --name pi-01 \
#     --project /home/evilk/work
set -euo pipefail

LEADER=""; TOKEN_FILE="/etc/evilk-mesh/token"; NAME="$(hostname -s)"; PROJECT="/home/evilk/work"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --leader) LEADER="$2"; shift 2;;
    --token-file) TOKEN_FILE="$2"; shift 2;;
    --name) NAME="$2"; shift 2;;
    --project) PROJECT="$2"; shift 2;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done
[[ -n "$LEADER" ]] || { echo "--leader is required" >&2; exit 2; }
[[ -f "$TOKEN_FILE" ]] || { echo "token file not found: $TOKEN_FILE" >&2; exit 2; }

install -d -m 0755 /opt/evilk-mesh /etc/evilk-mesh
install -d -m 0755 /var/lib/evilk-mesh
install -m 0644 "$(dirname "$0")/mesh_worker_pi.py" /opt/evilk-mesh/mesh_worker_pi.py

chmod 0600 "$TOKEN_FILE"
chown root:root "$TOKEN_FILE"

cat > /etc/evilk-mesh/worker.env <<ENV
EVILK_MESH_LEADER=$LEADER
EVILK_MESH_TOKEN_FILE=$TOKEN_FILE
EVILK_MESH_NAME=$NAME
EVILK_MESH_PROJECT=$PROJECT
EVILK_MESH_SPOOL=/var/lib/evilk-mesh/spool.jsonl
ENV
chmod 0600 /etc/evilk-mesh/worker.env

install -m 0644 "$(dirname "$0")/evilk-mesh-worker-pi.service" /etc/systemd/system/evilk-mesh-worker-pi.service
systemctl daemon-reload
systemctl enable --now evilk-mesh-worker-pi.service
systemctl --no-pager --full status evilk-mesh-worker-pi.service || true
