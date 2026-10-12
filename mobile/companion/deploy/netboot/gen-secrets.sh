#!/bin/sh
# gen-secrets.sh -- generate the per-device secrets, on the boot server only.
#
# Writes into ./secrets/ (gitignored). Nothing here is ever committed. Re-run
# is refused for files that already exist unless you pass --force, so you don't
# silently rotate a key the live device still uses.
#
# Produces:
#   secrets/companion.token          bearer token for the companion API
#   secrets/wg_pi_private.key        the Pi's WireGuard private key
#   secrets/wg_pi_public.key         the Pi's WireGuard public key (add as a
#                                    peer on your control node)
#   secrets/operator_ed25519[.pub]   optional SSH key for the operator account
#
# Requires: wireguard-tools (wg), openssl or python3, ssh-keygen (optional).

set -eu

cd "$(dirname "$0")"
mkdir -p secrets
chmod 700 secrets

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

_exists() { [ -s "$1" ] && [ "$FORCE" -eq 0 ]; }

# --- Companion bearer token -------------------------------------------------
if _exists secrets/companion.token; then
    echo "keep  secrets/companion.token (exists; --force to rotate)"
else
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d '\n=' | tr '+/' '-_' > secrets/companion.token
    else
        python3 - <<'PY' > secrets/companion.token
import secrets
print(secrets.token_urlsafe(32), end="")
PY
    fi
    chmod 600 secrets/companion.token
    echo "write secrets/companion.token"
fi

# --- WireGuard keypair for the Pi ------------------------------------------
if ! command -v wg >/dev/null 2>&1; then
    echo "error: wireguard-tools ('wg') not found. Install it, then re-run." >&2
    echo "       (Debian/Ubuntu: apt-get install wireguard-tools)" >&2
    exit 1
fi
if _exists secrets/wg_pi_private.key; then
    echo "keep  secrets/wg_pi_private.key (exists; --force to rotate)"
else
    umask 077
    wg genkey > secrets/wg_pi_private.key
    wg pubkey < secrets/wg_pi_private.key > secrets/wg_pi_public.key
    echo "write secrets/wg_pi_private.key"
    echo "write secrets/wg_pi_public.key"
fi

# --- Operator SSH key (optional) -------------------------------------------
if command -v ssh-keygen >/dev/null 2>&1; then
    if _exists secrets/operator_ed25519; then
        echo "keep  secrets/operator_ed25519 (exists; --force to rotate)"
    else
        ssh-keygen -t ed25519 -N '' -C "evilkit-operator" -f secrets/operator_ed25519 >/dev/null
        echo "write secrets/operator_ed25519[.pub]"
    fi
else
    echo "note  ssh-keygen not found; supply your own key in SSH_AUTHORIZED_KEY_FILE"
fi

echo
echo "Done. Next steps:"
echo "  1. Add the Pi as a WireGuard peer on your control node:"
echo "       [Peer]"
echo "       PublicKey = $(cat secrets/wg_pi_public.key 2>/dev/null || echo '<secrets/wg_pi_public.key>')"
echo "       AllowedIPs = 10.9.0.2/32"
echo "  2. Fill in deploy.conf (copy from deploy.conf.example)."
echo "  3. Run: sudo ./10-build-nfsroot.sh"
