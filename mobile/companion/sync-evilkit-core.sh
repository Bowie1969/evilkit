#!/bin/bash
# Sync vendored evilkit_core modules from the top-level evilkit package.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cp ../../evilkit/scope.py evilkit_core/scope.py
cp ../../evilkit/audit.py evilkit_core/audit.py

echo "Synced evilkit_core/scope.py and evilkit_core/audit.py from ../../evilkit/"
