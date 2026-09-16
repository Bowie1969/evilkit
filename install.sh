#!/usr/bin/env bash
# evilkit installer.
#
# Installs the CLI with uv or pipx when one is available, falling back to a
# plain pip --user install, then drops the colour theme into the Kimi Code
# themes directory. Safe to re-run.
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KIMI_HOME="${EVILKIT_KIMI_HOME:-$HOME/.kimi-code}"
THEMES_DIR="$KIMI_HOME/themes"

info() { printf 'evilkit: %s\n' "$*"; }
fail() { printf 'evilkit: %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || fail "python3 is required"

if [ "$(python3 -c 'import sys; print(sys.version_info >= (3, 11))')" != "True" ]; then
  fail "Python 3.11 or newer is required (found $(python3 -V 2>&1))"
fi

install_cli() {
  if command -v uv >/dev/null 2>&1; then
    info "installing with uv"
    uv tool install --force "$REPO_DIR"
  elif command -v pipx >/dev/null 2>&1; then
    info "installing with pipx"
    pipx install --force "$REPO_DIR"
  else
    info "installing with pip --user"
    python3 -m pip install --user --force-reinstall --quiet "$REPO_DIR"
  fi
}

install_cli

if [ -d "$KIMI_HOME" ]; then
  mkdir -p "$THEMES_DIR"
  cp "$REPO_DIR/evilkit/data/evilkit.json" "$THEMES_DIR/evilkit.json"
  info "theme installed to $THEMES_DIR/evilkit.json"
  info "set  theme = \"evilkit\"  in $KIMI_HOME/tui.toml to activate it"
else
  info "no $KIMI_HOME directory found — skipping the theme"
  info "install the Kimi Code CLI first, then re-run this script"
fi

if command -v evilkit >/dev/null 2>&1; then
  info "done — run 'evilkit doctor' to verify"
else
  info "installed, but 'evilkit' is not on your PATH"
  info "add your user bin directory (usually ~/.local/bin) to PATH and re-run 'evilkit doctor'"
fi
