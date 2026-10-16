#!/usr/bin/env bash
# Two EvilKit brain runs, two models, two terminals.
#   ./run-dual.sh qwen   # terminal 1 -> qwen/qwen3.8-2.4t-a95b   (dashboard :8008)
#   ./run-dual.sh kimi   # terminal 2 -> moonshotai/kimi-k3       (dashboard :8009)
# Each run needs its OWN Keystone range instance; do not point both at one live range.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
MODEL="${1:?usage: run-dual.sh qwen|kimi}"
case "$MODEL" in
  qwen) PROFILE=evilkit-qwen.toml; PORT=8008; SLUG=qwen/qwen3.8-2.4t-a95b ;;
  kimi) PROFILE=evilkit-kimi.toml; PORT=8009; SLUG=moonshotai/kimi-k3 ;;
  *) echo "unknown model: $MODEL" >&2; exit 2 ;;
esac
export EVILKIT_CONFIG="$HOME/.config/evilkit/profiles/$PROFILE"
RUN_DIR="$HOME/evilkit/runs/evilkit-$MODEL-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN_DIR"
echo "[dual] model=$SLUG"
echo "[dual] config=$EVILKIT_CONFIG"
echo "[dual] run dir=$RUN_DIR"
echo "[dual] dashboard will be at http://127.0.0.1:$PORT/dashboard/index.html"
evilkit brain
python3 -m keystone.dashboard serve --run-dir "$RUN_DIR" --port "$PORT"
