#!/bin/bash
# Build and export the evilkit companion image.
#
# Usage:
#   ./build-image.sh                    # build Docker image only
#   ./build-image.sh --export pi        # export an SD card image for Raspberry Pi
#   ./build-image.sh --export container # save docker image tarball

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-evilkit-companion}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
EXPORT_TYPE="${1:-}"

cd "$SCRIPT_DIR"

echo "Building companion Docker image..."
docker build --platform linux/arm64 -t "${IMAGE_NAME}:${IMAGE_TAG}" .

if [[ -z "${EXPORT_TYPE:-}" ]]; then
    echo "Built ${IMAGE_NAME}:${IMAGE_TAG}"
    exit 0
fi

case "$EXPORT_TYPE" in
    --export=container | --export container | container)
        OUT="${PROJECT_ROOT}/dist/${IMAGE_NAME}-${IMAGE_TAG}.tar.gz"
        mkdir -p "$(dirname "$OUT")"
        echo "Exporting container image to $OUT..."
        docker save "${IMAGE_NAME}:${IMAGE_TAG}" | gzip > "$OUT"
        echo "Saved $OUT"
        ;;
    --export=pi | --export pi | pi)
        echo "Raspberry Pi SD card export not yet implemented."
        echo "Manual steps:"
        echo "  1. Flash Raspberry Pi OS Lite (ARM64) to SD card."
        echo "  2. Boot Pi, enable ssh, install docker."
        echo "  3. Load ${IMAGE_NAME}:${IMAGE_TAG} via 'docker load < tarball'."
        echo "  4. Run container with --network host or published port 8787."
        exit 1
        ;;
    *)
        echo "Unknown export type: $EXPORT_TYPE"
        echo "Use --export=container or --export=pi"
        exit 1
        ;;
esac
