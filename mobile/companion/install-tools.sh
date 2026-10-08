#!/bin/sh
# Install the pentest tool bundle for the evilkit mobile companion.
# Intended to run inside an Alpine or Debian ARM64 container/image build.

set -eu

ARCH="${ARCH:-aarch64}"
INSTALL_DIR="${INSTALL_DIR:-/opt/evilkit-tools}"
NUCLEI_VERSION="${NUCLEI_VERSION:-3.3.5}"
FFUF_VERSION="${FFUF_VERSION:-2.1.0}"
TESTSSL_VERSION="${TESTSSL_VERSION:-3.2.0}"

mkdir -p "$INSTALL_DIR/bin"

echo "Installing base packages..."
if command -v apk >/dev/null 2>&1; then
    apk add --no-cache \
        python3 \
        curl \
        nmap \
        nmap-scripts \
        ncat \
        openssl \
        bind-tools \
        bash \
        coreutils \
        ca-certificates
elif command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        curl \
        nmap \
        ncat \
        openssl \
        dnsutils \
        bash \
        coreutils \
        ca-certificates
    rm -rf /var/lib/apt/lists/*
else
    echo "Unsupported package manager; install curl/nmap/openssl manually." >&2
    exit 1
fi

echo "Installing nuclei ${NUCLEI_VERSION}..."
curl -fsSL -o /tmp/nuclei.tar.gz \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip"
unzip -q -o /tmp/nuclei.tar.gz -d "$INSTALL_DIR/bin" 2>/dev/null || {
    # Older releases use .tar.gz; try tar as fallback.
    tar -xzf /tmp/nuclei.tar.gz -C "$INSTALL_DIR/bin"
}
rm -f /tmp/nuclei.tar.gz

echo "Installing ffuf ${FFUF_VERSION}..."
curl -fsSL -o /tmp/ffuf.tar.gz \
    "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz"
tar -xzf /tmp/ffuf.tar.gz -C "$INSTALL_DIR/bin" ffuf
chmod +x "$INSTALL_DIR/bin/ffuf"
rm -f /tmp/ffuf.tar.gz

echo "Installing testssl.sh ${TESTSSL_VERSION}..."
curl -fsSL -o /tmp/testssl.tar.gz \
    "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz"
tar -xzf /tmp/testssl.tar.gz -C /tmp
mv "/tmp/testssl.sh-${TESTSSL_VERSION}" "$INSTALL_DIR/testssl.sh"
ln -sf "$INSTALL_DIR/testssl.sh/testssl.sh" "$INSTALL_DIR/bin/testssl.sh"
rm -f /tmp/testssl.tar.gz

echo "Updating nuclei templates..."
"$INSTALL_DIR/bin/nuclei" -update-templates || echo "nuclei template update skipped"

echo "Tool bundle installed to $INSTALL_DIR"
echo "Add $INSTALL_DIR/bin to PATH."
