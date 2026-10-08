# evilkit mobile companion image
#
# Builds a small Linux container/image that runs the scope-gated companion
# server. Intended for ARM64 devices (Raspberry Pi Zero 2 W, travel routers,
# etc.) tethered to an iPhone.
#
# Build:
#   docker build --platform linux/arm64 -t evilkit-companion:latest .
#
# Run locally for testing:
#   docker run --rm -p 8787:8787 evilkit-companion:latest

FROM alpine:3.20

ARG ARCH=aarch64
ARG NUCLEI_VERSION=3.3.5
ARG FFUF_VERSION=2.1.0
ARG TESTSSL_VERSION=3.2.0

ENV INSTALL_DIR=/opt/evilkit-tools
ENV PATH="${INSTALL_DIR}/bin:${PATH}"
ENV DATA_DIR=/var/lib/evilkit-companion

# Install base tools via package manager, then add portable binaries.
COPY install-tools.sh /tmp/install-tools.sh
RUN chmod +x /tmp/install-tools.sh \
    && /tmp/install-tools.sh \
    && rm -f /tmp/install-tools.sh

# Copy the companion server and vendored evilkit core modules.
WORKDIR /opt/evilkit-companion
COPY evilkit_core ./evilkit_core
COPY server.py ./
COPY requirements.txt ./

# Runtime data volume for sessions and audit logs.
VOLUME ["/var/lib/evilkit-companion"]

EXPOSE 8787

# Generate a random token at startup unless one is provided.
ENV COMPANION_TOKEN=""
ENTRYPOINT ["python3", "/opt/evilkit-companion/server.py"]
CMD ["--host", "0.0.0.0", "--port", "8787", "--data-dir", "/var/lib/evilkit-companion"]
