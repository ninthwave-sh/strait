#!/bin/sh
# install.sh -- devcontainer feature install script for strait.
#
# Installs the strait-gateway binary (static musl build) and the
# entrypoint wrapper that configures CA trust and starts the gateway.
#
# This script is idempotent: re-running it overwrites the installed
# binaries and scripts without error.
#
# The proxy binary (strait itself) is NOT installed inside the container.
# It runs on the host for tamper resistance.

set -e

# ── Architecture detection ────────────────────────────────────────────

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    arm64)   TARGET="aarch64-unknown-linux-musl" ;;
    *)
        echo "strait feature: unsupported architecture: ${ARCH}" >&2
        exit 1
        ;;
esac

# ── Version resolution ────────────────────────────────────────────────

VERSION="${VERSION:-latest}"
REPO="ninthwave-io/strait"

if [ "${VERSION}" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/strait-gateway-${TARGET}"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/strait-gateway-${TARGET}"
fi

# ── Download and install gateway binary ───────────────────────────────

GATEWAY_PATH="/usr/local/bin/strait-gateway"

# If the binary is already present (e.g. bind-mounted), skip download.
if [ -x "${GATEWAY_PATH}" ]; then
    echo "strait feature: gateway already present at ${GATEWAY_PATH}; skipping download"
else
    echo "strait feature: installing gateway binary from ${DOWNLOAD_URL}"

    if command -v curl > /dev/null 2>&1; then
        curl -fsSL -o "${GATEWAY_PATH}" "${DOWNLOAD_URL}" || {
            echo "strait feature: download failed; gateway will not be available" >&2
            echo "strait feature: the container will still start, but network policy is inactive" >&2
            rm -f "${GATEWAY_PATH}"
        }
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "${GATEWAY_PATH}" "${DOWNLOAD_URL}" || {
            echo "strait feature: download failed; gateway will not be available" >&2
            rm -f "${GATEWAY_PATH}"
        }
    else
        echo "strait feature: neither curl nor wget found; skipping gateway download" >&2
        echo "strait feature: install curl or wget, or bind-mount the gateway binary" >&2
    fi

    if [ -f "${GATEWAY_PATH}" ]; then
        chmod 755 "${GATEWAY_PATH}"
        echo "strait feature: gateway installed at ${GATEWAY_PATH}"
    fi
fi

# ── Install entrypoint script ─────────────────────────────────────────

SHARE_DIR="/usr/local/share/strait"
mkdir -p "${SHARE_DIR}"

cat > "${SHARE_DIR}/entrypoint.sh" << 'ENTRYPOINT'
#!/bin/sh
# strait devcontainer feature entrypoint.
#
# 1. Build augmented CA bundle (system CAs + strait session CA).
# 2. Start the gateway (TCP 127.0.0.1:3128 -> proxy Unix socket).
# 3. Exec the next entrypoint or user command.
#
# If the proxy socket or CA PEM is not mounted (strait not running on
# the host), the entrypoint passes through to "$@" without error so
# the container still starts.

set -e

CA_PEM="/strait/ca.pem"
CA_BUNDLE="/tmp/strait-ca-bundle.pem"
PROXY_SOCKET="/strait/proxy.sock"
GATEWAY="/usr/local/bin/strait-gateway"

# ── CA trust setup ────────────────────────────────────────────────────

if [ -f "${CA_PEM}" ]; then
    # Detect system CA bundle (Debian, Alpine, RHEL/Fedora).
    SYSTEM_CA=""
    for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
        if [ -f "$f" ]; then
            SYSTEM_CA="$f"
            break
        fi
    done

    if [ -n "${SYSTEM_CA}" ]; then
        cat "${SYSTEM_CA}" "${CA_PEM}" > "${CA_BUNDLE}"
    else
        cp "${CA_PEM}" "${CA_BUNDLE}"
    fi
else
    echo "strait: CA PEM not found at ${CA_PEM}; skipping CA trust setup" >&2
    echo "strait: set STRAIT_CA_PEM on the host and restart the container" >&2
fi

# ── Gateway startup ──────────────────────────────────────────────────

if [ -x "${GATEWAY}" ] && [ -S "${PROXY_SOCKET}" ]; then
    exec "${GATEWAY}" --socket "${PROXY_SOCKET}" -- "$@"
fi

# Gateway or socket not available -- pass through without proxy.
if [ ! -x "${GATEWAY}" ]; then
    echo "strait: gateway binary not found; running without network policy" >&2
fi
if [ ! -S "${PROXY_SOCKET}" ]; then
    echo "strait: proxy socket not found at ${PROXY_SOCKET}; running without network policy" >&2
    echo "strait: set STRAIT_PROXY_SOCKET on the host and restart the container" >&2
fi

exec "$@"
ENTRYPOINT

chmod 755 "${SHARE_DIR}/entrypoint.sh"
echo "strait feature: entrypoint installed at ${SHARE_DIR}/entrypoint.sh"

# ── Verify no proxy binary ───────────────────────────────────────────

if command -v strait > /dev/null 2>&1; then
    echo "strait feature: WARNING: the strait proxy binary should not be inside the container" >&2
    echo "strait feature: the proxy runs on the host for tamper resistance" >&2
fi

echo "strait feature: install complete"
