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
    CHECKSUM_URL="https://github.com/${REPO}/releases/latest/download/strait-gateway-${TARGET}.sha256"
else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/strait-gateway-${TARGET}"
    CHECKSUM_URL="https://github.com/${REPO}/releases/download/v${VERSION}/strait-gateway-${TARGET}.sha256"
fi

# ── Download and install gateway binary ───────────────────────────────

GATEWAY_PATH="/usr/local/bin/strait-gateway"

# fetch_to PATH URL -- download URL to PATH, returning 0 on success.
fetch_to() {
    _path="$1"
    _url="$2"
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL -o "${_path}" "${_url}"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "${_path}" "${_url}"
    else
        return 127
    fi
}

# verify_checksum PATH URL -- download the published sha256 sidecar and
# verify PATH matches. Returns 0 on success, non-zero if the checksum is
# missing or does not match.
verify_checksum() {
    _path="$1"
    _url="$2"
    _sumfile="${_path}.sha256"
    if ! fetch_to "${_sumfile}" "${_url}" 2>/dev/null; then
        rm -f "${_sumfile}"
        return 1
    fi
    # Published files are `<hex>  <name>` (coreutils format). Extract the
    # hex and compute the actual sum with whichever tool is available.
    _expected=$(awk '{print $1}' "${_sumfile}")
    rm -f "${_sumfile}"
    if [ -z "${_expected}" ]; then
        return 1
    fi
    if command -v sha256sum > /dev/null 2>&1; then
        _actual=$(sha256sum "${_path}" | awk '{print $1}')
    elif command -v shasum > /dev/null 2>&1; then
        _actual=$(shasum -a 256 "${_path}" | awk '{print $1}')
    else
        echo "strait feature: no sha256sum or shasum available; skipping checksum verification" >&2
        return 0
    fi
    [ "${_expected}" = "${_actual}" ]
}

# If the binary is already present (e.g. bind-mounted), skip download.
if [ -x "${GATEWAY_PATH}" ]; then
    echo "strait feature: gateway already present at ${GATEWAY_PATH}; skipping download"
else
    echo "strait feature: installing gateway binary from ${DOWNLOAD_URL}"

    if fetch_to "${GATEWAY_PATH}" "${DOWNLOAD_URL}"; then
        if verify_checksum "${GATEWAY_PATH}" "${CHECKSUM_URL}"; then
            echo "strait feature: gateway checksum verified"
        else
            # Some releases may not yet publish a sidecar checksum. Treat a
            # missing sidecar as non-fatal but a mismatch as fatal.
            if fetch_to /tmp/strait-gateway-checksum-probe "${CHECKSUM_URL}" 2>/dev/null; then
                rm -f /tmp/strait-gateway-checksum-probe
                echo "strait feature: checksum mismatch for downloaded gateway; refusing to install" >&2
                rm -f "${GATEWAY_PATH}"
            else
                echo "strait feature: no published checksum for ${TARGET}; skipping verification" >&2
            fi
        fi
    else
        _rc=$?
        if [ "${_rc}" = "127" ]; then
            echo "strait feature: neither curl nor wget found; skipping gateway download" >&2
            echo "strait feature: install curl or wget, or bind-mount the gateway binary" >&2
        else
            echo "strait feature: download failed; gateway will not be available" >&2
            echo "strait feature: the container will still start, but network policy is inactive" >&2
            rm -f "${GATEWAY_PATH}"
        fi
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
#
# containerEnv sets SSL_CERT_FILE=/tmp/strait-ca-bundle.pem unconditionally,
# so the bundle must exist even in the passthrough case (strait not running
# on the host). Build a bundle from system CAs alone when the session CA is
# absent, so HTTPS calls from the container keep working.

SYSTEM_CA=""
for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
    if [ -f "$f" ]; then
        SYSTEM_CA="$f"
        break
    fi
done

if [ -f "${CA_PEM}" ]; then
    if [ -n "${SYSTEM_CA}" ]; then
        cat "${SYSTEM_CA}" "${CA_PEM}" > "${CA_BUNDLE}"
    else
        cp "${CA_PEM}" "${CA_BUNDLE}"
    fi
else
    echo "strait: CA PEM not mounted at ${CA_PEM}; building bundle from system CAs only" >&2
    echo "strait: set STRAIT_CA_PEM on the host and restart the container to enable policy" >&2
    if [ -n "${SYSTEM_CA}" ]; then
        cp "${SYSTEM_CA}" "${CA_BUNDLE}"
    else
        # No system CA found and no session CA. Create an empty bundle so
        # SSL_CERT_FILE points to a readable file; HTTPS will fail loudly
        # rather than blaming a missing env target.
        : > "${CA_BUNDLE}"
    fi
fi

# ── Gateway startup ──────────────────────────────────────────────────

if [ -x "${GATEWAY}" ] && [ -S "${PROXY_SOCKET}" ]; then
    exec "${GATEWAY}" --socket "${PROXY_SOCKET}" -- "$@"
fi

# Gateway or socket not available -- pass through without proxy.
# containerEnv set HTTP(S)_PROXY to a port nothing is listening on; unset
# the proxy vars so the container runs as a plain devcontainer instead of
# failing every outbound request with "connection refused".
if [ ! -x "${GATEWAY}" ]; then
    echo "strait: gateway binary not found; running without network policy" >&2
fi
if [ ! -S "${PROXY_SOCKET}" ]; then
    echo "strait: proxy socket not found at ${PROXY_SOCKET}; running without network policy" >&2
    echo "strait: set STRAIT_PROXY_SOCKET on the host and restart the container" >&2
fi

unset HTTPS_PROXY HTTP_PROXY https_proxy http_proxy
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
