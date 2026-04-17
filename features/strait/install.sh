#!/bin/sh
# install.sh -- strait devcontainer feature installer.
#
# Runs inside the builder context (as root) during `devcontainer build` or
# `docker build`. Installs the strait-agent binary, writes a config file
# from the feature options, and drops an entrypoint wrapper that execs
# `strait-agent entrypoint -- "$@"` when the container starts.
#
# The wrapper handles the CAP_NET_ADMIN + iptables + privilege-drop flow.
# The proxy subprocess is spawned by strait-agent, not by this script.
#
# Idempotent: re-running overwrites bundled artifacts without error.

set -e

# ---- Options -----------------------------------------------------------
#
# The devcontainer feature spec passes each option value to install.sh as
# an env var with the option name in uppercase. Fall back to defaults when
# the feature is installed by something that does not set them (direct
# docker build, local manual install, etc.).

HOST="${HOST:-/run/strait/host.sock}"
AGENT_USER="${AGENT_USER:-vscode}"
POLICY="${POLICY:-/etc/strait/policy.cedar}"
PROXY_PORT="${PROXY_PORT:-9443}"

# Reject obviously-bad option values early so misconfigured features fail
# at build time rather than producing a broken runtime entrypoint.
case "${PROXY_PORT}" in
    ''|*[!0-9]*)
        echo "strait feature: proxy_port must be a positive integer (got ${PROXY_PORT:-<empty>})" >&2
        exit 1
        ;;
esac
if [ "${PROXY_PORT}" -eq 0 ] 2>/dev/null || [ "${PROXY_PORT}" -gt 65535 ] 2>/dev/null; then
    echo "strait feature: proxy_port must be in 1..65535 (got ${PROXY_PORT})" >&2
    exit 1
fi
if [ -z "${AGENT_USER}" ]; then
    echo "strait feature: agent_user must not be empty" >&2
    exit 1
fi

# ---- Layout ------------------------------------------------------------

AGENT_BIN="/usr/local/bin/strait-agent"
CONFIG_DIR="/etc/strait"
CONFIG_PATH="${CONFIG_DIR}/strait-agent.toml"
SHARE_DIR="/usr/local/share/strait"
ENTRYPOINT_PATH="${SHARE_DIR}/entrypoint.sh"

mkdir -p "${CONFIG_DIR}" "${SHARE_DIR}"

# ---- iptables -----------------------------------------------------------
#
# strait-agent entrypoint shells out to `iptables` at container startup.
# Install it with the base image's package manager if missing. Refuse to
# silently succeed: without iptables the runtime entrypoint would fail
# with a less obvious error.

if ! command -v iptables >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y --no-install-recommends iptables
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache iptables
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y iptables
    elif command -v yum >/dev/null 2>&1; then
        yum install -y iptables
    else
        echo "strait feature: iptables missing and no supported package manager found." >&2
        echo "strait feature: install iptables in the base image before enabling this feature." >&2
        exit 1
    fi
fi

# ---- Arch detection -----------------------------------------------------
#
# The feature bundle ships one pre-built strait-agent per linux arch as
# `strait-agent-linux-amd64` / `strait-agent-linux-arm64`. Pick the one
# that matches the container's arch. `uname -m` reflects the container
# arch at feature-install time (docker buildx + --platform sets this up
# correctly via QEMU or a native arm64 builder).

UNAME_M="$(uname -m)"
case "${UNAME_M}" in
    x86_64|amd64)
        AGENT_ARCH="amd64"
        ;;
    aarch64|arm64)
        AGENT_ARCH="arm64"
        ;;
    *)
        echo "strait feature: unsupported architecture ${UNAME_M}" >&2
        echo "strait feature: supported: x86_64/amd64, aarch64/arm64" >&2
        exit 1
        ;;
esac

# ---- Bundled binary -----------------------------------------------------
#
# The install script accepts a binary from one of four sources, in order:
#
#   1. A pre-existing /usr/local/bin/strait-agent (bind-mount or COPY).
#   2. $STRAIT_AGENT_BINARY pointing at an explicit path.
#   3. A per-arch binary next to this script
#      (`strait-agent-linux-${AGENT_ARCH}`). This is what the release
#      feature bundle published to ghcr ships.
#   4. A sibling `strait-agent` file next to this script, for local
#      `features/strait/` development where a single arch is built.

FEATURE_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLED_BIN_ARCH="${FEATURE_DIR}/strait-agent-linux-${AGENT_ARCH}"
BUNDLED_BIN_GENERIC="${FEATURE_DIR}/strait-agent"

if [ -x "${AGENT_BIN}" ]; then
    echo "strait feature: using pre-installed ${AGENT_BIN}"
elif [ -n "${STRAIT_AGENT_BINARY:-}" ] && [ -x "${STRAIT_AGENT_BINARY}" ]; then
    install -m 0755 "${STRAIT_AGENT_BINARY}" "${AGENT_BIN}"
    echo "strait feature: installed strait-agent from STRAIT_AGENT_BINARY=${STRAIT_AGENT_BINARY}"
elif [ -x "${BUNDLED_BIN_ARCH}" ]; then
    install -m 0755 "${BUNDLED_BIN_ARCH}" "${AGENT_BIN}"
    echo "strait feature: installed bundled strait-agent (linux-${AGENT_ARCH}) to ${AGENT_BIN}"
elif [ -x "${BUNDLED_BIN_GENERIC}" ]; then
    install -m 0755 "${BUNDLED_BIN_GENERIC}" "${AGENT_BIN}"
    echo "strait feature: installed bundled strait-agent to ${AGENT_BIN}"
else
    cat >&2 <<EOF
strait feature: strait-agent binary not found.

Checked (in order):
  1. ${AGENT_BIN}                                 (pre-installed)
  2. \$STRAIT_AGENT_BINARY                         (explicit path)
  3. ${BUNDLED_BIN_ARCH}
  4. ${BUNDLED_BIN_GENERIC}

The published feature on ghcr (ghcr.io/ninthwave-io/strait) ships
per-arch binaries under source (3). If you are developing locally
against features/strait/ directly, build strait-agent for your
container arch and place it at (4), or set STRAIT_AGENT_BINARY.
EOF
    exit 1
fi

# ---- CAP_NET_ADMIN preflight (advisory) ---------------------------------
#
# CAP_NET_ADMIN applies at runtime, not during `docker build`. A build
# context without it is normal: docker buildkit drops non-default caps
# from the builder. Emit a clear message so operators know what to check
# if the runtime cap is also missing.
#
# The fail-hard check lives in strait-agent entrypoint (see
# agent/src/entrypoint.rs::ensure_cap_net_admin), which runs on every
# container start. It produces an actionable CAP_NET_ADMIN error that
# references this feature in its diagnostic.

if [ -r /proc/self/status ]; then
    CAP_EFF_HEX="$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
    if [ -n "${CAP_EFF_HEX}" ]; then
        # CAP_NET_ADMIN is bit 12 (mask 0x1000 in the lower 32 bits).
        LOW="$(printf '%s' "${CAP_EFF_HEX}" | awk '{ n=length($0); print substr($0, n>7?n-7:1) }')"
        if [ "$((0x${LOW} & 0x1000))" -ne 0 ]; then
            echo "strait feature: CAP_NET_ADMIN effective at build time"
        else
            cat <<EOF
strait feature: note -- CAP_NET_ADMIN is not effective in this build context.
                This is normal for docker buildkit builders. The runtime
                container must still be started with --cap-add=NET_ADMIN
                (the feature's capAdd: [NET_ADMIN] handles this for
                devcontainer runtimes). If CAP_NET_ADMIN is also missing
                at runtime, the entrypoint will fail fast with a
                diagnostic pointing at this feature.
EOF
        fi
    fi
fi

# ---- Config file --------------------------------------------------------
#
# Generate strait-agent.toml from the resolved option values. The
# entrypoint wrapper passes this to every strait-agent invocation via
# --config, so options honored here apply to both the entrypoint and the
# proxy subprocess it spawns.

cat > "${CONFIG_PATH}" <<TOML
# Generated by the strait devcontainer feature at install time.
# Hand-edits survive restarts but will be overwritten on feature rebuild.

[proxy]
port = ${PROXY_PORT}

[entrypoint]
agent_user = "${AGENT_USER}"
redirect_ports = [80, 443]

[host]
socket_path = "${HOST}"

# The Cedar policy path lives here so downstream tooling can discover it
# without re-reading the feature options. strait-agent picks it up when
# the proxy subprocess starts.
#
# policy_path = "${POLICY}"
TOML
chmod 0644 "${CONFIG_PATH}"

# Also expose the policy path as an env file so shells in the container
# can `source` it without parsing TOML. Useful for the proxy subprocess
# wiring until strait-agent's config schema adds a [policy] section.
cat > "${CONFIG_DIR}/env" <<ENVFILE
STRAIT_AGENT_CONFIG=${CONFIG_PATH}
STRAIT_AGENT_AGENT_USER=${AGENT_USER}
STRAIT_AGENT_PROXY_PORT=${PROXY_PORT}
STRAIT_AGENT_HOST_SOCKET=${HOST}
STRAIT_POLICY_PATH=${POLICY}
ENVFILE
chmod 0644 "${CONFIG_DIR}/env"

echo "strait feature: wrote ${CONFIG_PATH} and ${CONFIG_DIR}/env"

# ---- Entrypoint wrapper -------------------------------------------------
#
# The devcontainer runtime invokes this script as the container's
# entrypoint with the user's start command as positional args. It execs
# strait-agent, which installs iptables rules, drops privileges, and
# exec's the command as the agent user.

cat > "${ENTRYPOINT_PATH}" <<'ENTRYPOINT'
#!/bin/sh
# Generated by the strait devcontainer feature.
# Wraps the user's start command with strait-agent entrypoint so all
# outbound TCP from the agent user is REDIRECTed to the in-container
# proxy.

set -e

AGENT_BIN="/usr/local/bin/strait-agent"
CONFIG_PATH="/etc/strait/strait-agent.toml"

if [ ! -x "${AGENT_BIN}" ]; then
    cat >&2 <<'MSG'
strait entrypoint: /usr/local/bin/strait-agent is missing.
strait entrypoint: rebuild the devcontainer to re-run the feature install.
strait entrypoint: docs: https://github.com/ninthwave-io/strait
MSG
    exit 1
fi

if [ ! -r "${CONFIG_PATH}" ]; then
    cat >&2 <<MSG
strait entrypoint: ${CONFIG_PATH} is missing.
strait entrypoint: rebuild the devcontainer to re-run the feature install.
MSG
    exit 1
fi

# When invoked without a command, the container has nothing to run. Fall
# back to a sensible default shell so `docker run -it <image>` still
# gives the operator a prompt.
if [ "$#" -eq 0 ]; then
    set -- /bin/sh
fi

exec "${AGENT_BIN}" --config "${CONFIG_PATH}" entrypoint -- "$@"
ENTRYPOINT

chmod 0755 "${ENTRYPOINT_PATH}"
echo "strait feature: wrote ${ENTRYPOINT_PATH}"

echo "strait feature: install complete"
