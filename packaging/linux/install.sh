#!/bin/sh
# packaging/linux/install.sh -- strait-host tarball installer.
#
# Ships inside the Linux release tarball alongside the strait, strait-
# host, and strait-agent binaries plus the systemd user unit and config
# template. Running it installs the binaries into --prefix (default
# $HOME/.local), drops the systemd user unit at
# $HOME/.config/systemd/user/strait-host.service, seeds a default
# host.toml if one is not already there, creates /var/run/strait/ with
# the invoking user's ownership, and reloads + enables the user unit so
# `systemctl --user start strait-host` works immediately.
#
# When systemd is missing (minimal containers, non-systemd distros) the
# installer skips the unit step and prints a foreground command the user
# can run from a terminal instead. Nothing in the installer requires
# systemd to be the init system -- `--no-systemd` also forces the
# foreground fallback.
#
# Idempotent: re-running overwrites binaries and the unit in place,
# leaves an existing host.toml alone, and re-reloads the manager.

set -eu

SELF="${0##*/}"
TARBALL_DIR="$(cd "$(dirname "$0")" && pwd)"

PREFIX="${STRAIT_PREFIX:-${HOME}/.local}"
CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/strait"
UNIT_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
SOCKET_DIR="/var/run/strait"
WITH_SYSTEMD=auto
WITH_SOCKET_DIR=1
DRY_RUN=0
ENABLE_NOW=1

usage() {
    cat <<USAGE
Usage: ${SELF} [options]

Installs the strait-host control plane from a release tarball.

Options:
  --prefix PATH         Install prefix for binaries (default: \$HOME/.local).
                        Binaries go in \$PREFIX/bin.
  --config-dir PATH     Override the strait config dir
                        (default: \$XDG_CONFIG_HOME/strait, falls back to
                        \$HOME/.config/strait).
  --unit-dir PATH       Override the systemd user unit dir
                        (default: \$XDG_CONFIG_HOME/systemd/user).
  --socket-dir PATH     Override the runtime socket dir
                        (default: /var/run/strait).
  --no-systemd          Skip systemd unit install and foreground-only.
  --no-socket-dir       Skip /var/run/strait/ creation. Use when
                        installing on a build host or inside a test.
  --no-start            Install the unit but do not enable/start it.
  --dry-run             Print every action without changing the system.
  -h, --help            Show this help.

Env:
  STRAIT_PREFIX         Equivalent to --prefix when set.
USAGE
}

log() {
    printf '%s: %s\n' "${SELF}" "$*"
}

warn() {
    printf '%s: %s\n' "${SELF}" "$*" >&2
}

run() {
    if [ "${DRY_RUN}" -eq 1 ]; then
        printf '%s: + %s\n' "${SELF}" "$*"
    else
        "$@"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)        [ $# -lt 2 ] && { usage >&2; exit 2; }; PREFIX="$2"; shift 2 ;;
        --config-dir)    [ $# -lt 2 ] && { usage >&2; exit 2; }; CONFIG_DIR="$2"; shift 2 ;;
        --unit-dir)      [ $# -lt 2 ] && { usage >&2; exit 2; }; UNIT_DIR="$2"; shift 2 ;;
        --socket-dir)    [ $# -lt 2 ] && { usage >&2; exit 2; }; SOCKET_DIR="$2"; shift 2 ;;
        --no-systemd)    WITH_SYSTEMD=no; shift ;;
        --no-socket-dir) WITH_SOCKET_DIR=0; shift ;;
        --no-start)      ENABLE_NOW=0; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)
            warn "unknown option: $1"
            usage >&2
            exit 2
            ;;
    esac
done

# ── Source layout ───────────────────────────────────────────────────────
#
# The tarball lays out binaries in a `bin/` subdirectory alongside this
# installer and the packaging assets. The dev tree ships the same
# assets, so `./install.sh` also works when run directly from the
# checkout with `--prefix <tmp>` (see tests/packaging.rs).

BIN_SRC_DIR=""
# STRAIT_BIN_SRC_DIR wins if explicitly set so tests and advanced
# operators can pin the source without editing the tarball layout.
if [ -n "${STRAIT_BIN_SRC_DIR:-}" ]; then
    BIN_SRC_DIR="${STRAIT_BIN_SRC_DIR}"
else
    for candidate in \
            "${TARBALL_DIR}/bin" \
            "${TARBALL_DIR}/../bin" \
            "${TARBALL_DIR}/../../target/release" \
            "${TARBALL_DIR}/../../target/debug"; do
        if [ -x "${candidate}/strait-host" ]; then
            BIN_SRC_DIR="${candidate}"
            break
        fi
    done
fi

if [ -z "${BIN_SRC_DIR}" ]; then
    warn "could not locate strait-host binary next to the installer."
    warn "expected one of:"
    warn "  ${TARBALL_DIR}/bin/strait-host"
    warn "  ${TARBALL_DIR}/../bin/strait-host"
    warn "or set STRAIT_BIN_SRC_DIR to the directory that contains the built binaries."
    exit 1
fi

UNIT_SRC="${TARBALL_DIR}/strait-host.service"
TOML_TEMPLATE="${TARBALL_DIR}/../host.toml.example"
if [ ! -f "${TOML_TEMPLATE}" ]; then
    # Tarball layout keeps the template next to the installer.
    TOML_TEMPLATE="${TARBALL_DIR}/host.toml.example"
fi

if [ ! -f "${UNIT_SRC}" ]; then
    warn "missing systemd unit template at ${UNIT_SRC}"
    exit 1
fi
if [ ! -f "${TOML_TEMPLATE}" ]; then
    warn "missing host.toml template (looked in ${TARBALL_DIR}/../host.toml.example and ${TARBALL_DIR}/host.toml.example)"
    exit 1
fi

# ── systemd detection ───────────────────────────────────────────────────

detect_systemd() {
    if [ "${WITH_SYSTEMD}" = "no" ]; then
        echo "no"
        return
    fi
    if command -v systemctl >/dev/null 2>&1 && \
       [ -d /run/systemd/system ]; then
        echo "yes"
    else
        echo "no"
    fi
}
HAS_SYSTEMD="$(detect_systemd)"

# ── Install binaries ────────────────────────────────────────────────────

BIN_DST_DIR="${PREFIX}/bin"
log "installing binaries from ${BIN_SRC_DIR} to ${BIN_DST_DIR}"
run mkdir -p "${BIN_DST_DIR}"
for bin in strait strait-host strait-agent; do
    src="${BIN_SRC_DIR}/${bin}"
    if [ ! -x "${src}" ]; then
        # Missing non-host binaries are a warning, not fatal, so a host-
        # only dev build still installs.
        if [ "${bin}" = "strait-host" ]; then
            warn "required binary ${src} not found"
            exit 1
        fi
        warn "optional binary ${src} not found; skipping"
        continue
    fi
    run install -m 0755 "${src}" "${BIN_DST_DIR}/${bin}"
done

# ── Seed host.toml ──────────────────────────────────────────────────────

CONFIG_PATH="${CONFIG_DIR}/host.toml"
run mkdir -p "${CONFIG_DIR}"
if [ -f "${CONFIG_PATH}" ]; then
    log "keeping existing ${CONFIG_PATH}"
else
    log "writing default ${CONFIG_PATH}"
    run install -m 0644 "${TOML_TEMPLATE}" "${CONFIG_PATH}"
fi

# ── /var/run/strait/ ────────────────────────────────────────────────────

if [ "${WITH_SOCKET_DIR}" -eq 1 ]; then
    if [ -d "${SOCKET_DIR}" ] && [ -w "${SOCKET_DIR}" ]; then
        log "socket dir already writable: ${SOCKET_DIR}"
    elif [ "$(id -u)" -eq 0 ]; then
        log "creating socket dir ${SOCKET_DIR}"
        run install -d -m 0755 -o "${SUDO_USER:-root}" -g "${SUDO_USER:-root}" "${SOCKET_DIR}" \
            || run install -d -m 0755 "${SOCKET_DIR}"
    elif command -v sudo >/dev/null 2>&1; then
        log "creating socket dir ${SOCKET_DIR} (sudo)"
        run sudo install -d -m 0755 -o "$(id -un)" -g "$(id -gn)" "${SOCKET_DIR}"
    else
        warn "cannot create ${SOCKET_DIR}: not root and no sudo available."
        warn "create it manually before starting strait-host, or edit"
        warn "${CONFIG_PATH} to use a user-writable unix_socket path."
    fi
else
    log "skipping socket dir creation (--no-socket-dir)"
fi

# ── systemd user unit ───────────────────────────────────────────────────

UNIT_DST="${UNIT_DIR}/strait-host.service"
if [ "${HAS_SYSTEMD}" = "yes" ]; then
    log "installing systemd user unit at ${UNIT_DST}"
    run mkdir -p "${UNIT_DIR}"
    run install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
    run systemctl --user daemon-reload
    if [ "${ENABLE_NOW}" -eq 1 ]; then
        log "enabling and starting strait-host.service"
        run systemctl --user enable --now strait-host.service
    else
        log "unit installed; start it with: systemctl --user start strait-host.service"
    fi
    cat <<EOF

strait-host installed. Useful commands:

    systemctl --user status strait-host.service
    journalctl --user -u strait-host.service -f
    ${BIN_DST_DIR}/strait-host --help

EOF
else
    cat <<EOF

strait-host installed at ${BIN_DST_DIR}/strait-host, but systemd user
mode is not available (or was disabled with --no-systemd). Start the
host in the foreground with:

    ${BIN_DST_DIR}/strait-host serve

The config template was written to ${CONFIG_PATH}; edit it before
starting the host if you need to override defaults.

EOF
fi
