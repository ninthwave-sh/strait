#!/bin/sh
# packaging/linux/uninstall.sh -- reverse packaging/linux/install.sh.
#
# Removes the strait-host binaries, systemd user unit, and (optionally)
# the /var/run/strait/ socket directory. The user-level host.toml and
# the persisted rule store / observations log are left alone by default:
# they contain operator state the uninstall should not silently delete.
# Pass --purge to remove them too.

set -eu

SELF="${0##*/}"
PREFIX="${STRAIT_PREFIX:-${HOME}/.local}"
CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/strait"
UNIT_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
SOCKET_DIR="/var/run/strait"
WITH_SOCKET_DIR=1
PURGE=0
DRY_RUN=0

usage() {
    cat <<USAGE
Usage: ${SELF} [options]

Uninstalls the strait-host control plane.

Options:
  --prefix PATH         Same as install.sh --prefix (default: \$HOME/.local).
  --config-dir PATH     Override the strait config dir
                        (default: \$XDG_CONFIG_HOME/strait).
  --unit-dir PATH       Override the systemd user unit dir
                        (default: \$XDG_CONFIG_HOME/systemd/user).
  --socket-dir PATH     Override the runtime socket dir
                        (default: /var/run/strait).
  --no-socket-dir       Do not remove /var/run/strait/.
  --purge               Also remove host.toml, the rule store, and the
                        observations log. Destructive.
  --dry-run             Print every action without changing the system.
  -h, --help            Show this help.
USAGE
}

log() { printf '%s: %s\n' "${SELF}" "$*"; }
warn() { printf '%s: %s\n' "${SELF}" "$*" >&2; }
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
        --no-socket-dir) WITH_SOCKET_DIR=0; shift ;;
        --purge)         PURGE=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)
            warn "unknown option: $1"
            usage >&2
            exit 2
            ;;
    esac
done

# ── Stop and disable the systemd user unit ──────────────────────────────

UNIT_DST="${UNIT_DIR}/strait-host.service"
if command -v systemctl >/dev/null 2>&1 && [ -f "${UNIT_DST}" ]; then
    log "stopping and disabling strait-host.service"
    run systemctl --user disable --now strait-host.service 2>/dev/null || true
    run rm -f "${UNIT_DST}"
    run systemctl --user daemon-reload 2>/dev/null || true
elif [ -f "${UNIT_DST}" ]; then
    log "removing ${UNIT_DST}"
    run rm -f "${UNIT_DST}"
fi

# ── Binaries ────────────────────────────────────────────────────────────

for bin in strait strait-host strait-agent; do
    path="${PREFIX}/bin/${bin}"
    if [ -e "${path}" ]; then
        log "removing ${path}"
        run rm -f "${path}"
    fi
done

# ── Socket dir ──────────────────────────────────────────────────────────
#
# Always try to clean up the socket file even if we leave the dir alone,
# so stale sockets do not linger after uninstall.

SOCKET_FILE="${SOCKET_DIR}/host.sock"
if [ -S "${SOCKET_FILE}" ] || [ -e "${SOCKET_FILE}" ]; then
    log "removing stale socket ${SOCKET_FILE}"
    if [ -w "${SOCKET_DIR}" ] || [ "$(id -u)" -eq 0 ]; then
        run rm -f "${SOCKET_FILE}"
    elif command -v sudo >/dev/null 2>&1; then
        run sudo rm -f "${SOCKET_FILE}"
    fi
fi

if [ "${WITH_SOCKET_DIR}" -eq 1 ] && [ -d "${SOCKET_DIR}" ]; then
    log "removing ${SOCKET_DIR}"
    if [ -w "${SOCKET_DIR}" ] || [ "$(id -u)" -eq 0 ]; then
        run rmdir "${SOCKET_DIR}" 2>/dev/null || run rm -rf "${SOCKET_DIR}"
    elif command -v sudo >/dev/null 2>&1; then
        run sudo rm -rf "${SOCKET_DIR}"
    else
        warn "cannot remove ${SOCKET_DIR}: not root and no sudo available."
    fi
fi

# ── Optional purge of user state ────────────────────────────────────────

if [ "${PURGE}" -eq 1 ]; then
    log "purging user state"
    run rm -f "${CONFIG_DIR}/host.toml"
    run rm -f "${HOME}/.local/share/strait/rules.db"
    run rm -f "${HOME}/.local/share/strait/observations.jsonl"
fi

log "uninstall complete"
