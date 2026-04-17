#!/bin/sh
# packaging/macos/setup-socket-dir.sh -- create /var/run/strait/.
#
# /var/run is owned by root on macOS, so the Homebrew formula cannot
# create strait's socket directory without elevation. Ship this helper
# alongside the formula and instruct the user to run it once with sudo
# after install; it creates /var/run/strait/ owned by the invoking user
# with mode 0755 so strait-host can bind host.sock there without root.
#
# Idempotent: re-running just re-chowns and re-chmods.

set -eu

USAGE="Usage: sudo ${0##*/} [--user USER]"

TARGET_USER="${SUDO_USER:-${USER:-}}"
while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            [ $# -lt 2 ] && { echo "$USAGE" >&2; exit 2; }
            TARGET_USER="$2"
            shift 2
            ;;
        -h|--help)
            echo "$USAGE"
            exit 0
            ;;
        *)
            echo "$USAGE" >&2
            exit 2
            ;;
    esac
done

if [ -z "${TARGET_USER}" ]; then
    echo "setup-socket-dir: unable to determine target user; pass --user USER" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "setup-socket-dir: must run as root (try: sudo $0)" >&2
    exit 1
fi

if ! id "${TARGET_USER}" >/dev/null 2>&1; then
    echo "setup-socket-dir: user '${TARGET_USER}' does not exist" >&2
    exit 1
fi

# Use install(1) so ownership and mode are set atomically regardless of
# whether the directory already exists.
install -d -m 0755 -o "${TARGET_USER}" /var/run/strait
echo "setup-socket-dir: /var/run/strait ready (owner=${TARGET_USER}, mode=0755)"
