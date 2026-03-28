#!/usr/bin/env bash
# Shared helpers for manual test scripts.

set -uo pipefail
# NOTE: set -e is intentionally NOT used. Check functions track pass/fail
# via counters so all tests run even when some fail. Scripts call summary()
# at the end to report results and return the correct exit code.

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# Counters
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STRAIT="$REPO_ROOT/target/release/strait"
TMPDIR_BASE="${TMPDIR:-/tmp}/strait-manual-test-$$"

setup_tmpdir() {
    mkdir -p "$TMPDIR_BASE"
}

cleanup_tmpdir() {
    rm -rf "$TMPDIR_BASE"
}

section() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${RESET}"
    echo ""
}

check() {
    local description="$1"
    shift
    echo -n -e "  ${DIM}testing:${RESET} $description ... "
    local output
    if output=$("$@" 2>&1); then
        echo -e "${GREEN}PASS${RESET}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "${RED}FAIL${RESET}"
        if [[ -n "$output" ]]; then
            printf '    %s\n' "$output" | head -5
        fi
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

check_contains() {
    local description="$1"
    local haystack="$2"
    local needle="$3"
    echo -n -e "  ${DIM}testing:${RESET} $description ... "
    if echo "$haystack" | grep -qE "$needle"; then
        echo -e "${GREEN}PASS${RESET}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "${RED}FAIL${RESET}"
        echo -e "    ${DIM}expected to find: $needle${RESET}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

check_not_contains() {
    local description="$1"
    local haystack="$2"
    local needle="$3"
    echo -n -e "  ${DIM}testing:${RESET} $description ... "
    if echo "$haystack" | grep -qE "$needle"; then
        echo -e "${RED}FAIL${RESET}"
        echo -e "    ${DIM}should NOT contain: $needle${RESET}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo -e "${GREEN}PASS${RESET}"
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
    return 0
}

check_file_exists() {
    local description="$1"
    local path="$2"
    echo -n -e "  ${DIM}testing:${RESET} $description ... "
    if [[ -f "$path" ]]; then
        echo -e "${GREEN}PASS${RESET}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo -e "${RED}FAIL${RESET}"
        echo -e "    ${DIM}file not found: $path${RESET}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    return 0
}

skip() {
    local description="$1"
    local reason="$2"
    echo -e "  ${DIM}testing:${RESET} $description ... ${YELLOW}SKIP${RESET} ($reason)"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

manual_verify() {
    local description="$1"
    echo -e "  ${CYAN}▶ VERIFY:${RESET} $description"
}

wait_for_port() {
    local port="$1"
    local timeout="${2:-10}"
    local elapsed=0
    while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
        sleep 0.2
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout * 5)) ]]; then
            return 1
        fi
    done
}

# Wait for a process to write a specific string to a file
wait_for_output() {
    local file="$1"
    local pattern="$2"
    local timeout="${3:-10}"
    local elapsed=0
    while ! grep -q "$pattern" "$file" 2>/dev/null; do
        sleep 0.2
        elapsed=$((elapsed + 1))
        if [[ $elapsed -ge $((timeout * 5)) ]]; then
            return 1
        fi
    done
}

kill_bg() {
    local pid="$1"
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
}

# Kill background jobs portably (macOS-compatible, no xargs -r)
kill_jobs() {
    local pids
    pids=$(jobs -p 2>/dev/null) || true
    if [[ -n "$pids" ]]; then
        echo "$pids" | while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done
    fi
}

summary() {
    echo ""
    echo -e "${BOLD}━━━ Results ━━━${RESET}"
    echo -e "  ${GREEN}Passed: $PASS_COUNT${RESET}"
    if [[ $FAIL_COUNT -gt 0 ]]; then
        echo -e "  ${RED}Failed: $FAIL_COUNT${RESET}"
    fi
    if [[ $SKIP_COUNT -gt 0 ]]; then
        echo -e "  ${YELLOW}Skipped: $SKIP_COUNT${RESET}"
    fi
    echo ""
    if [[ $FAIL_COUNT -gt 0 ]]; then
        return 1
    fi
}
