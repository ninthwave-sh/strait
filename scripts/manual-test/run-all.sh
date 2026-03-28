#!/usr/bin/env bash
# run-all.sh — Run all manual test scripts in sequence.
#
# Usage:
#   ./scripts/manual-test/run-all.sh              # run everything
#   ./scripts/manual-test/run-all.sh --no-docker   # skip Docker tests
#   ./scripts/manual-test/run-all.sh 03 04         # run specific tests by number
#
# Prerequisites:
#   - cargo (Rust toolchain)
#   - Docker (for container tests — 04, 05, 06)
#   - GITHUB_TOKEN (for GitHub API tests — 03, 04, 08, 09)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

NO_DOCKER=false
SPECIFIC_TESTS=()

for arg in "$@"; do
    case "$arg" in
        --no-docker) NO_DOCKER=true ;;
        *) SPECIFIC_TESTS+=("$arg") ;;
    esac
done

# All test scripts in order
ALL_TESTS=(
    "01-build-and-check"
    "02-policy-tooling"
    "03-proxy-github"
    "04-observe-generate-enforce"
    "05-watch-live"
    "06-container-lifecycle"
    "07-error-handling"
    "08-init-observe"
    "09-sighup-reload"
)

DOCKER_TESTS=("04" "05" "06")

should_run() {
    local test_name="$1"
    local test_num="${test_name:0:2}"

    # If specific tests requested, only run those
    if [[ ${#SPECIFIC_TESTS[@]} -gt 0 ]]; then
        for t in "${SPECIFIC_TESTS[@]}"; do
            if [[ "$test_num" == "$t" ]]; then
                return 0
            fi
        done
        return 1
    fi

    # Skip Docker tests if requested
    if $NO_DOCKER; then
        for dt in "${DOCKER_TESTS[@]}"; do
            if [[ "$test_num" == "$dt" ]]; then
                return 1
            fi
        done
    fi

    return 0
}

echo ""
echo -e "${BOLD}strait manual verification suite${RESET}"
echo -e "${DIM}$(date)${RESET}"
echo ""

# Print environment
echo -e "Prerequisites:"
echo -e "  cargo:        $(command -v cargo >/dev/null && echo -e "${GREEN}found${RESET}" || echo -e "${RED}missing${RESET}")"
echo -e "  docker:       $(command -v docker >/dev/null && docker info >/dev/null 2>&1 && echo -e "${GREEN}running${RESET}" || echo -e "${YELLOW}not available${RESET}")"
echo -e "  GITHUB_TOKEN: $(test -n "${GITHUB_TOKEN:-}" && echo -e "${GREEN}set${RESET}" || echo -e "${YELLOW}not set${RESET}")"
echo ""

FAIL_TOTAL=0
RESULTS=()

for test_name in "${ALL_TESTS[@]}"; do
    if ! should_run "$test_name"; then
        echo -e "${DIM}--- skipping $test_name ---${RESET}"
        continue
    fi

    SCRIPT="$SCRIPT_DIR/$test_name.sh"
    if [[ ! -x "$SCRIPT" ]]; then
        echo -e "${YELLOW}$test_name: not executable (chmod +x it)${RESET}"
        continue
    fi

    echo ""
    echo -e "${BOLD}════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  $test_name${RESET}"
    echo -e "${BOLD}════════════════════════════════════════${RESET}"

    if "$SCRIPT"; then
        RESULTS+=("${GREEN}PASS${RESET}  $test_name")
    else
        RESULTS+=("${RED}FAIL${RESET}  $test_name")
        FAIL_TOTAL=$((FAIL_TOTAL + 1))
    fi
done

echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Overall Results${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo ""

for result in "${RESULTS[@]}"; do
    echo -e "  $result"
done

echo ""
exit "$FAIL_TOTAL"
