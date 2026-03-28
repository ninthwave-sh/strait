#!/usr/bin/env bash
# 01 — Build binary and verify prerequisites.
# No Docker or credentials required.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

section "Build & Prerequisites"

# Build release binary
echo -e "  ${DIM}building release binary...${RESET}"
(cd "$REPO_ROOT" && cargo build --release 2>&1) || {
    echo -e "  ${RED}cargo build --release failed${RESET}"
    exit 1
}
echo -e "  ${GREEN}build complete${RESET}"

check "binary exists" test -x "$STRAIT"

# Verify --help works for every subcommand
check "strait --help" "$STRAIT" --help
check "strait proxy --help" "$STRAIT" proxy --help
check "strait launch --help" "$STRAIT" launch --help
check "strait generate --help" "$STRAIT" generate --help
check "strait test --help" "$STRAIT" test --help
check "strait watch --help" "$STRAIT" watch --help
check "strait explain --help" "$STRAIT" explain --help
check "strait diff --help" "$STRAIT" diff --help
check "strait template --help" "$STRAIT" template --help
check "strait init --help" "$STRAIT" init --help

section "External Dependencies"

# Docker
if command -v docker &>/dev/null && docker info &>/dev/null; then
    check "docker daemon reachable" docker info
else
    skip "docker daemon reachable" "Docker not running — launch tests will be skipped"
fi

# GitHub token
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    check "GITHUB_TOKEN is set" test -n "$GITHUB_TOKEN"
else
    skip "GITHUB_TOKEN is set" "set GITHUB_TOKEN for GitHub API tests"
fi

summary
