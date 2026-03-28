#!/usr/bin/env bash
# 05 — Interactive watch test.
# Requires: Docker
#
# This test launches an agent in observe mode and runs `strait watch`
# in parallel so you can see live colored output. This is an interactive
# test — you verify visually that the watch output looks right.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    echo -e "${YELLOW}Docker not available — skipping watch test${RESET}"
    exit 0
fi

cleanup() {
    kill_jobs
    cleanup_tmpdir
}
trap cleanup EXIT

section "Live Watch Test (interactive)"

echo -e "  This test runs an agent that makes several HTTP requests while"
echo -e "  ${BOLD}strait watch${RESET} displays live colored events."
echo ""
echo -e "  ${CYAN}▶ What to verify:${RESET}"
echo -e "    - Green entries for allowed actions"
echo -e "    - Cyan entries for container lifecycle (start/stop)"
echo -e "    - Events appear in real time as the agent runs"
echo -e "    - Clean shutdown when the agent exits"
echo ""
echo -e "  ${DIM}Starting agent in observe mode...${RESET}"

# Launch agent in background
"$STRAIT" launch --observe \
    --image alpine:latest \
    --output "$TMPDIR_BASE/watch-observations.jsonl" \
    -- sh -c "
        apk add --no-cache curl >/dev/null 2>&1
        sleep 2
        echo 'Request 1: /zen'
        curl -sf https://api.github.com/zen || true
        sleep 1
        echo 'Request 2: /meta'
        curl -sf https://api.github.com/meta > /dev/null || true
        sleep 1
        echo 'Request 3: /octocat'
        curl -sf https://api.github.com/octocat || true
        sleep 1
        echo 'Done'
    " > "$TMPDIR_BASE/agent-stdout.log" 2> "$TMPDIR_BASE/agent-stderr.log" &
AGENT_PID=$!

# Give the agent a moment to start the observation socket
sleep 3

echo ""
echo -e "  ${BOLD}=== strait watch output ===${RESET}"
echo ""

# Run watch in foreground — it will exit when the socket closes
timeout 30 "$STRAIT" watch 2>/dev/null || true

echo ""
echo -e "  ${BOLD}=== end watch output ===${RESET}"
echo ""

wait "$AGENT_PID" 2>/dev/null || true

manual_verify "Did you see colored event output above?"
manual_verify "Were container start/stop events visible?"
manual_verify "Were network request events visible with hostnames?"

summary
