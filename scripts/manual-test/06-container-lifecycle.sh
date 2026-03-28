#!/usr/bin/env bash
# 06 — Container lifecycle edge cases.
# Requires: Docker
#
# Tests: signal handling, exit codes, cleanup, TTY, image pull.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    echo -e "${YELLOW}Docker not available — skipping container lifecycle tests${RESET}"
    exit 0
fi

cleanup() {
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    docker rm -f strait-lifecycle-test 2>/dev/null || true
    cleanup_tmpdir
}
trap cleanup EXIT

section "Container Exit Codes"

# Normal exit (0)
"$STRAIT" launch --observe \
    --image alpine:latest \
    --output "$TMPDIR_BASE/exit0.jsonl" \
    -- sh -c "exit 0" \
    > /dev/null 2> /dev/null
EXIT_0=$?
check "exit code 0 propagated" test "$EXIT_0" -eq 0

# Non-zero exit
"$STRAIT" launch --observe \
    --image alpine:latest \
    --output "$TMPDIR_BASE/exit1.jsonl" \
    -- sh -c "exit 42" \
    > /dev/null 2> /dev/null || true
EXIT_42=$?
check "non-zero exit code propagated" test "$EXIT_42" -ne 0

section "Container Cleanup"

# After launch, no orphaned containers should remain
"$STRAIT" launch --observe \
    --image alpine:latest \
    --output "$TMPDIR_BASE/cleanup.jsonl" \
    -- echo "hello" \
    > /dev/null 2> /dev/null || true

# Check no strait containers are running
RUNNING=$(docker ps --filter "label=strait" --format '{{.Names}}' 2>/dev/null || true)
check "no orphaned containers after clean exit" test -z "$RUNNING"

section "Signal Handling (SIGTERM)"

# Start a long-running container
"$STRAIT" launch --observe \
    --image alpine:latest \
    --output "$TMPDIR_BASE/signal.jsonl" \
    -- sleep 300 \
    > /dev/null 2> "$TMPDIR_BASE/signal-stderr.log" &
LAUNCH_PID=$!

# Wait for container to start
sleep 5

# Send SIGTERM
kill -TERM "$LAUNCH_PID" 2>/dev/null || true

# Wait for clean shutdown (should not hang)
TIMEOUT_EXIT=0
timeout 15 bash -c "wait $LAUNCH_PID 2>/dev/null" || TIMEOUT_EXIT=$?
check "SIGTERM causes clean shutdown within 15s" test "$TIMEOUT_EXIT" -ne 124

# Verify no orphaned container
sleep 1
RUNNING_AFTER=$(docker ps --filter "label=strait" --format '{{.Names}}' 2>/dev/null || true)
check "no orphaned container after SIGTERM" test -z "$RUNNING_AFTER"

section "Image Auto-Pull"

# Use an image that might not be cached locally
# (alpine:latest is likely cached, but this verifies the pull path works)
"$STRAIT" launch --observe \
    --image alpine:3.19 \
    --output "$TMPDIR_BASE/pull.jsonl" \
    -- echo "pulled" \
    > "$TMPDIR_BASE/pull-stdout.log" 2> "$TMPDIR_BASE/pull-stderr.log" || true

PULL_OUT=$(cat "$TMPDIR_BASE/pull-stdout.log")
check_contains "auto-pulled image ran successfully" "$PULL_OUT" "pulled"

section "Filesystem Mounts (Enforce Mode)"

# Create a simple policy that allows read but not write
cat > "$TMPDIR_BASE/fs-policy.cedar" <<'CEDAR'
permit(
    principal,
    action == Action::"fs:read",
    resource in Resource::"fs::/workspace"
);
CEDAR

# Create a test directory
mkdir -p "$TMPDIR_BASE/workspace"
echo "test content" > "$TMPDIR_BASE/workspace/readme.txt"

echo -e "  ${DIM}testing filesystem enforcement... (this may vary by container setup)${RESET}"

"$STRAIT" launch --policy "$TMPDIR_BASE/fs-policy.cedar" \
    --image alpine:latest \
    --output "$TMPDIR_BASE/fs-observations.jsonl" \
    -- sh -c "
        echo 'Attempting to read /workspace/readme.txt:'
        cat /workspace/readme.txt 2>&1 || echo 'READ FAILED'
        echo 'Attempting to write /workspace/new.txt:'
        echo 'new' > /workspace/new.txt 2>&1 || echo 'WRITE BLOCKED (expected)'
    " > "$TMPDIR_BASE/fs-stdout.log" 2> "$TMPDIR_BASE/fs-stderr.log" || true

FS_OUT=$(cat "$TMPDIR_BASE/fs-stdout.log")
echo ""
echo -e "  ${CYAN}▶ Human review — filesystem enforcement:${RESET}"
echo -e "${DIM}"
echo "$FS_OUT"
echo -e "${RESET}"
manual_verify "Read succeeded but write was blocked (read-only mount)?"

summary
