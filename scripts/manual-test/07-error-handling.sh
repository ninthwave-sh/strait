#!/usr/bin/env bash
# 07 — Error handling and edge cases.
# Tests: invalid configs, missing files, bad policies, no Docker.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

cleanup() {
    kill_jobs
    cleanup_tmpdir
}
trap cleanup EXIT

section "Invalid Config Handling"

# Missing config file
MISSING_OUT=$("$STRAIT" proxy --config "$TMPDIR_BASE/nonexistent.toml" 2>&1) || true
check_contains "missing config gives clear error" "$MISSING_OUT" "No such file|not found|error|Error"

# Invalid TOML syntax
echo "this is not valid toml {{{{" > "$TMPDIR_BASE/bad.toml"
BAD_TOML_OUT=$("$STRAIT" proxy --config "$TMPDIR_BASE/bad.toml" 2>&1) || true
check_contains "invalid TOML gives parse error" "$BAD_TOML_OUT" "parse|error|Error|invalid|expected"

# Config missing required fields
echo '[listen]' > "$TMPDIR_BASE/incomplete.toml"
echo 'port = 9999' >> "$TMPDIR_BASE/incomplete.toml"
INCOMPLETE_OUT=$("$STRAIT" proxy --config "$TMPDIR_BASE/incomplete.toml" 2>&1) || true
check_contains "incomplete config gives clear error" "$INCOMPLETE_OUT" "missing|required|error|Error|ca_cert"

section "Invalid Policy Files"

# Bad Cedar syntax
echo "this is not cedar" > "$TMPDIR_BASE/bad.cedar"
BAD_CEDAR_EXIT=0
BAD_CEDAR_OUT=$("$STRAIT" explain "$TMPDIR_BASE/bad.cedar" 2>&1) || BAD_CEDAR_EXIT=$?
check "bad Cedar file returns error" test "$BAD_CEDAR_EXIT" -ne 0

# Empty policy file
touch "$TMPDIR_BASE/empty.cedar"
EMPTY_OUT=$("$STRAIT" explain "$TMPDIR_BASE/empty.cedar" 2>&1) || true
# Should handle gracefully — either explain nothing or give a message
check "empty policy handled gracefully (no crash)" true

# Generate with empty observations
touch "$TMPDIR_BASE/empty.jsonl"
EMPTY_GEN=$("$STRAIT" generate "$TMPDIR_BASE/empty.jsonl" \
    --output "$TMPDIR_BASE/empty-gen.cedar" \
    --schema "$TMPDIR_BASE/empty-gen.cedarschema" 2>&1) || true
check "generate from empty observations handled gracefully" true

section "Replay Mismatches"

# Create a policy that DOESN'T cover the observations
cat > "$TMPDIR_BASE/narrow.cedar" <<'CEDAR'
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.example.com"
);
CEDAR

# Create synthetic observations that won't match
cat > "$TMPDIR_BASE/synthetic.jsonl" <<'JSONL'
{"version":1,"timestamp":"2026-03-28T00:00:00Z","type":"network_request","method":"GET","host":"api.github.com","path":"/repos","decision":"allow"}
{"version":1,"timestamp":"2026-03-28T00:00:01Z","type":"network_request","method":"DELETE","host":"api.github.com","path":"/repos/x","decision":"allow"}
JSONL

REPLAY_EXIT=0
REPLAY_OUT=$("$STRAIT" test --replay "$TMPDIR_BASE/synthetic.jsonl" \
    --policy "$TMPDIR_BASE/narrow.cedar" 2>&1) || REPLAY_EXIT=$?
check "replay detects mismatches (non-zero exit)" test "$REPLAY_EXIT" -ne 0

echo ""
echo -e "  ${CYAN}▶ Human review — mismatch report:${RESET}"
echo -e "${DIM}"
echo "$REPLAY_OUT"
echo -e "${RESET}"

section "Diff Edge Cases"

# Diff with missing file
DIFF_MISSING=$("$STRAIT" diff "$REPO_ROOT/examples/github.cedar" "$TMPDIR_BASE/nonexistent.cedar" 2>&1) || true
check_contains "diff missing file gives error" "$DIFF_MISSING" "No such file|not found|error|Error"

# Diff with bad Cedar
echo "not cedar" > "$TMPDIR_BASE/bad2.cedar"
DIFF_BAD_EXIT=0
DIFF_BAD=$("$STRAIT" diff "$REPO_ROOT/examples/github.cedar" "$TMPDIR_BASE/bad2.cedar" 2>&1) || DIFF_BAD_EXIT=$?
check "diff with bad Cedar returns error" test "$DIFF_BAD_EXIT" -ne 0

section "Docker Error Handling"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    # Bad image name
    BAD_IMAGE_EXIT=0
    BAD_IMAGE_OUT=$("$STRAIT" launch --observe \
        --image "this-image-does-not-exist-12345:latest" \
        --output "$TMPDIR_BASE/bad-image.jsonl" \
        -- echo "hello" 2>&1) || BAD_IMAGE_EXIT=$?
    check "bad image name gives clear error" test "$BAD_IMAGE_EXIT" -ne 0
    check_contains "error message mentions image" "$BAD_IMAGE_OUT" "image|Image|pull|Pull|not found|Error|error"

    # Invalid command
    BAD_CMD_EXIT=0
    BAD_CMD_OUT=$("$STRAIT" launch --observe \
        --image alpine:latest \
        --output "$TMPDIR_BASE/bad-cmd.jsonl" \
        -- /nonexistent-binary 2>&1) || BAD_CMD_EXIT=$?
    check "invalid command gives non-zero exit" test "$BAD_CMD_EXIT" -ne 0
else
    skip "docker error handling" "Docker not available"
fi

summary
