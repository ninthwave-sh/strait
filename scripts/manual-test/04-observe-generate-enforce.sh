#!/usr/bin/env bash
# 04 — Full observe → generate → warn → enforce lifecycle.
# Requires: Docker, GITHUB_TOKEN
#
# This is the core v0.3 workflow test. It exercises:
#   1. strait launch --observe (container + observation recording)
#   2. strait generate (policy from observations)
#   3. strait explain (human-readable summary)
#   4. strait test --replay (verify policy against observations)
#   5. strait launch --warn (log violations without blocking)
#   6. strait launch --policy (enforce — block violations)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

# Prerequisite checks
if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    echo -e "${YELLOW}Docker not available — skipping observe-generate-enforce tests${RESET}"
    exit 0
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo -e "${YELLOW}GITHUB_TOKEN not set — skipping (needed for real API calls)${RESET}"
    exit 0
fi

cleanup() {
    # Kill any background strait processes
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    # Remove any leftover containers
    docker rm -f strait-manual-test 2>/dev/null || true
    cleanup_tmpdir
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────
# Phase 1: OBSERVE
# ─────────────────────────────────────────────────────────────
section "Phase 1: Observe"

echo -e "  ${DIM}launching container in observe mode...${RESET}"
echo -e "  ${DIM}this will make real API calls through the proxy${RESET}"

# Run a simple agent that hits GitHub API
"$STRAIT" launch --observe \
    --image alpine:latest \
    --output "$TMPDIR_BASE/observations.jsonl" \
    -- sh -c "
        apk add --no-cache curl >/dev/null 2>&1
        echo '--- Hitting GitHub API ---'
        curl -sf https://api.github.com/zen || echo 'zen failed (expected — no policy allows it yet)'
        curl -sf https://api.github.com/meta | head -c 200 || echo 'meta failed'
        echo ''
        echo '--- Done ---'
    " > "$TMPDIR_BASE/observe-stdout.log" 2> "$TMPDIR_BASE/observe-stderr.log" || true

check_file_exists "observations.jsonl created" "$TMPDIR_BASE/observations.jsonl"

OBS_LINES=$(wc -l < "$TMPDIR_BASE/observations.jsonl" | tr -d ' ')
check "observations.jsonl has events" test "$OBS_LINES" -gt 0

OBS_CONTENT=$(cat "$TMPDIR_BASE/observations.jsonl")
check_contains "observations contain network events" "$OBS_CONTENT" "api.github.com\|network\|http"
check_contains "observations contain container events" "$OBS_CONTENT" "container\|Container\|start\|Start"

echo ""
echo -e "  ${CYAN}▶ Human review — observation sample:${RESET}"
echo -e "${DIM}"
head -5 "$TMPDIR_BASE/observations.jsonl" | python3 -m json.tool 2>/dev/null || head -5 "$TMPDIR_BASE/observations.jsonl"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Phase 2: GENERATE
# ─────────────────────────────────────────────────────────────
section "Phase 2: Generate Policy"

"$STRAIT" generate "$TMPDIR_BASE/observations.jsonl" \
    --output "$TMPDIR_BASE/generated.cedar" \
    --schema "$TMPDIR_BASE/generated.cedarschema" \
    > "$TMPDIR_BASE/generate-stdout.log" 2> "$TMPDIR_BASE/generate-stderr.log" || true

check_file_exists "generated.cedar created" "$TMPDIR_BASE/generated.cedar"
check_file_exists "generated.cedarschema created" "$TMPDIR_BASE/generated.cedarschema"

POLICY=$(cat "$TMPDIR_BASE/generated.cedar")
check_contains "generated policy has permit statements" "$POLICY" "permit"
check_contains "generated policy references github" "$POLICY" "api.github.com"

echo ""
echo -e "  ${CYAN}▶ Human review — generated policy:${RESET}"
echo -e "${DIM}"
cat "$TMPDIR_BASE/generated.cedar"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Phase 2b: EXPLAIN generated policy
# ─────────────────────────────────────────────────────────────
section "Phase 2b: Explain Generated Policy"

EXPLAIN=$("$STRAIT" explain "$TMPDIR_BASE/generated.cedar" 2>&1) || true
check_contains "explain output is non-empty" "$EXPLAIN" "."

echo ""
echo -e "  ${CYAN}▶ Human review — does this explanation make sense for what the agent did?${RESET}"
echo -e "${DIM}"
echo "$EXPLAIN"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Phase 3: REPLAY
# ─────────────────────────────────────────────────────────────
section "Phase 3: Replay Test"

REPLAY_OUTPUT=$("$STRAIT" test --replay "$TMPDIR_BASE/observations.jsonl" \
    --policy "$TMPDIR_BASE/generated.cedar" 2>&1) || true
REPLAY_EXIT=$?

# Generated policy should cover all observed actions
check "replay passes (generated policy covers observations)" test "$REPLAY_EXIT" -eq 0

echo ""
echo -e "  ${CYAN}▶ Human review — replay output:${RESET}"
echo -e "${DIM}"
echo "$REPLAY_OUTPUT"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Phase 4: WARN MODE
# ─────────────────────────────────────────────────────────────
section "Phase 4: Warn Mode"

echo -e "  ${DIM}launching container in warn mode with generated policy...${RESET}"

"$STRAIT" launch --warn "$TMPDIR_BASE/generated.cedar" \
    --image alpine:latest \
    --output "$TMPDIR_BASE/warn-observations.jsonl" \
    -- sh -c "
        apk add --no-cache curl >/dev/null 2>&1
        echo '--- Same requests (should not warn) ---'
        curl -sf https://api.github.com/zen || true
        curl -sf https://api.github.com/meta | head -c 200 || true
        echo ''
        echo '--- Novel request (should warn but still allow) ---'
        curl -sf https://api.github.com/rate_limit | head -c 200 || true
        echo ''
        echo '--- Done ---'
    " > "$TMPDIR_BASE/warn-stdout.log" 2> "$TMPDIR_BASE/warn-stderr.log" || true

WARN_CONTENT=$(cat "$TMPDIR_BASE/warn-stderr.log" "$TMPDIR_BASE/warn-observations.jsonl" 2>/dev/null)
check_contains "warn mode logs warnings for novel requests" "$WARN_CONTENT" "warn\|Warn\|WARN\|violation\|denied"

echo ""
echo -e "  ${CYAN}▶ Human review — did the novel request (rate_limit) trigger a warning but still succeed?${RESET}"
echo -e "${DIM}"
tail -10 "$TMPDIR_BASE/warn-stderr.log" 2>/dev/null
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Phase 5: ENFORCE MODE
# ─────────────────────────────────────────────────────────────
section "Phase 5: Enforce Mode"

echo -e "  ${DIM}launching container in enforce mode with generated policy...${RESET}"

"$STRAIT" launch --policy "$TMPDIR_BASE/generated.cedar" \
    --image alpine:latest \
    --output "$TMPDIR_BASE/enforce-observations.jsonl" \
    -- sh -c "
        apk add --no-cache curl >/dev/null 2>&1
        echo '--- Known request (should succeed) ---'
        HTTP_CODE_ZEN=\$(curl -s -o /dev/null -w '%{http_code}' https://api.github.com/zen)
        echo \"zen: \$HTTP_CODE_ZEN\"
        echo ''
        echo '--- Novel request (should be denied 403) ---'
        HTTP_CODE_RL=\$(curl -s -o /dev/null -w '%{http_code}' https://api.github.com/rate_limit)
        echo \"rate_limit: \$HTTP_CODE_RL\"
        echo ''
        echo '--- DELETE attempt (should be denied 403) ---'
        HTTP_CODE_DEL=\$(curl -s -o /dev/null -w '%{http_code}' -X DELETE https://api.github.com/repos/test/test)
        echo \"delete: \$HTTP_CODE_DEL\"
    " > "$TMPDIR_BASE/enforce-stdout.log" 2> "$TMPDIR_BASE/enforce-stderr.log" || true

ENFORCE_OUT=$(cat "$TMPDIR_BASE/enforce-stdout.log")
check_contains "known request allowed in enforce mode" "$ENFORCE_OUT" "200\|zen"
check_contains "novel request denied in enforce mode (403)" "$ENFORCE_OUT" "403"

echo ""
echo -e "  ${CYAN}▶ Human review — enforce output:${RESET}"
echo -e "${DIM}"
cat "$TMPDIR_BASE/enforce-stdout.log"
echo -e "${RESET}"

# ─────────────────────────────────────────────────────────────
# Phase 6: DIFF — observe policy vs hand-written policy
# ─────────────────────────────────────────────────────────────
section "Phase 6: Diff Generated vs Example"

DIFF_OUTPUT=$("$STRAIT" diff "$TMPDIR_BASE/generated.cedar" "$REPO_ROOT/examples/github.cedar" 2>&1) || true

echo -e "  ${CYAN}▶ Human review — how does the auto-generated policy differ from the hand-written example?${RESET}"
echo -e "${DIM}"
echo "$DIFF_OUTPUT" | head -30
echo -e "${RESET}"

summary
