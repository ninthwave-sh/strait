#!/usr/bin/env bash
# 09 — SIGHUP policy hot-reload.
# Requires: GITHUB_TOKEN
#
# Tests that sending SIGHUP to a running proxy reloads the Cedar policy
# without restarting. Verifies behavior changes after policy swap.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo -e "${YELLOW}GITHUB_TOKEN not set — skipping SIGHUP reload test${RESET}"
    exit 0
fi

cleanup() {
    kill_bg "${PROXY_PID:-0}"
    cleanup_tmpdir
}
trap cleanup EXIT

section "SIGHUP Policy Reload"

# Write initial restrictive policy (deny everything except /zen)
cat > "$TMPDIR_BASE/policy.cedar" <<'CEDAR'
@id("allow-zen-only")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource == Resource::"api.github.com/zen"
);
CEDAR

cat > "$TMPDIR_BASE/strait.toml" <<EOF
ca_cert_path = "$TMPDIR_BASE/ca.pem"

[listen]
address = "127.0.0.1"
port = 0

[mitm]
hosts = ["api.github.com"]

[policy]
file = "$TMPDIR_BASE/policy.cedar"

[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "GITHUB_TOKEN"

[identity]
default = "worker"
EOF

"$STRAIT" proxy --config "$TMPDIR_BASE/strait.toml" \
    > /dev/null 2> "$TMPDIR_BASE/stderr.log" &
PROXY_PID=$!

if ! wait_for_output "$TMPDIR_BASE/stderr.log" "PORT=" 15; then
    echo -e "${RED}Proxy failed to start${RESET}"
    exit 1
fi

PROXY_PORT=$(grep -o 'PORT=[0-9]*' "$TMPDIR_BASE/stderr.log" | head -1 | cut -d= -f2)
sleep 1

echo -e "  ${DIM}proxy on port $PROXY_PORT with restrictive policy${RESET}"

# Verify initial policy: /zen allowed, /user denied
ZEN_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/zen" 2>/dev/null) || true
check_contains "before reload: /zen allowed (200)" "$ZEN_CODE" "200"

USER_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user" 2>/dev/null) || true
check_contains "before reload: /user denied (403)" "$USER_CODE" "403"

# Swap to permissive policy
cat > "$TMPDIR_BASE/policy.cedar" <<'CEDAR'
@id("allow-all-reads")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
CEDAR

echo -e "  ${DIM}sending SIGHUP to reload policy...${RESET}"
kill -HUP "$PROXY_PID"
sleep 2

# Verify new policy: /user should now be allowed
USER_CODE_AFTER=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user" 2>/dev/null) || true
check_contains "after reload: /user allowed (200)" "$USER_CODE_AFTER" "200"

# Verify the reload was logged
RELOAD_LOG=$(cat "$TMPDIR_BASE/stderr.log")
check_contains "SIGHUP reload logged" "$RELOAD_LOG" "reload\|SIGHUP\|Reload"

summary
