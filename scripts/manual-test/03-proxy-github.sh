#!/usr/bin/env bash
# 03 — Proxy mode with real GitHub API.
# Requires: GITHUB_TOKEN

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo -e "${YELLOW}GITHUB_TOKEN not set — skipping proxy-github tests${RESET}"
    echo "Export GITHUB_TOKEN and re-run."
    exit 0
fi

section "Proxy Mode — GitHub API"

# Write a test config
# Write a test-specific policy (broader than examples/github.cedar so we can
# test both allowed and denied paths against real endpoints)
cat > "$TMPDIR_BASE/policy.cedar" <<'CEDAR'
// Allow all GET requests to api.github.com
@id("allow-reads")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);

// Deny repo deletion
@id("deny-repo-delete")
@reason("Repository deletion is too destructive")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);

// Deny admin settings
@id("deny-settings")
@reason("Admin settings must be changed through the GitHub UI")
forbid(
    principal,
    action == Action::"http:PATCH",
    resource in Resource::"api.github.com"
) when { context.path like "*/settings" };
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

[audit]
log_path = "$TMPDIR_BASE/audit.jsonl"

[health]
port = 0
EOF

# Start proxy in background, capture stderr for port discovery
"$STRAIT" proxy --config "$TMPDIR_BASE/strait.toml" \
    > "$TMPDIR_BASE/stdout.log" 2> "$TMPDIR_BASE/stderr.log" &
PROXY_PID=$!

cleanup() {
    kill_bg "$PROXY_PID"
    cleanup_tmpdir
}
trap cleanup EXIT

# Wait for proxy to start and discover its port
if ! wait_for_output "$TMPDIR_BASE/stderr.log" "PORT=" 15; then
    echo -e "${RED}Proxy failed to start within 15s${RESET}"
    cat "$TMPDIR_BASE/stderr.log"
    exit 1
fi

PROXY_PORT=$(grep -o 'PORT=[0-9]*' "$TMPDIR_BASE/stderr.log" | head -1 | cut -d= -f2)
echo -e "  ${DIM}proxy started on port $PROXY_PORT${RESET}"

# Wait for CA cert
sleep 1
check_file_exists "CA cert written" "$TMPDIR_BASE/ca.pem"

section "Allowed Requests"

# GET /user — should be allowed (policy permits all GET on api.github.com)
RESPONSE=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user" 2>/dev/null) || true
check_contains "GET /user returns 200" "$RESPONSE" "200"

# GET /user/repos — should work
REPOS_RESPONSE=$(curl -s \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user/repos?per_page=1" 2>/dev/null) || true
check_contains "GET /user/repos returns JSON" "$REPOS_RESPONSE" "id"

section "Denied Requests"

# DELETE on repos — should be denied by deny-repo-delete forbid
DELETE_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    -X DELETE \
    "https://api.github.com/repos/test-org/test-repo" 2>/dev/null) || true
check_contains "DELETE /repos denied (403)" "$DELETE_CODE" "403"

# PATCH on settings — should be denied by deny-settings forbid
PATCH_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    -X PATCH \
    "https://api.github.com/repos/test-org/test-repo/settings" 2>/dev/null) || true
check_contains "PATCH /settings denied (403)" "$PATCH_CODE" "403"

section "Credential Injection"

# Verify the proxy injected credentials (the request should succeed without
# us passing an Authorization header — the proxy adds it)
AUTH_RESPONSE=$(curl -s \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user" 2>/dev/null) || true
check_contains "credential injection works (user info returned)" "$AUTH_RESPONSE" "login"
check_not_contains "no auth error" "$AUTH_RESPONSE" "Bad credentials"

section "Audit Log"

sleep 1  # let audit flush
check_file_exists "audit log exists" "$TMPDIR_BASE/audit.jsonl"

AUDIT=$(cat "$TMPDIR_BASE/audit.jsonl")
check_contains "audit log has allow decisions" "$AUDIT" "allow"
check_contains "audit log has deny decisions" "$AUDIT" "deny"
check_contains "audit log records host" "$AUDIT" "api.github.com"
check_contains "audit log records method" "$AUDIT" "GET"

echo ""
echo -e "  ${CYAN}▶ Human review — audit log sample:${RESET}"
echo -e "${DIM}"
head -3 "$TMPDIR_BASE/audit.jsonl" | python3 -m json.tool 2>/dev/null || head -3 "$TMPDIR_BASE/audit.jsonl"
echo -e "${RESET}"

section "Health Check"

# Discover health port from stderr
HEALTH_PORT=$(grep -o 'health.*port.*[0-9]\+' "$TMPDIR_BASE/stderr.log" | grep -o '[0-9]\+$' | head -1) || true
if [[ -n "$HEALTH_PORT" ]]; then
    HEALTH_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HEALTH_PORT/healthz" 2>/dev/null) || true
    check_contains "health endpoint returns 200" "$HEALTH_CODE" "200"
else
    skip "health endpoint" "could not discover health port from logs"
fi

section "Passthrough (non-MITM host)"

# Request to a host NOT in mitm.hosts — with policy enforcement active,
# non-MITM hosts are denied (prevents open relay). curl returns 000 because
# the CONNECT tunnel is rejected with 403.
PASS_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
    --proxy "http://127.0.0.1:$PROXY_PORT" \
    "https://httpbin.org/get" 2>/dev/null) || true
check_contains "non-MITM host denied when policy active (000)" "$PASS_CODE" "000"

summary
