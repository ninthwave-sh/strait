#!/usr/bin/env bash
# 08 — strait init --observe (proxy-mode observation + policy generation).
# Requires: GITHUB_TOKEN
#
# This tests the non-container observation path: run the proxy, send
# traffic through it, and auto-generate a policy from observed requests.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
    echo -e "${YELLOW}GITHUB_TOKEN not set — skipping init-observe test${RESET}"
    exit 0
fi

cleanup() {
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    cleanup_tmpdir
}
trap cleanup EXIT

section "Init Observe (Proxy Mode)"

# Write minimal config (no [policy] section — observe mode ignores it)
cat > "$TMPDIR_BASE/init-config.toml" <<EOF
ca_cert_path = "$TMPDIR_BASE/ca.pem"

[listen]
address = "127.0.0.1"
port = 0

[mitm]
hosts = ["api.github.com"]

[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "GITHUB_TOKEN"

[identity]
default = "worker"
EOF

echo -e "  ${DIM}running: strait init --observe 10s --config init-config.toml${RESET}"
echo -e "  ${DIM}will observe for 10 seconds while we send traffic...${RESET}"

# Start init --observe in background
"$STRAIT" init --observe 10s \
    --config "$TMPDIR_BASE/init-config.toml" \
    --output-dir "$TMPDIR_BASE/init-output" \
    > "$TMPDIR_BASE/init-stdout.log" 2> "$TMPDIR_BASE/init-stderr.log" &
INIT_PID=$!

# Wait for proxy to start
sleep 3

# Discover port from stderr
PROXY_PORT=$(grep -o 'PORT=[0-9]*' "$TMPDIR_BASE/init-stderr.log" | head -1 | cut -d= -f2) || true

if [[ -z "$PROXY_PORT" ]]; then
    echo -e "  ${RED}Could not discover proxy port${RESET}"
    cat "$TMPDIR_BASE/init-stderr.log"
    kill_bg "$INIT_PID"
    exit 1
fi

echo -e "  ${DIM}proxy on port $PROXY_PORT — sending test traffic...${RESET}"

# Send varied requests through the proxy
curl -sf --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/zen" > /dev/null 2>&1 || true

curl -sf --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/meta" > /dev/null 2>&1 || true

curl -sf --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user" > /dev/null 2>&1 || true

curl -sf --proxy "http://127.0.0.1:$PROXY_PORT" \
    --cacert "$TMPDIR_BASE/ca.pem" \
    "https://api.github.com/user/repos?per_page=1" > /dev/null 2>&1 || true

echo -e "  ${DIM}waiting for observation period to end...${RESET}"
wait "$INIT_PID" 2>/dev/null || true

section "Generated Output"

# Check output files
INIT_FILES=$(ls "$TMPDIR_BASE/init-output/" 2>/dev/null || echo "")
check_contains "init generated .cedar file" "$INIT_FILES" ".cedar"

# Find the generated files
CEDAR_FILE=$(find "$TMPDIR_BASE/init-output" -name "*.cedar" -not -name "*.cedarschema" 2>/dev/null | head -1)
SCHEMA_FILE=$(find "$TMPDIR_BASE/init-output" -name "*.cedarschema" 2>/dev/null | head -1)

if [[ -n "$CEDAR_FILE" ]]; then
    check_file_exists "cedar policy created" "$CEDAR_FILE"

    POLICY=$(cat "$CEDAR_FILE")
    check_contains "generated policy has permit statements" "$POLICY" "permit"
    check_contains "generated policy covers observed host" "$POLICY" "api.github.com"

    echo ""
    echo -e "  ${CYAN}▶ Human review — auto-generated policy from proxy observation:${RESET}"
    echo -e "${DIM}"
    cat "$CEDAR_FILE"
    echo -e "${RESET}"

    # Explain it
    EXPLAIN=$("$STRAIT" explain "$CEDAR_FILE" 2>&1) || true
    echo -e "  ${CYAN}▶ Explanation:${RESET}"
    echo -e "${DIM}"
    echo "$EXPLAIN"
    echo -e "${RESET}"
else
    skip "policy content check" "no .cedar file found in output"
fi

if [[ -n "$SCHEMA_FILE" ]]; then
    check_file_exists "cedar schema created" "$SCHEMA_FILE"
fi

summary
