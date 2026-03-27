#!/bin/sh
# Test agent for E2E round-trip integration tests.
#
# Makes one HTTPS GET request and reads one file — the minimal
# activity needed to exercise the observe/generate/enforce pipeline.
#
# Usage inside Docker (curl must be available):
#   ./test-agent.sh <url> <filepath>
#
# Exit code 0 on success, non-zero on failure.

set -e

URL="${1:?Usage: test-agent.sh <url> <filepath>}"
FILE="${2:?Usage: test-agent.sh <url> <filepath>}"

# Network activity: one HTTPS GET request
curl -sf "$URL" > /dev/null

# Filesystem activity: read a file
cat "$FILE" > /dev/null

echo "test-agent: success"
