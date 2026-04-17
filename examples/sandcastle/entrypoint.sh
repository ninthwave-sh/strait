#!/bin/sh
# Container entrypoint for the sandcastle example.
#
# Hands control to `strait-agent entrypoint --`, which installs the
# iptables REDIRECT rules, drops privileges to $STRAIT_AGENT_AGENT_USER,
# and execs the agent command.
#
# This wrapper runs as root (container start); strait-agent does the
# privilege drop. Do not add `su` or `setpriv` here.

set -e

if [ "$#" -eq 0 ]; then
    set -- /bin/bash -l
fi

exec /usr/local/bin/strait-agent entrypoint -- "$@"
