# Base image only — no tool installation needed.
#
# strait mounts host binaries (claude, git, node) into the container
# automatically when your Cedar policy includes proc:exec rules.
# See policy.cedar for the full example.
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
