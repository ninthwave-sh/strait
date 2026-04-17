# Image used by examples/sandcastle/main.ts.
#
# Companion to docs/bring-your-own-sandbox.md. Builds a minimal Debian
# image with:
#
#   - a non-root agent user
#   - iptables (strait-agent shells out to it at entrypoint time)
#   - curl (so the example has an outbound-HTTP command to run)
#   - the strait-agent binary, copied in from the build context
#   - a tiny wrapper that execs `strait-agent entrypoint -- "$@"`
#
# Build prerequisite: copy a linux-matching strait-agent binary into
# examples/sandcastle/strait-agent before running `docker build`, e.g.
#
#   cargo build --release -p strait-agent
#   cp target/release/strait-agent examples/sandcastle/strait-agent
#
# On macOS hosts the container arch is linux/amd64 or linux/arm64 depending
# on Docker Desktop/OrbStack config. Cross-compile with `cargo build
# --release -p strait-agent --target aarch64-unknown-linux-gnu` (or use
# `cross`) if your workstation arch does not match the container arch.

FROM debian:bookworm-slim

ARG AGENT_USER=agent

# Packages: iptables for interception, curl for the demo request,
# ca-certificates so the agent user can verify strait's upstream TLS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iptables \
        curl \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Non-root agent user. strait-agent refuses to exec the agent command as
# uid 0, so this has to exist and must not be root.
RUN useradd --create-home --shell /bin/bash "${AGENT_USER}"

# Copy strait-agent from the build context. The sibling file must be a
# linux-ELF binary matching the container arch.
COPY strait-agent /usr/local/bin/strait-agent
RUN chmod 0755 /usr/local/bin/strait-agent

# Host socket path and agent user are wired through env vars so no
# strait-agent.toml is needed for this example.
ENV STRAIT_AGENT_AGENT_USER=${AGENT_USER} \
    STRAIT_AGENT_HOST_SOCKET=/run/strait/host.sock \
    STRAIT_AGENT_PROXY_PORT=9443

# Entrypoint wrapper. Kept separate so `docker run -it <image>` with no
# command still drops into a shell under strait.
COPY entrypoint.sh /usr/local/bin/strait-entrypoint
RUN chmod 0755 /usr/local/bin/strait-entrypoint

ENTRYPOINT ["/usr/local/bin/strait-entrypoint"]
CMD ["curl", "-sS", "https://api.github.com/meta"]
