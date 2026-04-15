# Docs: Publish devcontainer vs strait comparison doc (M-DC-1)

**Priority:** Medium
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`)
**Depends on:** None
**Domain:** devcontainer-comparison-doc
**Lineage:** bdc733a0-dd4a-4b22-9df2-d1082127b042

Publish `docs/devcontainer.md` that explains where strait sits relative to the devcontainer spec and Claude Code's reference iptables setup. The doc should walk readers through the Claude Code `init-firewall.sh` approach, show the equivalent strait configuration side by side, and document known incompatibilities (forwardPorts, privileged runArgs, mounts) up front. This is the externally-facing wedge narrative; it ships independently of the codebase narrowing and precedes the devcontainer.json reader so the positioning is in public before the implementation lands.

**Test plan:**
- Manual review: doc reads cold to a reader who has not seen the strategy doc
- Verify links to `docs/designs/devcontainer-strategy.md`, `https://containers.dev/`, and `https://code.claude.com/docs/en/devcontainer` resolve
- Verify the side-by-side example uses a real devcontainer.json shape and a real strait.toml shape (no placeholders)

Acceptance: `docs/devcontainer.md` exists, is linked from `README.md`, includes a side-by-side iptables-vs-strait comparison, explicitly lists rejected devcontainer.json fields (forwardPorts, privileged runArgs), and states the recommendation to remove `init-firewall.sh` once strait is in place.

Key files: `docs/devcontainer.md`, `README.md`, `examples/claude-code/README.md`
