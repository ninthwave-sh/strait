# Feat: Host install paths (M-INST-4)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` Phase 3
**Depends on:** H-HCP-1, H-HCP-2
**Domain:** install-surface
**Lineage:** 478ef2ef-a33d-44d6-b13f-8cd59c08105b

Provide a one-command install for `strait-host` on macOS and Linux. macOS: Homebrew cask that installs the binary and a launchd plist (`~/Library/LaunchAgents/io.ninthwave.strait.host.plist`) so the control plane runs automatically. Linux: tarball with an install script that drops a systemd user unit at `~/.config/systemd/user/strait-host.service` or falls back to a terminal-foreground run. Both surfaces create `/var/run/strait/` with the right permissions and seed a default `host.toml`.

**Test plan:**
- macOS: `brew install strait` followed by `launchctl list | grep strait` shows the service running; `strait-host status` reports healthy.
- Linux: tarball install + `systemctl --user start strait-host` boots the service; default socket path is reachable.
- Uninstall: both paths remove their artifacts without leaving stale sockets.

Acceptance: `brew install strait` installs and runs `strait-host` on macOS. Linux tarball + install script boots `strait-host` under systemd user mode. Both surfaces create the socket directory with the right ownership. Uninstall cleans up.

Key files: `Formula/strait.rb`, `packaging/linux/install.sh`, `packaging/linux/strait-host.service`, `packaging/macos/io.ninthwave.strait.host.plist`
