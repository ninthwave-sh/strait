// policy.cedar — Complete Cedar policy for Claude Code inside strait.
//
// Covers three domains:
//   http:  — API access (Anthropic, GitHub, telemetry, npm)
//   fs:    — filesystem access (project directory)
//   proc:  — host binary execution (claude, git, node)
//
// proc:exec rules serve double duty: they authorize execution at runtime
// AND tell strait which host binaries to bind-mount into the container.
// No custom Dockerfile or manual installation needed.
//
// Default disposition: DENY. Only the access patterns below are allowed.

// ---------------------------------------------------------------------------
// HTTP — API endpoints Claude Code needs
// ---------------------------------------------------------------------------

// Anthropic API (chat completions, tool use).
@id("allow-anthropic-api")
permit(
    principal == Agent::"claude-code",
    action in [Action::"http:GET", Action::"http:POST"],
    resource in Resource::"api.anthropic.com"
);

// GitHub API (repo operations, PR creation, issue management).
@id("allow-github-api")
permit(
    principal == Agent::"claude-code",
    action in [Action::"http:GET", Action::"http:POST", Action::"http:PATCH"],
    resource in Resource::"api.github.com"
);

// Anthropic telemetry (feature flags, usage stats).
@id("allow-anthropic-statsig")
permit(
    principal == Agent::"claude-code",
    action in [Action::"http:GET", Action::"http:POST"],
    resource in Resource::"statsig.anthropic.com"
);

// Sentry error reporting.
@id("allow-sentry")
permit(
    principal == Agent::"claude-code",
    action == Action::"http:POST",
    resource in Resource::"sentry.io"
);

// npm registry (package metadata lookups).
@id("allow-npm-registry")
permit(
    principal == Agent::"claude-code",
    action == Action::"http:GET",
    resource in Resource::"registry.npmjs.org"
);

// ---------------------------------------------------------------------------
// Filesystem — project directory access
// ---------------------------------------------------------------------------

// Read access to the project directory.
@id("allow-project-read")
permit(
    principal == Agent::"claude-code",
    action == Action::"fs:read",
    resource in Resource::"/project"
);

// Write access to the project directory.
@id("allow-project-write")
permit(
    principal == Agent::"claude-code",
    action == Action::"fs:write",
    resource in Resource::"/project"
);

// ---------------------------------------------------------------------------
// Process execution — host binaries mounted into the container
//
// Each proc:exec rule tells strait to find the binary on the host,
// resolve its path via $PATH, and bind-mount it read-only into the
// container at /usr/local/bin/<name>.
// ---------------------------------------------------------------------------

// Claude Code CLI.
@id("allow-exec-claude")
permit(
    principal == Agent::"claude-code",
    action == Action::"proc:exec",
    resource == Resource::"proc::claude"
);

// Git (for repo operations, diffs, commits).
@id("allow-exec-git")
permit(
    principal == Agent::"claude-code",
    action == Action::"proc:exec",
    resource == Resource::"proc::git"
);

// Node.js runtime (Claude Code dependency).
@id("allow-exec-node")
permit(
    principal == Agent::"claude-code",
    action == Action::"proc:exec",
    resource == Resource::"proc::node"
);

// ---------------------------------------------------------------------------
// FORBID — hard denials
// ---------------------------------------------------------------------------

// Block repo deletion through the GitHub API.
@id("deny-repo-delete")
@reason("Repository deletion is too destructive for agent access")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);
