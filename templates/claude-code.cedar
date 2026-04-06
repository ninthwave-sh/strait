// VALIDATED: 2026-04-06 strait template for Claude Code
// claude-code — Full-stack policy for Claude Code agent sessions.
//
// Designed for Claude Code with OAuth auth (Claude Max / Team / Enterprise).
// With OAuth, Anthropic API traffic is passthrough (not proxied through strait),
// so no Anthropic permit rules are needed here.
//
// If you use an API key instead of OAuth, uncomment the Anthropic API section
// below so strait can proxy and inject credentials for api.anthropic.com.
//
// Network:
//   Allows: GET, POST, DELETE to api.github.com scoped to your org
//   Allows: GET to registry.npmjs.org (npm package metadata/tarballs)
//   Denies: Push to main/release branches via Git Data API
//   Denies: Repository deletion
//
// Filesystem:
//   Allows: fs:read and fs:write to /project (workspace directory)
//   Allows: fs:read to system paths (libraries, tools)
//   Denies: fs:write outside the workspace
//
// Process:
//   Allows: proc:exec for claude, git, node, and common dev tools
//   Denies: proc:exec for destructive commands (rm -rf, chmod 777)
//
// To use: replace "your-org" with your GitHub organization name,
// and adjust filesystem paths for your workspace layout.

// ---------------------------------------------------------------------------
// NETWORK — Anthropic API (API key users only)
// ---------------------------------------------------------------------------
// Uncomment this section if you use an API key for Anthropic instead of OAuth.
// OAuth users (Max/Team/Enterprise) do not need these rules because Anthropic
// traffic bypasses the proxy entirely.
//
// @id("anthropic-api")
// permit(
//     principal,
//     action in [Action::"http:GET", Action::"http:POST"],
//     resource in Resource::"api.anthropic.com"
// );

// ---------------------------------------------------------------------------
// NETWORK — GitHub API (scoped to org)
// ---------------------------------------------------------------------------

// Read access to org repos: list, get details, issues, commits, pulls.
@id("github-read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/your-org"
);

// Write access to org repos: create PRs, post comments, push branches.
@id("github-write")
permit(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/your-org"
);

// Delete access to org repos: delete branches, dismiss reviews.
@id("github-delete")
permit(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos/your-org"
);

// GitHub user and search endpoints (non-repo reads).
@id("github-meta")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);

// ---------------------------------------------------------------------------
// NETWORK — npm registry (package installs)
// ---------------------------------------------------------------------------

// Read access to npm registry: package metadata and tarballs.
@id("npm-registry-read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"registry.npmjs.org"
);

// ---------------------------------------------------------------------------
// NETWORK — deny destructive GitHub operations
// ---------------------------------------------------------------------------

// Deny force-push to main via Git Data API.
@id("deny-push-main")
@reason("Direct pushes to main are prohibited; use pull requests")
forbid(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };

// Deny push to release branches.
@id("deny-push-release")
@reason("Release branches are protected; use the release workflow")
forbid(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/release/*" };

// Deny repository deletion (DELETE on the repo itself, not sub-resources).
@id("deny-repo-delete")
@reason("Repository deletion is too destructive for agent access")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
) unless { context.path like "*/*/*/*/*" };

// Deny access to repos outside the org.
@id("deny-outside-org")
@reason("Only repos in the specified organization are accessible")
forbid(
    principal,
    action in [Action::"http:POST", Action::"http:DELETE"],
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/your-org" };

// ---------------------------------------------------------------------------
// FILESYSTEM — workspace read/write, system read-only
// ---------------------------------------------------------------------------

// Full read/write access to the project workspace.
@id("workspace-readwrite")
permit(
    principal,
    action in [Action::"fs:read", Action::"fs:write"],
    resource in Resource::"fs::/project"
);

// Read-only access to system libraries, tools, and configuration.
@id("system-readonly")
permit(
    principal,
    action == Action::"fs:read",
    resource in Resource::"fs::/"
);

// Deny writes outside the workspace.
@id("deny-system-write")
@reason("Write access is restricted to the /project workspace directory")
forbid(
    principal,
    action == Action::"fs:write",
    resource in Resource::"fs::/"
) unless { resource in Resource::"fs::/project" };

// ---------------------------------------------------------------------------
// PROCESS — allowed dev tools
// ---------------------------------------------------------------------------

// Allow claude CLI.
@id("allow-claude")
permit(
    principal,
    action == Action::"proc:exec",
    resource
) when { context.command like "claude*" };

// Allow git commands.
@id("allow-git")
permit(
    principal,
    action == Action::"proc:exec",
    resource
) when { context.command like "git*" };

// Allow node and npm commands.
@id("allow-node")
permit(
    principal,
    action == Action::"proc:exec",
    resource
) when { context.command like "node*" || context.command like "npm*" || context.command like "npx*" };

// Allow common dev tools: cargo, python, pip, make, sh, bash, cat, ls, grep, find.
@id("allow-dev-tools")
permit(
    principal,
    action == Action::"proc:exec",
    resource
) when {
    context.command like "cargo*" ||
    context.command like "python*" ||
    context.command like "pip*" ||
    context.command like "make*" ||
    context.command like "sh*" ||
    context.command like "bash*" ||
    context.command like "cat*" ||
    context.command like "ls*" ||
    context.command like "grep*" ||
    context.command like "find*" ||
    context.command like "sed*" ||
    context.command like "awk*" ||
    context.command like "curl*" ||
    context.command like "jq*"
};

// ---------------------------------------------------------------------------
// PROCESS — deny destructive commands
// ---------------------------------------------------------------------------

// Deny rm -rf (recursive force delete).
@id("deny-rm-rf")
@reason("Recursive force-delete is too destructive for agent access")
forbid(
    principal,
    action == Action::"proc:exec",
    resource
) when { context.command like "rm -rf *" };

// Deny chmod 777 (world-writable permissions).
@id("deny-chmod-777")
@reason("Setting world-writable permissions is a security risk")
forbid(
    principal,
    action == Action::"proc:exec",
    resource
) when { context.command like "chmod 777*" };

// Deny git push --force to any branch (use --force-with-lease instead).
@id("deny-force-push")
@reason("Force-push is prohibited; use --force-with-lease for safer rebases")
forbid(
    principal,
    action == Action::"proc:exec",
    resource
) when { context.command like "git push --force*" || context.command like "git push -f *" };
