// policy.cedar -- Claude Code devcontainer dogfood.
//
// Default disposition is deny. Permit rules authorize outbound HTTP
// requests by method, host, and resource hierarchy. Forbid rules are
// hard guardrails that override permit.
//
// strait narrowed its policy domain to network egress only. Filesystem
// mounts and binary availability are handled by devcontainer.json.

// ---------------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------------

// Read access: repo metadata, issues, pulls, commits.
@id("allow-github-read")
permit(
    principal == Agent::"claude-code",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);

// Write access: create PRs, post comments, push branches.
@id("allow-github-write")
permit(
    principal == Agent::"claude-code",
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
);

// ---------------------------------------------------------------------------
// npm registry
// ---------------------------------------------------------------------------

// Package metadata and tarball downloads.
@id("allow-npm-registry")
permit(
    principal == Agent::"claude-code",
    action == Action::"http:GET",
    resource in Resource::"registry.npmjs.org"
);

// ---------------------------------------------------------------------------
// Guardrails (forbid always wins)
// ---------------------------------------------------------------------------

@id("deny-repo-delete")
@reason("Repository deletion is too destructive for agent access")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);

// NOTE: this guard blocks ref updates whose path already ends in
// `/git/refs/heads/main` (for example, fast-forwarding main via the
// update-a-reference API). It does NOT catch creating a brand-new
// `refs/heads/main` via `POST /repos/{owner}/{repo}/git/refs`, where
// the ref name lives in the request body rather than the URL path.
// Teams that need full main-branch protection should layer GitHub
// branch protection rules on top of this Cedar guard.
@id("deny-push-main")
@reason("Direct pushes to main are prohibited; use pull requests")
forbid(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };
