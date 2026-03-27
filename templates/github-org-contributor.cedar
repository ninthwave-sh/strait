// VALIDATED: 2026-03-27 strait init --observe
// github-org-contributor — Read + PR creation, deny push to main/release, deny admin.
//
// Allows: GET requests to repos within the org (read all).
// Allows: POST to pull request endpoints (create PRs).
// Denies: Push to main and release/* branches.
// Denies: Repository deletion.
// Denies: Admin settings access.
// Denies: Access to repos outside the org.
//
// To use: replace "your-org" with your GitHub organization name.

// ---------------------------------------------------------------------------
// PERMIT policies — what the agent is allowed to do
// ---------------------------------------------------------------------------

// Read access to any repo (or sub-resource) within the allowed org.
// Covers: list repos, get repo details, list issues, read commits, etc.
@id("read-org-repos")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/your-org"
);

// Create pull requests on org repos.
// Scoped to POST on paths ending in /pulls via context condition.
@id("create-prs")
permit(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/your-org"
) when { context.path like "*/pulls" };

// ---------------------------------------------------------------------------
// FORBID policies — hard denials that override any permit
// ---------------------------------------------------------------------------

// Deny push to the main branch (ref update via Git Data API).
@id("deny-push-main")
@reason("Direct pushes to main are prohibited; use pull requests instead")
forbid(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };

// Deny push to release branches (release/*).
@id("deny-push-release")
@reason("Release branches are protected; use the release workflow")
forbid(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/release/*" };

// Deny repository deletion.
@id("deny-repo-delete")
@reason("Repository deletion is too destructive for proxy access")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);

// Deny admin/settings access (PATCH on */settings endpoints).
@id("deny-settings")
@reason("Admin settings must be changed through the GitHub UI, not the API proxy")
forbid(
    principal,
    action == Action::"http:PATCH",
    resource in Resource::"api.github.com"
) when { context.path like "*/settings" };

// Deny access to repos outside the allowed org.
@id("deny-outside-org")
@reason("Only repos in the specified organization are accessible")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/your-org" };
