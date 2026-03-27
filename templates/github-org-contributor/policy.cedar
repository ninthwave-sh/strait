// github-org-contributor — Read + PR creation for a GitHub org.
// # VALIDATED: 2026-03-27 cedar-validate
//
// Entity model (built automatically by strait from each HTTP request):
//   Principal: Agent::"worker"           — the calling process
//   Action:    Action::"GET", "POST", …  — HTTP method
//   Resource:  Resource::"api.github.com/repos/our-org/repo-name"
//              — host + path segments, forming a hierarchy via Cedar `in`
//
// Default disposition: DENY. Allows read access and pull request creation.
// Denies direct pushes to main/release branches, repo deletion, and admin
// settings changes.
//
// To use: replace "our-org" with your GitHub organization name.

// ---------------------------------------------------------------------------
// PERMIT policies
// ---------------------------------------------------------------------------

// Read access to any repo (or sub-resource) within the allowed org.
@id("read-org-repos")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource in Resource::"api.github.com/repos/our-org"
);

// Create pull requests on org repos.
@id("create-prs")
permit(
    principal == Agent::"worker",
    action == Action::"POST",
    resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };

// Comment on issues and pull requests.
@id("create-comments")
permit(
    principal == Agent::"worker",
    action == Action::"POST",
    resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/comments" };

// ---------------------------------------------------------------------------
// FORBID policies — hard denials that override any permit
// ---------------------------------------------------------------------------

// Deny push to the main branch (ref update via Git Data API).
@id("deny-push-main")
@reason("Direct pushes to main are prohibited; use pull requests instead")
forbid(
    principal,
    action == Action::"POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };

// Deny push to release branches (release/*).
@id("deny-push-release")
@reason("Release branches are protected; use the release workflow")
forbid(
    principal,
    action == Action::"POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/release/*" };

// Deny repository deletion.
@id("deny-repo-delete")
@reason("Repository deletion is too destructive for proxy access")
forbid(
    principal,
    action == Action::"DELETE",
    resource in Resource::"api.github.com/repos"
);

// Deny admin/settings access.
@id("deny-settings")
@reason("Admin settings must be changed through the GitHub UI, not the API proxy")
forbid(
    principal,
    action == Action::"PATCH",
    resource in Resource::"api.github.com"
) when { context.path like "*/settings" };

// Deny access to repos outside the allowed org.
@id("deny-outside-org")
@reason("Only repos in the allowed organization are accessible through this proxy")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/our-org" };
