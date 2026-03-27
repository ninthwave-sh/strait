// github.cedar — Cedar policy for GitHub API access through strait.
//
// Entity model (built automatically by strait from each HTTP request):
//   Principal: Agent::"worker"           — the calling process
//   Action:    Action::"http:GET", "http:POST", …  — namespaced HTTP method
//   Resource:  Resource::"api.github.com/repos/our-org/repo-name"
//              — host + path segments, forming a hierarchy via Cedar `in`
//
// Default disposition: DENY. Requests without a matching `permit` are blocked.
// `forbid` policies override `permit` and include @reason annotations for
// audit trail clarity.
//
// To use: replace "our-org" with your GitHub organization name.

// ---------------------------------------------------------------------------
// PERMIT policies — what the agent is allowed to do
// ---------------------------------------------------------------------------

// Read access to any repo (or sub-resource) within the allowed org.
// Covers: list repos, get repo details, list issues, read commits, etc.
@id("read-org-repos")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/our-org"
);

// Create pull requests on org repos.
// Scoped to POST on paths ending in /pulls via context condition.
@id("create-prs")
permit(
    principal == Agent::"worker",
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };

// ---------------------------------------------------------------------------
// FORBID policies — hard denials that override any permit
// Each includes a @reason annotation documenting *why* the action is blocked.
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
// Cedar's default-deny already blocks these (no permit covers them), but
// this explicit forbid provides a clear audit trail with a named policy
// and reason annotation.
@id("deny-outside-org")
@reason("Only repos in the allowed organization are accessible through this proxy")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/our-org" };
