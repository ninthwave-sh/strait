// github-org-readonly — Read-only access to a GitHub org's repos.
// # VALIDATED: 2026-03-27 cedar-validate
//
// Entity model (built automatically by strait from each HTTP request):
//   Principal: Agent::"worker"           — the calling process
//   Action:    Action::"GET", "POST", …  — HTTP method
//   Resource:  Resource::"api.github.com/repos/our-org/repo-name"
//              — host + path segments, forming a hierarchy via Cedar `in`
//
// Default disposition: DENY. Only GET requests to repos in the allowed org
// are permitted. All write operations are blocked by default-deny.
//
// To use: replace "our-org" with your GitHub organization name.

// ---------------------------------------------------------------------------
// PERMIT policies
// ---------------------------------------------------------------------------

// Read access to any repo (or sub-resource) within the allowed org.
// Covers: list repos, get repo details, list issues, read commits, etc.
@id("read-org-repos")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource in Resource::"api.github.com/repos/our-org"
);

// ---------------------------------------------------------------------------
// FORBID policies — explicit denials for audit trail clarity
// ---------------------------------------------------------------------------

// Deny access to repos outside the allowed org.
// Cedar's default-deny already blocks these, but this explicit forbid
// provides a named policy and reason annotation in audit logs.
@id("deny-outside-org")
@reason("Only repos in the allowed organization are accessible through this proxy")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/our-org" };
