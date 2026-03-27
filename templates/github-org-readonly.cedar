// VALIDATED: 2026-03-27 strait init --observe
// github-org-readonly — Read-only access to a GitHub org's repos.
//
// Allows: GET requests to repos within the specified org.
// Denies: All write operations (POST, PUT, PATCH, DELETE).
// Denies: Access to repos outside the org.
//
// To use: replace "your-org" with your GitHub organization name.

// Read access to any repo (or sub-resource) within the allowed org.
// Covers: list repos, get repo details, list issues, read commits, etc.
@id("read-org-repos")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/your-org"
);

// Deny access to repos outside the allowed org.
// Cedar's default-deny already blocks these (no permit covers them), but
// this explicit forbid provides a clear audit trail with a named policy
// and reason annotation.
@id("deny-outside-org")
@reason("Only repos in the specified organization are accessible")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/your-org" };
