// VALIDATED: 2026-03-28 strait template infrastructure
// container-sandbox — Network policy for container sandboxes.
//
// Demonstrates how to scope outbound HTTP access for `strait launch --policy`.
// Customize hosts and path constraints for your use case.
//
// Network:
//   Allows: GET, POST to api.github.com (scoped to your org)
//   Allows: GET to registry endpoints (package installation)
//   Denies: All other network access
//
// To use: replace "your-org" with your GitHub organization name,
// and adjust host scopes for your workspace.

// ---------------------------------------------------------------------------
// NETWORK — scoped API access
// ---------------------------------------------------------------------------

// Read access to GitHub org repos.
@id("github-read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/your-org"
);

// PR creation on GitHub org repos.
@id("github-create-pr")
permit(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/your-org"
) when { context.path like "*/pulls" };
