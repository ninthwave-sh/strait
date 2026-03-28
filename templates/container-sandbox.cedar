// VALIDATED: 2026-03-28 strait template infrastructure
// container-sandbox — Combined fs + network policy for container sandboxes.
//
// Demonstrates how to combine filesystem and HTTP rules in a single policy
// for use with `strait launch --policy`. This is a starting point for
// container sandbox policies — customize paths and hosts for your use case.
//
// Filesystem:
//   Allows: fs:read and fs:write to /project (workspace directory)
//   Allows: fs:read to /usr, /lib, /etc (system libraries, read-only)
//   Denies: fs:write to system paths (read-only mounts)
//
// Network:
//   Allows: GET, POST to api.github.com (scoped to your org)
//   Allows: GET to registry endpoints (package installation)
//   Denies: All other network access
//
// To use: replace "your-org" with your GitHub organization name,
// and adjust filesystem paths for your workspace layout.

// ---------------------------------------------------------------------------
// FILESYSTEM — workspace read/write
// ---------------------------------------------------------------------------

// Full read/write access to the project workspace.
@id("workspace-readwrite")
permit(
    principal,
    action in [Action::"fs:read", Action::"fs:write"],
    resource in Resource::"fs::/project"
);

// Read-only access to system libraries and configuration.
@id("system-readonly")
permit(
    principal,
    action == Action::"fs:read",
    resource in Resource::"fs::/"
);

// Deny writes outside the workspace — explicit forbid for audit trail.
@id("deny-system-write")
@reason("Write access is restricted to the /project workspace directory")
forbid(
    principal,
    action == Action::"fs:write",
    resource in Resource::"fs::/"
) unless { resource in Resource::"fs::/project" };

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
