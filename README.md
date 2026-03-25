# strait

HTTPS proxy with Cedar policy evaluation, credential injection, and audit logging.

All traffic flows through the strait. Cedar policies determine what gets through. Allowed requests get credentials injected automatically — the calling process never sees the real secrets.

## How it works

```
Process (any workload)
  │  HTTP_PROXY=127.0.0.1:<port>
  ▼
strait
  ├─ Configured hosts → selective MITM
  │    Cedar policy eval → ALLOW / DENY
  │    Credential injection on ALLOW
  │    Structured JSON audit log
  │
  └─ Everything else → opaque tunnel (no MITM)
  │
  ▼
Upstream API
```

**Default-deny.** Configured hosts get MITM'd and policy-evaluated. If no Cedar rule matches, the request is denied. Unconfigured hosts pass through as opaque TCP tunnels.

## Quick start

```bash
# Start the proxy
strait --port 9443 --policy rules.cedar --credentials creds.toml

# Route traffic through it
HTTPS_PROXY=127.0.0.1:9443 curl https://api.github.com/user
```

## Cedar policies

strait evaluates a `.cedar` policy file against every MITM'd request. The entity hierarchy is built from the URL path — policies match on method, path, and headers.

```cedar
// Allow read access to org repos
permit(
  principal == Agent::"worker",
  action == Action::"GET",
  resource in Resource::"api.github.com/repos/our-org"
);

// Allow PR creation
permit(
  principal == Agent::"worker",
  action == Action::"POST",
  resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };

// Deny push to main
forbid(
  principal,
  action == Action::"POST",
  resource in Resource::"api.github.com/repos"
) when { context.path like "*/git/refs/heads/main" };
```

## Credential injection

Credentials are configured in TOML. The calling process never sees the real secrets — strait injects them on allowed requests only.

```toml
[github]
type = "bearer"
header = "Authorization"
value_prefix = "token "
source = "env:GITHUB_TOKEN"
```

Sources: environment variables (today), macOS Keychain (planned).

## Audit logging

Every policy decision is logged as structured JSON to stderr:

```json
{
  "ts": "2026-03-25T14:30:00.000Z",
  "session_id": "a1b2c3",
  "host": "api.github.com",
  "method": "GET",
  "path": "/repos/org/repo",
  "decision": "allow",
  "policy": "read-repos",
  "credential_injected": true,
  "latency_us": 42
}
```

Use `--audit-log <path>` to write to a file.

## Use cases

- **CI/CD pipelines** — govern what builds can fetch, with auditable records
- **Developer sandboxes** — control and log network access from dev environments
- **Contractor access** — policy-governed API access without sharing credentials
- **Compliance** — immutable audit trail of every API call a process makes
- **Agent sandboxing** — pair with a kernel sandbox for defense in depth

## Install

```bash
brew install ninthwave-sh/tap/strait    # macOS
cargo install strait                     # from source
```

## Status

Early development. Core proxy with CONNECT tunneling works. Cedar policy evaluation, credential injection, and selective MITM are in active development.

## License

MIT
