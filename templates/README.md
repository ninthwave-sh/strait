# Network Policy Templates

Built-in Cedar policy templates for common outbound HTTP access patterns.

These templates support strait's network-policy-for-devcontainers workflow. Keep environment shape in `devcontainer.json`, then use these templates as starting points for outbound API access rules.

## Available Templates

| Template | Description |
|---|---|
| `github-org-readonly` | Read-only access to a GitHub org's repos |
| `github-org-contributor` | Read + PR creation, deny push to main/release branches, deny repo admin |
| `aws-s3-readonly` | Read-only S3 access (GetObject, ListBucket) |
| `aws-s3-readwrite` | S3 read + write, deny DeleteBucket/DeleteObject |
| `container-sandbox` | Scoped HTTP access for a containerized agent |

## Shared Network Schema

`strait.cedarschema` is the shared schema for Strait's HTTP policy model. Use it when combining network rules from multiple hosts or services (for example GitHub + AWS). AWS context attributes (`aws_service`, `aws_region`) are declared as optional, so policies work correctly for both AWS and non-AWS hosts.

## Usage

List all available templates:

```bash
strait template list
```

Apply a template to a directory:

```bash
strait template apply github-org-readonly --output-dir ./policies
```

Print a template to stdout:

```bash
strait template apply aws-s3-readonly
```

## Customization

After applying a template, edit the generated `.cedar` file to match your environment:

- **GitHub templates**: Replace `your-org` with your GitHub organization name.
- **AWS templates**: Adjust region constraints or add bucket-level scoping as needed.

## Validation

Each template is validated against real API traffic using `strait init --observe` before inclusion. The `# VALIDATED:` comment in each file records when and how the template was verified.

To re-validate a template against your own traffic:

```bash
strait init --observe 5m --config strait.toml --output-dir ./observed
# Compare the generated policy against the template
```
