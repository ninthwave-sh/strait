# github-org-readonly

Read-only access to a GitHub organization's repositories.

## What it allows

- `GET` requests to any repo or sub-resource under `/repos/our-org/`
- Covers: list repos, get repo details, list issues, read commits, download artifacts

## What it denies

- All write operations (`POST`, `PUT`, `PATCH`, `DELETE`) — blocked by Cedar's default-deny
- Access to repos outside the allowed org — explicit `forbid` with audit reason

## Setup

1. Apply the template:

   ```bash
   strait template apply github-org-readonly --output-dir ./policies
   ```

2. Edit `policies/github-org-readonly.cedar` and replace `our-org` with your GitHub organization name.

3. Configure `strait.toml` to use the policy:

   ```toml
   [policy]
   path = "policies/github-org-readonly.cedar"
   schema_path = "policies/github-org-readonly.cedarschema"
   ```

4. Start strait:

   ```bash
   strait proxy --config strait.toml
   ```
