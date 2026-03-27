# github-org-contributor

Read access and pull request creation for a GitHub organization's repositories.
Denies direct pushes to protected branches and administrative operations.

## What it allows

- `GET` requests to any repo or sub-resource under `/repos/our-org/`
- `POST` to `/pulls` endpoints — create pull requests
- `POST` to `/comments` endpoints — comment on issues and PRs

## What it denies

- Direct pushes to `main` branch — explicit `forbid`
- Direct pushes to `release/*` branches — explicit `forbid`
- Repository deletion (`DELETE` on repos) — explicit `forbid`
- Admin settings changes (`PATCH` on settings) — explicit `forbid`
- Access to repos outside the allowed org — explicit `forbid`
- All other write operations — blocked by Cedar's default-deny

## Setup

1. Apply the template:

   ```bash
   strait template apply github-org-contributor --output-dir ./policies
   ```

2. Edit `policies/github-org-contributor.cedar` and replace `our-org` with your GitHub organization name.

3. Configure `strait.toml` to use the policy:

   ```toml
   [policy]
   path = "policies/github-org-contributor.cedar"
   schema_path = "policies/github-org-contributor.cedarschema"
   ```

4. Start strait:

   ```bash
   strait proxy --config strait.toml
   ```
