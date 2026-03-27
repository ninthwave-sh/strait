# aws-s3-readonly

Read-only access to Amazon S3 (GetObject, HeadObject, ListBucket).

## What it allows

- `GET` requests to any S3 endpoint — GetObject, ListBucket, ListObjects
- `HEAD` requests to any S3 endpoint — HeadObject, HeadBucket

## What it denies

- All S3 write operations (`PUT`, `POST`, `DELETE`, `PATCH`) — explicit `forbid`
- Access to non-S3 AWS services — blocked by Cedar's default-deny

## Setup

1. Apply the template:

   ```bash
   strait template apply aws-s3-readonly --output-dir ./policies
   ```

2. Configure `strait.toml` to use the policy:

   ```toml
   [policy]
   path = "policies/aws-s3-readonly.cedar"
   schema_path = "policies/aws-s3-readonly.cedarschema"
   ```

3. Start strait:

   ```bash
   strait proxy --config strait.toml
   ```

## Notes

- The AWS schema includes `aws_service` and `aws_region` context attributes,
  which strait sets automatically for `*.amazonaws.com` hosts.
- This template permits S3 access across all regions. To restrict to a specific
  region, add a `context.aws_region == "us-east-1"` condition to the permit policies.
