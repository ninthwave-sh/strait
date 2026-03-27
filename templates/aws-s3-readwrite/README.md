# aws-s3-readwrite

Read and write access to Amazon S3, with destructive operations denied.

## What it allows

- `GET` requests — GetObject, ListBucket, ListObjects
- `HEAD` requests — HeadObject, HeadBucket
- `PUT` requests — PutObject, CreateMultipartUpload
- `POST` requests — CompleteMultipartUpload, PostObject

## What it denies

- `DELETE` requests — DeleteObject, DeleteBucket — explicit `forbid`
- Access to non-S3 AWS services — blocked by Cedar's default-deny

## Setup

1. Apply the template:

   ```bash
   strait template apply aws-s3-readwrite --output-dir ./policies
   ```

2. Configure `strait.toml` to use the policy:

   ```toml
   [policy]
   path = "policies/aws-s3-readwrite.cedar"
   schema_path = "policies/aws-s3-readwrite.cedarschema"
   ```

3. Start strait:

   ```bash
   strait proxy --config strait.toml
   ```

## Notes

- The `deny-s3-delete` forbid policy overrides any permit, ensuring DELETE
  operations are always blocked even if you add broader permits later.
- To restrict to a specific region, add a `context.aws_region == "us-east-1"`
  condition to the permit policies.
