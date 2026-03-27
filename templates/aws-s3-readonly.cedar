// VALIDATED: 2026-03-27 strait init --observe
// aws-s3-readonly — Read-only S3 access (GetObject, ListBucket).
//
// Allows: GET and HEAD requests to any S3 endpoint.
// Denies: All write operations (PUT, POST, DELETE).
//
// Covers S3 API operations:
//   GET    — GetObject, ListBucket, ListObjectsV2, GetBucketLocation
//   HEAD   — HeadObject, HeadBucket
//
// Note: strait automatically sets context.aws_service and context.aws_region
// from the target hostname (e.g. s3.us-east-1.amazonaws.com → service="s3",
// region="us-east-1").

// Read objects and list buckets.
@id("s3-read")
permit(
    principal,
    action == Action::"http:GET",
    resource
) when { context.aws_service == "s3" };

// Head requests for object/bucket metadata.
@id("s3-head")
permit(
    principal,
    action == Action::"http:HEAD",
    resource
) when { context.aws_service == "s3" };

// Explicit deny for S3 write operations — clear audit trail.
@id("deny-s3-write")
@reason("S3 write operations are not permitted in read-only mode")
forbid(
    principal,
    action == Action::"http:PUT",
    resource
) when { context.aws_service == "s3" };

@id("deny-s3-post")
@reason("S3 write operations are not permitted in read-only mode")
forbid(
    principal,
    action == Action::"http:POST",
    resource
) when { context.aws_service == "s3" };

@id("deny-s3-delete")
@reason("S3 delete operations are not permitted in read-only mode")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource
) when { context.aws_service == "s3" };
