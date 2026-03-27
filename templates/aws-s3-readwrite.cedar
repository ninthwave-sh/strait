// VALIDATED: 2026-03-27 strait init --observe
// aws-s3-readwrite — S3 read + write, deny DeleteBucket/DeleteObject.
//
// Allows: GET, HEAD, PUT, POST requests to any S3 endpoint.
// Denies: DELETE operations (DeleteObject, DeleteBucket).
//
// Covers S3 API operations:
//   GET    — GetObject, ListBucket, ListObjectsV2, GetBucketLocation
//   HEAD   — HeadObject, HeadBucket
//   PUT    — PutObject, CreateBucket, CopyObject
//   POST   — CompleteMultipartUpload, SelectObjectContent
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

// Write objects and create buckets.
@id("s3-write")
permit(
    principal,
    action == Action::"http:PUT",
    resource
) when { context.aws_service == "s3" };

// Multipart upload and other POST-based S3 operations.
@id("s3-post")
permit(
    principal,
    action == Action::"http:POST",
    resource
) when { context.aws_service == "s3" };

// Deny all S3 delete operations — protects against accidental data loss.
@id("deny-s3-delete")
@reason("S3 delete operations are not permitted; protects against accidental data loss")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource
) when { context.aws_service == "s3" };
