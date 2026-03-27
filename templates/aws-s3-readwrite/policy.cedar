// aws-s3-readwrite — S3 read + write, deny DeleteBucket/DeleteObject.
// # VALIDATED: 2026-03-27 cedar-validate
//
// Entity model (built automatically by strait from each HTTP request):
//   Principal: Agent::"worker"           — the calling process
//   Action:    Action::"GET", "PUT", …   — HTTP method
//   Resource:  Resource::"s3.us-east-1.amazonaws.com/bucket/key"
//              — host + path segments, forming a hierarchy via Cedar `in`
//
// AWS-specific context attributes (set automatically by strait):
//   context.aws_service  — "s3"
//   context.aws_region   — e.g. "us-east-1"
//
// Default disposition: DENY. Allows S3 read and write operations but
// explicitly denies destructive operations (DELETE).

// ---------------------------------------------------------------------------
// PERMIT policies
// ---------------------------------------------------------------------------

// Allow S3 read operations: GetObject, ListBucket, ListObjects.
@id("allow-s3-get")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource
) when {
    context.aws_service == "s3"
};

// Allow S3 HeadObject / HeadBucket.
@id("allow-s3-head")
permit(
    principal == Agent::"worker",
    action == Action::"HEAD",
    resource
) when {
    context.aws_service == "s3"
};

// Allow S3 write operations: PutObject, CreateMultipartUpload.
@id("allow-s3-put")
permit(
    principal == Agent::"worker",
    action == Action::"PUT",
    resource
) when {
    context.aws_service == "s3"
};

// Allow S3 POST operations: CompleteMultipartUpload, PostObject.
@id("allow-s3-post")
permit(
    principal == Agent::"worker",
    action == Action::"POST",
    resource
) when {
    context.aws_service == "s3"
};

// ---------------------------------------------------------------------------
// FORBID policies — hard denials that override any permit
// ---------------------------------------------------------------------------

// Deny all S3 DELETE operations (DeleteObject, DeleteBucket).
@id("deny-s3-delete")
@reason("S3 delete operations are prohibited; use lifecycle policies for cleanup")
forbid(
    principal,
    action == Action::"DELETE",
    resource
) when {
    context.aws_service == "s3"
};
