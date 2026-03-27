// aws-s3-readonly — Read-only S3 access (GetObject, ListBucket).
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
// Default disposition: DENY. Only GET and HEAD requests to S3 are permitted.

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

// ---------------------------------------------------------------------------
// FORBID policies — explicit denials for audit trail clarity
// ---------------------------------------------------------------------------

// Deny all S3 write operations (PUT, POST, DELETE, PATCH).
// Cedar's default-deny already blocks these, but this explicit forbid
// provides a clear reason in audit logs.
@id("deny-s3-write")
@reason("S3 write operations are not allowed through this read-only policy")
forbid(
    principal,
    action,
    resource
) when {
    context.aws_service == "s3" &&
    context.method != "GET" &&
    context.method != "HEAD"
};
