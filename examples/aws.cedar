// aws.cedar — Cedar policy for AWS API access through strait.
//
// Entity model (built automatically by strait from each HTTP request):
//   Principal: Agent::"worker"           — the calling process
//   Action:    Action::"GET", "PUT", …   — HTTP method
//   Resource:  Resource::"s3.us-east-1.amazonaws.com/bucket/key"
//              — host + path segments, forming a hierarchy via Cedar `in`
//
// AWS-specific context attributes (set automatically by strait when the
// target host is an *.amazonaws.com endpoint):
//   context.aws_service  — AWS service name (e.g. "s3", "lambda", "iam")
//   context.aws_region   — AWS region (e.g. "us-east-1"; defaults to
//                          "us-east-1" for global endpoints like iam.amazonaws.com)
//
// Default disposition: DENY. Requests without a matching `permit` are blocked.
//
// To use: adjust service names, regions, and principal identities to match
// your environment.

// ---------------------------------------------------------------------------
// PERMIT policies — what the agent is allowed to do
// ---------------------------------------------------------------------------

// Allow S3 read/write in us-east-1.
// Covers: GetObject, PutObject, ListBucket, etc.
@id("allow-s3-us-east-1")
permit(
    principal == Agent::"worker",
    action,
    resource
) when {
    context.aws_service == "s3" &&
    context.aws_region == "us-east-1"
};

// Allow Lambda invocation in us-east-1.
// Lambda Invoke uses POST to /2015-03-31/functions/<name>/invocations.
@id("allow-lambda-invoke")
permit(
    principal == Agent::"worker",
    action == Action::"POST",
    resource
) when {
    context.aws_service == "lambda" &&
    context.aws_region == "us-east-1"
};

// Allow read-only DynamoDB access in any region.
// DynamoDB uses POST for all API actions (GetItem, Query, etc.).
@id("allow-dynamodb-read")
permit(
    principal == Agent::"worker",
    action == Action::"POST",
    resource
) when {
    context.aws_service == "dynamodb"
};

// ---------------------------------------------------------------------------
// FORBID policies — hard denials that override any permit
// Each includes a @reason annotation documenting *why* the action is blocked.
// ---------------------------------------------------------------------------

// Deny all access to GovCloud regions.
@id("deny-govcloud")
@reason("GovCloud regions require separate authorization")
forbid(
    principal,
    action,
    resource
) when {
    context.aws_region like "us-gov-*"
};

// Deny IAM write operations.
// IAM is a global service (iam.amazonaws.com); only allow read access through the proxy.
@id("deny-iam-write")
@reason("IAM modifications must go through the organization's SSO workflow")
forbid(
    principal,
    action == Action::"POST",
    resource
) when {
    context.aws_service == "iam"
};
