# Fix: parse_aws_host mishandles dualstack/FIPS endpoints (H-CP-22)

**Priority:** High
**Source:** design review of PRs #14, #17
**Depends on:** -
**Domain:** credentials

`parse_aws_host` assumes the last two segments before `.amazonaws.com` are `service.region`. This breaks for dualstack, FIPS, and VPC endpoints:

- `s3.dualstack.us-east-1.amazonaws.com` → service=`dualstack` (wrong, should be `s3`)
- `s3-fips.us-east-1.amazonaws.com` → service=`us-east-1` (wrong)
- `s3.dualstack.fips.us-east-1.amazonaws.com` → completely wrong

Required:
- Parse AWS hostnames correctly for all endpoint variants
- Known qualifiers (`dualstack`, `fips`, `vpce`) should be skipped when extracting service name
- Service is always the first segment (or derived from it, e.g., `s3-fips` → `s3`)
- Region is the segment that matches a region pattern (e.g., `us-east-1`, `eu-west-2`)

Also consider: China (`*.amazonaws.com.cn`) and GovCloud (`*.amazonaws-us-gov.com`) partition support.

**Test plan:**
- Unit test: `s3.dualstack.us-east-1.amazonaws.com` → service=s3, region=us-east-1
- Unit test: `s3-fips.us-east-1.amazonaws.com` → service=s3, region=us-east-1
- Unit test: `dynamodb.cn-north-1.amazonaws.com.cn` → service=dynamodb, region=cn-north-1 (if supporting China)
- Regression: existing hostname tests still pass

Key files: `src/credentials.rs` (parse_aws_host function), `src/sigv4.rs` (callers)
