# Fix: Credential robustness -- AWS China + proxy env vars (M-ER-6)

**Priority:** Medium
**Source:** ER-3 Findings 2, 5; ER-7 Finding 4
**Depends on:** None
**Domain:** credentials

China partition AWS endpoints (.amazonaws.com.cn) don't match the *.amazonaws.com credential pattern, causing silent credential injection failure. First-match-wins behavior in credential lookup may surprise users with overlapping patterns. Container environment only sets HTTPS_PROXY but many tools also check HTTP_PROXY, http_proxy, and https_proxy. Fix by expanding AWS host pattern matching to include .cn suffix, adding tracing when multiple credentials could match a host, and setting all four proxy environment variable variants in container config.

**Test plan:**
- Test that s3.cn-north-1.amazonaws.com.cn matches an AWS credential pattern
- Test that when multiple credentials match, a trace log indicates which one won
- Test that container env includes HTTPS_PROXY, HTTP_PROXY, https_proxy, http_proxy

Acceptance: China partition endpoints matched. Credential match logging added. All proxy env vars set in container.

Key files: `src/credentials.rs`, `src/container.rs`
