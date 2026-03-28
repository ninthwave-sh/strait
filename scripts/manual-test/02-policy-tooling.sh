#!/usr/bin/env bash
# 02 — Policy tooling: templates, explain, diff.
# No Docker or credentials required.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
setup_tmpdir

section "Template List"

TEMPLATES=$("$STRAIT" template list 2>&1)
check_contains "template list shows github-org-readonly" "$TEMPLATES" "github-org-readonly"
check_contains "template list shows aws-s3-readonly" "$TEMPLATES" "aws-s3-readonly"
check_contains "template list shows container-sandbox" "$TEMPLATES" "container-sandbox"

section "Template Apply"

"$STRAIT" template apply github-org-readonly --output-dir "$TMPDIR_BASE" 2>/dev/null
check_file_exists "github-org-readonly .cedar created" "$TMPDIR_BASE/github-org-readonly.cedar"
check_file_exists "github-org-readonly .cedarschema created" "$TMPDIR_BASE/github-org-readonly.cedarschema"

"$STRAIT" template apply container-sandbox --output-dir "$TMPDIR_BASE" 2>/dev/null
check_file_exists "container-sandbox .cedar created" "$TMPDIR_BASE/container-sandbox.cedar"

section "Explain"

EXPLAIN=$("$STRAIT" explain "$REPO_ROOT/examples/github.cedar" 2>&1)
check_contains "explain shows permit policies" "$EXPLAIN" "permit\|PERMIT\|allow\|ALLOW\|read"
check_contains "explain shows forbid policies" "$EXPLAIN" "forbid\|FORBID\|deny\|DENY"
check_contains "explain mentions github" "$EXPLAIN" "github\|GitHub"

EXPLAIN_AWS=$("$STRAIT" explain "$REPO_ROOT/examples/aws.cedar" 2>&1)
check_contains "explain handles AWS policy" "$EXPLAIN_AWS" "aws\|AWS\|s3\|S3\|lambda\|Lambda"

echo ""
echo -e "  ${CYAN}▶ Human review — does this read well?${RESET}"
echo -e "${DIM}"
echo "$EXPLAIN" | head -20
echo -e "${RESET}"

section "Diff"

# Diff identical policies — should show no changes
DIFF_SAME=$("$STRAIT" diff "$REPO_ROOT/examples/github.cedar" "$REPO_ROOT/examples/github.cedar" 2>&1)
DIFF_SAME_EXIT=$?
check "diff identical policies exits 0" test "$DIFF_SAME_EXIT" -eq 0

# Diff different policies — should show changes
DIFF_DIFF=$("$STRAIT" diff "$REPO_ROOT/examples/github.cedar" "$REPO_ROOT/examples/aws.cedar" 2>&1) || true
check_contains "diff different policies shows differences" "$DIFF_DIFF" "added\|removed\|Added\|Removed\|changed\|Changed\|+"

# Create a modified policy for meaningful diff
cat > "$TMPDIR_BASE/modified.cedar" <<'CEDAR'
@id("read-org-repos")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/our-org"
);

@id("write-issues")
permit(
    principal == Agent::"worker",
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/issues" };
CEDAR

DIFF_MOD=$("$STRAIT" diff "$REPO_ROOT/examples/github.cedar" "$TMPDIR_BASE/modified.cedar" 2>&1) || true
check_contains "diff detects added permission" "$DIFF_MOD" "issues\|added\|Added\|+"
check_contains "diff detects removed permission" "$DIFF_MOD" "pulls\|removed\|Removed\|-"

echo ""
echo -e "  ${CYAN}▶ Human review — does the diff output make sense?${RESET}"
echo -e "${DIM}"
echo "$DIFF_MOD" | head -20
echo -e "${RESET}"

cleanup_tmpdir
summary
