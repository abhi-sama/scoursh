#!/usr/bin/env bash
# tests/suites/aws-lint.sh - the meta-test for tests/lint-aws-readonly.sh
# (docs/FOUNDATION.md tension 23).
#
# The lint is the single most important safety property of the AWS module: it
# is what proves - independent of aws_ro's own runtime guard - that a mutating
# call cannot land in the shipped module.  A safety control that has never been
# proven to fail on the thing it exists to catch is not a control, it is a
# green checkmark.  This suite plants a mutating call in a disposable fixture
# tree, asserts the lint fails; removes it, asserts the lint passes.  Both
# directions, every time, per docs/FOUNDATION.md's rule that a test must name
# the reading it fails under.
#
# The fixture trees live entirely under $W (the scratch dir) and are never
# written into the real repository - tests/lint-aws-readonly.sh's optional
# SCAN_ROOT argument (added alongside this suite) points it at each fixture
# instead of $ROOT, so the real lib/modules/aws/tools trees are never touched.
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/aws-lint
mkdir -p "$W"

lint() {
  bash "$ROOT/tests/lint-aws-readonly.sh" "$1"
}

# check 4's allow-list tests use SCOURSH_AWS_LINT_ALLOWFILE (added alongside
# this suite) so they never write to the real, committed
# tests/aws-readonly-allow.txt - which is deliberately absent right now
# (docs/FOUNDATION.md tension 23: "seeded at §13 step 6").
lint_with_allowfile() {
  SCOURSH_AWS_LINT_ALLOWFILE=$1 bash "$ROOT/tests/lint-aws-readonly.sh" "$2"
}

fixture() {
  local dir=$1
  rm -rf "$dir"
  mkdir -p "$dir/modules/cloud/aws/live"
}

write_check() {
  local dir=$1 name=$2
  shift 2
  printf '%s\n' "$@" >"$dir/modules/cloud/aws/live/$name.sh"
}

# ---------------------------------------------------------------------------
printf '\n-- prove both directions: a planted mutating call fails, removing it passes --\n'
# ---------------------------------------------------------------------------
F1=$W/mutating
fixture "$F1"
write_check "$F1" iam \
  '#!/usr/bin/env bash' \
  'aws_ro iam create-user --user-name backdoor'

t_case 'a deliberately-planted mutating aws_ro call fails the lint'
assert_status 1 'create-user is refused' lint "$F1"
out=$(lint "$F1" 2>&1 || true)
assert_contains "$out" "not read-only" 'the failure names the offending operation, not just a bare non-zero exit'
assert_contains "$out" "create-user" 'the failure names the exact operation that was refused'

t_case 'removing the mutating call makes the same tree pass'
write_check "$F1" iam \
  '#!/usr/bin/env bash' \
  'aws_ro iam list-users'
assert_status 0 'list-users is clean' lint "$F1"

# ---------------------------------------------------------------------------
printf '\n-- check 1: a bare aws invocation, both directions --\n'
# ---------------------------------------------------------------------------
F2=$W/bare
fixture "$F2"
write_check "$F2" ec2 \
  '#!/usr/bin/env bash' \
  'aws ec2 describe-instances'

t_case 'a bare `aws` call (bypassing the chokepoint entirely) fails'
assert_status 1 'bare aws is refused even though describe-instances is itself read-only' lint "$F2"
out=$(lint "$F2" 2>&1 || true)
assert_contains "$out" "bare 'aws' invocation" 'the failure names check 1 specifically'

t_case 'routing the same call through aws_ro makes it pass'
write_check "$F2" ec2 \
  '#!/usr/bin/env bash' \
  'aws_ro ec2 describe-instances'
assert_status 0 'the identical operation is clean once it goes through aws_ro' lint "$F2"

# ---------------------------------------------------------------------------
printf '\n-- the lint has no false positives on read-only calls containing mutating substrings --\n'
# ---------------------------------------------------------------------------
# docs/FOUNDATION.md tension 23's own worked examples: a naive denylist grep
# fails on every one of these, which is why the lint stopped linting prose.
F3=$W/substrings
fixture "$F3"
write_check "$F3" mixed \
  '#!/usr/bin/env bash' \
  '# remediation: delete the public snapshot' \
  'update_available=1' \
  'aws_ro organizations describe-create-account-status' \
  'aws_ro iam list-attached-role-policies' \
  'aws_ro iam get-account-authorization-details' \
  'aws_ro eks describe-update'

t_case 'genuinely read-only operations pass despite containing create/attach/authoriz/update substrings'
assert_status 0 'no false positive from prose, comments, or variable names' lint "$F3"

# ---------------------------------------------------------------------------
printf '\n-- check 3: a variable operation is validated by its literals, not just by a readonly declaration --\n'
# ---------------------------------------------------------------------------
F4=$W/variable
fixture "$F4"
write_check "$F4" iam \
  '#!/usr/bin/env bash' \
  'readonly OPS=(list-users delete-user)' \
  'aws_ro iam "${OPS[1]}"'

t_case 'a mutating literal hidden inside an otherwise-readonly array still fails'
assert_status 1 'delete-user inside OPS is caught even though OPS itself is `readonly`' lint "$F4"
out=$(lint "$F4" 2>&1 || true)
assert_contains "$out" "delete-user" 'the failure names the specific array element that is not read-only'

t_case 'a readonly array of entirely read-only literals passes'
write_check "$F4" iam \
  '#!/usr/bin/env bash' \
  'readonly OPS=(list-users get-user)' \
  'aws_ro iam "${OPS[0]}"' \
  'aws_ro iam "${OPS[1]}"'
assert_status 0 'every literal in OPS matches the read-only prefix allowlist' lint "$F4"

t_case 'a variable with no readonly declaration in the file fails, regardless of its value'
write_check "$F4" iam \
  '#!/usr/bin/env bash' \
  'op=list-users' \
  'aws_ro iam "$op"'
assert_status 1 'op is not declared readonly, so the lint cannot certify it' lint "$F4"

# ---------------------------------------------------------------------------
printf '\n-- check 4: a stale allow-list entry fails, so the exception file cannot rot --\n'
# ---------------------------------------------------------------------------
F5=$W/allowlist
fixture "$F5"
write_check "$F5" sts \
  '#!/usr/bin/env bash' \
  'aws_ro sts assume-role --role-arn x'
ALLOW_FIXTURE=$W/allow.txt

t_case 'an operation covered by the allow-list, and present in the code, passes'
printf 'sts assume-role # required by multi-account support\n' >"$ALLOW_FIXTURE"
assert_status 0 'assume-role is allow-listed and appears in the fixture' lint_with_allowfile "$ALLOW_FIXTURE" "$F5"

t_case 'an allow-list entry no longer present in any file fails - it cannot rot into a blanket permission'
printf 'sts assume-role # required by multi-account support\nsts get-session-token # stale\n' >"$ALLOW_FIXTURE"
assert_status 1 'get-session-token is listed but appears in no code' lint_with_allowfile "$ALLOW_FIXTURE" "$F5"
out=$(lint_with_allowfile "$ALLOW_FIXTURE" "$F5" 2>&1 || true)
assert_contains "$out" "get-session-token" 'the failure names the stale entry'
assert_contains "$out" "appears in no code" 'the failure explains why: it would otherwise rot into a blanket permission'

t_summary aws-lint
