#!/usr/bin/env bash
# tests/suites/awscli.sh - lib/awscli.sh's aws_ro() runtime enforcement
# (docs/FOUNDATION.md tension 23).
#
# No AWS account, no network, no `aws` binary is required: every test here
# points SCOURSH_AWSCLI_BIN at a stub script under $W that records its argv
# and environment instead of calling AWS.  What is under test is the
# CHOKEPOINT'S OWN logic - the prefix allowlist, the exception-file lookup, the
# refused flags, the F17 pager fix - not anything AWS-shaped, which is why a
# stub is sufficient and correct rather than a compromise.
#
# tools/localstack-run.sh separately proves aws_ro against a real (emulated)
# API shape; that is an integration concern and deliberately lives outside this
# suite so `tests/run-tests.sh` never depends on docker.
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=lib/awscli.sh
source "$ROOT/lib/awscli.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"

W=$SCOURSH_SCRATCH/awscli
mkdir -p "$W/bin"

# A stub `aws`: records how it was invoked (argv, one per line, plus the
# AWS_PAGER value) to $STUB_LOG and exits 0.  `aws --version` answers with
# whichever major version the test wants, via $STUB_VERSION_LINE.
STUB_LOG=$W/stub.log
STUB_VERSION_FILE=$W/stub-version
printf 'aws-cli/2.15.0 Python/3.11.6 Linux/6.1.0 exe/x86_64.stub' >"$STUB_VERSION_FILE"

cat >"$W/bin/aws" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
  cat "$STUB_VERSION_FILE"
  exit 0
fi
{
  printf 'AWS_PAGER=%s\n' "${AWS_PAGER-<unset>}"
  for a in "$@"; do printf 'ARG:%s\n' "$a"; done
} >"$STUB_LOG"
exit 0
STUB
chmod +x "$W/bin/aws"

# Every test gets a private PATH with the stub first and a private, isolated
# allowlist file (so the suite never depends on - or accidentally seeds -
# tests/aws-readonly-allow.txt, which is deliberately absent at this build
# step; see docs/FOUNDATION.md tension 23's "Consequence for the build").
run_stub() {
  rm -f "$STUB_LOG"
  PATH="$W/bin:$PATH" STUB_VERSION_FILE="$STUB_VERSION_FILE" STUB_LOG="$STUB_LOG" \
    SCOURSH_AWSCLI_BIN=aws SCOURSH_AWSCLI_ALLOWLIST="$W/does-not-exist.txt" \
    bash -c '
      set -Eeuo pipefail
      source "'"$ROOT"'/lib/core.sh"
      source "'"$ROOT"'/lib/awscli.sh"
      aws_ro "$@"
    ' _ "$@"
}

log_has() { [[ -f $STUB_LOG ]] && grep -qF -- "$1" "$STUB_LOG"; }

# ---------------------------------------------------------------------------
printf '\n-- a read-only operation is invoked unmodified, output pinned --\n'
# ---------------------------------------------------------------------------
t_case 'describe/list/get/... prefixes pass through to the stub'
for op in describe-instances list-buckets get-bucket-policy search-transit-gateway-routes \
  lookup-events select-object-content head-object batch-get-item preview-generation \
  estimate-template-cost simulate-principal-policy; do
  assert_status 0 "aws_ro <svc> $op succeeds" run_stub svc "$op"
done

t_case 'the read-only call reaches the stub with the caller-supplied args intact'
run_stub s3 list-buckets --region us-east-1 >/dev/null
assert_true "$(log_has 'ARG:s3' && echo 0 || echo 1)" 'service is argv[1]'
assert_true "$(log_has 'ARG:list-buckets' && echo 0 || echo 1)" 'operation is argv[2]'
assert_true "$(log_has 'ARG:--region' && echo 0 || echo 1)" 'a caller flag survives'
assert_true "$(log_has 'ARG:us-east-1' && echo 0 || echo 1)" "a caller flag's value survives"

t_case '--output json is always appended, and cannot be supplied twice'
run_stub s3 list-buckets >/dev/null
assert_true "$(log_has 'ARG:--output' && echo 0 || echo 1)" '--output is present exactly once, pinned by aws_ro'
n=$(grep -cF 'ARG:--output' "$STUB_LOG")
assert_eq 1 "$n" 'no duplicate --output'

# ---------------------------------------------------------------------------
printf '\n-- finding F17: AWS_PAGER, never --no-cli-pager --\n'
# ---------------------------------------------------------------------------
t_case 'AWS_PAGER is pinned empty rather than passing --no-cli-pager'
run_stub s3 list-buckets >/dev/null
assert_true "$(log_has 'AWS_PAGER=' && echo 0 || echo 1)" \
  'AWS_PAGER is set (to empty), which both CLI v1 and v2 honour'
assert_true "$(log_has 'ARG:--no-cli-pager' && echo 1 || echo 0)" \
  '--no-cli-pager is never sent - it is v2-only and a v1 host rejects it at argument parsing'

t_case 'a v1 `aws --version` string does not change behaviour (the F17 failure mode, reproduced absent)'
printf 'aws-cli/1.32.0 Python/3.11.6 Linux/6.1.0 botocore/1.34.0' >"$STUB_VERSION_FILE"
assert_status 0 'the call still succeeds against a v1 stub' run_stub s3 list-buckets
printf 'aws-cli/2.15.0 Python/3.11.6 Linux/6.1.0 exe/x86_64.stub' >"$STUB_VERSION_FILE"

# ---------------------------------------------------------------------------
printf '\n-- a non-read-only operation is a scope violation (exit 3) --\n'
# ---------------------------------------------------------------------------
t_case 'mutating verbs abort with exit 3 and never reach the stub'
for op in create-bucket put-bucket-policy delete-object update-function-configuration \
  modify-db-instance attach-role-policy authorize-security-group-ingress terminate-instances; do
  rm -f "$STUB_LOG"
  assert_status 3 "aws_ro iam $op is refused" run_stub iam "$op"
  assert_true "$([[ ! -f $STUB_LOG ]] && echo 0 || echo 1)" \
    "iam $op never reached the stub - refused before exec, not after"
done

t_case 'a prefix collision inside a longer word is not fooled by substring matching'
assert_status 3 '`getting-started` is not the `get` prefix (must match on a - or end boundary)' \
  run_stub svc getting-started

# ---------------------------------------------------------------------------
printf '\n-- the exception file is the single source of truth at runtime too --\n'
# ---------------------------------------------------------------------------
t_case 'an allowlisted non-read operation is permitted only via the exception file'
assert_status 3 'sts assume-role is refused with no exception file present' run_stub sts assume-role

ALLOW=$W/allow.txt
printf 'sts assume-role # required by multi-account support\n' >"$ALLOW"
rc=0
PATH="$W/bin:$PATH" STUB_VERSION_FILE="$STUB_VERSION_FILE" STUB_LOG="$STUB_LOG" \
  SCOURSH_AWSCLI_BIN=aws SCOURSH_AWSCLI_ALLOWLIST="$ALLOW" \
  bash -c '
    set -Eeuo pipefail
    source "'"$ROOT"'/lib/core.sh"
    source "'"$ROOT"'/lib/awscli.sh"
    aws_ro sts assume-role --role-arn x
  ' >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" 'sts assume-role succeeds once the exact pair is in the exception file'

t_case 'the exception file match is exact, not a prefix'
printf 'sts assume-role-with-web-identity # a different operation entirely\n' >"$ALLOW"
rc=0
PATH="$W/bin:$PATH" STUB_VERSION_FILE="$STUB_VERSION_FILE" STUB_LOG="$STUB_LOG" \
  SCOURSH_AWSCLI_BIN=aws SCOURSH_AWSCLI_ALLOWLIST="$ALLOW" \
  bash -c '
    set -Eeuo pipefail
    source "'"$ROOT"'/lib/core.sh"
    source "'"$ROOT"'/lib/awscli.sh"
    aws_ro sts assume-role --role-arn x
  ' >/dev/null 2>&1 || rc=$?
assert_eq 3 "$rc" 'a listed sibling operation does not authorise a different one'

# ---------------------------------------------------------------------------
printf '\n-- refused flags: the lint cannot see through these --\n'
# ---------------------------------------------------------------------------
t_case '--cli-input-json and --cli-input-yaml are refused outright, not merely un-pinned'
assert_status 3 '--cli-input-json is refused' run_stub s3 list-buckets --cli-input-json 'file://x.json'
assert_status 3 '--cli-input-json= is refused' run_stub s3 list-buckets --cli-input-json=file://x.json
assert_status 3 '--cli-input-yaml is refused' run_stub s3 list-buckets --cli-input-yaml 'file://x.yaml'

t_case 'a caller cannot override the pinned --output'
assert_status 3 '--output text is refused rather than silently overridden' \
  run_stub s3 list-buckets --output text

# ---------------------------------------------------------------------------
printf '\n-- usage and missing-binary errors stay inside the frozen 0-5 contract --\n'
# ---------------------------------------------------------------------------
t_case 'fewer than two arguments is a usage/input error, not a crash'
assert_status 4 'aws_ro with one argument exits 4 (SCOURSH_EXIT_INPUT)' run_stub s3

t_case 'a missing `aws` binary is exit 4, not a raw "command not found"'
rc=0
PATH=/usr/bin:/bin SCOURSH_AWSCLI_BIN=scoursh-aws-does-not-exist \
  bash -c '
    set -Eeuo pipefail
    source "'"$ROOT"'/lib/core.sh"
    source "'"$ROOT"'/lib/awscli.sh"
    aws_ro s3 list-buckets
  ' >/dev/null 2>&1 || rc=$?
assert_eq 4 "$rc" 'a missing aws binary is reported as a missing required input'

t_summary awscli
