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
# tests/localstack/run.sh separately proves aws_ro against a real (emulated)
# API shape; that is an integration concern and deliberately lives outside this
# suite, and outside tests/run-tests.sh's default run, so the suite never
# depends on docker.
#
# shellcheck shell=bash
#
# SC2016: backticks in assertion prose are literal, not command substitution.
# shellcheck disable=SC2016

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# -x back-edge cut: lib/core.sh
# is already inlined elsewhere in this file's own source graph, and shellcheck
# re-expands EVERY source edge it follows.  Cutting this one loses no checking
# and is what keeps the linter's memory bounded - see the shellcheck stage in
# tests/run-tests.sh, and docs/CI-RUNBOOK.md.
# shellcheck source=/dev/null
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

# The stub is deliberately scriptable rather than fixed, because what this
# suite now has to exercise - a cache that must serve a repeat call WITHOUT
# reaching the CLI, an error class carried on stderr, a paginated sequence of
# different responses - are all facts about how many times the CLI ran and what
# it said, which a stub that always exits 0 with no output cannot express.
#
#   STUB_LOG          argv of the LAST call (overwritten; the original contract)
#   STUB_COUNT_FILE   one line appended per call - how the cache is measured,
#                     since "it did not re-fetch" is not observable any other way
#   STUB_STDOUT_FILE  a body to emit on stdout
#   STUB_STDERR_FILE  a diagnostic to emit on stderr
#   STUB_EXIT         the exit status (default 0)
#   STUB_SEQ_DIR      per-call responses: <n>.out, <n>.err, <n>.rc for call n,
#                     which is what makes a multi-page walk testable
cat >"$W/bin/aws" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
  cat "$STUB_VERSION_FILE"
  exit 0
fi
n=1
if [[ -n ${STUB_COUNT_FILE:-} ]]; then
  printf 'call\n' >>"$STUB_COUNT_FILE"
  n=$(wc -l <"$STUB_COUNT_FILE")
  n=${n//[[:space:]]/}
fi
{
  printf 'AWS_PAGER=%s\n' "${AWS_PAGER-<unset>}"
  for a in "$@"; do printf 'ARG:%s\n' "$a"; done
} >"$STUB_LOG"
rc=${STUB_EXIT:-0}
if [[ -n ${STUB_SEQ_DIR:-} ]]; then
  if [[ -f $STUB_SEQ_DIR/$n.out ]]; then cat "$STUB_SEQ_DIR/$n.out"; fi
  if [[ -f $STUB_SEQ_DIR/$n.err ]]; then cat "$STUB_SEQ_DIR/$n.err" >&2; fi
  if [[ -f $STUB_SEQ_DIR/$n.rc ]]; then rc=$(cat "$STUB_SEQ_DIR/$n.rc"); fi
else
  if [[ -n ${STUB_STDOUT_FILE:-} && -f ${STUB_STDOUT_FILE} ]]; then cat "$STUB_STDOUT_FILE"; fi
  if [[ -n ${STUB_STDERR_FILE:-} && -f ${STUB_STDERR_FILE} ]]; then cat "$STUB_STDERR_FILE" >&2; fi
fi
exit "$rc"
STUB
chmod +x "$W/bin/aws"

# Every test gets a private PATH with the stub first and a private, isolated
# allowlist file (so the suite never depends on - or accidentally seeds -
# tests/aws-readonly-allow.txt, which is deliberately absent at this build
# step; see docs/FOUNDATION.md tension 23's "Consequence for the build").
#
# Each invocation also gets a FRESH response-cache directory.  SCOURSH_SCRATCH
# is exported (lib/core.sh, deliberately, so xargs -P workers share it), so
# every one of these subprocesses would otherwise share ONE cache - and the
# second `run_stub s3api list-buckets` in this file would be served from it and
# never reach the stub, silently emptying the argv assertions below.  A fresh
# directory per call keeps each of those assertions measuring exactly what it
# always measured; the cache itself is measured on purpose in section "the
# response cache", against a deliberately SHARED directory.
run_stub() {
  rm -f "$STUB_LOG"
  local cdir
  cdir=$(mktemp -d "$W/cache.XXXXXX")
  PATH="$W/bin:$PATH" STUB_VERSION_FILE="$STUB_VERSION_FILE" STUB_LOG="$STUB_LOG" \
    SCOURSH_AWSCLI_BIN=aws SCOURSH_AWSCLI_ALLOWLIST="$W/does-not-exist.txt" \
    SCOURSH_AWS_CACHE_DIR="$cdir" \
    bash -c '
      set -Eeuo pipefail
      source "'"$ROOT"'/lib/core.sh"
      source "'"$ROOT"'/lib/awscli.sh"
      aws_ro "$@"
    ' _ "$@"
}

# `snip BODY` - run BODY with lib/awscli.sh loaded in the stub environment, and
# hand back its stdout.  Everything after the original 46 assertions is written
# against this rather than run_stub, because the outcome contract is carried in
# GLOBALS the caller reads after the call, which a helper that only returns an
# exit status cannot show.
#
# Any STUB_* / SCOURSH_AWS_* variable the caller exports reaches the subprocess.
# The cache directory is the exception and is opted into by a name of this
# suite's OWN - SNIP_CACHE_DIR - never by exporting SCOURSH_AWS_CACHE_DIR:
# this file sources lib/awscli.sh at the top, so SCOURSH_AWS_CACHE_DIR is
# already set in the suite's own shell, and reading it here silently gave every
# snip in the file one shared cache.  Measured: the identity fixture from one
# case was replayed into the next, so a test asserting a MISSING Account field
# passed back the previous test's account id.
snip() {
  local body=$1 f cdir
  f=$(mktemp "$W/snip.XXXXXX")
  printf '%s\n' "$body" >"$f"
  cdir=${SNIP_CACHE_DIR:-}
  [[ -n $cdir ]] || cdir=$(mktemp -d "$W/cache.XXXXXX")
  PATH="$W/bin:$PATH" STUB_VERSION_FILE="$STUB_VERSION_FILE" STUB_LOG="$STUB_LOG" \
    SCOURSH_AWSCLI_BIN=aws \
    SCOURSH_AWSCLI_ALLOWLIST="${SCOURSH_AWSCLI_ALLOWLIST_T:-$W/does-not-exist.txt}" \
    SCOURSH_AWS_CACHE_DIR="$cdir" \
    bash -c '
      set -Eeuo pipefail
      source "'"$ROOT"'/lib/core.sh"
      source "'"$ROOT"'/lib/awscli.sh"
      source "$1"
    ' _ "$f"
}

# The standard tail of a snip body: every field of the outcome contract, one
# per line, so an assertion names the field it is about.
REPORT='printf "OUTCOME=%s\nRC=%s\nSTATUS=%s\nCODE=%s\nTRUNC=%s\nTOKEN=%s\nCACHED=%s\nPAGES=%s\nKNOWN=%s\nLOSS=%s\n" \
  "$SCOURSH_AWS_RO_OUTCOME" "$rc" "$SCOURSH_AWS_RO_STATUS" "$SCOURSH_AWS_RO_CODE" \
  "$SCOURSH_AWS_RO_TRUNCATED" "$SCOURSH_AWS_RO_NEXT_TOKEN" "$SCOURSH_AWS_RO_CACHED" \
  "$SCOURSH_AWS_RO_PAGES" \
  "$(aws_ro_outcome_is_known "$SCOURSH_AWS_RO_OUTCOME" && echo yes || echo no)" \
  "$(aws_ro_outcome_is_coverage_loss && echo yes || echo no)"'

calls_reset() { : >"$1"; }
calls_of() {
  local n
  n=$(wc -l <"$1")
  printf '%s' "${n//[[:space:]]/}"
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
run_stub s3api list-buckets --region us-east-1 >/dev/null
assert_true "$(log_has 'ARG:s3api' && echo 0 || echo 1)" 'service is argv[1]'
assert_true "$(log_has 'ARG:list-buckets' && echo 0 || echo 1)" 'operation is argv[2]'
assert_true "$(log_has 'ARG:--region' && echo 0 || echo 1)" 'a caller flag survives'
assert_true "$(log_has 'ARG:us-east-1' && echo 0 || echo 1)" "a caller flag's value survives"

t_case '--output json is always appended, and cannot be supplied twice'
run_stub s3api list-buckets >/dev/null
assert_true "$(log_has 'ARG:--output' && echo 0 || echo 1)" '--output is present exactly once, pinned by aws_ro'
n=$(grep -cF 'ARG:--output' "$STUB_LOG")
assert_eq 1 "$n" 'no duplicate --output'

# ---------------------------------------------------------------------------
printf '\n-- finding F17: AWS_PAGER, never --no-cli-pager --\n'
# ---------------------------------------------------------------------------
t_case 'AWS_PAGER is pinned empty rather than passing --no-cli-pager'
run_stub s3api list-buckets >/dev/null
assert_true "$(log_has 'AWS_PAGER=' && echo 0 || echo 1)" \
  'AWS_PAGER is set (to empty), which both CLI v1 and v2 honour'
assert_true "$(log_has 'ARG:--no-cli-pager' && echo 1 || echo 0)" \
  '--no-cli-pager is never sent - it is v2-only and a v1 host rejects it at argument parsing'

t_case 'a v1 `aws --version` string does not change behaviour (the F17 failure mode, reproduced absent)'
printf 'aws-cli/1.32.0 Python/3.11.6 Linux/6.1.0 botocore/1.34.0' >"$STUB_VERSION_FILE"
assert_status 0 'the call still succeeds against a v1 stub' run_stub s3api list-buckets
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
assert_status 3 '--cli-input-json is refused' run_stub s3api list-buckets --cli-input-json 'file://x.json'
assert_status 3 '--cli-input-json= is refused' run_stub s3api list-buckets --cli-input-json=file://x.json
assert_status 3 '--cli-input-yaml is refused' run_stub s3api list-buckets --cli-input-yaml 'file://x.yaml'

t_case 'a caller cannot override the pinned --output'
assert_status 3 '--output text is refused rather than silently overridden' \
  run_stub s3api list-buckets --output text

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
    aws_ro s3api list-buckets
  ' >/dev/null 2>&1 || rc=$?
assert_eq 4 "$rc" 'a missing aws binary is reported as a missing required input'


# ===========================================================================
# Everything below this line is new with the P1 chokepoint work: the response
# cache, credential plumbing, account identity, error CLASSIFICATION and
# truncation.  The 46 assertions above are unchanged and still measure exactly
# what they measured; see run_stub's own note on why each of them now gets a
# private cache directory.
# ===========================================================================

FX=$W/fx
mkdir -p "$FX"

printf '{\n    "Buckets": [\n        {\n            "Name": "example-bucket"\n        }\n    ]\n}\n' >"$FX/buckets.json"
printf '{\n    "Account": "123456789012",\n    "Arn": "arn:aws:iam::123456789012:role/example-readonly",\n    "UserId": "AROAEXAMPLE:session"\n}\n' >"$FX/identity.json"
printf '{\n    "UserId": "AROAEXAMPLE:session"\n}\n' >"$FX/identity-no-account.json"

err_file() { printf '%s\n' "$2" >"$FX/$1.err"; printf '%s' "$FX/$1.err"; }

# ---------------------------------------------------------------------------
printf '\n-- the response cache: one fetch per identical key (tension 16) --\n'
# ---------------------------------------------------------------------------
t_case 'a repeated identical call is served from the cache, not re-fetched'
SHARED=$W/cache-shared
mkdir -p "$SHARED"
CALLS=$W/calls.log
calls_reset "$CALLS"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_COUNT_FILE=$CALLS STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/c1" s3api list-buckets || rc=$?
first=$SCOURSH_AWS_RO_CACHED
aws_ro_into "$SCOURSH_SCRATCH/c2" s3api list-buckets || rc=$?
same=no
cmp -s "$SCOURSH_SCRATCH/c1" "$SCOURSH_SCRATCH/c2" && same=yes
printf "FIRST_CACHED=%s\nSECOND_CACHED=%s\nSAME=%s\n" "$first" "$SCOURSH_AWS_RO_CACHED" "$same"
'"$REPORT"
)
assert_eq 1 "$(calls_of "$CALLS")" 'the CLI was invoked exactly once for two identical calls'
assert_contains "$out" 'FIRST_CACHED=0' 'the first call was a real fetch'
assert_contains "$out" 'SECOND_CACHED=1' 'the second call was served from the cache'
assert_contains "$out" 'SAME=yes' 'the cached body is byte-identical to the fetched one'
assert_contains "$out" 'OUTCOME=ok' 'a cache hit still carries a classified outcome'

t_case 'a differing argument is a different key, and is fetched'
rm -rf "$SHARED"; mkdir -p "$SHARED"
calls_reset "$CALLS"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_COUNT_FILE=$CALLS STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/d1" s3api get-bucket-acl --bucket alpha || rc=$?
aws_ro_into "$SCOURSH_SCRATCH/d2" s3api get-bucket-acl --bucket beta || rc=$?
printf "DONE\n"'
)
assert_contains "$out" 'DONE' 'both calls completed'
assert_eq 2 "$(calls_of "$CALLS")" 'two different buckets are two fetches, not one cache hit'

# What this measures is the operator-visible property - one region's answer is
# never served for another - and NOT the `region` component of the key shape
# docs/FOUNDATION.md freezes, which is belt-and-braces: an ambient region also
# becomes a --region argument, and the arguments are in the key too.  Saying so
# here rather than letting the case name claim a discrimination it does not
# have; the `account` component below is the one that genuinely is load-bearing.
t_case "the same call in two regions is two calls - one region's answer is never served for another"
rm -rf "$SHARED"; mkdir -p "$SHARED"
calls_reset "$CALLS"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_COUNT_FILE=$CALLS STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_use_region us-east-1
aws_ro_into "$SCOURSH_SCRATCH/r1" ec2 describe-instances || rc=$?
aws_ro_use_region eu-west-1
aws_ro_into "$SCOURSH_SCRATCH/r2" ec2 describe-instances || rc=$?
printf "DONE\n"'
)
assert_contains "$out" 'DONE' 'both regional calls completed'
assert_eq 2 "$(calls_of "$CALLS")" \
  "us-east-1's answer is not served for eu-west-1 - a region-blind key would report one region's resources as every region's"

t_case 'a principal change never serves the previous principal\'s cached answers'
# Step 6's sts assume-role path changes principal mid-run.  Every entry already
# in the cache is the OLD principal's view, and the identity call itself is the
# one call whose key cannot carry an account - the account is what it is
# resolving - so without aws_ro_identity_forget dropping the cache, the new
# principal's `sts get-caller-identity` is served the old principal's answer and
# every finding after the switch is attributed to an account it was never
# observed in.  Removing the cache clear makes this case do 2 calls, not 4.
rm -rf "$SHARED"; mkdir -p "$SHARED"
SEQ=$W/seq-acct
rm -rf "$SEQ"; mkdir -p "$SEQ"
cp "$FX/identity.json" "$SEQ/1.out"
cp "$FX/buckets.json" "$SEQ/2.out"
printf '{\n    "Account": "210987654321",\n    "Arn": "arn:aws:iam::210987654321:role/other"\n}\n' >"$SEQ/3.out"
cp "$FX/buckets.json" "$SEQ/4.out"
calls_reset "$CALLS"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_COUNT_FILE=$CALLS STUB_SEQ_DIR=$SEQ
  snip 'rc=0
aws_ro_account_id_set a1 || rc=$?
aws_ro_into "$SCOURSH_SCRATCH/a1" s3api list-buckets || rc=$?
aws_ro_identity_forget
aws_ro_account_id_set a2 || rc=$?
aws_ro_into "$SCOURSH_SCRATCH/a2" s3api list-buckets || rc=$?
printf "A1=%s\nA2=%s\nCACHED=%s\n" "$a1" "$a2" "$SCOURSH_AWS_RO_CACHED"'
)
assert_contains "$out" 'A1=123456789012' 'the first principal was resolved'
assert_contains "$out" 'A2=210987654321' 'aws_ro_identity_forget really re-resolves'
assert_contains "$out" 'CACHED=0' \
  "the second principal's list-buckets was fetched, not served from the first principal's entry"
assert_not_contains "$out" 'A2=123456789012' \
  'the new principal is never reported as the old one'
assert_eq 4 "$(calls_of "$CALLS")" 'four CLI calls: two identities and two listings'

t_case 'SCOURSH_AWS_CACHE=0 disables the cache entirely'
rm -rf "$SHARED"; mkdir -p "$SHARED"
calls_reset "$CALLS"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_COUNT_FILE=$CALLS STUB_STDOUT_FILE=$FX/buckets.json \
    SCOURSH_AWS_CACHE=0
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/n1" s3api list-buckets || rc=$?
aws_ro_into "$SCOURSH_SCRATCH/n2" s3api list-buckets || rc=$?
printf "CACHED=%s\n" "$SCOURSH_AWS_RO_CACHED"'
)
assert_contains "$out" 'CACHED=0' 'nothing is served from the cache when it is off'
assert_eq 2 "$(calls_of "$CALLS")" 'both calls reached the CLI'

t_case 'a FAILED call is never cached - a transient throttle must not become a permanent hole'
rm -rf "$SHARED"; mkdir -p "$SHARED"
SEQ=$W/seq-fail
rm -rf "$SEQ"; mkdir -p "$SEQ"
printf 'An error occurred (ThrottlingException) when calling the ListBuckets operation: Rate exceeded\n' >"$SEQ/1.err"
printf '254\n' >"$SEQ/1.rc"
cp "$FX/buckets.json" "$SEQ/2.out"
calls_reset "$CALLS"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_COUNT_FILE=$CALLS STUB_SEQ_DIR=$SEQ
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/f1" s3api list-buckets || rc=$?
first_outcome=$SCOURSH_AWS_RO_OUTCOME
rc=0
aws_ro_into "$SCOURSH_SCRATCH/f2" s3api list-buckets || rc=$?
printf "FIRST=%s\nSECOND=%s\nRETRY_RC=%s\n" "$first_outcome" "$SCOURSH_AWS_RO_OUTCOME" "$rc"'
)
assert_contains "$out" 'FIRST=throttled' 'the first call was classified as throttling'
assert_contains "$out" 'SECOND=ok' 'the retry was re-issued and succeeded'
assert_contains "$out" 'RETRY_RC=0' 'the retry returned success'
assert_eq 2 "$(calls_of "$CALLS")" 'the failure was not cached, so the retry reached the CLI'

# ---------------------------------------------------------------------------
printf '\n-- credential plumbing: --profile and --region actually reach the CLI --\n'
# ---------------------------------------------------------------------------
t_case 'the ambient profile and region are applied to a call that carries neither'
out=$(
  export STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_use_profile staging
aws_ro_use_region eu-west-2
aws_ro_into "$SCOURSH_SCRATCH/p1" s3api list-buckets || rc=$?
printf "RC=%s\n" "$rc"'
)
assert_contains "$out" 'RC=0' 'the call succeeded'
assert_true "$(log_has 'ARG:--profile' && echo 0 || echo 1)" '--profile reached the CLI'
assert_true "$(log_has 'ARG:staging' && echo 0 || echo 1)" 'the profile NAME reached the CLI'
assert_true "$(log_has 'ARG:--region' && echo 0 || echo 1)" '--region reached the CLI'
assert_true "$(log_has 'ARG:eu-west-2' && echo 0 || echo 1)" 'the region NAME reached the CLI'

t_case 'no ambient profile or region means neither flag is invented'
out=$(
  export STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/p2" s3api list-buckets || rc=$?
printf "RC=%s\n" "$rc"'
)
assert_contains "$out" 'RC=0' 'the call succeeded'
assert_true "$(log_has 'ARG:--profile' && echo 1 || echo 0)" \
  'no --profile is sent when none is configured - an empty flag is not the CLI default'
assert_true "$(log_has 'ARG:--region' && echo 1 || echo 0)" 'no --region is sent when none is configured'

t_case "a caller's own --region wins and is never duplicated"
out=$(
  export STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_use_region eu-west-2
aws_ro_into "$SCOURSH_SCRATCH/p3" ec2 describe-instances --region us-east-1 || rc=$?
printf "RC=%s\n" "$rc"'
)
assert_contains "$out" 'RC=0' 'the call succeeded'
n=$(grep -cF 'ARG:--region' "$STUB_LOG")
assert_eq 1 "$n" \
  'exactly one --region - two of them makes the winner a property of the CLI argument parser, not of this file'
assert_true "$(log_has 'ARG:us-east-1' && echo 0 || echo 1)" "the caller's region is the one sent"
assert_true "$(log_has 'ARG:eu-west-2' && echo 1 || echo 0)" 'the ambient region did not ride along too'

t_case "a caller's own --profile= form is recognised as already-present"
out=$(
  export STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_use_profile staging
aws_ro_into "$SCOURSH_SCRATCH/p4" s3api list-buckets --profile=audit || rc=$?
printf "RC=%s\n" "$rc"'
)
assert_contains "$out" 'RC=0' 'the call succeeded'
n=$(grep -cF 'ARG:--profile' "$STUB_LOG")
assert_eq 1 "$n" 'the --profile=VALUE spelling counts as present, so the ambient one is not added'

# ---------------------------------------------------------------------------
printf '\n-- account identity: sts get-caller-identity, resolved once --\n'
# ---------------------------------------------------------------------------
t_case 'the account id and caller ARN are resolved from the response'
calls_reset "$CALLS"
out=$(
  export STUB_COUNT_FILE=$CALLS STUB_STDOUT_FILE=$FX/identity.json
  snip 'rc=0
aws_ro_account_id_set acct || rc=$?
aws_ro_account_id_set again || rc=$?
printf "RC=%s\nACCT=%s\nAGAIN=%s\nARN=%s\n" "$rc" "$acct" "$again" "$SCOURSH_AWS_CALLER_ARN"'
)
assert_contains "$out" 'RC=0' 'identity resolution succeeded'
assert_contains "$out" 'ACCT=123456789012' 'the account id was parsed'
assert_contains "$out" 'ARN=arn:aws:iam::123456789012:role/example-readonly' 'the caller ARN was parsed'
assert_contains "$out" 'AGAIN=123456789012' 'the memoised value is returned on a second call'
assert_eq 1 "$(calls_of "$CALLS")" \
  'the identity is resolved ONCE per process - a per-region re-resolution is a call per region for a fact that cannot change'

t_case 'a 200 with no Account field is a failure, not an empty account id'
out=$(
  export STUB_STDOUT_FILE=$FX/identity-no-account.json
  snip 'rc=0
aws_ro_account_id_set acct || rc=$?
printf "RC=%s\nACCT=[%s]\n" "$rc" "$acct"'
)
assert_contains "$out" 'RC=1' 'the caller is told the identity is unusable'
assert_contains "$out" 'ACCT=[]' \
  'no invented account id - an empty one would land in the account_id component of every cloud finding'

t_case 'a denied get-caller-identity reports the class, not an empty identity'
printf 'An error occurred (AccessDenied) when calling the GetCallerIdentity operation: explicit deny\n' >"$FX/id-denied.err"
out=$(
  export STUB_STDERR_FILE=$FX/id-denied.err STUB_EXIT=254
  snip 'rc=0
aws_ro_account_id_set acct || rc=$?
printf "RC=%s\nOUT=%s\n" "$rc" "$SCOURSH_AWS_RO_OUTCOME"'
)
assert_contains "$out" 'RC=1' 'the failure is reported'
assert_contains "$out" 'OUT=access_denied' 'and it is reported as what it was'

# ---------------------------------------------------------------------------
printf '\n-- error classification: "denied" is not "empty" (the honesty piece) --\n'
# ---------------------------------------------------------------------------
# Each row is CODE-or-message -> outcome -> whether the caller owes a
# coverage_reduction.  Before this existed, every one of these rows produced a
# CLEAN result with no resources - "it did not look" and "it looked and found
# nothing" rendered identically, which is the data/advisories.db defect this
# project has already paid for once.
classify() {
  local diag=$1
  printf '%s\n' "$diag" >"$FX/c.err"
  (
    export STUB_STDERR_FILE=$FX/c.err STUB_EXIT=254
    snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/cls" s3api list-buckets || rc=$?
'"$REPORT"
  )
}

while IFS='|' read -r diag want loss; do
  [[ -n $diag ]] || continue
  t_case "classification: $want"
  got=$(classify "$diag")
  assert_contains "$got" "OUTCOME=$want" "'${diag:0:52}...' classifies as $want"
  assert_contains "$got" "LOSS=$loss" "$want is${loss/yes/} a coverage loss (LOSS=$loss)"
  assert_contains "$got" 'KNOWN=yes' "$want is in the frozen outcome vocabulary"
done <<'ROWS'
An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied|access_denied|yes
An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: You are not authorized|access_denied|yes
An error occurred (AccessDeniedException) when calling the ListKeys operation: denied|access_denied|yes
An error occurred (AuthFailure) when calling the DescribeInstances operation: credentials not validated|auth_failure|yes
An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: bad token|auth_failure|yes
An error occurred (ExpiredToken) when calling the ListBuckets operation: token expired|auth_failure|yes
An error occurred (OptInRequired) when calling the DescribeInstances operation: region not enabled|region_not_enabled|yes
An error occurred (ThrottlingException) when calling the ListRoles operation: Rate exceeded|throttled|yes
An error occurred (RequestLimitExceeded) when calling the DescribeInstances operation: slow down|throttled|yes
An error occurred (NoSuchBucketPolicy) when calling the GetBucketPolicy operation: The bucket policy does not exist|not_found|no
An error occurred (ResourceNotFoundException) when calling the DescribeKey operation: absent|not_found|no
An error occurred (UnsupportedOperation) when calling the DescribeInstances operation: not available here|unsupported|yes
An error occurred (SomeBrandNewErrorCode) when calling the ListThings operation: who knows|error|yes
Unable to locate credentials. You can configure credentials by running "aws configure".|no_credentials|yes
The config profile (staging) could not be found|no_credentials|yes
Could not connect to the endpoint URL: "https://ec2.ap-east-1.amazonaws.com/"|endpoint_unreachable|yes
aws: error: argument operation: Invalid choice: list-nothing|cli_usage|yes
ROWS

t_case 'a failed call returns 1, never the CLI raw status, which is outside the frozen 0-5 contract'
got=$(classify 'An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied')
assert_contains "$got" 'RC=1' \
  "aws_ro returns 1; a caller writing 'aws_ro ... || exit \$?' must not take the run outside tension 14's 0-5"
assert_contains "$got" 'STATUS=254' "the CLI's own status is preserved for anyone who wants it"

t_case 'a successful call is a coverage loss for nobody'
out=$(
  export STUB_STDOUT_FILE=$FX/buckets.json
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/okc" s3api list-buckets || rc=$?
'"$REPORT"
)
assert_contains "$out" 'OUTCOME=ok' 'a clean call is ok'
assert_contains "$out" 'LOSS=no' 'and owes no coverage_reduction'

t_case 'the reduction reason string is derived from the outcome, not re-invented per call site'
out=$(
  export STUB_STDERR_FILE=$FX/id-denied.err STUB_EXIT=254
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/rr" s3api list-buckets || rc=$?
aws_ro_reduction_reason_set reason
printf "REASON=%s\n" "$reason"'
)
assert_contains "$out" 'REASON=aws_api_access_denied' 'the coverage_reduction reason is machine-readable and names the class'

# The two naive readings, each pinned in the direction it fails.  Classifying
# on the whole stderr as a SUBSTRING is the obvious implementation and is wrong
# both ways round: the message quotes back caller-supplied resource names.
t_case 'the AWS error CODE decides, never a substring of the message'
got=$(classify "An error occurred (NoSuchBucket) when calling the GetBucketAcl operation: The specified bucket access-denied-logs does not exist")
assert_contains "$got" 'OUTCOME=not_found' \
  'a bucket NAMED access-denied-logs is still a not_found - a substring reader invents a coverage hole here'
assert_contains "$got" 'LOSS=no' 'and therefore owes no coverage_reduction'

got=$(classify "An error occurred (AccessDenied) when calling the GetBucketPolicy operation: no policy for NoSuchBucketPolicy-example")
assert_contains "$got" 'OUTCOME=access_denied' \
  'the mirror image: a resource name containing NoSuchBucketPolicy does not turn a real denial into an answer'
assert_contains "$got" 'LOSS=yes' 'the denial is still a coverage loss'

# ---------------------------------------------------------------------------
printf '\n-- truncation: a short list must not read as a complete one --\n'
# ---------------------------------------------------------------------------
trunc_case() {
  local body=$1
  printf '%s' "$body" >"$FX/t.json"
  (
    export STUB_STDOUT_FILE=$FX/t.json
    snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/tr" iam list-roles || rc=$?
'"$REPORT"
  )
}

t_case 'a continuation token makes the response truncated, and the call still succeeds'
got=$(trunc_case '{
    "Roles": [],
    "IsTruncated": true,
    "Marker": "",
    "NextToken": "AAAA-token"
}
')
assert_contains "$got" 'OUTCOME=truncated' 'the outcome names the incompleteness'
assert_contains "$got" 'TRUNC=1' 'the truncation flag is set'
assert_contains "$got" 'TOKEN=AAAA-token' 'the continuation token is available to the caller'
assert_contains "$got" 'RC=0' 'the call itself succeeded - the data is valid, just partial'
assert_contains "$got" 'LOSS=yes' 'a partial list is a coverage loss'

t_case 'a null NextToken is the LAST page, not a truncated one'
got=$(trunc_case '{
    "Roles": [],
    "NextToken": null
}
')
assert_contains "$got" 'OUTCOME=ok' \
  'AWS emits "NextToken": null on the final page; reading it as a token reports every complete list as partial'
assert_contains "$got" 'TRUNC=0' 'nothing is truncated'

t_case 'IsTruncated false is not truncation'
got=$(trunc_case '{
    "Roles": [],
    "IsTruncated": false
}
')
assert_contains "$got" 'OUTCOME=ok' 'the flag is read, not merely detected as present'

t_case 'IsTruncated true with no continuation token is still truncation'
got=$(trunc_case '{
    "Contents": [],
    "IsTruncated": true
}
')
assert_contains "$got" 'OUTCOME=truncated' 'S3 can say a listing is short without offering a marker'
assert_contains "$got" 'TOKEN=' 'and there is no token to resume with'

t_case 'a NextToken inside response CONTENT is content, not a continuation token'
got=$(trunc_case '{
    "PolicyNames": [
        "NextToken"
    ],
    "Statement": "{\"key\": \"NextToken\"}"
}
')
assert_contains "$got" 'OUTCOME=ok' \
  'a bare "NextToken" string element in an array has no colon after it and is not a key - a prefix-only test reads it as a token'
assert_contains "$got" 'TRUNC=0' 'and does not mark a complete response partial'

t_case 'a cached truncated response replays as truncated'
rm -rf "$SHARED"; mkdir -p "$SHARED"
printf '{\n    "Roles": [],\n    "NextToken": "BBBB"\n}\n' >"$FX/t2.json"
out=$(
  export SNIP_CACHE_DIR=$SHARED STUB_STDOUT_FILE=$FX/t2.json
  snip 'rc=0
aws_ro_into "$SCOURSH_SCRATCH/tc1" iam list-roles || rc=$?
rc=0
aws_ro_into "$SCOURSH_SCRATCH/tc2" iam list-roles || rc=$?
'"$REPORT"
)
assert_contains "$out" 'CACHED=1' 'the second call was a cache hit'
assert_contains "$out" 'OUTCOME=truncated' \
  'the cache must not launder a partial response into a complete-looking one'

# ---------------------------------------------------------------------------
printf '\n-- aws_ro_paged: following a continuation token, with a ceiling --\n'
# ---------------------------------------------------------------------------
t_case 'a two-page listing is walked to the end'
SEQ=$W/seq-pages
rm -rf "$SEQ"; mkdir -p "$SEQ"
printf '{\n    "Roles": [{"RoleName": "a"}],\n    "NextToken": "PAGE2"\n}\n' >"$SEQ/1.out"
printf '{\n    "Roles": [{"RoleName": "b"}]\n}\n' >"$SEQ/2.out"
calls_reset "$CALLS"
PAGES=$W/pages
rm -rf "$PAGES"
out=$(
  export STUB_SEQ_DIR=$SEQ STUB_COUNT_FILE=$CALLS
  snip 'rc=0
aws_ro_paged "'"$PAGES"'" --starting-token iam list-roles || rc=$?
'"$REPORT"
)
assert_contains "$out" 'RC=0' 'the walk succeeded'
assert_contains "$out" 'PAGES=2' 'two pages were fetched'
assert_contains "$out" 'OUTCOME=ok' 'a fully-walked listing is complete, not truncated'
assert_file_exists "$PAGES/page-0001.json" 'page 1 was written'
assert_file_exists "$PAGES/page-0002.json" 'page 2 was written'
assert_true "$(grep -qF 'ARG:PAGE2' "$STUB_LOG" && echo 0 || echo 1)" \
  "the second request carried page 1's token"
assert_true "$(grep -qF 'ARG:--starting-token' "$STUB_LOG" && echo 0 || echo 1)" \
  "the token flag is the caller's, because which flag resumes an operation is a fact about that operation"

t_case 'the page ceiling is a DECLARED truncation, never a silently short list'
SEQ=$W/seq-forever
rm -rf "$SEQ"; mkdir -p "$SEQ"
for i in 1 2 3 4 5 6; do
  printf '{\n    "Roles": [],\n    "NextToken": "MORE%s"\n}\n' "$i" >"$SEQ/$i.out"
done
rm -rf "$PAGES"
calls_reset "$CALLS"
out=$(
  export STUB_SEQ_DIR=$SEQ STUB_COUNT_FILE=$CALLS SCOURSH_AWS_MAX_PAGES=3
  snip 'rc=0
aws_ro_paged "'"$PAGES"'" --starting-token iam list-roles || rc=$?
'"$REPORT"
)
assert_contains "$out" 'RC=0' 'the walk returns success - the pages it did fetch are real'
assert_contains "$out" 'PAGES=3' 'it stopped at the ceiling'
assert_contains "$out" 'OUTCOME=truncated' 'and says so, so the caller records a coverage_reduction'
assert_contains "$out" 'LOSS=yes' 'a ceilinged walk is a coverage loss'

t_case 'a truncated response with no token ends the walk honestly rather than looping'
SEQ=$W/seq-notoken
rm -rf "$SEQ"; mkdir -p "$SEQ"
printf '{\n    "Contents": [],\n    "IsTruncated": true\n}\n' >"$SEQ/1.out"
rm -rf "$PAGES"
calls_reset "$CALLS"
out=$(
  export STUB_SEQ_DIR=$SEQ STUB_COUNT_FILE=$CALLS
  snip 'rc=0
aws_ro_paged "'"$PAGES"'" --continuation-token s3api list-objects-v2 --bucket b || rc=$?
'"$REPORT"
)
assert_contains "$out" 'PAGES=1' 'one page was fetched'
assert_contains "$out" 'OUTCOME=truncated' 'the shortfall is declared'
assert_eq 1 "$(calls_of "$CALLS")" \
  'it did not re-issue page 1 forever - with no token, resuming would repeat the same request'

t_case 'a failure part-way through a walk is reported as that failure, not as a short list'
SEQ=$W/seq-midfail
rm -rf "$SEQ"; mkdir -p "$SEQ"
printf '{\n    "Roles": [],\n    "NextToken": "P2"\n}\n' >"$SEQ/1.out"
printf 'An error occurred (AccessDenied) when calling the ListRoles operation: denied\n' >"$SEQ/2.err"
printf '254\n' >"$SEQ/2.rc"
rm -rf "$PAGES"
calls_reset "$CALLS"
out=$(
  export STUB_SEQ_DIR=$SEQ STUB_COUNT_FILE=$CALLS
  snip 'rc=0
aws_ro_paged "'"$PAGES"'" --starting-token iam list-roles || rc=$?
'"$REPORT"
)
assert_contains "$out" 'RC=1' 'the walk reports failure'
assert_contains "$out" 'OUTCOME=access_denied' \
  'and the reason survives the walk - a partial page set reported as ok is the whole defect this file exists to close'
assert_file_absent "$PAGES/page-0002.json" 'the failed page was not left behind as a half-written result'


t_summary awscli
