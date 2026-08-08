#!/usr/bin/env bash
# tests/suites/aws-fixtures.sh - the fixture harness for AWS posture checks
# (tests/lib/aws-fixtures.sh; docs/DESIGN.md §8.1).
#
# No real check exists yet - modules/cloud/aws lands at §13 step 6, and this
# credential-less pass is explicitly scoped not to add any of it.  What is
# proven here is the MECHANISM: a stub `aws` binary serves a recorded/synthetic
# response, a check calls aws_ro exactly as it would against a real account,
# and lib/findings.sh's real finding_new/finding_set/finding_get carries the
# result - known-bad flags, known-good does not, offline, no network, no
# LocalStack.  _example_check_s3_public_read_acl below is a REFERENCE, not a
# shipped check; see tests/fixtures/aws/README.md.
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
# shellcheck source=lib/findings.sh
source "$ROOT/lib/findings.sh"
# shellcheck source=tests/lib/assert.sh
source "$ROOT/tests/lib/assert.sh"
# shellcheck source=tests/lib/aws-fixtures.sh
source "$ROOT/tests/lib/aws-fixtures.sh"

W=$SCOURSH_SCRATCH/aws-fixtures
aws_fixture_stub_install "$W/bin"
export PATH="$W/bin:$PATH"
export AWS_FIXTURE_RESPONSE=''

# --- the reference check (template only; see tests/fixtures/aws/README.md) --
#
# Flags an S3 bucket ACL that grants any permission to the well-known
# AllUsers group URI.  A plain substring test rather than real JSON parsing,
# because no JSON accessor exists in the repository yet (nothing has needed
# one) - that is a real open question for whichever step-6 check lands first,
# not something this harness should quietly decide by inventing one here.  What
# this function demonstrates is the SHAPE a real check takes: call aws_ro,
# inspect the body, build the finding through the real data model.
_example_check_s3_public_read_acl() {
  local bucket=$1 body
  body=$(aws_ro s3api get-bucket-acl --bucket "$bucket")
  finding_new
  if [[ $body == *'"URI": "http://acs.amazonaws.com/groups/global/AllUsers"'* ]]; then
    finding_set check_id EXAMPLE-S3-PUBLIC-READ-ACL
    finding_set module cloud
    finding_set title 'S3 bucket ACL grants access to the AllUsers group'
    finding_set base_severity high
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
printf '\n-- the harness: known-bad flags, known-good does not, fully offline --\n'
# ---------------------------------------------------------------------------
t_case 'a bucket ACL granting AllUsers is flagged'
AWS_FIXTURE_RESPONSE=$(aws_fixture_path example-s3-public-read-acl bad)
if _example_check_s3_public_read_acl demo-bucket; then
  assert_eq EXAMPLE-S3-PUBLIC-READ-ACL "$(finding_get check_id)" \
    'the finding carries the check_id the reference check sets'
  assert_eq cloud "$(finding_get module)" 'the finding carries the expected module'
  assert_eq high "$(finding_get base_severity)" 'the finding carries the expected severity'
else
  _t_no 'known-bad fixture must be flagged' 'the check returned "not flagged"'
fi

t_case 'the identical bucket with a private ACL is not flagged'
AWS_FIXTURE_RESPONSE=$(aws_fixture_path example-s3-public-read-acl good)
rc=0
_example_check_s3_public_read_acl demo-bucket || rc=$?
assert_eq 1 "$rc" 'known-good fixture produces no finding'

t_case 'the two fixtures actually differ (a check that ignored its input would still pass the suite otherwise)'
bad_body=$(cat "$(aws_fixture_path example-s3-public-read-acl bad)")
good_body=$(cat "$(aws_fixture_path example-s3-public-read-acl good)")
assert_ne "$bad_body" "$good_body" 'good.json and bad.json are not byte-identical'

t_summary aws-fixtures
