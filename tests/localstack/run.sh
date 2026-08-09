#!/usr/bin/env bash
# tests/localstack/run.sh - the LocalStack integration path for lib/awscli.sh.
#
# LocalStack is a TEST dependency ONLY.  It is never started, never contacted,
# and never referenced by anything scan.sh (§13 step 2) or any module will do
# at scan time - none of lib/, modules/, config/, rules/, or data/ imports,
# sources, or shells out to anything LocalStack-specific; this script and its
# own doc comments are the only place the word appears in a functional sense.
# This script exists because
# tests/suites/awscli.sh and tests/suites/aws-fixtures.sh prove aws_ro's OWN
# logic against a stub `aws` that never leaves the process; what they cannot
# prove is that aws_ro's calls are shaped the way a real AWS API expects, or
# that the read-only guard survives contact with a real (if emulated)
# endpoint rather than a script that agrees with the test by construction.
# LocalStack closes that gap without an AWS account, without anything
# billable, and without touching a real API.
#
# It brings up LocalStack, seeds one S3 bucket through the real `aws` CLI
# directly (bucket creation is a mutating call, so it deliberately does NOT go
# through aws_ro - that would defeat the very guarantee being tested), then
# exercises aws_ro against the running instance: two read calls that must
# return the seeded bucket's real API shape, and one mutating call that must
# be refused before it ever reaches the endpoint.  It tears LocalStack down
# whether or not any of that succeeded.
#
# Usage:
#   tests/localstack/run.sh [up|verify|down|all]
#   (default: all - up, verify, down, in order)
#
# Requires: docker, and a real `aws` CLI on PATH (v1 or v2 - this path is
# also finding F17's real-world proof: a genuine AWS CLI v1 install is used
# in review, and --no-cli-pager fails argument parsing on it exactly as the
# finding describes, while aws_ro's AWS_PAGER='' does not).  Neither is
# required to run scoursh itself, or to run tests/run-tests.sh - see
# AGENTS.md, "AWS module: what exists ahead of step 6".
#
# shellcheck shell=bash

set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
# shellcheck source=lib/core.sh
source "$ROOT/lib/core.sh"
# shellcheck source=lib/awscli.sh
source "$ROOT/lib/awscli.sh"

: "${LOCALSTACK_IMAGE:=localstack/localstack:3}"
: "${LOCALSTACK_PORT:=4566}"
# A fixed name, not one keyed on $$: `up` and `down` are meant to be run as
# separate invocations for interactive debugging ("bring it up, poke at it,
# tear it down"), which only works if they agree on which container that is.
# One consequence, accepted on purpose: two concurrent runs collide - the same
# constraint the fixed default port already imposes.
CONTAINER=scoursh-localstack-test
ENDPOINT="http://localhost:$LOCALSTACK_PORT"
BUCKET=scoursh-localstack-fixture

# The real `aws` CLI, used only for TEST SETUP (seeding LocalStack) and for
# checking LocalStack's own health endpoint - never for anything aws_ro is
# meant to gate.  Fake, fixed credentials: LocalStack does not check them, and
# a real credential must never be needed to run a test.
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_PAGER=''

check_prereqs() {
  require_cmd docker curl
  _have aws || die "$SCOURSH_EXIT_INPUT" \
    "tests/localstack/run.sh needs a real 'aws' CLI on PATH (v1 or v2; e.g. 'pip install --user awscli' or 'brew install awscli'). It is a TEST dependency only - scoursh itself never requires it."
}

localstack_up() {
  log_info "starting LocalStack ($LOCALSTACK_IMAGE) as $CONTAINER on port $LOCALSTACK_PORT"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" -p "$LOCALSTACK_PORT:4566" \
    -e SERVICES=s3 -e DEBUG=0 "$LOCALSTACK_IMAGE" >/dev/null

  local tries=0
  while (( tries < 60 )); do
    if [[ $(curl -s -o /dev/null -w '%{http_code}' "$ENDPOINT/_localstack/health" 2>/dev/null) == 200 ]]; then
      log_info "LocalStack is healthy"
      return 0
    fi
    tries=$(( tries + 1 ))
    sleep 1
  done
  die "$SCOURSH_EXIT_INCOMPLETE" "LocalStack did not become healthy within 60s"
}

localstack_seed() {
  log_info "seeding s3://$BUCKET (via the real aws CLI directly - NOT aws_ro; creating a bucket is mutating on purpose)"
  aws --endpoint-url "$ENDPOINT" s3 mb "s3://$BUCKET" >/dev/null
}

localstack_down() {
  log_info "tearing down $CONTAINER"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

# Combines core_cleanup (scratch-dir erasure, tension 4 rule 5) with the
# LocalStack teardown, and REPLACES rather than chains lib/core.sh's own EXIT
# trap - a second `trap ... EXIT` call always replaces the first in bash, so
# calling core_cleanup explicitly here is what keeps that guarantee, not an
# accident of ordering.
_cleanup_all() {
  local status=$?
  localstack_down
  core_cleanup
  return "$status"
}

verify_against_localstack() {
  log_info "aws_ro s3api list-buckets"
  local list
  list=$(aws_ro s3api list-buckets --endpoint-url "$ENDPOINT")
  [[ $list == *"\"$BUCKET\""* ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" "aws_ro s3api list-buckets did not return the seeded bucket:"$'\n'"$list"
  log_info "  ok - the seeded bucket is present in a real API-shaped response"

  log_info "aws_ro s3api get-bucket-acl"
  local acl
  acl=$(aws_ro s3api get-bucket-acl --bucket "$BUCKET" --endpoint-url "$ENDPOINT")
  [[ $acl == *'"Owner"'* && $acl == *'"Grants"'* ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" "aws_ro s3api get-bucket-acl did not return the expected shape:"$'\n'"$acl"
  log_info "  ok - Owner/Grants are present, the same shape tests/fixtures/aws/ example-s3-public-read-acl fixtures use"

  log_info "aws_ro s3api create-bucket (must be refused BEFORE it reaches LocalStack)"
  # aws_ro's failure path is die(), which calls exit - not return - so calling
  # it directly here would terminate this whole script rather than yield a
  # checkable status.  Run it in a subshell, exactly as
  # tests/suites/awscli.sh does for every refusal it asserts.
  local rc=0
  ( aws_ro s3api create-bucket --bucket scoursh-should-never-exist --endpoint-url "$ENDPOINT" ) \
    >/dev/null 2>&1 || rc=$?
  [[ $rc == 3 ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" "aws_ro s3api create-bucket was not refused with exit 3 (got $rc) - the read-only guard did not hold against a live endpoint"
  log_info "  ok - refused with exit 3, before any request left the process"

  local buckets_after
  buckets_after=$(aws --endpoint-url "$ENDPOINT" s3api list-buckets --output json)
  [[ $buckets_after != *'"scoursh-should-never-exist"'* ]] \
    || die "$SCOURSH_EXIT_INCOMPLETE" "the refused create-bucket call somehow still created a bucket - the guard is not load-bearing"
  log_info "  ok - confirmed independently: no bucket named scoursh-should-never-exist exists"
}

cmd=${1:-all}
case $cmd in
  up)
    check_prereqs
    localstack_up
    localstack_seed
    log_info "LocalStack is up at $ENDPOINT (container $CONTAINER). Run 'tests/localstack/run.sh down' when finished."
    ;;
  verify)
    verify_against_localstack
    ;;
  down)
    localstack_down
    ;;
  all)
    check_prereqs
    trap _cleanup_all EXIT
    localstack_up
    localstack_seed
    verify_against_localstack
    log_info "tests/localstack/run.sh: all checks passed"
    ;;
  *)
    printf 'usage: tests/localstack/run.sh [up|verify|down|all]\n' >&2
    exit "$SCOURSH_EXIT_USAGE"
    ;;
esac
