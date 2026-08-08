#!/usr/bin/env bash
# tests/lib/aws-fixtures.sh - the fixture harness for AWS posture checks
# (docs/DESIGN.md §8.1's read-only check catalog, docs/FOUNDATION.md
# tension 23's chokepoint).
#
# The catalog at §8.1 is large and none of it is built yet - modules/cloud/aws
# lands at §13 step 6, and this credential-less pass is explicitly scoped not
# to add any of it (see AGENTS.md, "AWS module: what exists ahead of step 6").
# What this file gives step 6 instead is the PATTERN every check will test
# against: record a real (or hand-written, CIS-shaped) AWS API response once,
# replay it through a stub `aws` binary, and assert the check's finding
# output - known-bad flags, known-good does not - with no network, no
# account, and no dependency on LocalStack having every service implemented.
#
# tests/suites/aws-fixtures.sh exercises this harness against ONE reference
# check, `_example_check_s3_public_read_acl`, defined in that suite file, not
# here and not under modules/ - it is a template proving the mechanism works,
# not a shipped check, and tests/lint-aws-readonly.sh does not even look at
# it, since it never scans tests/.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_AWS_FIXTURES_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_AWS_FIXTURES_SOURCED=1

# `aws_fixture_stub_install BINDIR` - writes a stub `aws` into
# BINDIR/aws that serves whatever file $AWS_FIXTURE_RESPONSE names, as the
# raw --output json body, for any call other than `--version`.  The stub does
# not inspect service/operation/args: one fixture file is one canned response,
# which is all a single-call posture check needs, and keeps the harness itself
# free of any AWS-shaped parsing.
aws_fixture_stub_install() {
  local bindir=$1
  mkdir -p "$bindir"
  cat >"$bindir/aws" <<'STUB'
#!/usr/bin/env bash
if [[ ${1:-} == --version ]]; then
  printf 'aws-cli/2.15.0 Python/3.11.6 Linux/6.1.0 exe/x86_64.fixture\n'
  exit 0
fi
if [[ -z ${AWS_FIXTURE_RESPONSE:-} || ! -r $AWS_FIXTURE_RESPONSE ]]; then
  printf 'aws-fixture-stub: AWS_FIXTURE_RESPONSE is unset or unreadable (wanted %s)\n' \
    "${AWS_FIXTURE_RESPONSE:-<unset>}" >&2
  exit 254
fi
cat -- "$AWS_FIXTURE_RESPONSE"
STUB
  chmod +x "$bindir/aws"
}

# `aws_fixture_path CHECK_ID KIND` - tests/fixtures/aws/<check-id>/<kind>.json,
# the documented location for a check's fixtures (KIND is `good` or `bad`;
# see tests/fixtures/aws/README.md).  Resolved against the install root
# (tension 26), never the scan root, since fixtures ship with scoursh itself.
aws_fixture_path() {
  printf '%s/tests/fixtures/aws/%s/%s.json' "$SCOURSH_INSTALL_ROOT" "$1" "$2"
}
