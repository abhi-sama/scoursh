#!/usr/bin/env bash
# lib/awscli.sh - the single AWS API chokepoint.
#
# Owns:
#   docs/DESIGN.md      §8 (Module - Cloud / AWS, live + IaC)
#   docs/FOUNDATION.md  tension 23 (a read-only AWS lint that survives contact
#     with reality)
#
# Every AWS call scoursh ever makes goes through aws_ro().  It is what
# lib/http.sh (§13 step 3) is for outbound HTTP: one enforcement chokepoint,
# checked at RUNTIME so the read-only guarantee holds even if the lint that
# also checks it is wrong - tension 23's stated reason for choosing this shape
# over a smarter grep.
#
# tests/lint-aws-readonly.sh skips this file by name: it is the one place a
# bare `aws` invocation is legitimate, because it is the only place one exists.
#
# STATUS: docs/DESIGN.md §13 places lib/awscli.sh and modules/cloud/aws/live/
# at the start of step 6.  This file lands ahead of that as the credential-less
# half of the AWS module - the chokepoint, its runtime enforcement, and the
# test infrastructure that exercises it - while step 2 (scan.sh) is still the
# next item on the critical path.  See AGENTS.md, "AWS module: what exists
# ahead of step 6". No live/ script exists yet, so aws_ro has no shipped caller
# today; it is exercised by tests/suites/awscli.sh (a stub `aws`, no network)
# and tools/localstack-run.sh (a real emulator, still not an AWS account).
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_AWSCLI_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_AWSCLI_SOURCED=1

# shellcheck source=lib/core.sh
source "${BASH_SOURCE[0]%/*}/core.sh"

# ---------------------------------------------------------------------------
# 1. Configuration
# ---------------------------------------------------------------------------
: "${SCOURSH_AWSCLI_BIN:=aws}"
# tests/aws-readonly-allow.txt is scoursh's own exception list (tension 23 item
# 4), resolved against the install root like every other shipped file
# (tension 26) - never against the scan root, which is a property of the tree
# being scanned and has nothing to do with it.
: "${SCOURSH_AWSCLI_ALLOWLIST:=$SCOURSH_INSTALL_ROOT/tests/aws-readonly-allow.txt}"

# The frozen read-only prefix allowlist, byte-identical to tension 23's
# RESOLUTION and to tests/lint-aws-readonly.sh's copy. Kept in one place would
# be nicer, but the lint must be able to check invocations without executing
# this file (it inspects source text), so the two are independently frozen and
# a discrepancy between them is exactly what the lint's own tests pin.
readonly SCOURSH_AWS_RO_PREFIXES='^(describe|list|get|search|lookup|select|head|batch-get|preview|estimate|simulate)(-|$)'

SCOURSH_AWSCLI_CAP=''    # '' = not probed yet; present | absent thereafter
SCOURSH_AWSCLI_MAJOR=''  # '' = not probed yet; 1 | 2 | unknown thereafter

# Probed once per process, mirroring the tension 24 capability layer's shape
# (probe once, cache, record). Not folded into that layer itself: `aws` is
# module-specific, not a portability primitive every file needs.
_awscli_probe() {
  [[ -n $SCOURSH_AWSCLI_CAP ]] && return 0
  if _have "$SCOURSH_AWSCLI_BIN"; then
    SCOURSH_AWSCLI_CAP=present
    local v=''
    v=$("$SCOURSH_AWSCLI_BIN" --version 2>&1) || true
    case $v in
      aws-cli/1.*) SCOURSH_AWSCLI_MAJOR=1 ;;
      aws-cli/2.*) SCOURSH_AWSCLI_MAJOR=2 ;;
      *) SCOURSH_AWSCLI_MAJOR=unknown ;;
    esac
  else
    SCOURSH_AWSCLI_CAP=absent
    SCOURSH_AWSCLI_MAJOR=unknown
  fi
  # run_record no-ops with no run directory (e.g. under the test suite), so
  # this is safe to call unconditionally. Finding F17's second half: record the
  # detected major version regardless of which branch below is taken.
  run_record aws_cli_major "$SCOURSH_AWSCLI_MAJOR"
}

# `awscli_allowlisted SERVICE OPERATION` - true only for an exact, uncommented
# "service operation" pair in SCOURSH_AWSCLI_ALLOWLIST. tests/lint-aws-readonly.sh
# parses the same file with the same exactness (whole-token match, `#` strips
# a trailing comment), so the two can never authorise different sets.
awscli_allowlisted() {
  local svc=$1 op=$2
  [[ -f $SCOURSH_AWSCLI_ALLOWLIST ]] || return 1
  scan_match "$SCOURSH_SCRATCH/awscli-allow-hit" \
    -e "^${svc}[[:space:]]+${op}([[:space:]]|\$)" -- "$SCOURSH_AWSCLI_ALLOWLIST"
}

# `aws_ro SERVICE OPERATION [ARGS...]` - the single chokepoint (tension 23).
#
# A non-read operation aborts with exit 3 (SCOURSH_EXIT_SCOPE), the same class
# as an out-of-scope HTTP host: the tool attempting something it is not
# authorised to do.  This is the guarantee that survives a typo, a
# dynamically-constructed operation name, and a broken lint - tension 23's
# stated reason runtime enforcement backs the lint rather than replacing it.
aws_ro() {
  (( $# >= 2 )) || die "$SCOURSH_EXIT_INPUT" "aws_ro requires SERVICE and OPERATION, got: $*"
  local svc=$1 op=$2
  shift 2
  _awscli_probe
  [[ $SCOURSH_AWSCLI_CAP == present ]] \
    || die "$SCOURSH_EXIT_INPUT" "aws_ro: '$SCOURSH_AWSCLI_BIN' is not installed"

  # tension 23 item 5: --cli-input-json/--cli-input-yaml would let a call's real
  # shape come from somewhere the lint never sees, so they are refused outright
  # rather than merely un-pinned.  --output is refused too, so the pin below
  # can never be silently overridden by a caller argument that appears first.
  local a=''
  for a in "$@"; do
    case $a in
      --cli-input-json | --cli-input-json=* | --cli-input-yaml | --cli-input-yaml=*)
        die "$SCOURSH_EXIT_SCOPE" \
          "aws_ro: '$svc $op' passes --cli-input-json/--cli-input-yaml, which the read-only lint cannot inspect"
        ;;
      --output | --output=*)
        die "$SCOURSH_EXIT_SCOPE" "aws_ro: '$svc $op' attempts to override the pinned --output json"
        ;;
    esac
  done

  if [[ ! $op =~ $SCOURSH_AWS_RO_PREFIXES ]] && ! awscli_allowlisted "$svc" "$op"; then
    die "$SCOURSH_EXIT_SCOPE" \
      "aws_ro: '$svc $op' is not a read-only operation and is not in $SCOURSH_AWSCLI_ALLOWLIST"
  fi

  # AWS_PAGER='' rather than --no-cli-pager (finding F17): the flag is CLI
  # v2-only and a v1 host rejects it at argument parsing before the call is
  # even attempted, so every AWS call would fail while reporting a tool error
  # rather than a finding.  The environment variable is honoured by both major
  # versions and needs no version detection to use safely.
  AWS_PAGER='' "$SCOURSH_AWSCLI_BIN" "$svc" "$op" "$@" --output json
}
