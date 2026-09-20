#!/usr/bin/env bash
# modules/cloud/aws/live/inspector.sh - the §8.1 Inspector2 read-only pass
# (docs/DESIGN.md §8.1's `inspector` row; docs/STEP6-CLOUD-PLAN.md CLOUD-33).
#
# A SERVICE SCRIPT, sourced once per enabled region (`inspector` is
# `regional` in modules/cloud/aws/engine.sh's `_CLOUD_SERVICES` table -
# Inspector2's account-status is genuinely a per-(account, region) fact).  No
# sourced-once guard, for the identical reason cloudtrail.sh's own header
# gives.  Its pure half is modules/cloud/aws/live/governance_engine.sh.
#
# THE FILENAME IS `inspector.sh` BUT THE AWS CLI SERVICE IS `inspector2` -
# transcribed verbatim from docs/STEP6-CLOUD-PLAN.md's own CLOUD-33 row and
# `_CLOUD_SERVICES`'s already-declared `live/inspector.sh:regional` entry.
# Every call below is spelled `inspector2`, literally, for the identical
# reason every call in this bundle is: tests/lint-aws-readonly.sh parses the
# operation text out of the source line.
#
# NO `cis:` VALUE IS AUTHORED ON THIS CHECK'S RECORD, for the identical
# reason guardduty.sh's own header states: CIS Amazon Web Services
# Foundations Benchmark v3.0.0 has no Inspector2 control, and
# modules/cloud/aws/live/checks.rules's header forbids inventing one.
#
# ONE CALL, NOT A LIST-THEN-GET PAIR, AND THAT IS A FACT ABOUT THE API, NOT A
# DEPARTURE FROM THIS BUNDLE'S SHAPE.  `batch-get-account-status` (its own
# `batch-get` prefix is in `SCOURSH_AWS_RO_PREFIXES`) answers, in one
# request with no arguments, whether Inspector2 scanning is enabled for the
# CALLING account in the CURRENT region, broken down by resource type (EC2,
# ECR, Lambda) - there is no list of "detectors" or "recorders" to walk
# first, because Inspector2's account-level enablement is not itself a
# collection of resources the way a GuardDuty detector or a Config recorder
# is.
#
# SCOPE: only the three resource types every Inspector2 account has carried
# since general availability - `ec2`, `ecr`, `lambda` - are read.  A later
# resource type Inspector2 adds (Lambda code scanning has its own nested
# key in newer API versions, for instance) is a stated, not a silent, gap:
# widening the set this check reads is a small, separate change rather than
# one folded in here under time pressure.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/governance_engine.sh
source "${BASH_SOURCE[0]%/*}/governance_engine.sh"

declare -g _INSP_ID=CLOUD-INSPECTOR-DISABLED-01
declare -ga _INSP_RESOURCE_TYPES=(ec2 ecr lambda)

_insp_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local id=$_INSP_ID

  if ! gov_selected "$id"; then
    run_record coverage_reduction "module=cloud reason=all_inspector_checks_deselected service=inspector2 account=$account region=$region - $id was removed by this run's check-selection filters, so no Inspector2 API call was made."
    return 0
  fi

  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-insp.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local f=$work/batch-get-account-status.json rc=0
  aws_ro inspector2 batch-get-account-status >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=inspector2 operation=batch-get-account-status account=$account region=$region - the account status could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so $id was not tested in this region."
    return 0
  fi

  gov_doc_load "$f" || true
  if ! gov_doc_has "$(gov_path accounts 0 accountId)"; then
    # `batch-get-account-status` with no `--account-ids` names the caller's
    # own account, so an empty `accounts` array here is a document shape
    # this pass did not expect (never observed against a real account) -
    # honestly reported as not tested rather than read as "clean".
    run_record coverage_reduction "module=cloud reason=unexpected_response_shape service=inspector2 check=$id account=$account region=$region - batch-get-account-status returned no entry for this account, so $id was not tested."
    return 0
  fi

  run_record checks_run "$id"

  local rtype status
  local -a off=()
  for rtype in "${_INSP_RESOURCE_TYPES[@]+"${_INSP_RESOURCE_TYPES[@]}"}"; do
    status=''
    gov_doc_get status "$(gov_path accounts 0 resourceState "$rtype" status)"
    [[ $status == ENABLED ]] || off+=("$rtype=${status:-UNKNOWN}")
  done

  (( ${#off[@]} > 0 )) || return 0

  local partition
  partition=$(gov_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")
  local joined
  joined=$(IFS=,; printf '%s' "${off[*]}")
  gov_emit_finding "$id" "$(gov_account_root_arn "$partition" "$account")" '' \
    "Amazon Inspector2 is not fully enabled for account $account in region $region: $joined. No automated vulnerability scan is running for the affected resource type(s), so a newly-disclosed CVE against an in-use EC2 AMI, ECR image, or Lambda function's dependencies is not detected until something else finds it. Enable Inspector2 scanning for every resource type this account actually uses."
  return 0
}

_insp_run_service
