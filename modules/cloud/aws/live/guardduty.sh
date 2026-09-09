#!/usr/bin/env bash
# modules/cloud/aws/live/guardduty.sh - the §8.1 GuardDuty read-only pass
# (docs/DESIGN.md §8.1's `guardduty` row; docs/STEP6-CLOUD-PLAN.md CLOUD-32).
#
# A SERVICE SCRIPT, sourced once per enabled region (`guardduty` is
# `regional` in modules/cloud/aws/engine.sh's `_CLOUD_SERVICES` table - a
# GuardDuty detector is genuinely a per-(account, region) object).  No
# sourced-once guard, for the identical reason cloudtrail.sh's own header
# gives.  Its pure half is modules/cloud/aws/live/governance_engine.sh.
#
# NO `cis:` VALUE IS AUTHORED ON THIS CHECK'S RECORD, AND THAT IS DELIBERATE.
# CIS Amazon Web Services Foundations Benchmark v3.0.0 (data/cis-mappings'
# own scope, per its header) has no GuardDuty control anywhere in its
# sections 1-5 - section 4 (the CloudWatch metric-filter/alarm controls) is
# the closest thing to a detection-service section and does not name it
# either.  modules/cloud/aws/live/checks.rules's own header states the rule
# this follows: `cis` is authored only where a real control exists, and
# inventing one to satisfy a "must cite CIS" habit is the overstated-coverage
# failure docs/DESIGN.md §15 forbids.
#
# THE MULTI-CALL SHAPE IS list-detectors THEN, PER DETECTOR, get-detector -
# the identical "list, then per-resource get" pattern s3.sh's own
# get-bucket-location established, applied to GuardDuty's own two-call
# design: `list-detectors` names only IDs, and only `get-detector` reveals
# whether a given detector is actually `Status: ENABLED`.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/governance_engine.sh
source "${BASH_SOURCE[0]%/*}/governance_engine.sh"

declare -g _GD_ID=CLOUD-GUARDDUTY-DISABLED-01

_gd_detector_arn() {
  printf 'arn:%s:guardduty:%s:%s:detector/%s' "$1" "$2" "$3" "$4"
}

_gd_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local id=$_GD_ID

  if ! gov_selected "$id"; then
    run_record coverage_reduction "module=cloud reason=all_guardduty_checks_deselected service=guardduty account=$account region=$region - $id was removed by this run's check-selection filters, so no GuardDuty API call was made."
    return 0
  fi

  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-gd.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local listf=$work/list-detectors.json rc=0
  aws_ro guardduty list-detectors >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=guardduty operation=list-detectors account=$account region=$region - the detector list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so $id was not tested in this region."
    return 0
  fi

  gov_doc_load "$listf" || true
  local partition
  partition=$(gov_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  if ! gov_doc_has "$(gov_path DetectorIds 0)"; then
    run_record checks_run "$id"
    gov_emit_finding "$id" "$(gov_account_root_arn "$partition" "$account")" '' \
      "GuardDuty has no detector at all in region $region of account $account (list-detectors returned an empty list), so no threat-detection findings are being generated for this region's CloudTrail management events, VPC Flow Logs, or DNS query logs. Enable GuardDuty in this region."
    return 0
  fi

  local i=0 detid='' any=0 f
  while :; do
    gov_doc_has "$(gov_path DetectorIds "$i")" || break
    gov_doc_get detid "$(gov_path DetectorIds "$i")"
    i=$(( i + 1 ))
    [[ -n $detid ]] || continue
    _gd_check_detector "$work" "$partition" "$account" "$region" "$detid"
    any=1
  done

  (( any )) && run_record checks_run "$id"
  return 0
}

_gd_check_detector() {
  local work=$1 partition=$2 account=$3 region=$4 detid=$5
  local id=$_GD_ID
  local safe=${detid//[^A-Za-z0-9._-]/_}
  local f=$work/get-detector.$safe.json rc=0 status=''
  aws_ro guardduty get-detector --detector-id "$detid" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=guardduty operation=get-detector detector=$detid account=$account region=$region - the detector's status could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so $id was not tested for it."
    return 0
  fi
  gov_doc_load "$f" || true
  gov_doc_get status Status
  [[ $status == ENABLED ]] && return 0
  gov_emit_finding "$id" "$(_gd_detector_arn "$partition" "$region" "$account" "$detid")" '' \
    "GuardDuty detector $detid in region $region of account $account exists but is not enabled (get-detector reports Status $status), so it generates no threat-detection findings while in this state, exactly as if it did not exist. Enable the detector, and alert on this state in future so a disabled detector is noticed quickly."
  return 0
}

_gd_run_service
