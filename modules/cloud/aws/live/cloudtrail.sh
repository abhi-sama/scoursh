#!/usr/bin/env bash
# modules/cloud/aws/live/cloudtrail.sh - the §8.1 CloudTrail read-only pass
# (docs/DESIGN.md §8.1's `cloudtrail` row; docs/STEP6-CLOUD-PLAN.md CLOUD-30).
#
# THIS IS A SERVICE SCRIPT, reached by `cloud_run_service`'s plain `source`,
# exactly as modules/cloud/aws/live/s3.sh's own header describes.  It carries
# NO sourced-once guard: `cloudtrail` is a `regional` row in
# modules/cloud/aws/engine.sh's `_CLOUD_SERVICES` table, so this file is
# legitimately sourced once PER ENABLED REGION, and a guard would silently
# turn every region after the first into a no-op - the failure that reads as
# a complete multi-region audit.  Its pure half is
# modules/cloud/aws/live/governance_engine.sh (shared with the other four
# governance/detection services; see that file's header for why one shared
# engine rather than five).
#
# WHY THIS IS A `regional` ROW EVEN THOUGH A TRAIL IS AN ACCOUNT-WIDE
# RESOURCE.  A CloudTrail trail has exactly one `HomeRegion`, and
# `describe-trails` called from region R returns every trail HOMED in R plus
# a SHADOW COPY of every MULTI-REGION trail homed anywhere else (the CLI's
# default `--include-shadow-trails true`).  That shadowing is what this
# script relies on for two distinct facts, at two distinct filtering rules:
#
#   1. A trail is only EXAMINED for NOT_MULTI_REGION and
#      LOG_FILE_VALIDATION_OFF in the pass whose region equals its OWN
#      `HomeRegion`.  Every other region sees only a shadow of it and skips
#      it, so a multi-region trail is judged exactly once rather than once
#      per enabled region - the identical "own the pass whose cell you land
#      in" discipline s3.sh's own header states for why the bucket's real
#      region belongs in `loc_region` and not in the cell.
#   2. A COMPLETELY EMPTY `trailList` in ANY SINGLE region's response is
#      sufficient evidence that the ACCOUNT HAS NO TRAIL AT ALL, anywhere -
#      because if one existed and were multi-region it would shadow into
#      this region too, and if it existed and were single-region it would
#      still be a non-empty list entry visible from ITS OWN home region's
#      pass (which is a different pass, but this one's own emptiness is
#      still real evidence about what THIS region can see: nothing, home or
#      shadowed). NOT_ENABLED-01's "no trail visible from here" branch fires
#      on exactly that emptiness, citing the account itself
#      (`gov_account_root_arn`) rather than a trail that does not exist.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23),
# spelled literally with a literal service and operation at each call site -
# never through a wrapper taking the operation in a variable, for the reason
# s3.sh's own header states at length: tests/lint-aws-readonly.sh parses the
# operation text out of the source line.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/governance_engine.sh
source "${BASH_SOURCE[0]%/*}/governance_engine.sh"

# `declare -g`, reset on every pass (this file is re-sourced once per
# region), exactly as s3.sh's own per-pass state is.
declare -g _CT_LIST_EMPTY=0
declare -gA _CT_EVALUATED=()
declare -gA _CT_LOST=()
declare -gA _CT_LOST_REASON=()

declare -ga _CT_CHECK_IDS=(
  CLOUD-CLOUDTRAIL-NOT_ENABLED-01
  CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01
  CLOUD-CLOUDTRAIL-LOG_FILE_VALIDATION_OFF-01
)

_ct_note_evaluated() {
  _CT_EVALUATED[$1]=$(( ${_CT_EVALUATED[$1]:-0} + 1 ))
}

_ct_note_lost() {
  _CT_LOST[$1]=$(( ${_CT_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, s3.sh's own rule: the earliest failure is the most
  # actionable one and the one that explains the rest.
  [[ -n ${_CT_LOST_REASON[$1]:-} ]] || _CT_LOST_REASON[$1]=$2
}

_ct_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}

  local id selected=0
  for id in "${_CT_CHECK_IDS[@]+"${_CT_CHECK_IDS[@]}"}"; do
    gov_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_cloudtrail_checks_deselected service=cloudtrail account=$account region=$region - every CLOUD-CLOUDTRAIL-* check id was removed by this run's check-selection filters, so no CloudTrail API call was made."
    return 0
  fi

  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-ct.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local listf=$work/describe-trails.json rc=0
  aws_ro cloudtrail describe-trails >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    for id in "${_CT_CHECK_IDS[@]+"${_CT_CHECK_IDS[@]}"}"; do
      _ct_note_lost "$id" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=cloudtrail operation=describe-trails account=$account region=$region - the trail list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so none of the ${#_CT_CHECK_IDS[@]} CLOUD-CLOUDTRAIL-* checks ran in this region."
    _ct_record_coverage "$account" "$region"
    return 0
  fi

  gov_doc_load "$listf" || true
  local i=0 arn='' home='' multi='' logval=''
  local -a homed_arns=()
  local partition
  partition=$(gov_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  gov_doc_has "$(gov_path trailList 0 TrailARN)" || _CT_LIST_EMPTY=1

  while :; do
    gov_doc_has "$(gov_path trailList "$i" TrailARN)" || break
    gov_doc_get arn "$(gov_path trailList "$i" TrailARN)"
    gov_doc_get home "$(gov_path trailList "$i" HomeRegion)"
    gov_doc_get multi "$(gov_path trailList "$i" IsMultiRegionTrail)"
    gov_doc_get logval "$(gov_path trailList "$i" LogFileValidationEnabled)"
    i=$(( i + 1 ))
    # A shadow copy of a trail homed elsewhere: this pass is not the owner
    # and skips it entirely - it will be judged once, in its own home
    # region's pass.
    [[ $home == "$region" ]] || continue
    homed_arns+=("$arn")
    _ct_check_multi_region "$arn" "$multi"
    _ct_check_log_validation "$arn" "$logval"
  done

  if (( ${#homed_arns[@]} == 0 )); then
    # Nothing homed in this region - whether because trailList was globally
    # EMPTY (in which case this is always true too, since the walk above
    # never runs) or because it carried only shadow copies of trails homed
    # elsewhere.  ALL THREE checks are a VACUOUS pass over an empty set of
    # this-region-owned trails here, not a coverage loss - exactly the
    # reasoning s3.sh's own "buckets=0" branch states: the pass genuinely
    # looked and there was nothing home here to examine, and that is a real
    # answer, not a failure to look.  NOT_ENABLED-01 is no different from its
    # two siblings in this regard - get-trail-status has nothing to call
    # against when there is no home-owned trail - and marking only the other
    # two vacuously evaluated would leave NOT_ENABLED-01 misreported as a
    # coverage loss in the shadow-only case (a real gap this file shipped
    # with once and corrected in the same change).
    _ct_note_evaluated CLOUD-CLOUDTRAIL-NOT_ENABLED-01
    _ct_note_evaluated CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01
    _ct_note_evaluated CLOUD-CLOUDTRAIL-LOG_FILE_VALIDATION_OFF-01
    run_record notes "module=cloud service=cloudtrail account=$account region=$region trails_homed=0 - no trail is homed in this region, so all three CLOUD-CLOUDTRAIL-* checks are covered vacuously here."
  fi

  if (( _CT_LIST_EMPTY )); then
    # No entry at all, home or shadow: per this file's own header, that is
    # sufficient evidence the account has NO CloudTrail trail anywhere.
    if gov_selected CLOUD-CLOUDTRAIL-NOT_ENABLED-01; then
      gov_emit_finding CLOUD-CLOUDTRAIL-NOT_ENABLED-01 \
        "$(gov_account_root_arn "$partition" "$account")" '' \
        "No CloudTrail trail exists in account $account, observed from region $region (describe-trails returned an empty trail list, and a multi-region trail homed in any other region would still have shadowed into this response). There is no audit record of API activity in this account at all."
    fi
  else
    _ct_check_logging_status "$work" "${homed_arns[@]+"${homed_arns[@]}"}"
  fi

  _ct_record_coverage "$account" "$region"
  return 0
}

_ct_check_multi_region() {
  local arn=$1 multi=$2
  local id=CLOUD-CLOUDTRAIL-NOT_MULTI_REGION-01
  gov_selected "$id" || return 0
  _ct_note_evaluated "$id"
  [[ $multi == true ]] && return 0
  gov_emit_finding "$id" "$arn" '' \
    "CloudTrail trail $arn is not a multi-region trail (IsMultiRegionTrail is false), so it records API activity only in its own home region and nothing at all in every other region of this account. CIS 3.1 requires at least one enabled, logging, multi-region trail before an account can be said to have CloudTrail coverage."
}

_ct_check_log_validation() {
  local arn=$1 logval=$2
  local id=CLOUD-CLOUDTRAIL-LOG_FILE_VALIDATION_OFF-01
  gov_selected "$id" || return 0
  _ct_note_evaluated "$id"
  [[ $logval == true ]] && return 0
  gov_emit_finding "$id" "$arn" '' \
    "Log file validation is not enabled on CloudTrail trail $arn (LogFileValidationEnabled is false), so a delivered log file can be modified or deleted after the fact with no cryptographic means to detect the tampering. Enable log file validation so each delivered log file's digest is signed and can be verified independently."
}

# `_ct_check_logging_status WORKDIR ARN...` - the per-trail get-trail-status
# call, over every trail this pass owns (its own HomeRegion).  A second call
# per trail, exactly the "list/describe then per-resource get" shape s3.sh
# already established for get-bucket-location.
_ct_check_logging_status() {
  local work=$1
  shift
  local id=CLOUD-CLOUDTRAIL-NOT_ENABLED-01
  gov_selected "$id" || return 0
  local arn safe rc logging f
  for arn in "$@"; do
    safe=${arn//[^A-Za-z0-9._-]/_}
    f=$work/status.$safe.json
    rc=0
    aws_ro cloudtrail get-trail-status --name "$arn" >"$f" || rc=$?
    if (( rc != 0 )); then
      local reason=''
      aws_ro_reduction_reason_set reason
      _ct_note_lost "$id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=cloudtrail operation=get-trail-status trail=$arn - the trail's logging status could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so CLOUD-CLOUDTRAIL-NOT_ENABLED-01 was not tested for this trail."
      continue
    fi
    gov_doc_load "$f" || true
    _ct_note_evaluated "$id"
    gov_doc_get logging IsLogging
    [[ $logging == true ]] && continue
    gov_emit_finding "$id" "$arn" '' \
      "CloudTrail trail $arn exists but is not currently logging (get-trail-status reports IsLogging false), so no record of API activity is being delivered while it remains in this state, exactly as if the trail did not exist. Start logging on the trail (StartLogging), and alert on this state in future so a stopped trail is noticed quickly."
  done
  return 0
}

_ct_record_coverage() {
  local account=$1 region=$2 id
  for id in "${_CT_CHECK_IDS[@]+"${_CT_CHECK_IDS[@]}"}"; do
    gov_selected "$id" || continue
    if (( ${_CT_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      if (( ${_CT_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_CT_LOST_REASON[$id]} service=cloudtrail check=$id account=$account region=$region trails_unanswered=${_CT_LOST[$id]} - this check ran but ${_CT_LOST[$id]} trail(s) in this region did not answer, so it is covered for some of this region's trails and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_CT_LOST_REASON[$id]:-no_trail_examined} service=cloudtrail check=$id account=$account region=$region - this check answered for NO trail in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that CloudTrail is correctly configured."
    fi
  done
  return 0
}

_ct_run_service
