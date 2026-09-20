#!/usr/bin/env bash
# modules/cloud/aws/live/apigw.sh - the §8.4 API Gateway read-only service
# AND the write side of the cross-module endpoint inventory
# (docs/DESIGN.md §8.4; docs/STEP6-CLOUD-PLAN.md CLOUD-22).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  It carries NO
# sourced-once guard - `apigw` is a `regional` row in `_CLOUD_SERVICES`, so
# this is legitimately reached once per enabled region, and a guard would
# silently make every region after the first a no-op.  Its pure half - every
# classifier, the ARN builder, the endpoint-inventory reader/writer and the
# emitter - is modules/cloud/aws/live/apigw_engine.sh, which does have one.
#
# TWO DELIVERABLES, ONE SCRIPT.  §8.4's own text answers "what are all my
# endpoints" as well as "which of them has no authorizer": `get-rest-apis` +
# `get-resources --embed methods` name the whole route surface (every REST
# API, resource path and HTTP verb) and each verb's own `authorizationType`
# in ONE pair of calls per account/region, so the open-auth check and the
# inventory write below walk the SAME response rather than paying for it
# twice.  `get-api-keys` is called once per region for `apiKeyRequired`
# context ALONE - EXISTENCE ONLY, never `--include-value` - because a key
# whose value this script had read would be a secret on disk the instant the
# response landed in `$work` (docs/FOUNDATION.md tension 9).
#
# WHY THE ENDPOINT-INVENTORY WRITE IS GATED ON THE SAME `--profile-scan` /
# `--intensity` CHECK SELECTION AS THE FINDING.  Both deliverables are pulled
# out of the identical `get-resources` response, so "no CLOUD-APIGW-* check
# is selected" genuinely means no reason exists to make either call - the
# module does not invent a second, unconditional code path to keep writing
# an inventory nobody asked to look for.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (tension 23), spelled literally at each
# call site with a literal service and operation, per
# modules/cloud/aws/live/s3.sh's own header note on why a wrapper would defeat
# `tests/lint-aws-readonly.sh`.  Every response is redirected to a file rather
# than captured with `$(...)`, for `aws_ro_into`'s own reason: a command
# substitution runs in a subshell, so every `SCOURSH_AWS_RO_*` outcome global
# it sets is set in a process that then exits, turning a denied call into an
# indistinguishable empty response.
#
# THE HONESTY ACCOUNTING, mirroring modules/cloud/aws/live/s3.sh's three
# rules exactly, applied to METHODS rather than buckets:
#   1. `checks_run` NAMES WHAT SUCCEEDED - a check id is recorded only if its
#      own condition was actually EVALUATED for at least one method.
#   2. AN `AccessDenied` (or any other coverage-loss outcome) IS A
#      `coverage_reduction`, NEVER SILENCE.
#   3. A REST API WITH ZERO METHODS, OR AN ACCOUNT WITH ZERO REST APIs, IS A
#      REAL ANSWER, NOT A LOSS: the list call succeeded and there was nothing
#      to examine, which is exactly what a vacuously-covered check means.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/apigw_engine.sh
source "${BASH_SOURCE[0]%/*}/apigw_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g` throughout, for modules/cloud/aws/live/s3.sh's own reason: this
# file is sourced from INSIDE `cloud_run_service`, so a bare `declare` would
# make every one of these a local that dies with the pass.  Reset here rather
# than only declared, so a second pass in one process never inherits the
# first's counters.
declare -g _APIGW_APIS_TOTAL=0
declare -g _APIGW_LIST_TRUNCATED=0
declare -gA _APIGW_EVALUATED=()
declare -gA _APIGW_LOST=()
declare -gA _APIGW_LOST_REASON=()

declare -g APIGW_OPEN_AUTH_ID=CLOUD-APIGW-OPEN_AUTH_ROUTE-01
declare -g APIGW_OPEN_AUTH_KEY_ONLY_ID=CLOUD-APIGW-OPEN_AUTH_KEY_ONLY-01

declare -ga _APIGW_CHECK_IDS=(
  "$APIGW_OPEN_AUTH_ID"
  "$APIGW_OPEN_AUTH_KEY_ONLY_ID"
)

# `_apigw_selected ID` - tension 15's per-check filter, through the module
# engine's own `cloud_check_selected`.  Permissive when the function is
# absent, per modules/cloud/aws/live/s3.sh's own `_s3_selected` header: a
# direct-engine test suite sources this script with no module engine in the
# process, and a fail-CLOSED default there would make the whole pass inert
# while every "stays quiet" assertion in that suite still passed green.
_apigw_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_apigw_note_evaluated() {
  _APIGW_EVALUATED[$1]=$(( ${_APIGW_EVALUATED[$1]:-0} + 1 ))
}

_apigw_note_lost() {
  # FIRST reason wins, matching modules/cloud/aws/live/s3.sh's own
  # `_s3_note_lost`: a run whose first ten methods were denied and whose
  # eleventh was throttled should report the permission problem, the
  # actionable one that explains the other ten.
  _APIGW_LOST[$1]=$(( ${_APIGW_LOST[$1]:-0} + 1 ))
  [[ -n ${_APIGW_LOST_REASON[$1]:-} ]] || _APIGW_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_apigw_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  # `mktemp -d`, never a name built from `$$` or a fixed string, for
  # modules/cloud/aws/live/s3.sh's own CWE-377/CWE-59 reason: a predictable
  # scratch path is one a local user can pre-create as a symlink this process
  # then writes THROUGH.  No `-p` (tension 24: `-p` is a GNU spelling).
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-apigw.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_APIGW_CHECK_IDS[@]+"${_APIGW_CHECK_IDS[@]}"}"; do
    _apigw_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_apigw_checks_deselected service=apigw account=$account region=$region - every CLOUD-APIGW-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no API Gateway call was made, no route was examined and this pass contributed nothing to the endpoint inventory."
    rm -rf -- "$work"
    return 0
  fi

  apigw_inv_reset
  local inv=${SCOURSH_RUN_DIR:-}/inventory/endpoints.json
  if [[ -n ${SCOURSH_RUN_DIR:-} ]]; then
    mkdir -p "${SCOURSH_RUN_DIR}/inventory"
    apigw_inv_merge_existing "$inv"
  fi

  # -------------------------------------------------------------------------
  # get-api-keys - existence-only context, once per region.  NEVER
  # `--include-value`: this call is scoped to counting entries, and a value
  # this script had read would be a secret on disk from the moment the
  # response landed in $work (tension 9).
  # -------------------------------------------------------------------------
  local keycount='' rc=0
  aws_ro apigateway get-api-keys >"$work/get-api-keys.json" || rc=$?
  if (( rc == 0 )); then
    apigw_doc_load "$work/get-api-keys.json" || true
    local ki=0
    while apigw_doc_has "$(apigw_path items "$ki" id)"; do
      ki=$(( ki + 1 ))
    done
    keycount=$ki
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
      keycount="at least $keycount"
    fi
  fi

  # -------------------------------------------------------------------------
  # get-rest-apis - the account/region's whole REST API surface.
  # -------------------------------------------------------------------------
  rc=0
  aws_ro apigateway get-rest-apis >"$work/get-rest-apis.json" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    for id in "${_APIGW_CHECK_IDS[@]+"${_APIGW_CHECK_IDS[@]}"}"; do
      _apigw_note_lost "$id" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=apigw operation=get-rest-apis account=$account region=$region - the account's REST API list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO API Gateway route was examined and neither CLOUD-APIGW-* check ran."
    run_record coverage_gap "cloud apigw: the REST API list for account $account region $region could not be read, so no route's authorizer configuration was tested and nothing was contributed to the endpoint inventory. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds apigateway:GET."
    _apigw_finish_inventory "$inv"
    rm -rf -- "$work"
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _APIGW_LIST_TRUNCATED=1
  fi

  apigw_doc_load "$work/get-rest-apis.json" || true
  local -a apis=() api_names=()
  local ai=0 api_id='' api_name=''
  while apigw_doc_has "$(apigw_path items "$ai" id)"; do
    apigw_doc_get api_id "$(apigw_path items "$ai" id)"
    apigw_doc_get api_name "$(apigw_path items "$ai" name)"
    [[ -n $api_id ]] && { apis+=("$api_id"); api_names+=("${api_name:-$api_id}"); }
    ai=$(( ai + 1 ))
  done
  _APIGW_APIS_TOTAL=${#apis[@]}

  local partition=''
  partition=$(apigw_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  local i
  for (( i = 0; i < ${#apis[@]}; i++ )); do
    _apigw_examine_api "${apis[$i]}" "${api_names[$i]}" "$partition" "$region" "$keycount" "$work"
  done

  _apigw_finish_inventory "$inv"
  _apigw_record_coverage "$account" "$region"
  rm -rf -- "$work"
  return 0
}

# `_apigw_finish_inventory FILE` - write the merged accumulator back, exactly
# once per pass, whatever happened above.  A no-op with no run directory
# (a direct-engine test that never set SCOURSH_RUN_DIR).
_apigw_finish_inventory() {
  local file=$1
  [[ -n ${SCOURSH_RUN_DIR:-} ]] || return 0
  apigw_inv_write "$file" "${SCOURSH_RUN_ID:-}"
  if (( _APIGW_INV_TRUNCATED )); then
    run_record coverage_gap "cloud apigw: the endpoint inventory reached its ${_APIGW_INV_MAX}-entry bound while this pass was adding API Gateway routes, so an unknown number of routes were never added to reports/<run>/inventory/endpoints.json and will not be offered to a later DAST run as candidates."
  fi
  return 0
}

# `_apigw_examine_api API_ID API_NAME PARTITION REGION KEYCOUNT WORK` - the
# stages (for the inventory URL) and the resources+methods (for the
# authorizer check and the inventory's method/path) of one REST API.
_apigw_examine_api() {
  local api_id=$1 api_name=$2 partition=$3 region=$4 keycount=$5 work=$6
  local safe=${api_id//[^A-Za-z0-9._-]/_}
  local id

  # -- stages: resolved separately from resources, because get-stages' own
  # JSON shape names its array `item` (singular) rather than `items` - one of
  # the handful of API Gateway v1 operations that predate the `items`
  # convention every other list response in this file uses (get-rest-apis,
  # get-resources and get-api-keys all use `items`).  Getting this wrong reads
  # as "this API has zero stages" for every API in the account, which is the
  # silent-short-list failure this codebase's honesty rules exist to catch.
  local -a stages=()
  local rc=0
  aws_ro apigateway get-stages --rest-api-id "$api_id" >"$work/$safe.stages.json" || rc=$?
  if (( rc != 0 )); then
    local stages_reason=''
    aws_ro_reduction_reason_set stages_reason
    run_record coverage_reduction "module=cloud reason=$stages_reason service=apigw operation=get-stages api=$api_id region=$region - this API's deployed stages could not be read, so none of its routes have a resolvable invoke URL and none were added to the endpoint inventory. Its authorizer configuration below is unaffected."
  else
    apigw_doc_load "$work/$safe.stages.json" || true
    local si=0 stage=''
    while apigw_doc_has "$(apigw_path item "$si" stageName)"; do
      apigw_doc_get stage "$(apigw_path item "$si" stageName)"
      [[ -n $stage ]] && stages+=("$stage")
      si=$(( si + 1 ))
    done
    if (( ${#stages[@]} == 0 )); then
      run_record notes "module=cloud service=apigw api=$api_id region=$region stages=0 - this REST API has no deployed stage, so none of its routes are requestable yet and none were added to the endpoint inventory"
    fi
  fi

  # -- resources + embedded methods --
  rc=0
  aws_ro apigateway get-resources --rest-api-id "$api_id" --embed methods \
    >"$work/$safe.resources.json" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    for id in "${_APIGW_CHECK_IDS[@]+"${_APIGW_CHECK_IDS[@]}"}"; do
      _apigw_note_lost "$id" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=apigw operation=get-resources api=$api_id region=$region - this API's resource/method tree could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so none of its routes was examined."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=apigw operation=get-resources api=$api_id region=$region - this API's resource list came back INCOMPLETE, so an unknown number of its resources were never examined."
  fi

  apigw_doc_load "$work/$safe.resources.json" || true
  local ri=0 path='' methods='' verb
  while apigw_doc_has "$(apigw_path items "$ri" id)"; do
    apigw_doc_get path "$(apigw_path items "$ri" path)"
    [[ -n $path ]] || path=/
    methods=''
    apigw_resource_methods_set methods "$ri"
    for verb in $methods; do
      # CORS preflight carries no credential of any kind by browser design
      # (see apigw_engine.sh's own header) - flagging it is a false-positive
      # flood on the single most common API Gateway configuration there is.
      [[ $verb == OPTIONS ]] && continue
      _apigw_examine_method "$api_id" "$api_name" "$partition" "$region" \
        "$path" "$verb" "$ri" "$keycount" "${stages[*]+"${stages[*]}"}"
    done
    ri=$(( ri + 1 ))
  done
  return 0
}

# `_apigw_examine_method ... RESOURCE_INDEX KEYCOUNT STAGES` - one route.
# STAGES is a single SPACE-JOINED string rather than an array passed by name:
# bash 4.2 (tension 24's frozen minimum) has no namerefs, and an API Gateway
# stage name is an AWS-assigned identifier that never contains whitespace, so
# plain word-splitting below is a safe, sufficient substitute for an array
# reference here - the same "space-joined, split unquoted" shape this
# codebase already uses for `S3_BPA_SETTINGS`.
_apigw_examine_method() {
  local api_id=$1 api_name=$2 partition=$3 region=$4 path=$5 verb=$6 idx=$7
  local keycount=$8 stages_joined=$9

  _apigw_note_evaluated "$APIGW_OPEN_AUTH_ID"
  _apigw_note_evaluated "$APIGW_OPEN_AUTH_KEY_ONLY_ID"

  local authtype=''
  apigw_method_authtype_set authtype "$idx" "$verb" || true

  if apigw_method_is_open "$authtype"; then
    local arn=''
    arn=$(apigw_method_arn "$partition" "$region" "${SCOURSH_CLOUD_ACCOUNT_ID:-}" "$api_id" "$verb" "$path")
    if apigw_method_apikey_required "$idx" "$verb"; then
      if _apigw_selected "$APIGW_OPEN_AUTH_KEY_ONLY_ID"; then
        apigw_emit_finding "$APIGW_OPEN_AUTH_KEY_ONLY_ID" "$arn" "$region" \
          "$verb $path on REST API $api_name ($api_id, $region) has authorizationType NONE and is gated only by apiKeyRequired: true. An API key is not an authorizer - API Gateway checks only that SOME provisioned key was presented, never who is calling, and a leaked or shared key grants the same access to anyone who holds it. This account currently provisions ${keycount:-an unknown number of} API key(s) (existence only; values are never read by this scan). Attach a real authorizer (AWS_IAM, a Cognito user pool, or a Lambda authorizer) if callers need to be individually identified, or accept this as an intentional machine-to-machine key if they do not."
      fi
    else
      if _apigw_selected "$APIGW_OPEN_AUTH_ID"; then
        apigw_emit_finding "$APIGW_OPEN_AUTH_ID" "$arn" "$region" \
          "$verb $path on REST API $api_name ($api_id, $region) has authorizationType NONE and apiKeyRequired false, so it can be invoked by anyone who has this endpoint's URL with no credential of any kind - no API key, no IAM signature, no bearer token. Attach an authorizer (AWS_IAM, a Cognito user pool, or a Lambda authorizer) unless this route is genuinely meant to be public."
      fi
    fi
  fi

  # -- inventory contribution: every route is a candidate for DAST, whatever
  # its authorization looks like, per docs/DESIGN.md §8.4's own "fed to DAST
  # as candidate targets" - only the SCOPE GATE decides whether it is ever
  # actually requested, applied later by the consumer (docs/FOUNDATION.md
  # tension 21's own last paragraph), never by this producer.
  local stage url
  for stage in $stages_joined; do
    url="https://$api_id.execute-api.$region.amazonaws.com/$stage$path"
    apigw_inv_add "$verb" "$url"
  done
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up - byte-identical shape to modules/cloud/aws/live/s3.sh's own
#    `_s3_record_coverage`, applied to methods rather than buckets.
# ---------------------------------------------------------------------------
_apigw_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_APIGW_CHECK_IDS[@]+"${_APIGW_CHECK_IDS[@]}"}"; do
    _apigw_selected "$id" || continue
    if (( ${_APIGW_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_APIGW_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_APIGW_LOST_REASON[$id]} service=apigw check=$id account=$account region=$region methods_answered=${_APIGW_EVALUATED[$id]} methods_unanswered=${_APIGW_LOST[$id]} - this check ran, but ${_APIGW_LOST[$id]} method(s) did not answer, so it is covered for some of this region's routes and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_APIGW_LOST_REASON[$id]:-no_method_examined} service=apigw check=$id account=$account region=$region apis_total=${_APIGW_APIS_TOTAL} - this check answered for NO method in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every route is correctly authorized."
    fi
  done

  if (( _APIGW_APIS_TOTAL == 0 )); then
    # A genuine absence of REST APIs in this region.  The list call still
    # succeeded, so this run DID look and there was nothing to examine -
    # modules/cloud/aws/live/s3.sh's own "vacuously covered" case, applied
    # here.
    run_record notes "module=cloud service=apigw account=$account region=$region apis=0 - this region has no REST API, so every CLOUD-APIGW-* check is covered vacuously"
  fi

  if (( _APIGW_LIST_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=apigw operation=get-rest-apis account=$account region=$region apis_seen=$_APIGW_APIS_TOTAL - the REST API list came back INCOMPLETE, so an unknown number of this region's APIs were never enumerated."
    run_record coverage_gap "cloud apigw: the REST API list for account $account region $region was truncated at $_APIGW_APIS_TOTAL API(s), so an unknown number of APIs were never examined and none of their routes reached the endpoint inventory."
  fi

  if (( ran == 0 && _APIGW_APIS_TOTAL > 0 )); then
    run_record coverage_gap "cloud apigw: account $account region $region has $_APIGW_APIS_TOTAL REST API(s) and NOT ONE of the ${#_APIGW_CHECK_IDS[@]} CLOUD-APIGW-* checks answered for any of them, so no route's authorizer configuration was tested. This is a run that did not look, not an API estate with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_apigw_run_service
