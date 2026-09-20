#!/usr/bin/env bash
# modules/cloud/aws/live/ssm.sh - the §8.1 SSM (Systems Manager Parameter
# Store) read-only service pass (docs/DESIGN.md §8.1's `ssm` row;
# docs/STEP6-CLOUD-PLAN.md CLOUD-09).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with the same
# no-sourced-once-guard contract kms.sh's own header explains (`ssm` is
# `regional`; one run legitimately reaches it once per region).
#
# TWO PARALLEL CHECKS, NEITHER GATING THE OTHER.  `STRING_TYPE_SENSITIVE` is a
# pure NAME/TYPE classification over the already-loaded `describe-parameters`
# entry and costs no extra call.  `PUBLIC_POLICY` costs one
# `get-resource-policies` call per parameter and is independent of the first -
# a parameter can be flagged by neither, either, or both.
#
# THE ARN IS BUILT, NEVER TRUSTED FROM A RESPONSE FIELD: see
# `ssm_engine.sh`'s own `ssm_parameter_arn` header for why
# `describe-parameters` has no ARN field to read at all.
#
# THE HONESTY ACCOUNTING is the same three rules kms.sh's and s3.sh's own
# headers state, applied to parameters. `STRING_TYPE_SENSITIVE` never costs a
# call and so is never itself a coverage loss - only `describe-parameters`
# failing outright can lose it - while `PUBLIC_POLICY` is lost per-parameter
# exactly as kms.sh's own policy check is.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/ssm_engine.sh
source "${BASH_SOURCE[0]%/*}/ssm_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _SSM_PARAMS_TOTAL=0
declare -gA _SSM_EVALUATED=()
declare -gA _SSM_LOST=()
declare -gA _SSM_LOST_REASON=()

declare -ga _SSM_CHECK_IDS=(
  CLOUD-SSM-STRING_TYPE_SENSITIVE-01
  CLOUD-SSM-PUBLIC_POLICY-01
)

_ssm_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_ssm_note_evaluated() {
  _SSM_EVALUATED[$1]=$(( ${_SSM_EVALUATED[$1]:-0} + 1 ))
}

_ssm_note_lost() {
  _SSM_LOST[$1]=$(( ${_SSM_LOST[$1]:-0} + 1 ))
  [[ -n ${_SSM_LOST_REASON[$1]:-} ]] || _SSM_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_ssm_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-ssm.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_SSM_CHECK_IDS[@]+"${_SSM_CHECK_IDS[@]}"}"; do
    _ssm_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_ssm_checks_deselected service=ssm account=$account region=$region - every CLOUD-SSM-* check id was removed by this run's check-selection filters, so no SSM API call was made and no parameter was examined."
    return 0
  fi

  local listf=$work/describe-parameters.json rc=0
  aws_ro ssm describe-parameters >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=ssm operation=describe-parameters account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's parameter list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO parameter was examined and neither CLOUD-SSM-* check ran."
    run_record coverage_gap "cloud ssm: the parameter list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no parameter's type or resource policy was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds ssm:DescribeParameters."
    return 0
  fi

  ssm_doc_load "$listf" || true
  local partition
  partition=$(ssm_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  local i=0 name=''
  local -a names=()
  while :; do
    ssm_param_entry_field_set name "$i" Name || break
    [[ -n $name ]] && names+=("$i:$name")
    i=$(( i + 1 ))
  done
  _SSM_PARAMS_TOTAL=${#names[@]}

  local entry idx pname arn
  for entry in "${names[@]+"${names[@]}"}"; do
    idx=${entry%%:*}
    pname=${entry#*:}
    arn=$(ssm_parameter_arn "$partition" "$region" "$account" "$pname")
    _ssm_examine_parameter "$idx" "$pname" "$arn" "$work" "$listf"
  done

  _ssm_record_coverage "$account" "$region"
  return 0
}

# `_ssm_examine_parameter INDEX NAME ARN WORKDIR LISTFILE` - INDEX addresses
# the parameter's own entry in the describe-parameters document, reloaded
# from LISTFILE before the type check because the policy call below reloads
# the shared `_SSM_DOC` map in between.
_ssm_examine_parameter() {
  local idx=$1 name=$2 arn=$3 work=$4 listf=$5

  local id=CLOUD-SSM-STRING_TYPE_SENSITIVE-01
  if _ssm_selected "$id"; then
    ssm_doc_load "$listf" || true
    _ssm_note_evaluated "$id"
    local type=''
    ssm_param_entry_field_set type "$idx" Type
    if [[ $type != SecureString ]] && ssm_name_looks_sensitive "$name"; then
      ssm_emit_finding "$id" "$arn" '' \
        "Parameter $arn is stored as type $type, and its name ('$name') matches a shape (password/secret/token/credential/key) this project associates with sensitive material. A $type parameter is neither encrypted at rest by SSM nor access-logged the way a SecureString read is, so its value is readable in the console and API output by anyone with ssm:GetParameter. Re-create it as a SecureString (\`aws ssm put-parameter --type SecureString\`), which encrypts the value with a KMS key and requires kms:Decrypt in addition to ssm:GetParameter to read it. This is a NAME-based heuristic, not a content scan - confirm the value is genuinely sensitive before treating this as confirmed, and note it will miss a differently-named parameter that also holds a secret."
    fi
  fi

  local id2=CLOUD-SSM-PUBLIC_POLICY-01
  _ssm_selected "$id2" || return 0
  local rc=0 safe=${idx}
  aws_ro ssm get-resource-policies --resource-arn "$arn" >"$work/$safe.policy.json" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _ssm_note_lost "$id2" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=ssm operation=get-resource-policies parameter_arn=$arn - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this parameter's resource policy was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
    return 0
  fi
  ssm_doc_load "$work/$safe.policy.json" || true
  _ssm_note_evaluated "$id2"

  # `Policies` is an ARRAY - a parameter with no policy attached returns an
  # empty one (no error), which is the ordinary case and produces no
  # findings, matching cloud_policy_is_public's own "empty document" default.
  local pi=0 ptext='' found=0
  while :; do
    ssm_policy_entry_field_set ptext "$pi" Policy || break
    cloud_policy_load "$ptext" && cloud_policy_is_public && { found=1; }
    pi=$(( pi + 1 ))
  done
  (( found )) || return 0
  ssm_emit_finding "$id2" "$arn" '' \
    "A resource policy attached to SSM parameter $arn contains an Allow statement granting to an unqualified wildcard principal with no Condition narrowing it. An SSM resource policy controls cross-account access to the parameter directly, so a wildcard grant here means any AWS principal that can reach the parameter's ARN, in any account, can call GetParameter against it. Replace the wildcard with the specific account(s) or role(s) that need access."
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_ssm_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_SSM_CHECK_IDS[@]+"${_SSM_CHECK_IDS[@]}"}"; do
    _ssm_selected "$id" || continue
    if (( ${_SSM_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_SSM_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_SSM_LOST_REASON[$id]} service=ssm check=$id account=$account region=$region params_answered=${_SSM_EVALUATED[$id]} params_unanswered=${_SSM_LOST[$id]} - this check ran, but ${_SSM_LOST[$id]} parameter(s) did not answer, so it is covered for some of this region's parameters and not for others."
      fi
    elif (( ${_SSM_LOST[$id]:-0} > 0 )); then
      run_record coverage_reduction "module=cloud reason=${_SSM_LOST_REASON[$id]:-no_parameter_examined} service=ssm check=$id account=$account region=$region params_total=${_SSM_PARAMS_TOTAL} - this check answered for NO parameter in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every parameter is configured correctly."
    fi
  done

  if (( _SSM_PARAMS_TOTAL == 0 )); then
    run_record notes "module=cloud service=ssm account=$account region=$region parameters=0 - the region's parameter list was read successfully and contains no parameter, so every CLOUD-SSM-* check is covered vacuously."
  fi

  if (( ran == 0 && _SSM_PARAMS_TOTAL > 0 )); then
    run_record coverage_gap "cloud ssm: account $account region $region has ${_SSM_PARAMS_TOTAL} parameter(s) and NOT ONE of the ${#_SSM_CHECK_IDS[@]} CLOUD-SSM-* checks answered for any of them, so no parameter's type or resource policy was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above says why."
  fi
  return 0
}

_ssm_run_service
