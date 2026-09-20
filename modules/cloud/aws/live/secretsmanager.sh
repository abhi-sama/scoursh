#!/usr/bin/env bash
# modules/cloud/aws/live/secretsmanager.sh - the §8.1 Secrets Manager
# read-only service pass (docs/DESIGN.md §8.1's `secretsmanager` row;
# docs/STEP6-CLOUD-PLAN.md CLOUD-08).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with the same
# no-sourced-once-guard contract `kms.sh`'s own header explains (this service
# is `regional`, and one run legitimately reaches it once per region).
#
# ONE CALL PER SECRET, NOT TWO.  `list-secrets` already answers the rotation
# question directly (`SecretList[n].RotationEnabled`) - unlike KMS, which
# needs a dedicated `get-key-rotation-status` call - so the only per-secret
# call this pass makes is `get-resource-policy`, for the wildcard-policy
# check.  A secret that is already scheduled for deletion
# (`secm_secret_deleted`) or owned by another AWS service
# (`secm_secret_owning_service`) is skipped for the rotation check as OUT OF
# SCOPE, the identical "not evaluated, not lost" distinction kms.sh applies to
# an AWS-managed key - see this pass's own `_secm_examine_secret` for where
# each is drawn.
#
# THE HONESTY ACCOUNTING is the same three rules kms.sh's and s3.sh's own
# headers state, applied to secrets.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/secretsmanager_engine.sh
source "${BASH_SOURCE[0]%/*}/secretsmanager_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _SECM_SECRETS_TOTAL=0
declare -g _SECM_SECRETS_ROTATION_ELIGIBLE=0
declare -gA _SECM_EVALUATED=()
declare -gA _SECM_LOST=()
declare -gA _SECM_LOST_REASON=()

declare -ga _SECM_CHECK_IDS=(
  CLOUD-SECRETSMANAGER-NO_ROTATION-01
  CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01
)

_secm_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_secm_note_evaluated() {
  _SECM_EVALUATED[$1]=$(( ${_SECM_EVALUATED[$1]:-0} + 1 ))
}

_secm_note_lost() {
  _SECM_LOST[$1]=$(( ${_SECM_LOST[$1]:-0} + 1 ))
  [[ -n ${_SECM_LOST_REASON[$1]:-} ]] || _SECM_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_secm_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-secm.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_SECM_CHECK_IDS[@]+"${_SECM_CHECK_IDS[@]}"}"; do
    _secm_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_secretsmanager_checks_deselected service=secretsmanager account=$account region=$region - every CLOUD-SECRETSMANAGER-* check id was removed by this run's check-selection filters, so no Secrets Manager API call was made and no secret was examined."
    return 0
  fi

  local listf=$work/list-secrets.json rc=0
  aws_ro secretsmanager list-secrets >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=secretsmanager operation=list-secrets account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's secret list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO secret was examined and neither CLOUD-SECRETSMANAGER-* check ran."
    run_record coverage_gap "cloud secretsmanager: the secret list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no secret's rotation setting or resource policy was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds secretsmanager:ListSecrets."
    return 0
  fi

  secm_doc_load "$listf" || true
  local i=0 arn=''
  local -a arns=()
  while :; do
    secm_doc_get arn "$(secm_path SecretList "$i" ARN)" || break
    [[ -n $arn ]] && arns+=("$i:$arn")
    i=$(( i + 1 ))
  done
  _SECM_SECRETS_TOTAL=${#arns[@]}

  local entry idx sarn
  for entry in "${arns[@]+"${arns[@]}"}"; do
    idx=${entry%%:*}
    sarn=${entry#*:}
    _secm_examine_secret "$idx" "$sarn" "$work" "$listf"
  done

  _secm_record_coverage "$account" "$region"
  return 0
}

# `_secm_examine_secret INDEX ARN WORKDIR LISTFILE` - INDEX addresses the
# secret's own entry in the ALREADY-LOADED list-secrets document for the
# rotation fields; the document is reloaded from LISTFILE before each read
# because the per-secret policy call below reloads the shared `_SECM_DOC` map
# in between.
_secm_examine_secret() {
  local idx=$1 arn=$2 work=$3 listf=$4
  local safe=${idx}
  local id=CLOUD-SECRETSMANAGER-NO_ROTATION-01

  if _secm_selected "$id"; then
    secm_doc_load "$listf" || true
    if secm_secret_deleted "$idx"; then
      : # scheduled for deletion: neither evaluated nor lost, simply out of scope
    elif [[ -n $(secm_secret_owning_service "$idx") ]]; then
      : # another AWS service owns this secret's rotation lifecycle
    else
      _SECM_SECRETS_ROTATION_ELIGIBLE=$(( _SECM_SECRETS_ROTATION_ELIGIBLE + 1 ))
      _secm_note_evaluated "$id"
      if ! secm_secret_rotation_enabled "$idx"; then
        secm_emit_finding "$id" "$arn" '' \
          "Automatic rotation is NOT enabled for secret $arn. A secret with no rotation schedule has the same value from creation until someone manually changes it, so a leaked or over-shared credential stays valid indefinitely once exposed - through a log, a screen share, a former employee's shell history, or a compromised host that once read it. Configure rotation with a Lambda rotation function (AWS provides templates for RDS/DocumentDB/Redshift credentials, and a custom function covers any other secret type) so a leaked value has a bounded lifetime even when the leak itself is never detected."
      fi
    fi
  fi

  local id2=CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01
  _secm_selected "$id2" || return 0
  local rc=0
  aws_ro secretsmanager get-resource-policy --secret-id "$arn" >"$work/$safe.policy.json" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _secm_note_lost "$id2" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=secretsmanager operation=get-resource-policy secret_arn=$arn - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this secret's resource policy was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
    return 0
  fi
  secm_doc_load "$work/$safe.policy.json" || true
  _secm_note_evaluated "$id2"
  local policy=''
  policy=$(secm_policy_field)
  cloud_policy_load "$policy" || return 0
  cloud_policy_is_public || return 0
  secm_emit_finding "$id2" "$arn" '' \
    "The resource policy attached to secret $arn contains an Allow statement granting to an unqualified wildcard principal with no Condition narrowing it. A Secrets Manager resource policy controls who can retrieve the secret's VALUE directly - unlike an IAM policy, which the calling principal's own account must also grant - so a wildcard grant here means any AWS principal that can reach the secret's ARN, in any account, can call GetSecretValue against it. Replace the wildcard with the specific account(s) or role(s) that need access."
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_secm_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_SECM_CHECK_IDS[@]+"${_SECM_CHECK_IDS[@]}"}"; do
    _secm_selected "$id" || continue
    if (( ${_SECM_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_SECM_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_SECM_LOST_REASON[$id]} service=secretsmanager check=$id account=$account region=$region secrets_answered=${_SECM_EVALUATED[$id]} secrets_unanswered=${_SECM_LOST[$id]} - this check ran, but ${_SECM_LOST[$id]} secret(s) did not answer, so it is covered for some of this region's secrets and not for others."
      fi
    elif (( ${_SECM_LOST[$id]:-0} > 0 )); then
      run_record coverage_reduction "module=cloud reason=${_SECM_LOST_REASON[$id]:-no_secret_examined} service=secretsmanager check=$id account=$account region=$region secrets_total=${_SECM_SECRETS_TOTAL} - this check answered for NO secret in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every secret is configured correctly."
    fi
  done

  if (( _SECM_SECRETS_TOTAL == 0 )); then
    run_record notes "module=cloud service=secretsmanager account=$account region=$region secrets=0 - the region's secret list was read successfully and contains no secret, so every CLOUD-SECRETSMANAGER-* check is covered vacuously."
  elif (( _SECM_SECRETS_ROTATION_ELIGIBLE == 0 )) && _secm_selected CLOUD-SECRETSMANAGER-NO_ROTATION-01; then
    run_record notes "module=cloud service=secretsmanager account=$account region=$region - every secret in this region is either scheduled for deletion or owned by another AWS service, so CLOUD-SECRETSMANAGER-NO_ROTATION-01 had no eligible secret to evaluate."
  fi

  if (( ran == 0 && _SECM_SECRETS_TOTAL > 0 )); then
    run_record coverage_gap "cloud secretsmanager: account $account region $region has ${_SECM_SECRETS_TOTAL} secret(s) and NOT ONE of the ${#_SECM_CHECK_IDS[@]} CLOUD-SECRETSMANAGER-* checks answered for any of them, so no secret's rotation setting or resource policy was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above says why."
  fi
  return 0
}

_secm_run_service
