#!/usr/bin/env bash
# modules/cloud/aws/live/kms.sh - the §8.1 KMS read-only service pass
# (docs/DESIGN.md §8.1's `kms` row; docs/STEP6-CLOUD-PLAN.md CLOUD-07).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  It carries NO sourced-once
# guard, for the reason `s3.sh`'s own header states at length: `kms` is
# `regional` (`_CLOUD_SERVICES`), so one run legitimately reaches this file
# once per enabled region, and a guard would silently make every region after
# the first a no-op.  Its pure half is `modules/cloud/aws/live/kms_engine.sh`.
#
# THE TWO CALLS PER KEY, AND WHY A THIRD IS DELIBERATELY NOT MADE.
# `describe-key` is read first because it is what decides whether the other
# two calls are even worth making - an AWS-managed key is administered by the
# owning service and neither ROTATION_DISABLED nor PUBLIC_POLICY is this
# account's finding to report on it, and an ineligible key type
# (`kms_key_rotation_eligible`, kms_engine.sh) skips the rotation call
# specifically rather than spend it on a call KMS itself would refuse.  There
# is no third `get-key-policy` gate: EVERY key, of every state and type, has
# exactly one key policy, and it is this account's to fix regardless of
# whether the key happens to be enabled today.
#
# THE HONESTY ACCOUNTING IS THE SAME THREE RULES `s3.sh`'s OWN HEADER STATES,
# applied to keys instead of buckets:
#   1. `checks_run` NAMES WHAT SUCCEEDED - a check id is recorded only if its
#      own API call actually answered for at least one key.
#   2. AN `AccessDenied` (or throttle, or any other coverage-loss outcome) IS
#      A `coverage_reduction`, NEVER SILENCE.
#   3. A key this pass correctly judged OUT OF SCOPE for a check (an
#      AWS-managed key, an ineligible key type for rotation) is neither
#      evaluated nor lost for that check - it simply never contributes,
#      which is why the applicable-key counts below are tracked separately
#      from the total.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/kms_engine.sh
source "${BASH_SOURCE[0]%/*}/kms_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _KMS_KEYS_TOTAL=0
declare -g _KMS_KEYS_CUSTOMER_MANAGED=0
declare -g _KMS_KEYS_ROTATION_ELIGIBLE=0
declare -gA _KMS_EVALUATED=()
declare -gA _KMS_LOST=()
declare -gA _KMS_LOST_REASON=()

declare -ga _KMS_CHECK_IDS=(
  CLOUD-KMS-ROTATION_DISABLED-01
  CLOUD-KMS-PUBLIC_POLICY-01
)

# `_kms_selected ID` - tension 15's per-check filter.  The `declare -F` guard
# is PERMISSIVE when absent (a direct-engine test suite has no module engine
# in the process), the identical trap `s3.sh`'s own `_s3_selected` header
# records: a fail-CLOSED default would make every direct-engine suite inert
# while every "stays quiet" assertion in it still passed green.
_kms_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_kms_note_evaluated() {
  _KMS_EVALUATED[$1]=$(( ${_KMS_EVALUATED[$1]:-0} + 1 ))
}

_kms_note_lost() {
  _KMS_LOST[$1]=$(( ${_KMS_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, the identical rule s3.sh's own `_s3_note_lost` states:
  # the actionable failure (a permission gap) explains every later one on the
  # same run, where last-wins would report whichever failure happened last.
  [[ -n ${_KMS_LOST_REASON[$1]:-} ]] || _KMS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_kms_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  # `mktemp -d`, no `-p` (tension 24), a NAME never built from `$$`/`$BASHPID` -
  # every scratch path here is a symlink target a local user could pre-create,
  # the identical CWE-377-via-CWE-59 lesson s3.sh's own header records.
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-kms.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_KMS_CHECK_IDS[@]+"${_KMS_CHECK_IDS[@]}"}"; do
    _kms_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_kms_checks_deselected service=kms account=$account region=$region - every CLOUD-KMS-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no KMS API call was made and no key was examined."
    return 0
  fi

  local listf=$work/list-keys.json rc=0
  aws_ro kms list-keys >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=kms operation=list-keys account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's key list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO KMS key was examined and neither CLOUD-KMS-* check ran."
    run_record coverage_gap "cloud kms: the key list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no key's rotation setting or key policy was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds kms:ListKeys."
    return 0
  fi

  local -a keys=()
  local i=0 kid=''
  kms_doc_load "$listf" || true
  while :; do
    kms_doc_get kid "$(kms_path Keys "$i" KeyId)" || break
    [[ -n $kid ]] && keys+=("$kid")
    i=$(( i + 1 ))
  done
  _KMS_KEYS_TOTAL=${#keys[@]}

  local k
  for k in "${keys[@]+"${keys[@]}"}"; do
    _kms_examine_key "$k" "$work"
  done

  _kms_record_coverage "$account" "$region"
  return 0
}

# `_kms_examine_key KEY_ID WORKDIR` - never returns non-zero: a key that
# cannot be examined is an accounted-for reduction, not a reason to abandon
# the ones after it.
_kms_examine_key() {
  local kid=$1 work=$2
  local safe=${kid//[^A-Za-z0-9._-]/_}
  local rc=0

  rc=0
  aws_ro kms describe-key --key-id "$kid" >"$work/$safe.describe.json" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    local cid
    for cid in "${_KMS_CHECK_IDS[@]+"${_KMS_CHECK_IDS[@]}"}"; do
      _kms_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=kms operation=describe-key key_id=$kid - the key's metadata could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so its type, state and manager could not be established and it was not examined at all."
    return 0
  fi
  kms_doc_load "$work/$safe.describe.json" || true

  if ! kms_key_is_customer_managed; then
    # An AWS-managed key: administered by the owning service, neither check
    # applies.  Not a reduction - a key correctly judged out of scope is not
    # a coverage loss, the identical distinction kms_engine.sh's own
    # `kms_key_rotation_eligible` header draws.
    return 0
  fi
  _KMS_KEYS_CUSTOMER_MANAGED=$(( _KMS_KEYS_CUSTOMER_MANAGED + 1 ))

  local arn
  arn=$(kms_key_arn)
  if [[ -z $arn ]]; then
    # `describe-key` answered but named no ARN - a document shape this run did
    # not expect.  Recorded as a reduction on both checks rather than
    # inventing an ARN: `loc_resource_key` is a fingerprint component
    # (tension 5), and a guessed ARN a later fix corrected would leave every
    # finding permanently unresolvable, the identical reasoning s3.sh applies
    # to a bucket whose region cannot be established.
    local cid
    for cid in "${_KMS_CHECK_IDS[@]+"${_KMS_CHECK_IDS[@]}"}"; do
      _kms_note_lost "$cid" aws_api_error
    done
    run_record coverage_reduction "module=cloud reason=aws_api_error service=kms operation=describe-key key_id=$kid - the response named no key ARN, so this key was not examined at all."
    return 0
  fi

  _kms_check_rotation "$kid" "$arn" "$work/$safe.rotation.json"
  _kms_check_policy "$kid" "$arn" "$work/$safe.policy.json"
  return 0
}

_kms_check_rotation() {
  local kid=$1 arn=$2 f=$3
  local id=CLOUD-KMS-ROTATION_DISABLED-01
  _kms_selected "$id" || return 0
  kms_key_rotation_eligible || return 0
  _KMS_KEYS_ROTATION_ELIGIBLE=$(( _KMS_KEYS_ROTATION_ELIGIBLE + 1 ))

  local rc=0
  aws_ro kms get-key-rotation-status --key-id "$kid" >"$f" || rc=$?
  if (( rc != 0 )); then
    _kms_call_lost "$kid" get-key-rotation-status "$id"
    return 0
  fi
  kms_doc_load "$f" || true
  _kms_note_evaluated "$id"
  local enabled=''
  kms_rotation_enabled_set enabled && return 0
  kms_emit_finding "$id" "$arn" '' \
    "Automatic annual key rotation is NOT enabled for customer-managed KMS key $arn. Without it the same backing key material protects everything ever encrypted under this key indefinitely, so a single compromise of that material - or of the personnel/process controlling it - has no natural expiry. Enable key rotation (\`aws kms enable-key-rotation --key-id $kid\`); AWS re-encrypts nothing when it rotates, so decrypting old ciphertext still works and no application change is required."
  return 0
}

_kms_check_policy() {
  local kid=$1 arn=$2 f=$3
  local id=CLOUD-KMS-PUBLIC_POLICY-01
  _kms_selected "$id" || return 0

  local rc=0
  aws_ro kms get-key-policy --key-id "$kid" --policy-name default >"$f" || rc=$?
  if (( rc != 0 )); then
    _kms_call_lost "$kid" get-key-policy "$id"
    return 0
  fi
  kms_doc_load "$f" || true
  _kms_note_evaluated "$id"

  local policy=''
  policy=$(kms_policy_field)
  cloud_policy_load "$policy" || return 0
  cloud_policy_is_public || return 0
  kms_emit_finding "$id" "$arn" '' \
    "The key policy on KMS key $arn contains an Allow statement granting to an unqualified wildcard principal (Principal \"*\" or Principal.AWS \"*\") with no Condition narrowing it. A KMS key policy is the ONLY access-control surface for the key - unlike S3, where IAM also gates access - so a wildcard grant here means any AWS principal that can reach the key's ARN, in any account, can request the operations this statement allows. Replace the wildcard with the specific account(s), role(s) or organisation id that need access, and confirm nothing legitimately depended on the open grant before removing it."
  return 0
}

_kms_call_lost() {
  local kid=$1 op=$2
  shift 2
  local reason='' cid
  aws_ro_reduction_reason_set reason
  for cid in "$@"; do
    _kms_note_lost "$cid" "$reason"
  done
  run_record coverage_reduction "module=cloud reason=$reason service=kms operation=$op key_id=$kid checks=[$*] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this property of this key was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_kms_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_KMS_CHECK_IDS[@]+"${_KMS_CHECK_IDS[@]}"}"; do
    _kms_selected "$id" || continue
    if (( ${_KMS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_KMS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_KMS_LOST_REASON[$id]} service=kms check=$id account=$account region=$region keys_answered=${_KMS_EVALUATED[$id]} keys_unanswered=${_KMS_LOST[$id]} - this check ran, but ${_KMS_LOST[$id]} key(s) did not answer, so it is covered for some of this region's keys and not for others."
      fi
    elif (( ${_KMS_LOST[$id]:-0} > 0 )); then
      run_record coverage_reduction "module=cloud reason=${_KMS_LOST_REASON[$id]:-no_key_examined} service=kms check=$id account=$account region=$region keys_total=${_KMS_KEYS_TOTAL} - this check answered for NO key in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every key is configured correctly."
    fi
  done

  if (( _KMS_KEYS_TOTAL == 0 )); then
    run_record notes "module=cloud service=kms account=$account region=$region keys=0 - the region's key list was read successfully and contains no key, so every CLOUD-KMS-* check is covered vacuously."
  elif (( _KMS_KEYS_CUSTOMER_MANAGED == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_kms_keys_aws_managed service=kms account=$account region=$region keys_total=${_KMS_KEYS_TOTAL} - every key in this region is AWS-managed, so neither CLOUD-KMS-* check has a customer-managed key to evaluate. This is a real, declared absence of applicable resources, not a coverage loss."
  fi

  if (( _KMS_KEYS_CUSTOMER_MANAGED > 0 && _KMS_KEYS_ROTATION_ELIGIBLE == 0 )) && _kms_selected CLOUD-KMS-ROTATION_DISABLED-01; then
    run_record notes "module=cloud service=kms account=$account region=$region - none of the ${_KMS_KEYS_CUSTOMER_MANAGED} customer-managed key(s) in this region is an enabled, AWS_KMS-origin, symmetric encryption key, so CLOUD-KMS-ROTATION_DISABLED-01 had no eligible key to evaluate (asymmetric, HMAC, imported-material and disabled keys do not support the same automatic rotation)."
  fi

  if (( ran == 0 && _KMS_KEYS_CUSTOMER_MANAGED > 0 )); then
    run_record coverage_gap "cloud kms: account $account region $region has ${_KMS_KEYS_CUSTOMER_MANAGED} customer-managed key(s) and NOT ONE of the ${#_KMS_CHECK_IDS[@]} CLOUD-KMS-* checks answered for any of them, so no key's rotation setting or key policy was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above says why."
  fi
  return 0
}

_kms_run_service
