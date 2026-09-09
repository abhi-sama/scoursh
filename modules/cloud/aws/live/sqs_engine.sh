#!/usr/bin/env bash
# modules/cloud/aws/live/sqs_engine.sh - the pure half of the §8.1 SQS
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-29).
#
# The sns_engine.sh split, applied to SQS: `list-queues` names every queue by
# URL only (no ARN, no attributes), so `get-queue-attributes --attribute-names
# All` is the one per-queue call that answers both checks AND supplies the
# ARN itself (`Attributes.QueueArn`) - unlike SNS's `list-topics`, which
# already returns each topic's ARN directly.
#
# `sqs` IS `regional`, for the identical reason `sns` is: every queue this
# pass examines already belongs to `SCOURSH_CLOUD_REGION`, so `loc_region` is
# read straight off the pass's own ambient region rather than resolved
# per-resource.
#
# THE POLICY CHECK IS THE IDENTICAL CONSERVATIVE RULE sns_engine.sh's own
# `sns_policy_is_public` documents at length - Effect Allow, a wildcard
# Principal, and NO Condition at all - and is duplicated here rather than
# shared, for the reason this module's own JSON-flattener duplication already
# establishes (modules/cloud/aws/engine.sh's header): a shared classifier
# would need to live somewhere every future policy-bearing service
# (kms, secretsmanager, ssm, lambda - each already named in
# docs/STEP6-CLOUD-PLAN.md as needing "over-broad resource policy" detection)
# would source, and growing that into modules/cloud/aws/engine.sh now, ahead
# of those tickets, is exactly the premature shared-file growth that file's
# own header warns against.  A real third occurrence is the signal to lift it,
# not the second.
#
# SQS ATTRIBUTES ARE ALL STRINGS, EVEN BOOLEANS.  The SQS `Attributes` map is
# `Map<String,String>` end to end - `SqsManagedSseEnabled` therefore arrives
# as the flattened STRING `"true"`/`"false"`, never a JSON boolean, which is
# why `sqs_queue_encrypted` compares against the literal string rather than
# reading a `type` of `b`.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_SQS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_SQS_ENGINE_SOURCED=1

# -x back-edge cut: see sns_engine.sh's identical note.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _SQS_DOC=()
declare -gA _SQS_DOCT=()
declare -gA _SQS_POLICY_DOC=()
declare -gA _SQS_POLICY_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading a response document
# ---------------------------------------------------------------------------
sqs_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

sqs_doc_load() {
  local file=$1
  _SQS_DOC=()
  _SQS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _SQS_DOC[$path]=$val
    _SQS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

sqs_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_SQS_DOC[$__path]:-}"
  [[ -n ${_SQS_DOCT[$__path]+set} ]]
}

sqs_policy_string_load() {
  local text=$1
  _SQS_POLICY_DOC=()
  _SQS_POLICY_DOCT=()
  [[ -n $text ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _SQS_POLICY_DOC[$path]=$val
    _SQS_POLICY_DOCT[$path]=$type
  done < <(cloud_json_flatten <<<"$text" 2>/dev/null)
  return 0
}

sqs_policy_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_SQS_POLICY_DOC[$__path]:-}"
  [[ -n ${_SQS_POLICY_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Classifiers
# ---------------------------------------------------------------------------
_sqs_statement_condition_present() {
  local prefix
  prefix=$(sqs_path Statement "$1" Condition)
  local k
  for k in "${!_SQS_POLICY_DOCT[@]}"; do
    [[ $k == "$prefix"* ]] && return 0
  done
  return 1
}

_sqs_statement_principal_is_wildcard() {
  local i=$1 v=''
  sqs_policy_doc_get v "$(sqs_path Statement "$i" Principal)"
  [[ $v == '*' ]] && return 0
  sqs_policy_doc_get v "$(sqs_path Statement "$i" Principal AWS)"
  [[ $v == '*' ]] && return 0
  local j=0
  while sqs_policy_doc_get v "$(sqs_path Statement "$i" Principal AWS "$j")"; do
    [[ $v == '*' ]] && return 0
    j=$(( j + 1 ))
  done
  return 1
}

# `sqs_policy_is_public` - the byte-for-byte same rule as
# sns_engine.sh's `sns_policy_is_public`; see that function's own header (and
# this file's own, above) for why it is a separate copy rather than a shared
# call.
sqs_policy_is_public() {
  local i=0 effect=''
  while sqs_policy_doc_get effect "$(sqs_path Statement "$i" Effect)"; do
    if [[ $effect == Allow ]] \
      && _sqs_statement_principal_is_wildcard "$i" \
      && ! _sqs_statement_condition_present "$i"; then
      return 0
    fi
    i=$(( i + 1 ))
  done
  return 1
}

# `sqs_queue_arn_set VARNAME` - `Attributes.QueueArn`, over the loaded
# `get-queue-attributes` document.  Unlike SNS's `list-topics`, `list-queues`
# returns only a URL, so the ARN this check cites is read from the SAME
# per-queue call the checks themselves depend on rather than a separate
# lookup.
sqs_queue_arn_set() {
  local __var=$1 __p
  __p=$(sqs_path Attributes QueueArn)
  printf -v "$__var" '%s' "${_SQS_DOC[$__p]:-}"
  [[ -n ${_SQS_DOC[$__p]:-} ]]
}

sqs_queue_policy_string_set() {
  local __var=$1 __p
  __p=$(sqs_path Attributes Policy)
  printf -v "$__var" '%s' "${_SQS_DOC[$__p]:-}"
  [[ -n ${_SQS_DOC[$__p]:-} ]]
}

# `sqs_queue_encrypted` - true when the queue has either a customer-managed
# KMS key (`KmsMasterKeyId`) or the newer SQS-managed default encryption
# (`SqsManagedSseEnabled`, a STRING "true"/"false" per this file's own header
# note) turned on.  UNLIKE SNS, SQS DOES have a managed-by-default encryption
# option - so, mirroring S3's SSE-S3 exemption (s3_engine.sh's own
# `s3_encryption_algorithm_set` note), `SqsManagedSseEnabled=true` is NOT a
# finding: it is a real, AWS-managed encryption-at-rest configuration, and
# flagging every queue that has not opted into a customer-managed key instead
# would flag the majority of correctly-configured queues.
sqs_queue_encrypted() {
  local kms sse
  kms=${_SQS_DOC[$(sqs_path Attributes KmsMasterKeyId)]:-}
  [[ -n $kms ]] && return 0
  sse=${_SQS_DOC[$(sqs_path Attributes SqsManagedSseEnabled)]:-}
  [[ $sse == true ]] && return 0
  return 1
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
sqs_registry_locate_set() {
  local __setvar=$1 __idxvar=$2 __id=$3 __set='' __idx=''
  printf -v "$__setvar" '%s' ''
  printf -v "$__idxvar" '%s' ''
  for __set in "${CHECKS_REGISTRY_SETS[@]+"${CHECKS_REGISTRY_SETS[@]}"}"; do
    __idx=$(records_index_of_id "$__set" "$__id" 2>/dev/null) || continue
    printf -v "$__setvar" '%s' "$__set"
    printf -v "$__idxvar" '%s' "$__idx"
    return 0
  done
  return 1
}

sqs_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  sqs_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/sqs emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-SQS-PUBLIC_POLICY-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
