#!/usr/bin/env bash
# modules/cloud/aws/live/secretsmanager_engine.sh - the pure half of the §8.1
# Secrets Manager read-only service (docs/DESIGN.md §8.1;
# docs/STEP6-CLOUD-PLAN.md CLOUD-08).
#
# Same run.sh/engine.sh split as kms_engine.sh/kms.sh and s3_engine.sh/s3.sh;
# see either of those headers for why the split exists at all.
#
# REGIONAL, LIKE KMS: `secretsmanager list-secrets` names only the secrets
# whose primary or replica region is the CURRENT one, so the resource's real
# region IS the pass's region and the coverage cell is `<account>/<region>` -
# see kms_engine.sh's own header for the fuller version of this argument,
# which applies identically here.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_SECRETSMANAGER_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_SECRETSMANAGER_ENGINE_SOURCED=1

# -x back-edge cut: see kms_engine.sh's own identical note.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _SECM_DOC=()
declare -gA _SECM_DOCT=()

# `secm_doc_load FILE` - the byte-identical shape of `kms_doc_load` one file
# over; see that function's own header for the subshell hazard `< <(...)`
# avoids.
secm_doc_load() {
  local file=$1
  _SECM_DOC=()
  _SECM_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _SECM_DOC[$path]=$val
    _SECM_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

secm_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

secm_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_SECM_DOC[$__path]:-}"
  [[ -n ${_SECM_DOCT[$__path]+set} ]]
}

# `secm_list_entry_get_set VARNAME INDEX FIELD` - a scalar field of the
# `list-secrets` response's `SecretList[INDEX]`, over the CURRENTLY LOADED
# document.  Returns 1 (and VARNAME empty) when the field is absent - which,
# for `RotationEnabled` and `OwningService`, is itself a meaningful answer
# rather than a parse failure (see `secm_secret_rotation_enabled` and
# `secm_secret_owning_service` below).
secm_list_entry_field_set() {
  local __var=$1 __idx=$2 __field=$3
  secm_doc_get "$__var" "$(secm_path SecretList "$__idx" "$__field")"
}

# `secm_secret_rotation_enabled INDEX` - true when `SecretList[INDEX]`'s
# `RotationEnabled` is the boolean `true`.  ABSENT AND `false` MEAN THE SAME
# THING: a secret that has never had rotation configured carries no
# `RotationEnabled` key at all, exactly as an S3 bucket that never had
# versioning enabled returns `{}` rather than `Status: None`
# (`s3_versioning_status_set`'s own header) - so this is a direct field read,
# never a presence test.
secm_secret_rotation_enabled() {
  local idx=$1 v=''
  secm_list_entry_field_set v "$idx" RotationEnabled
  [[ $v == true ]]
}

# `secm_secret_owning_service INDEX` - the secret's `OwningService`, or empty
# for an operator-created secret.  A secret another AWS service created and
# manages (RDS's master-credential integration, for example) is that
# service's rotation policy to set, not a gap this account's operator can
# close from the Secrets Manager console alone - so the rotation check treats
# it as out of scope, the identical distinction kms_engine.sh's own
# `kms_key_is_customer_managed` draws for an AWS-managed KMS key.
secm_secret_owning_service() {
  local idx=$1 v=''
  secm_list_entry_field_set v "$idx" OwningService
  printf '%s' "$v"
}

# `secm_secret_deleted INDEX` - true when the secret carries `DeletedDate`,
# meaning it is already scheduled for permanent deletion. Not worth
# reporting a rotation or policy finding against a resource this account has
# already decided to remove.
secm_secret_deleted() {
  local idx=$1
  [[ -n ${_SECM_DOCT[$(secm_path SecretList "$idx" DeletedDate)]+set} ]]
}

# `secm_policy_field` - the `ResourcePolicy` leaf of a loaded
# `get-resource-policy` document, already unescaped once by `secm_doc_load`
# and ready for `cloud_policy_load` (see that function's own header for why a
# second unescape there would be wrong).
# EMPTY MEANS "NO POLICY ATTACHED", NOT AN ERROR: `get-resource-policy`
# answers 200 with no `ResourcePolicy` field at all when the secret carries
# none, the identical "an absent key in a successful response is a real
# answer" shape `s3_logging_target_set`'s own header documents for
# `LoggingEnabled`.
secm_policy_field() { printf '%s' "${_SECM_DOC[ResourcePolicy]:-}"; }

# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------
secm_registry_locate_set() {
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

# `secm_emit_finding CHECK_ID ARN SUB_KEY EVIDENCE` - see kms_emit_finding's
# own header for why REGION/ACCOUNT come from the pass's own context rather
# than an argument.
secm_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  secm_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/secretsmanager emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-SECRETSMANAGER-PUBLIC_POLICY-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      finding_set sensitive_data true
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-}"
  finding_set loc_account_id "${SCOURSH_CLOUD_ACCOUNT_ID:-}"
  finding_set loc_region "${SCOURSH_CLOUD_REGION:-}"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
