#!/usr/bin/env bash
# modules/cloud/aws/live/kms_engine.sh - the pure half of the §8.1 KMS
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-07).
#
# The run.sh/engine.sh split modules/sast/ established, reused one level down
# by s3_engine.sh/s3.sh (CLOUD-05) and copied here verbatim: this file is a
# pure function library with the standard sourced-once guard and no side
# effect at source time; modules/cloud/aws/live/kms.sh is the file that DOES
# something when `cloud_run_service` sources it.
#
# KMS IS `regional`, UNLIKE S3, AND THAT REMOVES A WHOLE CLASS OF S3's OWN
# BOOKKEEPING.  `kms list-keys` names only the keys that live in the CURRENT
# region (there is no cross-region KMS namespace to reconcile), so the
# resource's real region IS the pass's region and there is no separate
# per-resource region call to make, no `loc_region`-versus-`cell` split to
# document, and the coverage cell IS `<account>/<region>` rather than
# `<account>/global` - `modules/cloud/aws/engine.sh`'s own service table
# already states this as a fact about the service's API namespace, not a
# judgement made here.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_KMS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_KMS_ENGINE_SOURCED=1

# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is
# reached, and `shellcheck -x` re-expands EVERY source edge it follows rather
# than memoising - see tests/lint-source-graph.sh.  A direct-engine test suite
# sources engine.sh itself, mirroring s3_engine.sh's own identical guard.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, never a bare `declare`, for the reason s3_engine.sh's own
# header documents at length: this file executes inside `cloud_run_service`'s
# function scope in a real run, where a bare `declare -A` would create a local
# that dies with the pass.
declare -gA _KMS_DOC=()
declare -gA _KMS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `kms_doc_load FILE` - the byte-identical shape of `s3_doc_load` one level
# up, applied to a KMS response.  See that function's own header for why a
# whole-document map is required rather than `cloud_json_leaf` per lookup: a
# `describe-key` response is read for several distinct leaves per key, and a
# per-lookup re-flatten would re-parse the same document that many times.
kms_doc_load() {
  local file=$1
  _KMS_DOC=()
  _KMS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)`, never a pipe: a `... | while read` loop runs its body in a
  # SUBSHELL and every assignment made inside it is discarded the instant the
  # subshell exits, leaving an empty map and a check that reports every key
  # clean - lib/core.sh's `worker_id_set` lesson, in its loop form, and the
  # identical trap `s3_doc_load`'s own header names.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _KMS_DOC[$path]=$val
    _KMS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

kms_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

kms_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_KMS_DOC[$__path]:-}"
  [[ -n ${_KMS_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The classifiers
# ---------------------------------------------------------------------------
# `kms_key_manager` / `kms_key_state` / `kms_key_spec` / `kms_key_usage` /
# `kms_key_origin` - the loaded `describe-key` document's `KeyMetadata`
# fields, read once each and named so a call site never has to spell the
# US-joined path itself.
kms_key_manager() { printf '%s' "${_KMS_DOC[KeyMetadata$'\x1f'KeyManager]:-}"; }
kms_key_state()   { printf '%s' "${_KMS_DOC[KeyMetadata$'\x1f'KeyState]:-}"; }
kms_key_spec()    { printf '%s' "${_KMS_DOC[KeyMetadata$'\x1f'KeySpec]:-}"; }
kms_key_usage()   { printf '%s' "${_KMS_DOC[KeyMetadata$'\x1f'KeyUsage]:-}"; }
kms_key_origin()  { printf '%s' "${_KMS_DOC[KeyMetadata$'\x1f'Origin]:-}"; }
kms_key_arn()     { printf '%s' "${_KMS_DOC[KeyMetadata$'\x1f'Arn]:-}"; }

# `kms_key_is_customer_managed` - only a customer-managed key's rotation and
# policy are this account's to fix; an AWS-managed key (`aws/s3`, `aws/rds`,
# ...) is administered by the owning service and neither check applies to it.
kms_key_is_customer_managed() {
  [[ $(kms_key_manager) == CUSTOMER ]]
}

# `kms_key_rotation_eligible` - the narrower gate for the ROTATION check
# alone: `get-key-rotation-status` is only meaningful for an ENABLED,
# customer-managed, AWS_KMS-origin, SYMMETRIC_DEFAULT/ENCRYPT_DECRYPT key.  A
# key outside this set (pending deletion, imported key material, an
# asymmetric signing key, an HMAC key) is OUT OF SCOPE for this check rather
# than a coverage loss - the call is never attempted, so no `unsupported`
# outcome is ever manufactured for a key this check was never going to be
# able to say anything about.  Getting this gate wrong in the PERMISSIVE
# direction (calling the API anyway) would turn a real "not applicable" into
# a `coverage_reduction` that reads like a permission problem; getting it
# wrong in the RESTRICTIVE direction (skipping an eligible key) would
# silently under-report - both are stated here rather than left to be
# rediscovered.
kms_key_rotation_eligible() {
  kms_key_is_customer_managed || return 1
  [[ $(kms_key_state) == Enabled ]] || return 1
  [[ $(kms_key_origin) == AWS_KMS ]] || return 1
  [[ $(kms_key_spec) == SYMMETRIC_DEFAULT ]] || return 1
  [[ $(kms_key_usage) == ENCRYPT_DECRYPT ]] || return 1
  return 0
}

# `kms_rotation_enabled_set VARNAME` - the loaded `get-key-rotation-status`
# document's `KeyRotationEnabled`.  Returns 0 when rotation IS enabled (a
# pass), 1 otherwise - the same "return status carries the verdict" shape
# `s3_versioning_status_set` uses one level up.
kms_rotation_enabled_set() {
  local __var=$1 __v
  __v=${_KMS_DOC[KeyRotationEnabled]:-}
  printf -v "$__var" '%s' "$__v"
  [[ $__v == true ]]
}

# `kms_policy_field` - the `Policy` leaf of a loaded `get-key-policy`
# document, already unescaped once by `kms_doc_load` and ready for
# `cloud_policy_load` (see that function's own header for why a second
# unescape there would be wrong).
kms_policy_field() { printf '%s' "${_KMS_DOC[Policy]:-}"; }

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
# `kms_registry_locate_set` / `kms_emit_finding` - the byte-identical shape
# of `s3_registry_locate_set`/`s3_emit_finding` one level up; see that
# file's own header for why the static half of a finding is never restated
# here, and why a check id with no registry record is a loud internal error.
kms_registry_locate_set() {
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

# `kms_emit_finding CHECK_ID ARN SUB_KEY EVIDENCE` - REGION and ACCOUNT are
# read from `SCOURSH_CLOUD_REGION`/`SCOURSH_CLOUD_ACCOUNT_ID`, the pass's own
# context, rather than taken as arguments: unlike S3's bucket-region
# resolution, a KMS key's real region genuinely IS the pass's region (this
# file's own header explains why), so there is nothing here to resolve or to
# keep from colliding with the cell the way s3_emit_finding's own header
# warns about.
kms_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  kms_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/kms emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-KMS-PUBLIC_POLICY-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
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
