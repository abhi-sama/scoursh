#!/usr/bin/env bash
# modules/cloud/aws/live/ecr_engine.sh - the pure half of the §8.1 ECR
# read-only service (docs/STEP6-CLOUD-PLAN.md CLOUD-25).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3_engine.sh established:
# this file is a pure function library with the standard sourced-once guard
# and no side effect at source time, and modules/cloud/aws/live/ecr.sh is the
# file that DOES something when `cloud_run_service` sources it.
#
# TWO CHECKS COME FREE OFF THE ONE LIST CALL, AND THAT SHAPES THE WHOLE
# SCRIPT.  `describe-repositories` already returns `imageTagMutability` and
# `imageScanningConfiguration.scanOnPush` per repository, so
# CLOUD-ECR-MUTABLE_TAGS-01 and CLOUD-ECR-SCAN_ON_PUSH_OFF-01 need no
# per-repository call at all - unlike s3.sh, whose seven checks each need
# their own operation because `list-buckets` names buckets and nothing
# about them.  Only CLOUD-ECR-PUBLIC_REPOSITORY-01 needs the per-resource
# `get-repository-policy` call, because a repository's public exposure is a
# property of a resource POLICY the list call does not carry.
#
# THERE IS NO ECR ANALOGUE OF S3's `get-bucket-policy-status`, AND THAT IS
# WHY THIS CHECK IS `confidence: medium` RATHER THAN `high`.  S3's own
# `s3_policy_is_public` reads AWS's OWN evaluation of the policy
# (`docs/DESIGN.md`'s reasoning: "the verdict is AWS's, not ours").  ECR has
# no equivalent single-call verdict, so `ecr.sh` reads the policy text
# itself and asks `iam_policy_engine.sh`'s `iampol_public_principal_grant_set`
# whether any `Effect: Allow` statement names the wildcard principal - the
# same heuristic every published open-source AWS CSPM tool uses for exactly
# this gap, and the reason the check's own record states the limitation in
# its remediation text rather than silently claiming AWS's own verdict.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_ECR_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_ECR_ENGINE_SOURCED=1

# -x back-edge cut: see s3_engine.sh's identical note - a real run already
# has modules/cloud/aws/engine.sh inlined by the time a service script
# reaches this file; only a direct-engine test sources it standalone.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _ECR_DOC=()
declare -gA _ECR_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading the describe-repositories document
# ---------------------------------------------------------------------------
ecr_doc_load() {
  local file=$1
  _ECR_DOC=()
  _ECR_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _ECR_DOC[$path]=$val
    _ECR_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

ecr_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

ecr_doc_has() {
  [[ -n ${_ECR_DOCT[$1]+set} ]]
}

ecr_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_ECR_DOC[$__path]:-}"
  [[ -n ${_ECR_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Per-repository classifiers, over the loaded describe-repositories doc
# ---------------------------------------------------------------------------
# `ecr_repo_name_set VARNAME I` / `ecr_repo_arn_set VARNAME I` - read
# repositories[I]'s own name and ARN, both supplied directly by AWS.  Unlike
# S3's bucket ARN (constructed, because list-buckets names only the bucket),
# ECR hands back a real ARN per repository - nothing here is built.
ecr_repo_name_set() {
  ecr_doc_get "$1" "$(ecr_path repositories "$2" repositoryName)"
}

ecr_repo_arn_set() {
  ecr_doc_get "$1" "$(ecr_path repositories "$2" repositoryArn)"
}

# `ecr_repo_tags_mutable I` - true when repositories[I]'s tag mutability is
# `MUTABLE` (AWS's own default for a repository created with no
# --image-tag-mutability, so this is the commonest finding rather than an
# edge case).
ecr_repo_tags_mutable() {
  [[ ${_ECR_DOC[$(ecr_path repositories "$1" imageTagMutability)]:-} == MUTABLE ]]
}

# `ecr_repo_scan_on_push_off I` - true when repositories[I]'s
# `imageScanningConfiguration.scanOnPush` is anything other than the boolean
# `true` - ABSENT counts as off, the same "an absent key is a gap, not a
# pass" rule s3_engine.sh's `s3_bpa_gaps_set` states, because a repository
# created before scan-on-push existed, or created with the setting
# unspecified, carries no scanning at all rather than some safe default.
ecr_repo_scan_on_push_off() {
  [[ ${_ECR_DOC[$(ecr_path repositories "$1" imageScanningConfiguration scanOnPush)]:-} != true ]]
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
# `ecr_registry_locate_set SETVAR IDXVAR CHECK_ID` - as s3_registry_locate_set.
ecr_registry_locate_set() {
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

# `ecr_emit_finding CHECK_ID REPO_ARN SUB_KEY EVIDENCE` - as
# s3_emit_finding: the static half (title, severity, cwe, owasp, remediation,
# `cis` where one is authored) comes entirely from the check RECORD via
# `finding_from_record`, never restated here.  ECR is a `regional` row in
# `_CLOUD_SERVICES` (unlike S3's `global`), so `SCOURSH_CLOUD_REGION` IS the
# repository's own real region - there is no separate per-resource region
# call the way s3.sh needs, and the finding's `cell` and `loc_region` are
# therefore the SAME value, which is the ordinary regional-service shape
# every later CLOUD-2x/3x service reuses.  SUB_KEY carries the offending
# statement's Sid for CLOUD-ECR-PUBLIC_REPOSITORY-01 and is empty for the
# other two checks, whose ARN alone already fully identifies the finding.
ecr_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  ecr_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/ecr emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-ECR-PUBLIC_REPOSITORY-01)
      finding_set exposure external
      finding_set auth none
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
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
