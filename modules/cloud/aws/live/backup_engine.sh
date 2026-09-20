#!/usr/bin/env bash
# modules/cloud/aws/live/backup_engine.sh - the pure half of the §8.1 AWS
# Backup read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md
# CLOUD-12).
#
# `backup` IS `regional` (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES`), so
# `loc_region` is the pass's own ambient region, exactly as
# sns_engine.sh/sqs_engine.sh/acm_engine.sh record for their own services.
#
# WHAT "CRITICAL RESOURCE" MEANS IN THIS CHECK, AND WHY - A DELIBERATE, STATED
# SCOPE DECISION.  docs/STEP6-CLOUD-PLAN.md's own CLOUD-12 note says this
# check "cross-references findings from CLOUD-05/13/14" (S3, EC2, ELB), but
# neither CLOUD-13 (`aws/live/ec2.sh`) nor CLOUD-14 (`aws/live/elb.sh`) exists
# on disk yet, and this file must not depend on another service's SCRIPT
# existing - `cloud_run_service` treats an absent script as a clean no-op, and
# `_CLOUD_SERVICES`' own header calls every row a PEER, invoked in any order.
# The v1 scope here is EBS VOLUMES: `ec2 describe-volumes` is a direct,
# self-contained read-only call this file makes on its own, EBS is a REGIONAL
# resource (so it needs no S3-style per-resource region resolution - the
# region a volume was listed in IS its region), and AWS Backup natively
# supports EBS as a resource type. S3 buckets were considered and rejected for
# v1: cross-referencing them correctly would need each bucket's own region
# resolved via `get-bucket-location` (a second, duplicative per-bucket call
# this service would be re-doing purely to filter "which buckets belong to
# THIS regional pass"), which is exactly the kind of expensive, duplicated
# work this module's own peer-service model is meant to avoid. Extending this
# check to S3/EC2-instance/RDS/ELB coverage is a stated, deliberate follow-up,
# not an oversight.
#
# THE COMPARISON IS AGAINST `backup list-protected-resources`, AWS'S OWN
# ANSWER TO "WHAT DOES THIS ACCOUNT'S BACKUP CONFIGURATION CURRENTLY PROTECT
# IN THIS REGION" - never a re-derivation from `list-backup-plans` /
# `list-backup-selections` / `get-backup-selection`.  The plan/selection path
# would also have to evaluate TAG-BASED and CONDITION-BASED selections (a
# selection may name resources by tag rather than by ARN), which needs a
# per-resource tag read this scope does not add; `list-protected-resources`
# answers the coverage question directly, with no re-implementation of AWS
# Backup's own selection-matching logic. It is a regional call, matching this
# pass's own `describe-volumes` call: a volume's backup jobs in AWS Backup run
# from a vault in the volume's OWN region, so the two calls made in the SAME
# region agree.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_BACKUP_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_BACKUP_ENGINE_SOURCED=1

# -x back-edge cut: see sns_engine.sh's identical note.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _BAK_DOC=()
declare -gA _BAK_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading a response document
# ---------------------------------------------------------------------------
backup_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

backup_doc_load() {
  local file=$1
  _BAK_DOC=()
  _BAK_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _BAK_DOC[$path]=$val
    _BAK_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

backup_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_BAK_DOC[$__path]:-}"
  [[ -n ${_BAK_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Classifiers
# ---------------------------------------------------------------------------
# `backup_partition_of CALLER_ARN` - byte-for-byte s3_engine.sh's
# `s3_partition_of`, duplicated for the reason route53_engine.sh's own header
# gives (a real third occurrence, not this one, is the signal to share it).
backup_partition_of() {
  local arn=${1:-} rest part
  case $arn in
    arn:*)
      rest=${arn#arn:}
      part=${rest%%:*}
      [[ -n $part ]] && { printf '%s' "$part"; return 0; }
      ;;
  esac
  printf '%s' aws
}

# `backup_volume_arn PARTITION REGION ACCOUNT VOLUME_ID`.
backup_volume_arn() {
  printf 'arn:%s:ec2:%s:%s:volume/%s' "$1" "$2" "$3" "$4"
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
backup_registry_locate_set() {
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

backup_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  backup_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/backup emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  finding_set exposure internal
  finding_set auth user
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
