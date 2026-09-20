#!/usr/bin/env bash
# modules/cloud/aws/live/efs_engine.sh - the pure half of the §8.1 EFS
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-19).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3.sh + s3_engine.sh
# established, copied verbatim - see opensearch_engine.sh's own header for the
# fuller restatement, not repeated here.
#
# EFS HAS NO `PubliclyAccessible`-STYLE FIELD, UNLIKE REDSHIFT, AND FOR A
# STRUCTURAL REASON RATHER THAN AN OMISSION: an EFS file system has no public
# endpoint at all - it is reached only through mount targets inside a VPC
# subnet, so "public" here cannot mean "reachable from the internet with no
# VPC" the way opensearch_engine.sh's own check does. It means the resource
# POLICY grants access without restricting it - to an unrelated account, or
# with no restriction at all - which is exactly
# modules/cloud/aws/engine.sh's `cloud_policy_is_wide_open` heuristic, applied
# to `describe-file-system-policy`'s `Policy` document instead of
# OpenSearch's `AccessPolicies`. See that function's own header for what it
# does and does not evaluate.
#
# ONE POLICY CALL SERVES TWO CHECKS (public access, encryption in transit),
# AND THE TWO READ "NO POLICY" IN OPPOSITE DIRECTIONS. `PolicyNotFound`
# (classified `not_found` by lib/awscli.sh - it matches the `*NotFound` glob)
# means the file system has no resource policy at all. For PUBLIC ACCESS that
# is a real answer meaning "not public" (there is no Allow statement to be
# open, exactly as an absent S3 bucket policy is "not public" in
# s3_engine.sh's own `_s3_check_policy`). For ENCRYPTION IN TRANSIT it is the
# OPPOSITE: no policy means no `Deny`-on-plaintext statement exists either, so
# TLS is NOT enforced - the finding FIRES. Getting this backwards in either
# direction is the false-negative-that-reads-as-a-pass shape this project's
# testing rule exists to catch, so modules/cloud/aws/live/efs.sh calls the
# two classifiers separately over the SAME loaded document rather than
# folding "no policy" into one shared boolean.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_EFS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_EFS_ENGINE_SOURCED=1

if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # -x back-edge cut: see opensearch_engine.sh's own identical note.
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _EFS_DOC=()
declare -gA _EFS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
efs_doc_load() {
  local file=$1
  _EFS_DOC=()
  _EFS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _EFS_DOC[$path]=$val
    _EFS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# ---------------------------------------------------------------------------
# 2. The classifiers
# ---------------------------------------------------------------------------
# `efs_is_encrypted` - `Encrypted` on one already-extracted `describe-file-
# systems` list entry (the caller passes the value; this file's list-walking
# lives in efs.sh, the same split s3.sh keeps between "read the list" and
# "classify one entry").
efs_is_encrypted() {
  [[ $1 == true ]]
}

# `efs_policy_is_wide_open POLICY_TEXT` - loads POLICY_TEXT (the unescaped
# `Policy` string from `describe-file-system-policy`, or empty for "no
# policy") and applies `cloud_policy_is_wide_open`.  Empty POLICY_TEXT is NOT
# open, per this file's own header note.
efs_policy_is_wide_open() {
  local text=$1
  [[ -n $text ]] || return 1
  cloud_policy_load "$text" || return 1
  cloud_policy_is_wide_open
}

# `efs_policy_denies_insecure_transport POLICY_TEXT` - the mirror image: empty
# POLICY_TEXT means NO enforcement exists, so this returns 1 (not denied,
# i.e. the NO_ENCRYPTION_IN_TRANSIT check fires) rather than short-circuiting
# to a pass.
efs_policy_denies_insecure_transport() {
  local text=$1
  [[ -n $text ]] || return 1
  cloud_policy_load "$text" || return 1
  cloud_policy_denies_insecure_transport
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
efs_registry_locate_set() {
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

# `efs_emit_finding CHECK_ID ARN EVIDENCE` - see opensearch_engine.sh's own
# `opensearch_emit_finding` header: the cell and the region are the same
# value here too, since `efs` is a `regional` service.
efs_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  efs_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/efs emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-EFS-PUBLIC_ACCESS-01)
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
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
