#!/usr/bin/env bash
# modules/cloud/aws/live/redshift_engine.sh - the pure half of the §8.1
# Redshift read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md
# CLOUD-18).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3.sh + s3_engine.sh
# established, copied verbatim - see opensearch_engine.sh's own header for the
# fuller restatement, not repeated here.
#
# TWO OF THREE CHECKS ARE DIRECT API BOOLEANS, NOT HEURISTICS.
# `describe-clusters` answers `PubliclyAccessible` and `Encrypted` directly on
# every cluster, so those two checks carry `confidence: high` exactly as
# S3's exact-field checks do - unlike OpenSearch/EFS's policy-text heuristic,
# there is nothing here to misread.
#
# ENCRYPTION IN TRANSIT HAS NO DIRECT FIELD AND NEEDS A SECOND CALL PER
# CLUSTER.  Redshift's TLS enforcement is a CLUSTER PARAMETER
# (`require_ssl`), not a `describe-clusters` attribute, so it is read via
# `describe-cluster-parameters --parameter-group-name <the cluster's own
# group>`.  A Redshift cluster carries exactly one parameter group (unlike an
# RDS instance's list of several), so the first (and only) entry in
# `ClusterParameterGroups` is the one to read - not an arbitrary choice among
# several, the way s3_engine.sh's own encryption-rule note has to caveat
# "only the first rule is read" for a field S3 genuinely allows to repeat.
#
# `describe-cluster-parameters` CAN PAGINATE (a `Marker` in its response), and
# this file does not follow it.  `lib/awscli.sh`'s own generic truncation
# detector (`_awscli_detect_truncation`) recognises `NextToken` / `NextMarker`
# / `NextContinuationToken` / `NextPageToken` / `nextForwardToken` /
# `NextRecordName` / `IsTruncated` - Redshift's Query-protocol JSON spells its
# continuation key the bare `Marker`, which is NOT on that list, so a
# truncated parameter list is not detected as `truncated` here and
# `require_ssl` could in principle sit on a page this call never reaches. This
# is a stated, inherited limitation of the shared chokepoint's truncation
# vocabulary, not something this ticket's scope extends to fixing across
# every `aws_ro` caller; `require_ssl` is one of Redshift's engine-default
# parameters and is returned on ordinary accounts, so this is a real but
# narrow gap rather than the common case.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_REDSHIFT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_REDSHIFT_ENGINE_SOURCED=1

if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # -x back-edge cut: see opensearch_engine.sh's own identical note.
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _RS_DOC=()
declare -gA _RS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
redshift_doc_load() {
  local file=$1
  _RS_DOC=()
  _RS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _RS_DOC[$path]=$val
    _RS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

# ---------------------------------------------------------------------------
# 2. The ARN
# ---------------------------------------------------------------------------
# `redshift_cluster_arn PARTITION REGION ACCOUNT IDENTIFIER` -
# `arn:<partition>:redshift:<region>:<account>:cluster:<identifier>`, the
# published Redshift resource-ARN format.  Constructed rather than read: a
# cluster's `ClusterNamespaceArn` field names a DIFFERENT resource (the
# cluster's namespace, a distinct ARN with its own UUID) and is not this
# ARN - using it would cite a resource that is not the one the finding is
# about.
redshift_cluster_arn() {
  printf 'arn:%s:redshift:%s:%s:cluster:%s' "$1" "$2" "$3" "$4"
}

# ---------------------------------------------------------------------------
# 3. The classifiers
# ---------------------------------------------------------------------------
# `redshift_require_ssl_enabled` - true when the loaded `describe-cluster-
# parameters` document's `require_ssl` parameter is `true`.  Absent from the
# response entirely (should not happen for an engine-default parameter, but a
# defensive read) is treated as NOT enabled - the reading that fails toward a
# finding rather than a silent pass, per this project's own testing rule.
redshift_require_ssl_enabled() {
  local i=0 name val
  while [[ -n ${_RS_DOCT[Parameters$'\x1f'$i$'\x1f'ParameterName]+set} ]]; do
    name=${_RS_DOC[Parameters$'\x1f'$i$'\x1f'ParameterName]:-}
    if [[ $name == require_ssl ]]; then
      val=${_RS_DOC[Parameters$'\x1f'$i$'\x1f'ParameterValue]:-}
      [[ $val == true ]]
      return $?
    fi
    i=$(( i + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 4. Emission
# ---------------------------------------------------------------------------
redshift_registry_locate_set() {
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

# `redshift_emit_finding CHECK_ID ARN EVIDENCE` - see opensearch_engine.sh's
# own `opensearch_emit_finding` header: the cell and the region are the same
# value here too, since `redshift` is a `regional` service.
redshift_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  redshift_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/redshift emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-REDSHIFT-PUBLIC_ACCESS-01)
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
