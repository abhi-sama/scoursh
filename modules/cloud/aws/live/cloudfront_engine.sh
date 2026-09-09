#!/usr/bin/env bash
# modules/cloud/aws/live/cloudfront_engine.sh - the pure half of the §8.1
# CloudFront read-only service (docs/DESIGN.md §8.1;
# docs/STEP6-CLOUD-PLAN.md CLOUD-24).
#
# The run.sh/engine.sh split s3_engine.sh established: this file is a pure
# function library with the standard sourced-once guard and no side effect at
# source time; modules/cloud/aws/live/cloudfront.sh is the file that DOES
# something when `cloud_run_service` sources it.
#
# CLOUDFRONT HAS NO PER-RESOURCE REGION AT ALL, UNLIKE S3.  A distribution is
# served from CloudFront's global edge network - there is no AWS region it
# "lives in" for a `get-distribution` call to resolve the way s3.sh resolves
# a bucket's.  `loc_region` for every finding here is therefore the literal
# `global`, exactly as docs/STEP6-CLOUD-PLAN.md's CLOUD-24 row states
# ("Global service; `region: global`"), and the cell
# modules/cloud/aws/run.sh already publishes for the `global` pass
# (`<account>/global`) agrees with it - unlike s3.sh, there is no
# cell-vs-resource-region split to reconcile here.
#
# THE ARN IS READ, NEVER CONSTRUCTED.  `get-distribution` returns a real
# `Distribution.ARN` field directly (`arn:aws:cloudfront::<account>:
# distribution/<id>`), so - unlike s3.sh's bucket ARN and elb.sh's Classic
# ELB ARN, both of which the API never returns - there is no partition to
# infer and nothing to build: one fact, one source.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_CLOUDFRONT_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_CLOUDFRONT_ENGINE_SOURCED=1

# -x back-edge cut: see s3_engine.sh's and elb_engine.sh's identical note -
# every file in this edge's chain is already inlined by the time this file is
# reached in the source graph that matters.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _CFD_DOC=()
declare -gA _CFD_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document (s3_doc_load's/elb_doc_load's pattern)
# ---------------------------------------------------------------------------
cfd_doc_load() {
  local file=$1
  _CFD_DOC=()
  _CFD_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _CFD_DOC[$path]=$val
    _CFD_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

cfd_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

cfd_doc_has() {
  [[ -n ${_CFD_DOCT[$1]+set} ]]
}

cfd_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_CFD_DOC[$__path]:-}"
  [[ -n ${_CFD_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The classifiers
# ---------------------------------------------------------------------------
# `cfd_viewer_policy_allows_http VALUE` - true for the ONE ViewerProtocolPolicy
# enum value that permits a viewer to reach this distribution over plain
# HTTP: `allow-all`.  `redirect-to-https` and `https-only` both enforce TLS at
# the viewer connection and are not flagged.
cfd_viewer_policy_allows_http() {
  [[ $1 == allow-all ]]
}

# `cfd_min_protocol_is_weak VALUE` - true for a MinimumProtocolVersion the
# CloudFront API can actually return that does NOT guarantee TLS 1.2.
#
# THE FIELD IS A CLOSED ENUM, UNLIKE elb.sh's POLICY NAME, so this is a
# membership test rather than elb_policy_is_weak's "proves strong" heuristic:
# CloudFront defines the exact set of values this field can hold (there is no
# operator-authored free text here the way there is a custom ELB policy
# name), so a fixed weak-list is complete rather than merely a best effort.
# `SSLv3`, `TLSv1` and `TLSv1_2016` predate a TLS-1.2 floor outright;
# `TLSv1.1_2016` explicitly names 1.1.  Every `TLSv1.2_*` value (`_2018`,
# `_2019`, `_2021`) and any later `TLSv1.3` value CloudFront adds guarantees
# 1.2 or better and is not flagged - matched by prefix so a future dated
# suffix this file has never seen still passes, rather than a hardcoded exact
# list flagging it as unrecognised-therefore-weak.
cfd_min_protocol_is_weak() {
  case $1 in
    SSLv3 | TLSv1 | TLSv1_2016 | TLSv1.1_2016) return 0 ;;
    TLSv1.2_* | TLSv1.3*) return 1 ;;
    # An empty value means the response carried none - CloudFront's API
    # always populates this field for every distribution, so an empty read
    # is a document this file did not expect, not a real "no minimum".
    # Reported as weak: the honest default under uncertainty is to say so
    # rather than to assume the strongest possible reading.
    *) return 0 ;;
  esac
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
cfd_registry_locate_set() {
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

# `cfd_emit_finding CHECK_ID ARN SUB_KEY EVIDENCE` - no REGION argument,
# unlike s3_emit_finding/elb_emit_finding: every CloudFront finding's
# `loc_region` is the literal `global` (this file's own header), so there is
# nothing for a caller to supply.
cfd_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  cfd_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/cloudfront emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-CLOUDFRONT-NO_LOGGING-01)
      finding_set exposure internal
      finding_set auth user
      ;;
    *)
      finding_set exposure internet
      finding_set auth none
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/global}"
  finding_set loc_account_id "$account"
  finding_set loc_region global
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
