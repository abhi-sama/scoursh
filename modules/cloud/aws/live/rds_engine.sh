#!/usr/bin/env bash
# modules/cloud/aws/live/rds_engine.sh - the pure half of the §8.1 RDS
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-15).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3_engine.sh's own header
# documents, applied here unchanged: this file is a pure function library with
# the standard sourced-once guard and no side effect at source time, and
# modules/cloud/aws/live/rds.sh is the file that DOES something when
# `cloud_run_service` sources it.  Nothing here calls `aws_ro`, reads the run
# context or emits anything by itself.
#
# UNLIKE S3, RDS RETURNS EVERY PROPERTY THIS TICKET NEEDS INLINE ON THE LIST
# CALL.  `describe-db-instances` already carries `PubliclyAccessible`,
# `StorageEncrypted` and `BackupRetentionPeriod` on every element, so three of
# this script's four checks need no per-instance follow-up call at all - that
# is a fact about RDS's API shape, not a scope narrowing.  The fourth check
# (public snapshots) is the one property the list call does NOT carry, and
# `describe-db-snapshot-attributes` is a genuine list -> per-resource get, the
# same shape s3.sh's per-bucket calls use.
#
# TWO TRUNCATION SIGNALS lib/awscli.sh's shared `_awscli_detect_truncation`
# DOES NOT RECOGNISE, MEASURED AGAINST THE REAL RDS API SHAPE RATHER THAN
# ASSUMED.  Every RDS `describe-*` operation paginates with a bare `Marker` in
# the response (the family's own convention: DescribeDBInstances,
# DescribeDBSnapshots, DescribeDBClusters and friends all use `Marker`, never
# `NextMarker`/`NextToken`/any of the other keys `_awscli_detect_truncation`'s
# frozen table names) - RDS is the one AWS API family that spells its own
# continuation key differently from every service that table was built against.
# A response that IS truncated therefore comes back with `SCOURSH_AWS_RO_OUTCOME`
# still `ok`, and a caller that trusted that alone would report a short
# instance or snapshot list as a complete one - exactly the coverage-loss gap
# tension 25/lib/awscli.sh section 3 exists to close, reopened by one API
# family's own naming choice.  `rds_marker_present` below is what closes it;
# every list call in rds.sh checks it explicitly rather than trusting the
# outcome alone.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_RDS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_RDS_ENGINE_SOURCED=1

# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is
# reached, and `shellcheck -x` re-expands EVERY source edge it follows rather
# than memoising - see tests/lint-source-graph.sh.  A direct-engine test suite
# sources engine.sh itself.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g` on every global this file introduces, for the reason
# s3_engine.sh's own header records at length: in a real run nothing sources
# this file at top level, and `cloud_run_service` reaches it from inside a
# function, where a bare `declare -A` would create a LOCAL that dies with the
# first service pass.
declare -gA _RDS_DOC=()
declare -gA _RDS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `rds_doc_load FILE` - flatten FILE once into `_RDS_DOC`/`_RDS_DOCT`, the
# byte-identical pattern s3_engine.sh's `s3_doc_load` documents at length (an
# array field cannot be read leaf-by-leaf without already knowing its length,
# and only the type map tells an absent key from an explicit false/null one).
rds_doc_load() {
  local file=$1
  _RDS_DOC=()
  _RDS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe: a piped `while` runs its body in a
  # subshell and every key it stored is discarded when that subshell exits -
  # lib/core.sh's standing subshell lesson, in its loop form.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _RDS_DOC[$path]=$val
    _RDS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

rds_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

rds_doc_has() {
  [[ -n ${_RDS_DOCT[$1]+set} ]]
}

rds_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_RDS_DOC[$__path]:-}"
  [[ -n ${_RDS_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Truncation - the sharp edge this file's header names
# ---------------------------------------------------------------------------
# `rds_marker_present` - true when the LOADED document carries a non-empty,
# non-null `Marker` key at the top level, RDS's own (and only) continuation
# signal.  Called after `rds_doc_load` on a list response, alongside - never
# instead of - checking `SCOURSH_AWS_RO_OUTCOME` for `truncated`: a cached
# response reports `ok` unconditionally (lib/awscli.sh's `_awscli_serve_cached`
# never re-derives truncation), so this is the one place a truncated RDS list
# is actually detected at all.
rds_marker_present() {
  local t=${_RDS_DOCT[Marker]:-}
  case $t in
    '' | z) return 1 ;;
  esac
  [[ -n ${_RDS_DOC[Marker]:-} ]]
}

# ---------------------------------------------------------------------------
# 3. The snapshot-public classifier
# ---------------------------------------------------------------------------
# `rds_snapshot_attribute_is_public` - true when the LOADED
# `describe-db-snapshot-attributes` document's `restore` attribute names `all`
# among its values.  `all` is the literal, documented AWS sentinel for "every
# AWS account may restore this snapshot" (RFC-shaped, not a heuristic): a
# specific account id in the same list is a SHARE, not a public exposure, and
# is deliberately not flagged here - sharing with a named account is the
# ordinary, intended use of the `restore` attribute and reporting it would
# flood every estate that uses cross-account snapshot copies for backup.
rds_snapshot_attribute_is_public() {
  local __i=0 __name='' __j=0 __val=''
  while :; do
    rds_doc_has "$(rds_path DBSnapshotAttributesResult DBSnapshotAttributes "$__i" AttributeName)" || break
    rds_doc_get __name "$(rds_path DBSnapshotAttributesResult DBSnapshotAttributes "$__i" AttributeName)"
    if [[ $__name == restore ]]; then
      __j=0
      while rds_doc_has "$(rds_path DBSnapshotAttributesResult DBSnapshotAttributes "$__i" AttributeValues "$__j")"; do
        rds_doc_get __val "$(rds_path DBSnapshotAttributesResult DBSnapshotAttributes "$__i" AttributeValues "$__j")"
        [[ $__val == all ]] && return 0
        __j=$(( __j + 1 ))
      done
    fi
    __i=$(( __i + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 4. Emission
# ---------------------------------------------------------------------------
# `rds_registry_locate_set SETVAR IDXVAR CHECK_ID` - find CHECK_ID in the check
# registry this run loaded.  Byte-identical to s3_engine.sh's own
# `s3_registry_locate_set`; kept as a separate copy rather than a shared
# helper for the reason that file's own header gives for not centralising a
# service's classifiers in the module engine - a helper thirty services would
# each source grows into the union of thirty services' concerns.
rds_registry_locate_set() {
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

# `rds_emit_finding CHECK_ID ARN REGION SUB_KEY EVIDENCE`
#
# THE STATIC HALF COMES FROM THE CHECK RECORD, exactly as
# s3_engine.sh's `s3_emit_finding` documents at length - title, severity,
# confidence, cwe, owasp, remediation, references and `cis` are all fields of
# the registry record and are never restated here.
#
# UNLIKE S3, THE ARN IS NOT CONSTRUCTED - RDS returns a real, fully-qualified
# ARN (`DBInstanceArn`/`DBSnapshotArn`) directly on every response element,
# carrying its own account id, region and partition, so there is nothing to
# guess and no partition lookup needed.
#
# THE CELL IS THE PASS'S OWN REGION, AND FOR A REGIONAL SERVICE THAT IS THE
# SAME REGION THE FINDING CITES - unlike S3's global/per-bucket split, RDS is
# scanned once per enabled region (`_CLOUD_SERVICES` marks `live/rds.sh`
# `regional`), so the cell `cloud_run_service` published and the resource's own
# region are one and the same value here.
rds_emit_finding() {
  local check_id=$1 arn=$2 region=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  rds_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/rds emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-RDS-PUBLIC_ACCESS-01 | CLOUD-RDS-PUBLIC_SNAPSHOT-01)
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
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
