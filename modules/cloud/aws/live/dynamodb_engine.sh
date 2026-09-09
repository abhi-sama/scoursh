#!/usr/bin/env bash
# modules/cloud/aws/live/dynamodb_engine.sh - the pure half of the §8.1
# DynamoDB read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md
# CLOUD-16).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3_engine.sh's own header
# documents, applied here unchanged: a pure function library with the standard
# sourced-once guard and no side effect at source time.
# modules/cloud/aws/live/dynamodb.sh is the file that DOES something.
#
# A SECOND TRUNCATION SIGNAL THE SHARED DETECTOR DOES NOT RECOGNISE, in the
# identical spirit rds_engine.sh's own header records (measured against the
# real API shape, not assumed): `list-tables` paginates with
# `LastEvaluatedTableName`, a name unique to this one DynamoDB operation and
# absent from `_awscli_detect_truncation`'s frozen key table
# (lib/awscli.sh section 3). A truncated table list therefore reports
# `SCOURSH_AWS_RO_OUTCOME=ok` unless this file checks the key itself, exactly
# the RDS `Marker` gap one level up.
#
# WHAT "PUBLIC ACCESSIBILITY" MEANS FOR A SERVICE WITH NO PUBLIC ENDPOINT
# CONCEPT.  Unlike S3 or RDS, DynamoDB has no bucket-policy-style internet-
# facing toggle: every table is reached through the AWS API endpoint (public,
# IAM-authenticated) or through a VPC Gateway endpoint, and the exposure this
# ticket's own scope names - "(VPC endpoint policy)" - is about the SECOND
# path: a Gateway endpoint created with no custom policy carries AWS's own
# documented default, a `Principal: "*"`, `Action: "*"`, `Resource: "*"`
# "Full Access" statement, which lets ANY principal reachable from inside the
# VPC use the endpoint to reach DynamoDB - not the wider internet, but a wider
# set of callers than an operator who bothered to attach an endpoint likely
# intended. `ddb_vpce_policy_is_default_full_access` below is a TEXT-SHAPE
# heuristic over the endpoint's own policy document, not an AWS-evaluated
# verdict: there is no `get-bucket-policy-status`-style evaluator API for a
# VPC endpoint policy, so this is the honest ceiling of what a read-only
# script can determine, and the check registry marks it `confidence: medium`
# for exactly that reason.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_DYNAMODB_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_DYNAMODB_ENGINE_SOURCED=1

# -x back-edge cut: see rds_engine.sh's own identical note - every file this
# edge would reach is already inlined by the time this file is sourced in a
# real run.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _DDB_DOC=()
declare -gA _DDB_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document - byte-identical pattern to
#    rds_engine.sh's own rds_doc_load/rds_path/rds_doc_has/rds_doc_get.
# ---------------------------------------------------------------------------
ddb_doc_load() {
  local file=$1
  _DDB_DOC=()
  _DDB_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _DDB_DOC[$path]=$val
    _DDB_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

ddb_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

ddb_doc_has() {
  [[ -n ${_DDB_DOCT[$1]+set} ]]
}

ddb_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_DDB_DOC[$__path]:-}"
  [[ -n ${_DDB_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Truncation - this file's own sharp edge
# ---------------------------------------------------------------------------
# `ddb_last_evaluated_present` - true when the LOADED document carries a
# non-empty, non-null `LastEvaluatedTableName` at the top level.  Checked
# alongside, never instead of, `SCOURSH_AWS_RO_OUTCOME` - a cached response
# reports `ok` unconditionally.
ddb_last_evaluated_present() {
  local t=${_DDB_DOCT[LastEvaluatedTableName]:-}
  case $t in
    '' | z) return 1 ;;
  esac
  [[ -n ${_DDB_DOC[LastEvaluatedTableName]:-} ]]
}

# ---------------------------------------------------------------------------
# 3. The classifiers
# ---------------------------------------------------------------------------
# `ddb_table_encrypted` - true when the LOADED `describe-table` document's
# `SSEDescription.Status` is `ENABLED`.
#
# AN ABSENT `SSEDescription` IS NOT "UNENCRYPTED" IN THE LITERAL SENSE - every
# DynamoDB table has been encrypted at rest with an AWS-owned key by default
# since December 2017, whether or not `SSEDescription` appears in the
# response at all. What its ABSENCE means is narrower and is what this check
# actually reports: no SEPARATE, AUDITABLE key was ever configured for this
# table, so there is no key policy to restrict who may use it and no
# CloudTrail key-usage event when it is used - the identical distinction
# `s3_encryption_algorithm_set`'s own header draws between SSE-S3 (a pass) and
# no configuration at all (a finding), carried over to DynamoDB's own default.
ddb_table_encrypted() {
  [[ ${_DDB_DOC[$(ddb_path Table SSEDescription Status)]:-} == ENABLED ]]
}

# `ddb_pitr_enabled` - true when the LOADED `describe-continuous-backups`
# document's `PointInTimeRecoveryStatus` is `ENABLED`.
ddb_pitr_enabled() {
  [[ ${_DDB_DOC[$(ddb_path ContinuousBackupsDescription PointInTimeRecoveryDescription PointInTimeRecoveryStatus)]:-} == ENABLED ]]
}

# `ddb_vpce_policy_is_default_full_access RAW_POLICY_TEXT` - a best-effort
# TEXT-SHAPE test for AWS's own documented, unmodified default Gateway
# endpoint policy: `{"Version":"2008-10-17","Statement":[{"Effect":"Allow",
# "Principal":"*","Action":"*","Resource":"*"}]}`, however the CLI's own
# pretty-printer happens to have spaced it.
#
# A `Condition` KEY ANYWHERE IN THE DOCUMENT IS TREATED AS "NOT THE DEFAULT",
# EVEN WHEN Principal AND Action ARE STILL BOTH `*` - the identical caution
# `s3_policy_is_public`'s own header states for a real evaluator's verdict,
# applied here as a text-level substitute: a wildcard Principal narrowed by a
# real Condition (`aws:SourceVpc`, `aws:PrincipalOrgID`) is a policy an
# operator deliberately reviewed and is not the untouched default, and
# reporting it anyway is a false positive on the operator's own hardening
# work. The unmodified AWS default carries no Condition block at all.
ddb_vpce_policy_is_default_full_access() {
  local raw=$1
  [[ $raw == *'"Condition"'* ]] && return 1
  case $raw in
    *'"Principal":"*"'* | *'"Principal": "*"'*) ;;
    *) return 1 ;;
  esac
  case $raw in
    *'"Action":"*"'* | *'"Action": "*"'*) return 0 ;;
  esac
  return 1
}

# ---------------------------------------------------------------------------
# 4. The ARN
# ---------------------------------------------------------------------------
# `ddb_partition_of CALLER_ARN` - byte-identical to s3_engine.sh's
# `s3_partition_of`, kept as a separate copy for the reason that file's own
# header gives for not centralising a service's concerns in the module
# engine.
ddb_partition_of() {
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

# `ddb_vpc_endpoint_arn PARTITION ACCOUNT REGION ID` -
# `arn:<partition>:ec2:<region>:<account>:vpc-endpoint/<id>`, AWS's own
# documented ARN format for a VPC endpoint (an EC2 resource type, so it takes
# the `ec2` service segment even though the endpoint fronts DynamoDB).
# `describe-vpc-endpoints` returns no ARN field on the endpoint element
# itself, unlike RDS's inline `DBInstanceArn`/`DBSnapshotArn`, so this is
# constructed rather than read - the same shape s3_engine.sh's `s3_bucket_arn`
# already uses for the identical reason.
ddb_vpc_endpoint_arn() {
  printf 'arn:%s:ec2:%s:%s:vpc-endpoint/%s' "$1" "$3" "$2" "$4"
}

# `ddb_table_arn PARTITION REGION ACCOUNT NAME` -
# `arn:<partition>:dynamodb:<region>:<account>:table/<name>`, DynamoDB's own
# documented, deterministic table ARN format.
#
# CONSTRUCTED, NEVER READ OFF `describe-table` - AND THAT IS WHAT KEEPS BOTH
# PER-TABLE CHECKS CITING THE SAME RESOURCE.  `describe-table`'s own response
# does carry a `TableArn`, but `describe-continuous-backups`' response does
# not carry any ARN at all - so a first draft that read the ARN off
# `describe-table` for the encryption check and fell back to the bare table
# NAME for the backup check (which makes no `describe-table` call of its own)
# put the SAME table's two findings under two DIFFERENT `loc_resource_key`
# values, which is a real defect: a consumer correlating findings by resource
# would never see them as the same table, and `tests/suites/cloud-
# dynamodb.sh`'s own C-section is what caught it - a resource-key lookup
# keyed on the ARN silently found only one of the two checks. Deriving it
# here, identically, for every caller removes the possibility of the two
# drifting apart again.
ddb_table_arn() {
  printf 'arn:%s:dynamodb:%s:%s:table/%s' "$1" "$2" "$3" "$4"
}

# ---------------------------------------------------------------------------
# 5. Emission
# ---------------------------------------------------------------------------
ddb_registry_locate_set() {
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

# `ddb_emit_finding CHECK_ID ARN REGION SUB_KEY EVIDENCE` - the static half
# comes from the check record, exactly as s3_emit_finding/rds_emit_finding
# document at length.
ddb_emit_finding() {
  local check_id=$1 arn=$2 region=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  ddb_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/dynamodb emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01)
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
