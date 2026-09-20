#!/usr/bin/env bash
# modules/cloud/aws/live/dynamodb.sh - the §8.1 DynamoDB read-only service
# pass (docs/DESIGN.md §8.1's `dynamodb` row; docs/STEP6-CLOUD-PLAN.md
# CLOUD-16).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with no
# sourced-once guard - `dynamodb` is a `regional` row in `_CLOUD_SERVICES`,
# reached once per enabled region, and a guard would silently make every
# region after the first a no-op. Its pure half is
# modules/cloud/aws/live/dynamodb_engine.sh, which does have a guard.
#
# THREE CHECKS, THREE DIFFERENT CALL SHAPES, and that variety is a fact about
# the API rather than an inconsistency to fix:
#
#   - Encryption and PITR are PER-TABLE: list-tables, then describe-table and
#     describe-continuous-backups for each name - the same list -> per-
#     resource get shape s3.sh's per-bucket calls use.
#   - The VPC-endpoint-policy check is PER-REGION, not per-table: a Gateway
#     endpoint is an account/VPC construct, not a property of any one table,
#     so it is examined once per pass from a single describe-vpc-endpoints
#     call rather than once per table.
#
# CELL EQUALS REGION HERE, the identical reasoning rds.sh's own header gives:
# `dynamodb` is `regional`, so the coverage cell `cloud_run_service` published
# and every finding's `loc_region` are the same value.
#
# EVERY AWS CALL GOES THROUGH `aws_ro`, spelled literally with a literal
# service and operation at each call site - s3.sh's and rds.sh's own reason:
# tests/lint-aws-readonly.sh parses the operation out of the source line, and
# a wrapper taking it in a variable would be invisible to it.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, identically to s3.sh/rds.sh:
# `checks_run` names what succeeded; a denied, throttled or truncated call is
# a `coverage_reduction`, never silence - see dynamodb_engine.sh's own header
# for the `LastEvaluatedTableName` truncation sharp edge this file checks for
# explicitly.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/dynamodb_engine.sh
source "${BASH_SOURCE[0]%/*}/dynamodb_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _DDB_TABLES_TOTAL=0
declare -g _DDB_TABLES_TRUNCATED=0
declare -gA _DDB_EVALUATED=()
declare -gA _DDB_LOST=()
declare -gA _DDB_LOST_REASON=()

declare -ga _DDB_CHECK_IDS=(
  CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01
  CLOUD-DYNAMODB-NO_ENCRYPTION-01
  CLOUD-DYNAMODB-NO_BACKUPS-01
)

# `_ddb_selected ID` - byte-identical reasoning to s3.sh's own `_s3_selected`
# and rds.sh's own `_rds_selected`: the `declare -F` guard is PERMISSIVE when
# absent, so a direct-engine test suite with no module engine in the process
# still exercises this script rather than going silently inert.
_ddb_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_ddb_note_evaluated() {
  _DDB_EVALUATED[$1]=$(( ${_DDB_EVALUATED[$1]:-0} + 1 ))
}

_ddb_note_lost() {
  _DDB_LOST[$1]=$(( ${_DDB_LOST[$1]:-0} + 1 ))
  [[ -n ${_DDB_LOST_REASON[$1]:-} ]] || _DDB_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_ddb_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-dynamodb.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_DDB_CHECK_IDS[@]+"${_DDB_CHECK_IDS[@]}"}"; do
    _ddb_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_dynamodb_checks_deselected service=dynamodb account=$account region=$region - every CLOUD-DYNAMODB-* check id was removed by this run's check-selection filters, so no DynamoDB API call was made and no table was examined."
    return 0
  fi

  _ddb_check_vpc_endpoints "$work" "$account" "$region"

  local partition
  partition=$(ddb_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  local id_enc=CLOUD-DYNAMODB-NO_ENCRYPTION-01 id_bak=CLOUD-DYNAMODB-NO_BACKUPS-01
  if _ddb_selected "$id_enc" || _ddb_selected "$id_bak"; then
    local listf=$work/list-tables.json rc=0
    aws_ro dynamodb list-tables >"$listf" || rc=$?
    if (( rc != 0 )); then
      local reason=''
      aws_ro_reduction_reason_set reason
      local cid
      for cid in "$id_enc" "$id_bak"; do
        _ddb_selected "$cid" && _ddb_note_lost "$cid" "$reason"
      done
      run_record coverage_reduction "module=cloud reason=$reason service=dynamodb operation=list-tables account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's table list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no table was examined for encryption or backup/PITR configuration."
      run_record coverage_gap "cloud dynamodb: the table list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no table's encryption-at-rest or point-in-time-recovery setting was tested in this region."
    else
      ddb_doc_load "$listf" || true
      ddb_last_evaluated_present && _DDB_TABLES_TRUNCATED=1
      # Drain the WHOLE table-name list into a plain array BEFORE examining
      # any one table, never interleaved with the per-table calls below -
      # `_ddb_examine_table` itself calls `ddb_doc_load` on describe-table's
      # and describe-continuous-backups' own responses, which overwrites the
      # SAME shared `_DDB_DOC`/`_DDB_DOCT` maps this list walk reads.
      # Interleaving the two would silently stop the walk after the first
      # table, once its own per-table response clobbered the list document
      # out from under it - see rds.sh's own identical note (measured there
      # as a real defect against this exact fixture shape, not assumed).
      local -a names=()
      local i=0 name=''
      while :; do
        ddb_doc_has "$(ddb_path TableNames "$i")" || break
        ddb_doc_get name "$(ddb_path TableNames "$i")"
        [[ -n $name ]] && names+=("$name")
        i=$(( i + 1 ))
      done
      _DDB_TABLES_TOTAL=$i
      local t
      for t in "${names[@]+"${names[@]}"}"; do
        _ddb_examine_table "$t" "$region" "$work" "$account" "$partition"
      done
    fi
  fi

  _ddb_record_coverage "$account" "$region"
  return 0
}

# `_ddb_check_vpc_endpoints WORKDIR ACCOUNT REGION` - the one per-region call.
# Never returns non-zero: an unreadable endpoint list is an accounted-for
# reduction, not a reason to abandon the per-table checks after it.
_ddb_check_vpc_endpoints() {
  local work=$1 account=$2 region=$3
  local id=CLOUD-DYNAMODB-PUBLIC_ENDPOINT_POLICY-01
  _ddb_selected "$id" || return 0

  local f=$work/describe-vpc-endpoints.json rc=0
  aws_ro ec2 describe-vpc-endpoints >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _ddb_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=dynamodb operation=describe-vpc-endpoints account=$account region=$region - the region's VPC endpoint list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no Gateway endpoint's policy was examined for this region."
    return 0
  fi

  ddb_doc_load "$f" || true
  # This call's own continuation key IS `NextToken`, which
  # `_awscli_detect_truncation` already recognises - `SCOURSH_AWS_RO_OUTCOME`
  # alone is trustworthy here, unlike list-tables below.
  local truncated=0
  [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && truncated=1

  # The call SUCCEEDED, so the check is credited whether or not any DynamoDB
  # endpoint exists in this region - "this account has no DynamoDB VPC
  # endpoint" is a genuine, different fact from "the endpoint's policy could
  # not be read", and crediting only the second would make an account with no
  # such endpoint read as untested rather than as having nothing this check
  # applies to.
  _ddb_note_evaluated "$id"

  local caller_arn=${SCOURSH_AWS_CALLER_ARN:-}
  local partition
  partition=$(ddb_partition_of "$caller_arn")

  local k=0 vid='' svc='' vtype='' policy=''
  while :; do
    ddb_doc_has "$(ddb_path VpcEndpoints "$k" VpcEndpointId)" || break
    ddb_doc_get vid "$(ddb_path VpcEndpoints "$k" VpcEndpointId)"
    ddb_doc_get svc "$(ddb_path VpcEndpoints "$k" ServiceName)"
    ddb_doc_get vtype "$(ddb_path VpcEndpoints "$k" VpcEndpointType)"
    # `.dynamodb` at the end of the service name, never a bare substring: a
    # service like `com.amazonaws.REGION.dynamodb-streams` (a real, separate
    # AWS service) would otherwise be misclassified as this one.
    if [[ $svc == *.dynamodb && $vtype == Gateway ]]; then
      policy=''
      if ddb_doc_has "$(ddb_path VpcEndpoints "$k" PolicyDocument)"; then
        ddb_doc_get policy "$(ddb_path VpcEndpoints "$k" PolicyDocument)"
      fi
      if [[ -n $policy ]] && ddb_vpce_policy_is_default_full_access "$policy"; then
        local arn
        arn=$(ddb_vpc_endpoint_arn "$partition" "$account" "$region" "$vid")
        ddb_emit_finding "$id" "$arn" "$region" "$vid" \
          "DynamoDB VPC Gateway endpoint $vid ($region) still carries AWS's own default 'Full Access' policy - Principal \"*\", Action \"*\", Resource \"*\", with no Condition narrowing it. Any principal that can reach this endpoint from inside the VPC - not merely the roles or accounts an operator intended - can use it to call any DynamoDB API action against any table in this account and region. Attach a scoped policy naming the specific principals, actions and table ARNs this endpoint is meant to serve."
      fi
    fi
    k=$(( k + 1 ))
  done

  if (( truncated )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=dynamodb operation=describe-vpc-endpoints account=$account region=$region endpoints_seen=$k - the VPC endpoint list came back INCOMPLETE, so an unknown number of this region's endpoints were never examined for a permissive policy."
    run_record coverage_gap "cloud dynamodb: the VPC endpoint list for account $account region $region was truncated, so an unknown number of endpoints were never examined for a permissive policy."
  fi
  return 0
}

# `_ddb_examine_table NAME REGION WORKDIR` - the two per-table checks.  Never
# returns non-zero: a table whose properties could not be read is an
# accounted-for reduction, not a reason to abandon the ones after it.
_ddb_examine_table() {
  local name=$1 region=$2 work=$3 account=$4 partition=$5
  local safe=${name//[^A-Za-z0-9._-]/_}
  # Constructed once, via `ddb_table_arn` (dynamodb_engine.sh), and used by
  # BOTH checks below - see that function's own header for why: reading the
  # ARN off `describe-table`'s response for one check and falling back to the
  # bare table name for the other (which makes no `describe-table` call of
  # its own) put the same table's two findings under two different
  # `loc_resource_key` values, a real defect this suite's own C-section
  # caught by looking one of them up by ARN and finding only the other.
  local arn
  arn=$(ddb_table_arn "$partition" "$region" "$account" "$name")

  local id_enc=CLOUD-DYNAMODB-NO_ENCRYPTION-01
  if _ddb_selected "$id_enc"; then
    local tf=$work/$safe.describe-table.json rc=0
    aws_ro dynamodb describe-table --table-name "$name" >"$tf" || rc=$?
    if (( rc != 0 )); then
      local reason=''
      aws_ro_reduction_reason_set reason
      _ddb_note_lost "$id_enc" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=dynamodb operation=describe-table table=$name - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this table's encryption configuration was NOT tested."
    else
      ddb_doc_load "$tf" || true
      _ddb_note_evaluated "$id_enc"
      if ! ddb_table_encrypted; then
        ddb_emit_finding "$id_enc" "$arn" "$region" '' \
          "DynamoDB table $name ($region) has no explicit encryption-at-rest configuration (describe-table returned no SSEDescription with Status ENABLED), so it relies on the default AWS-owned key: the data IS encrypted, but there is no separate, auditable key policy, no key rotation an operator controls, and no CloudTrail key-usage event when the key is used. Enable SSE with an AWS-managed key (alias/aws/dynamodb, no configuration needed) or a customer-managed key where a defined rotation schedule or key-policy separation of duties is required."
      fi
    fi
  fi

  local id_bak=CLOUD-DYNAMODB-NO_BACKUPS-01
  if _ddb_selected "$id_bak"; then
    local bf=$work/$safe.describe-continuous-backups.json rc2=0
    aws_ro dynamodb describe-continuous-backups --table-name "$name" >"$bf" || rc2=$?
    if (( rc2 != 0 )); then
      local reason2=''
      aws_ro_reduction_reason_set reason2
      _ddb_note_lost "$id_bak" "$reason2"
      run_record coverage_reduction "module=cloud reason=$reason2 service=dynamodb operation=describe-continuous-backups table=$name - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this table's point-in-time-recovery setting was NOT tested."
    else
      ddb_doc_load "$bf" || true
      _ddb_note_evaluated "$id_bak"
      if ! ddb_pitr_enabled; then
        ddb_emit_finding "$id_bak" "$arn" "$region" '' \
          "DynamoDB table $name ($region) has point-in-time recovery DISABLED, so a restore is only possible from a manual on-demand backup, if one exists, rather than to any second within the last 35 days. An accidental delete-item/put-item overwrite, a bad application deploy, or a compromised credential that damages this table's data is then recoverable only as far back as the last manual backup. Enable PITR (update-continuous-backups --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true); it costs storage proportional to the table's own change rate and needs no downtime to turn on."
      fi
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_ddb_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_DDB_CHECK_IDS[@]+"${_DDB_CHECK_IDS[@]}"}"; do
    _ddb_selected "$id" || continue
    if (( ${_DDB_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_DDB_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_DDB_LOST_REASON[$id]} service=dynamodb check=$id account=$account region=$region resources_answered=${_DDB_EVALUATED[$id]} resources_unanswered=${_DDB_LOST[$id]} - this check ran, but ${_DDB_LOST[$id]} resource(s) did not answer, so it is covered for some of this region's resources and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_DDB_LOST_REASON[$id]:-no_resource_examined} service=dynamodb check=$id account=$account region=$region tables_total=${_DDB_TABLES_TOTAL} - this check answered for NO resource in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every resource is configured correctly."
    fi
  done

  if (( _DDB_TABLES_TOTAL == 0 )); then
    run_record notes "module=cloud service=dynamodb account=$account region=$region tables=0 - the region's table list was read successfully and contains no table, so the per-table CLOUD-DYNAMODB-* checks are covered vacuously."
  fi

  if (( _DDB_TABLES_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=dynamodb operation=list-tables account=$account region=$region tables_seen=$_DDB_TABLES_TOTAL - the table list came back INCOMPLETE (a LastEvaluatedTableName continuation token was present, which lib/awscli.sh's shared truncation detector does not recognise), so an unknown number of this region's tables were never enumerated."
    run_record coverage_gap "cloud dynamodb: the table list for account $account region $region was truncated at $_DDB_TABLES_TOTAL table(s), so an unknown number of tables were never examined."
  fi

  if (( ran == 0 && _DDB_TABLES_TOTAL > 0 )); then
    run_record coverage_gap "cloud dynamodb: account $account region $region has $_DDB_TABLES_TOTAL table(s) and NOT ONE of the ${#_DDB_CHECK_IDS[@]} CLOUD-DYNAMODB-* checks answered for any resource, so no table's encryption, backup/PITR or VPC endpoint exposure was tested. This is a run that did not look, not a region with nothing wrong."
  fi
  return 0
}

_ddb_run_service
