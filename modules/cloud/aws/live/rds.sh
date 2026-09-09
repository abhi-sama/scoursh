#!/usr/bin/env bash
# modules/cloud/aws/live/rds.sh - the §8.1 RDS read-only service pass
# (docs/DESIGN.md §8.1's `rds` row; docs/STEP6-CLOUD-PLAN.md CLOUD-15).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard - `rds` is a `regional` row in
# `_CLOUD_SERVICES`, so this file is legitimately reached once per enabled
# region, and a guard would silently make every region after the first a
# no-op.  Its pure half - every classifier, the truncation detector and the
# emitter - is modules/cloud/aws/live/rds_engine.sh, which does have a guard.
#
# WHY RDS IS A `regional` ROW.  Every RDS resource (instance, snapshot) lives
# in exactly one region and is addressed by a regional endpoint; there is no
# S3-shaped global namespace call here.  `cloud_run_service` therefore reaches
# this file once per region `regions.sh` resolved, with the ambient
# `SCOURSH_AWS_REGION` already set - every `aws_ro rds ...` call below
# addresses the CURRENT region without an explicit `--region` flag, unlike
# s3.sh's per-bucket calls, which must carry one because the pass itself is
# global.
#
# CELL EQUALS REGION HERE, AND THAT IS THE ORDINARY CASE tension 12 is built
# around - unlike S3's global/per-bucket split (see s3.sh's own note on why
# that split exists), a regional service's coverage cell and its findings'
# `loc_region` are the SAME value, because the pass genuinely visited nothing
# but that one region.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23), spelled
# literally at each call site with a literal service and operation, for the
# identical reason s3.sh's own header states: tests/lint-aws-readonly.sh parses
# the operation out of the source line, and a wrapper taking the operation in a
# variable would be invisible to it.  The response is redirected to a file
# rather than captured with `$(...)`, for `aws_ro_into`'s own subshell reason.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, identically to s3.sh:
#   1. `checks_run` NAMES WHAT SUCCEEDED - a check id is recorded only once its
#      own property was actually read for at least one resource.
#   2. AN `AccessDenied`, A THROTTLE, OR A TRUNCATED LIST IS A
#      `coverage_reduction`, NEVER SILENCE.  See rds_engine.sh's own header for
#      the RDS-specific truncation sharp edge (a bare `Marker`, which the
#      shared `_awscli_detect_truncation` does not recognise) this file checks
#      for explicitly rather than trusting `SCOURSH_AWS_RO_OUTCOME` alone.
#   3. A snapshot's `restore` attribute naming a SPECIFIC ACCOUNT (a share) is
#      NOT the same fact as naming `all` (public), and only the second is a
#      finding - see rds_engine.sh's own classifier note.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/rds_engine.sh
source "${BASH_SOURCE[0]%/*}/rds_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, for s3.sh's own reason: this file is sourced from INSIDE
# `cloud_run_service`, so a bare `declare` would make every one of these a
# local that dies with the pass.  Reset here rather than only declared, so a
# second pass in one process (a second region, or a second `scan_main` call in
# a test process) does not inherit the first pass's counters.
declare -g _RDS_INSTANCES_TOTAL=0
declare -g _RDS_INSTANCES_TRUNCATED=0
declare -g _RDS_SNAPSHOTS_TOTAL=0
declare -g _RDS_SNAPSHOTS_TRUNCATED=0
declare -gA _RDS_EVALUATED=()
declare -gA _RDS_LOST=()
declare -gA _RDS_LOST_REASON=()

# Every check id this pass can emit, in registry order - read by the
# selection gate, the `checks_run` roll-up and the not-evaluated accounting
# alike, the identical reasoning s3.sh's own `_S3_CHECK_IDS` header gives.
declare -ga _RDS_CHECK_IDS=(
  CLOUD-RDS-PUBLIC_ACCESS-01
  CLOUD-RDS-NO_ENCRYPTION-01
  CLOUD-RDS-NO_BACKUPS-01
  CLOUD-RDS-PUBLIC_SNAPSHOT-01
)

# `_rds_selected ID` - tension 15's per-check filter.  The `declare -F` guard
# is PERMISSIVE when the function is absent, byte-identical reasoning to
# s3.sh's own `_s3_selected`: a direct-engine test suite sources this script
# with no module engine in the process, and a fail-CLOSED default would make
# the whole pass inert while every "stays quiet" assertion in that suite still
# passed green.
_rds_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_rds_note_evaluated() {
  _RDS_EVALUATED[$1]=$(( ${_RDS_EVALUATED[$1]:-0} + 1 ))
}

_rds_note_lost() {
  _RDS_LOST[$1]=$(( ${_RDS_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, s3.sh's own reasoning: the earliest failure is usually
  # the actionable one and explains the rest.
  [[ -n ${_RDS_LOST_REASON[$1]:-} ]] || _RDS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_rds_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}
  # `mktemp -d`, never a name built from `$$` or a fixed string - the
  # CWE-377-via-CWE-59 reason s3.sh's own note gives at length.  No `-p`
  # (tension 24: GNU-only).
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-rds.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_RDS_CHECK_IDS[@]+"${_RDS_CHECK_IDS[@]}"}"; do
    _rds_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_rds_checks_deselected service=rds account=$account region=$region - every CLOUD-RDS-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no RDS API call was made and no instance or snapshot was examined."
    return 0
  fi

  # -------------------------------------------------------------------------
  # The instances.  A single list call carries every property the three
  # per-instance checks need - see rds_engine.sh's own header for why that is
  # a fact about RDS's API shape rather than a scope choice.
  # -------------------------------------------------------------------------
  local listf=$work/describe-db-instances.json rc=0
  aws_ro rds describe-db-instances >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    local cid
    for cid in CLOUD-RDS-PUBLIC_ACCESS-01 CLOUD-RDS-NO_ENCRYPTION-01 CLOUD-RDS-NO_BACKUPS-01; do
      _rds_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=rds operation=describe-db-instances account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's instance list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no instance was examined for public accessibility, encryption or backup retention."
    run_record coverage_gap "cloud rds: the instance list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no instance's public-accessibility, encryption-at-rest or backup-retention setting was tested in this region. A clean result here is the absence of a test, not the absence of a problem."
  else
    rds_doc_load "$listf" || true
    rds_marker_present && _RDS_INSTANCES_TRUNCATED=1
    local i=0 arn='' iid='' pub='' enc='' backup=''
    while :; do
      rds_doc_has "$(rds_path DBInstances "$i" DBInstanceIdentifier)" || break
      rds_doc_get iid "$(rds_path DBInstances "$i" DBInstanceIdentifier)"
      rds_doc_get arn "$(rds_path DBInstances "$i" DBInstanceArn)"
      rds_doc_get pub "$(rds_path DBInstances "$i" PubliclyAccessible)"
      rds_doc_get enc "$(rds_path DBInstances "$i" StorageEncrypted)"
      rds_doc_get backup "$(rds_path DBInstances "$i" BackupRetentionPeriod)"
      [[ -n $arn ]] && _rds_examine_instance "$arn" "$iid" "$region" "$pub" "$enc" "$backup"
      i=$(( i + 1 ))
    done
    _RDS_INSTANCES_TOTAL=$i
  fi

  # -------------------------------------------------------------------------
  # The snapshots - list, then per-manual-snapshot get.
  # -------------------------------------------------------------------------
  local id_ps=CLOUD-RDS-PUBLIC_SNAPSHOT-01
  if _rds_selected "$id_ps"; then
    local snapf=$work/describe-db-snapshots.json rc2=0
    aws_ro rds describe-db-snapshots >"$snapf" || rc2=$?
    if (( rc2 != 0 )); then
      local reason2=''
      aws_ro_reduction_reason_set reason2
      _rds_note_lost "$id_ps" "$reason2"
      run_record coverage_reduction "module=cloud reason=$reason2 service=rds operation=describe-db-snapshots account=$account region=$region - the region's snapshot list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no snapshot was examined for public restore access."
    else
      rds_doc_load "$snapf" || true
      rds_marker_present && _RDS_SNAPSHOTS_TRUNCATED=1
      # Drain the WHOLE list into plain arrays BEFORE examining any one
      # snapshot, never interleaved with the per-resource call below. This is
      # not a style choice: `_rds_examine_snapshot` itself calls
      # `rds_doc_load` on the snapshot's OWN attributes response, which
      # overwrites the SAME shared `_RDS_DOC`/`_RDS_DOCT` maps this list walk
      # reads through `rds_doc_has`/`rds_doc_get` - so a loop that called it
      # mid-walk would have its own list document clobbered out from under it
      # after the first snapshot, and silently stop after examining exactly
      # one. s3.sh's own bucket loop avoids this identical hazard the same
      # way: `buckets=()` is fully populated from `_S3_DOC` before
      # `_s3_examine_bucket` (which reloads `_S3_DOC` per check) is ever
      # called. Measured here as a real defect, not a hypothetical one - see
      # AGENTS.md's own "measured, not assumed" section.
      local -a snap_ids=() snap_arns=() snap_types=()
      local j=0 sarn='' sid='' stype=''
      while :; do
        rds_doc_has "$(rds_path DBSnapshots "$j" DBSnapshotIdentifier)" || break
        rds_doc_get sid "$(rds_path DBSnapshots "$j" DBSnapshotIdentifier)"
        rds_doc_get sarn "$(rds_path DBSnapshots "$j" DBSnapshotArn)"
        rds_doc_get stype "$(rds_path DBSnapshots "$j" SnapshotType)"
        snap_ids+=("$sid")
        snap_arns+=("$sarn")
        snap_types+=("$stype")
        j=$(( j + 1 ))
      done
      _RDS_SNAPSHOTS_TOTAL=$j
      local k=0
      for (( k = 0; k < j; k++ )); do
        # Only a MANUAL snapshot can ever be shared or made public - AWS does
        # not permit modify-db-snapshot-attribute on an automated snapshot at
        # all, so calling describe-db-snapshot-attributes on one can only
        # ever answer "not public", spending a real API call to learn a fact
        # already true by construction. Skipping it is a scope narrowing
        # backed by that documented AWS constraint, not a guess.
        if [[ ${snap_types[$k]} == manual && -n ${snap_arns[$k]} ]]; then
          _rds_examine_snapshot "${snap_arns[$k]}" "${snap_ids[$k]}" "$region"
        fi
      done
    fi
  fi

  _rds_record_coverage "$account" "$region"
  return 0
}

# `_rds_examine_instance ARN ID REGION PUBLICLY_ACCESSIBLE STORAGE_ENCRYPTED
#  BACKUP_RETENTION_PERIOD` - the three checks a single describe-db-instances
# element already answers.  Never returns non-zero.
_rds_examine_instance() {
  local arn=$1 iid=$2 region=$3 pub=$4 enc=$5 backup=$6
  local id=CLOUD-RDS-PUBLIC_ACCESS-01
  if _rds_selected "$id"; then
    _rds_note_evaluated "$id"
    if [[ $pub == true ]]; then
      rds_emit_finding "$id" "$arn" "$region" '' \
        "RDS instance $iid ($region) is configured PubliclyAccessible=true, so it has a public endpoint reachable from outside its VPC subject only to its security group rules. A misconfigured or overly permissive security group is then the only remaining barrier between this database and the internet. Set PubliclyAccessible to false and reach the instance through a bastion host, VPN, or an application tier inside the same VPC."
    fi
  fi

  id=CLOUD-RDS-NO_ENCRYPTION-01
  if _rds_selected "$id"; then
    _rds_note_evaluated "$id"
    if [[ $enc != true ]]; then
      rds_emit_finding "$id" "$arn" "$region" '' \
        "RDS instance $iid ($region) has StorageEncrypted=false, so its underlying storage, automated backups, read replicas and snapshots are all unencrypted at rest. Encryption at rest can only be enabled at CREATION time - remediating this requires creating an encrypted snapshot of the instance and restoring a new instance from it, then cutting over."
    fi
  fi

  id=CLOUD-RDS-NO_BACKUPS-01
  if _rds_selected "$id"; then
    _rds_note_evaluated "$id"
    if [[ $backup == 0 ]]; then
      rds_emit_finding "$id" "$arn" "$region" '' \
        "RDS instance $iid ($region) has BackupRetentionPeriod=0, so automated backups are disabled - which also disables point-in-time recovery, since PITR is built on the automated backup and transaction-log stream. An accidental deletion, a bad migration, or a compromised credential that damages this database's data is then unrecoverable except from a manual snapshot taken before the incident, if one exists. Set a non-zero retention period (7-35 days) to enable both automated backups and PITR."
    fi
  fi
  return 0
}

# `_rds_examine_snapshot ARN ID REGION` - the one per-resource GET this file
# makes.  Never returns non-zero: a snapshot whose attributes could not be
# read is an accounted-for reduction, not a reason to abandon the ones after
# it.
_rds_examine_snapshot() {
  local arn=$1 sid=$2 region=$3
  local id=CLOUD-RDS-PUBLIC_SNAPSHOT-01
  local f rc=0
  f=$(mktemp "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-rds-snapattr.XXXXXX")
  aws_ro rds describe-db-snapshot-attributes --db-snapshot-identifier "$sid" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _rds_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=rds operation=describe-db-snapshot-attributes snapshot=$sid - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this snapshot's restore-attribute list was NOT tested. Its absence from the findings is not evidence that it is private."
    rm -f -- "$f"
    return 0
  fi
  rds_doc_load "$f" || true
  rm -f -- "$f"
  _rds_note_evaluated "$id"
  if rds_snapshot_attribute_is_public; then
    rds_emit_finding "$id" "$arn" "$region" '' \
      "RDS snapshot $sid ($region) has its 'restore' attribute set to 'all', meaning ANY AWS account in this partition may restore a full copy of this database from it - not merely a named account, every account. This is AWS's own documented sentinel for a public snapshot, not an inference. Remove 'all' from the snapshot's restore attribute immediately (modify-db-snapshot-attribute --values-to-remove all) and review whether the snapshot was ever restored by an account you did not authorise."
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_rds_record_coverage() {
  local account=$1 region=$2 id
  local ran=0 lost=0
  for id in "${_RDS_CHECK_IDS[@]+"${_RDS_CHECK_IDS[@]}"}"; do
    _rds_selected "$id" || continue
    if (( ${_RDS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_RDS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_RDS_LOST_REASON[$id]} service=rds check=$id account=$account region=$region resources_answered=${_RDS_EVALUATED[$id]} resources_unanswered=${_RDS_LOST[$id]} - this check ran, but ${_RDS_LOST[$id]} resource(s) did not answer, so it is covered for some of this region's resources and not for others."
      fi
    else
      lost=$(( lost + 1 ))
      run_record coverage_reduction "module=cloud reason=${_RDS_LOST_REASON[$id]:-no_resource_examined} service=rds check=$id account=$account region=$region instances_total=${_RDS_INSTANCES_TOTAL} snapshots_total=${_RDS_SNAPSHOTS_TOTAL} - this check answered for NO resource in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every resource is configured correctly."
    fi
  done

  if (( _RDS_INSTANCES_TOTAL == 0 && _RDS_SNAPSHOTS_TOTAL == 0 )); then
    # A genuinely empty region. The instance list (and, when selected, the
    # snapshot list) was still read successfully - the run DID look and found
    # nothing to look at, which is what lets a prior finding for a since-
    # deleted instance be classified `fixed` rather than sitting at `unknown`
    # forever. This is the one place "no findings" legitimately means "nothing
    # wrong".
    run_record notes "module=cloud service=rds account=$account region=$region instances=0 snapshots=0 - the region's RDS instance and snapshot lists were read successfully and contain nothing, so every CLOUD-RDS-* check is covered vacuously."
  fi

  if (( _RDS_INSTANCES_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=rds operation=describe-db-instances account=$account region=$region instances_seen=$_RDS_INSTANCES_TOTAL - the instance list came back INCOMPLETE (a Marker continuation token was present), so an unknown number of this region's RDS instances were never enumerated and were not examined by any CLOUD-RDS-* check."
    run_record coverage_gap "cloud rds: the instance list for account $account region $region was truncated at $_RDS_INSTANCES_TOTAL instance(s), so an unknown number of instances were never examined. A clean result for those instances is the absence of a test, not the absence of a problem."
  fi

  if (( _RDS_SNAPSHOTS_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=rds operation=describe-db-snapshots account=$account region=$region snapshots_seen=$_RDS_SNAPSHOTS_TOTAL - the snapshot list came back INCOMPLETE (a Marker continuation token was present), so an unknown number of this region's RDS snapshots were never enumerated and were not examined for public restore access."
    run_record coverage_gap "cloud rds: the snapshot list for account $account region $region was truncated at $_RDS_SNAPSHOTS_TOTAL snapshot(s), so an unknown number of snapshots were never examined for public restore access."
  fi

  if (( ran == 0 && (_RDS_INSTANCES_TOTAL > 0 || _RDS_SNAPSHOTS_TOTAL > 0) )); then
    run_record coverage_gap "cloud rds: account $account region $region has $_RDS_INSTANCES_TOTAL instance(s) and $_RDS_SNAPSHOTS_TOTAL snapshot(s), and NOT ONE of the ${#_RDS_CHECK_IDS[@]} CLOUD-RDS-* checks answered for any of them, so no resource's public accessibility, encryption, backup retention or snapshot exposure was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_rds_run_service
