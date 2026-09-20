#!/usr/bin/env bash
# modules/cloud/aws/live/backup.sh - the §8.1 AWS Backup read-only service
# pass (docs/DESIGN.md §8.1's `backup` row; docs/STEP6-CLOUD-PLAN.md
# CLOUD-12).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with NO
# sourced-once guard - `backup` is `regional`, reached once per enabled
# region.  Its pure half is modules/cloud/aws/live/backup_engine.sh, which
# states this check's v1 scope decision (EBS volumes, compared against
# `backup list-protected-resources`) at length; read it first.
#
# TWO CALLS, BOTH REGIONAL AND BOTH SELF-CONTAINED: `ec2 describe-volumes`
# names every EBS volume in this region; `backup list-protected-resources`
# names every resource AWS Backup itself currently protects in this region.
# Neither depends on another service's script existing on disk - this file
# calls `ec2` directly, matching the "peers, any order" contract
# modules/cloud/aws/run.sh's own header states for the whole service table.
#
# A FAILURE OF EITHER CALL IS A COVERAGE LOSS FOR THE WHOLE CHECK, NEVER A
# REASON TO GUESS.  A denied `describe-volumes` means the volume universe is
# unknown, so nothing can be said either way.  A denied
# `list-protected-resources` is the sharper trap: treating "we could not read
# what is protected" as "therefore nothing is protected" would manufacture a
# finding against a properly-backed-up volume purely because a permission was
# missing - the identical direction of failure route53.sh's own denied-bucket-
# list handling refuses to guess in.
#
# EVERY AWS CALL GOES THROUGH `aws_ro`, spelled literally with a literal
# service and operation (tests/lint-aws-readonly.sh; s3.sh's own header).
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/backup_engine.sh
source "${BASH_SOURCE[0]%/*}/backup_engine.sh"

declare -g _BAK_VOLUMES_TOTAL=0
declare -g _BAK_VOLUMES_EXAMINED=0
declare -gA _BAK_EVALUATED=()
declare -gA _BAK_LOST=()
declare -gA _BAK_LOST_REASON=()

declare -ga _BAK_CHECK_IDS=(
  CLOUD-BACKUP-NO_PLAN_COVERAGE-01
)

_backup_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_backup_note_lost() {
  _BAK_LOST[$1]=$(( ${_BAK_LOST[$1]:-0} + 1 ))
  [[ -n ${_BAK_LOST_REASON[$1]:-} ]] || _BAK_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_backup_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-backup.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  _backup_selected CLOUD-BACKUP-NO_PLAN_COVERAGE-01 || {
    run_record coverage_reduction "module=cloud reason=all_backup_checks_deselected service=backup account=$account region=$region - CLOUD-BACKUP-NO_PLAN_COVERAGE-01 was removed by this run's check-selection filters, so no Backup/EC2 API call was made and no volume was examined."
    return 0
  }

  local volf=$work/describe-volumes.json rc=0
  aws_ro ec2 describe-volumes >"$volf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _backup_note_lost CLOUD-BACKUP-NO_PLAN_COVERAGE-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=backup operation=describe-volumes account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's EBS volume list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so backup coverage was not evaluated for this region."
    run_record coverage_gap "cloud backup: the EBS volume list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no volume's backup coverage was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds ec2:DescribeVolumes."
    _backup_record_coverage "$account" "$region"
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=backup operation=describe-volumes account=$account region=$region - the volume list came back INCOMPLETE, so an unknown number of this region's volumes were never enumerated."
    run_record coverage_gap "cloud backup: the EBS volume list for account $account region $region was truncated, so an unknown number of volumes were never examined. A clean result for those volumes is the absence of a test, not the absence of a problem."
  fi

  local -a volume_ids=()
  local i=0 vid=''
  backup_doc_load "$volf" || true
  while :; do
    backup_doc_get vid "$(backup_path Volumes "$i" VolumeId)" || break
    [[ -n $vid ]] && volume_ids+=("$vid")
    i=$(( i + 1 ))
  done
  _BAK_VOLUMES_TOTAL=${#volume_ids[@]}

  local partition
  partition=$(backup_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")
  local -a arns=()
  for vid in "${volume_ids[@]+"${volume_ids[@]}"}"; do
    arns+=("$(backup_volume_arn "$partition" "$region" "$account" "$vid")")
  done

  if (( ${#arns[@]} == 0 )); then
    _BAK_EVALUATED[CLOUD-BACKUP-NO_PLAN_COVERAGE-01]=1
    run_record notes "module=cloud service=backup account=$account region=$region volumes=0 - the region's EBS volume list was read successfully and contains no volume, so CLOUD-BACKUP-NO_PLAN_COVERAGE-01 is covered vacuously."
    _backup_record_coverage "$account" "$region"
    return 0
  fi

  local protf=$work/list-protected-resources.json
  rc=0
  aws_ro backup list-protected-resources >"$protf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _backup_note_lost CLOUD-BACKUP-NO_PLAN_COVERAGE-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=backup operation=list-protected-resources account=$account region=$region - the region's Backup-protected-resource list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this region's ${#arns[@]} volume(s) were NOT tested. Their absence from the findings is not evidence that they are backed up: a denied read of what IS protected must never be read as 'therefore nothing is protected'."
    run_record coverage_gap "cloud backup: the Backup-protected-resource list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so backup coverage was not evaluated for any of this region's ${#arns[@]} volume(s)."
    _backup_record_coverage "$account" "$region"
    return 0
  fi
  local -A protected=()
  local parn=''
  backup_doc_load "$protf" || true
  i=0
  while :; do
    backup_doc_get parn "$(backup_path Results "$i" ResourceArn)" || break
    [[ -n $parn ]] && protected[$parn]=1
    i=$(( i + 1 ))
  done

  _BAK_EVALUATED[CLOUD-BACKUP-NO_PLAN_COVERAGE-01]=1
  local a
  for a in "${arns[@]+"${arns[@]}"}"; do
    _BAK_VOLUMES_EXAMINED=$(( _BAK_VOLUMES_EXAMINED + 1 ))
    if [[ -z ${protected[$a]:-} ]]; then
      backup_emit_finding CLOUD-BACKUP-NO_PLAN_COVERAGE-01 "$a" \
        "EBS volume $a in region $region has no recovery point recorded against it by AWS Backup (backup list-protected-resources does not name this ARN), so no backup plan currently covers it. A volume with no recovery point is unrecoverable if it is accidentally deleted, corrupted, or encrypted by ransomware. Add this volume to a backup plan's resource selection (by ARN, tag, or an account-wide wildcard selection), or confirm it is intentionally excluded (e.g. purely ephemeral scratch storage)."
    fi
  done

  _backup_record_coverage "$account" "$region"
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_backup_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_BAK_CHECK_IDS[@]+"${_BAK_CHECK_IDS[@]}"}"; do
    _backup_selected "$id" || continue
    if (( ${_BAK_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
    else
      run_record coverage_reduction "module=cloud reason=${_BAK_LOST_REASON[$id]:-no_volume_examined} service=backup check=$id account=$account region=$region volumes_total=${_BAK_VOLUMES_TOTAL} volumes_examined=${_BAK_VOLUMES_EXAMINED} - this check did not complete for this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every volume is backed up."
    fi
  done

  if (( ran == 0 && _BAK_VOLUMES_TOTAL > 0 )); then
    run_record coverage_gap "cloud backup: account $account region $region has $_BAK_VOLUMES_TOTAL volume(s) and CLOUD-BACKUP-NO_PLAN_COVERAGE-01 did not complete, so no volume's backup coverage was tested. This is a run that did not look, not a region with nothing wrong - the coverage_reduction above names the failure class."
  fi
  return 0
}

_backup_run_service
