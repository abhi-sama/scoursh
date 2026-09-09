#!/usr/bin/env bash
# modules/cloud/aws/live/efs.sh - the §8.1 EFS read-only service pass
# (docs/DESIGN.md §8.1's `efs` row; docs/STEP6-CLOUD-PLAN.md CLOUD-19).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with the identical
# contract s3.sh's own header states at length - no sourced-once guard here,
# since `efs` is `regional` and this pass legitimately runs once per enabled
# region. Its pure half is modules/cloud/aws/live/efs_engine.sh, which does
# have a guard.
#
# `describe-file-systems` ANSWERS ENCRYPTION AT REST DIRECTLY (`Encrypted`)
# AND CARRIES THE ARN VERBATIM (`FileSystemArn`) - no per-resource call needed
# for either, the same shape opensearch.sh's `DomainStatus.ARN` gives.  Only
# the two policy-derived checks (public access, encryption in transit) need
# the second, `describe-file-system-policy` call, and ONE call serves BOTH -
# see efs_engine.sh's own header for why the two read an absent policy in
# opposite directions.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/efs_engine.sh
source "${BASH_SOURCE[0]%/*}/efs_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _EFS_TOTAL=0
declare -g _EFS_EXAMINED=0
declare -gA _EFS_EVALUATED=()
declare -gA _EFS_LOST=()
declare -gA _EFS_LOST_REASON=()

declare -ga _EFS_CHECK_IDS=(
  CLOUD-EFS-PUBLIC_ACCESS-01
  CLOUD-EFS-NO_ENCRYPTION_AT_REST-01
  CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01
)

_efs_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_efs_note_evaluated() {
  _EFS_EVALUATED[$1]=$(( ${_EFS_EVALUATED[$1]:-0} + 1 ))
}

_efs_note_lost() {
  _EFS_LOST[$1]=$(( ${_EFS_LOST[$1]:-0} + 1 ))
  [[ -n ${_EFS_LOST_REASON[$1]:-} ]] || _EFS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_efs_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-efs.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_EFS_CHECK_IDS[@]+"${_EFS_CHECK_IDS[@]}"}"; do
    _efs_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_efs_checks_deselected service=efs account=$account region=$region - every CLOUD-EFS-* check id was removed by this run's check-selection filters, so no EFS API call was made and no file system was examined."
    return 0
  fi

  local listf=$work/describe-file-systems.json rc=0
  aws_ro efs describe-file-systems >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=efs operation=describe-file-systems account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the file system list for this region could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO EFS file system was examined and none of the ${#_EFS_CHECK_IDS[@]} CLOUD-EFS-* checks ran."
    run_record coverage_gap "cloud efs: the file system list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no file system's public accessibility, encryption at rest or encryption in transit was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds elasticfilesystem:DescribeFileSystems."
    return 0
  fi

  efs_doc_load "$listf" || true
  local -a ids=() encs=() arns=()
  local i=0 fid enc arn
  while [[ -n ${_EFS_DOCT[FileSystems$'\x1f'$i$'\x1f'FileSystemId]+set} ]]; do
    fid=${_EFS_DOC[FileSystems$'\x1f'$i$'\x1f'FileSystemId]:-}
    enc=${_EFS_DOC[FileSystems$'\x1f'$i$'\x1f'Encrypted]:-}
    arn=${_EFS_DOC[FileSystems$'\x1f'$i$'\x1f'FileSystemArn]:-}
    if [[ -n $fid ]]; then
      ids+=("$fid")
      encs+=("$enc")
      arns+=("${arn:-arn:aws:elasticfilesystem:${region}:${account}:file-system/$fid}")
    fi
    i=$(( i + 1 ))
  done
  _EFS_TOTAL=${#ids[@]}

  local j
  for (( j = 0; j < ${#ids[@]}; j++ )); do
    _efs_examine_fs "${ids[$j]}" "${encs[$j]}" "${arns[$j]}" "$work"
  done

  _efs_record_coverage "$account" "$region"
  return 0
}

# `_efs_examine_fs ID ENCRYPTED ARN WORKDIR` - ENCRYPTED is already read off
# the `describe-file-systems` list response, for the identical reason
# redshift.sh's own `_rs_examine_cluster` takes PUBLICLY_ACCESSIBLE/ENCRYPTED
# as arguments rather than re-reading them: the policy call below overwrites
# the same document arrays. Never returns non-zero.
_efs_examine_fs() {
  local fid=$1 enc=$2 arn=$3 work=$4
  local safe=${fid//[^A-Za-z0-9._-]/_}
  _EFS_EXAMINED=$(( _EFS_EXAMINED + 1 ))

  local id=CLOUD-EFS-NO_ENCRYPTION_AT_REST-01
  if _efs_selected "$id"; then
    _efs_note_evaluated "$id"
    if ! efs_is_encrypted "$enc"; then
      efs_emit_finding "$id" "$arn" \
        "EFS file system $fid ($arn) has Encrypted=false, so the data and metadata it stores are held unencrypted on the underlying storage. Encryption at rest can only be set at creation time - there is no in-place toggle - so migrating the data to a new, encrypted file system (AWS DataSync or an EFS-to-EFS copy) is required to close this."
    fi
  fi

  local need_policy=0
  _efs_selected CLOUD-EFS-PUBLIC_ACCESS-01 && need_policy=1
  _efs_selected CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01 && need_policy=1
  (( need_policy )) || return 0

  local rc=0
  aws_ro efs describe-file-system-policy --file-system-id "$fid" >"$work/$safe.policy.json" || rc=$?
  local policy=''
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # `PolicyNotFound`: this file system has no resource policy at all.
      # Both checks are answered, in OPPOSITE directions - see
      # efs_engine.sh's own header note.
      policy=''
    else
      local reason=''
      aws_ro_reduction_reason_set reason
      local cid
      for cid in CLOUD-EFS-PUBLIC_ACCESS-01 CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01; do
        _efs_selected "$cid" && _efs_note_lost "$cid" "$reason"
      done
      run_record coverage_reduction "module=cloud reason=$reason service=efs operation=describe-file-system-policy file_system=$fid - the file system's resource policy could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so its public accessibility and in-transit-encryption enforcement were NOT tested."
      return 0
    fi
  else
    efs_doc_load "$work/$safe.policy.json" || true
    policy=${_EFS_DOC[Policy]:-}
  fi

  id=CLOUD-EFS-PUBLIC_ACCESS-01
  if _efs_selected "$id"; then
    _efs_note_evaluated "$id"
    if efs_policy_is_wide_open "$policy"; then
      efs_emit_finding "$id" "$arn" \
        "EFS file system $fid ($arn) has a resource policy granting an Allow statement to the wildcard Principal \"*\", so any principal that can reach a mount target for this file system - including one outside this account, if network access is otherwise available - can mount it without being named on the policy. This is a heuristic reading of the raw Policy document, not AWS's own evaluation; review the full policy for any Condition before treating this as certain. Scope the policy to specific principals, or a Condition on elasticfilesystem:AccessedViaMountTarget plus the expected VPC/account."
    fi
  fi

  id=CLOUD-EFS-NO_ENCRYPTION_IN_TRANSIT-01
  if _efs_selected "$id"; then
    _efs_note_evaluated "$id"
    if ! efs_policy_denies_insecure_transport "$policy"; then
      efs_emit_finding "$id" "$arn" \
        "EFS file system $fid ($arn) has no resource policy statement that denies access when aws:SecureTransport is false, so a client can mount it over unencrypted NFS instead of the TLS-wrapped transport the mount helper's -o tls option provides. Add a Deny statement conditioned on Bool aws:SecureTransport=false to the file system policy to require every client to connect over TLS."
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_efs_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_EFS_CHECK_IDS[@]+"${_EFS_CHECK_IDS[@]}"}"; do
    _efs_selected "$id" || continue
    if (( ${_EFS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_EFS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_EFS_LOST_REASON[$id]} service=efs check=$id account=$account region=$region filesystems_answered=${_EFS_EVALUATED[$id]} filesystems_unanswered=${_EFS_LOST[$id]} of ${_EFS_TOTAL} - this check ran, but ${_EFS_LOST[$id]} file system(s) did not answer, so it is covered for some of this region's file systems and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_EFS_LOST_REASON[$id]:-no_filesystem_examined} service=efs check=$id account=$account region=$region filesystems_total=${_EFS_TOTAL} filesystems_examined=${_EFS_EXAMINED} - this check answered for NO file system in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every file system is configured correctly."
    fi
  done

  if (( _EFS_TOTAL == 0 )); then
    run_record notes "module=cloud service=efs account=$account region=$region filesystems=0 - the file system list was read successfully and contains no file system, so every CLOUD-EFS-* check is covered vacuously."
  fi

  if (( ran == 0 && _EFS_TOTAL > 0 )); then
    run_record coverage_gap "cloud efs: account $account region $region has $_EFS_TOTAL file system(s) and NOT ONE of the ${#_EFS_CHECK_IDS[@]} CLOUD-EFS-* checks answered for any of them, so no file system's public accessibility, encryption at rest or encryption in transit was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_efs_run_service
