#!/usr/bin/env bash
# modules/cloud/aws/live/redshift.sh - the §8.1 Redshift read-only service
# pass (docs/DESIGN.md §8.1's `redshift` row; docs/STEP6-CLOUD-PLAN.md
# CLOUD-18).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with the identical
# contract s3.sh's own header states at length - no sourced-once guard here,
# since `redshift` is `regional` and this pass legitimately runs once per
# enabled region.  Its pure half is
# modules/cloud/aws/live/redshift_engine.sh, which does have a guard.
#
# `describe-clusters` ANSWERS TWO OF THE THREE CHECKS DIRECTLY
# (`PubliclyAccessible`, `Encrypted`), so those are read straight off the list
# response with no per-cluster call at all.  Only the third
# (`require_ssl`, encryption in transit) needs the second,
# `describe-cluster-parameters` call - see redshift_engine.sh's own header for
# why, and for the stated pagination gap on that one call.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/redshift_engine.sh
source "${BASH_SOURCE[0]%/*}/redshift_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _RS_CLUSTERS_TOTAL=0
declare -g _RS_CLUSTERS_EXAMINED=0
declare -gA _RS_EVALUATED=()
declare -gA _RS_LOST=()
declare -gA _RS_LOST_REASON=()

declare -ga _RS_CHECK_IDS=(
  CLOUD-REDSHIFT-PUBLIC_ACCESS-01
  CLOUD-REDSHIFT-NO_ENCRYPTION_AT_REST-01
  CLOUD-REDSHIFT-NO_ENCRYPTION_IN_TRANSIT-01
)

_rs_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_rs_note_evaluated() {
  _RS_EVALUATED[$1]=$(( ${_RS_EVALUATED[$1]:-0} + 1 ))
}

_rs_note_lost() {
  _RS_LOST[$1]=$(( ${_RS_LOST[$1]:-0} + 1 ))
  [[ -n ${_RS_LOST_REASON[$1]:-} ]] || _RS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_rs_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-redshift.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_RS_CHECK_IDS[@]+"${_RS_CHECK_IDS[@]}"}"; do
    _rs_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_redshift_checks_deselected service=redshift account=$account region=$region - every CLOUD-REDSHIFT-* check id was removed by this run's check-selection filters, so no Redshift API call was made and no cluster was examined."
    return 0
  fi

  local listf=$work/describe-clusters.json rc=0
  aws_ro redshift describe-clusters >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=redshift operation=describe-clusters account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the cluster list for this region could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO Redshift cluster was examined and none of the ${#_RS_CHECK_IDS[@]} CLOUD-REDSHIFT-* checks ran."
    run_record coverage_gap "cloud redshift: the cluster list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no cluster's public accessibility, encryption at rest or encryption in transit was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds redshift:DescribeClusters."
    return 0
  fi

  redshift_doc_load "$listf" || true
  local -a ids=() pubs=() encs=() pgs=()
  local i=0 cid pub enc pg
  while [[ -n ${_RS_DOCT[Clusters$'\x1f'$i$'\x1f'ClusterIdentifier]+set} ]]; do
    cid=${_RS_DOC[Clusters$'\x1f'$i$'\x1f'ClusterIdentifier]:-}
    pub=${_RS_DOC[Clusters$'\x1f'$i$'\x1f'PubliclyAccessible]:-}
    enc=${_RS_DOC[Clusters$'\x1f'$i$'\x1f'Encrypted]:-}
    pg=${_RS_DOC[Clusters$'\x1f'$i$'\x1f'ClusterParameterGroups$'\x1f'0$'\x1f'ParameterGroupName]:-}
    if [[ -n $cid ]]; then
      ids+=("$cid")
      pubs+=("$pub")
      encs+=("$enc")
      pgs+=("$pg")
    fi
    i=$(( i + 1 ))
  done
  _RS_CLUSTERS_TOTAL=${#ids[@]}

  local j
  for (( j = 0; j < ${#ids[@]}; j++ )); do
    _rs_examine_cluster "${ids[$j]}" "${pubs[$j]}" "${encs[$j]}" "${pgs[$j]}" "$work"
  done

  _rs_record_coverage "$account" "$region"
  return 0
}

# `_rs_examine_cluster IDENTIFIER PUBLICLY_ACCESSIBLE ENCRYPTED PARAM_GROUP
# WORKDIR` - PUBLICLY_ACCESSIBLE/ENCRYPTED are already-read fields off the
# `describe-clusters` list response (passed in rather than re-read, since the
# `require_ssl` call below overwrites the same document arrays this function
# would otherwise have to re-load from).  Never returns non-zero.
_rs_examine_cluster() {
  local cid=$1 pub=$2 enc=$3 pg=$4 work=$5
  local safe=${cid//[^A-Za-z0-9._-]/_}
  local arn
  arn=$(redshift_cluster_arn "$(cloud_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")" \
    "${SCOURSH_CLOUD_REGION:-}" "${SCOURSH_CLOUD_ACCOUNT_ID:-}" "$cid")
  _RS_CLUSTERS_EXAMINED=$(( _RS_CLUSTERS_EXAMINED + 1 ))

  local id=CLOUD-REDSHIFT-PUBLIC_ACCESS-01
  if _rs_selected "$id"; then
    _rs_note_evaluated "$id"
    if [[ $pub == true ]]; then
      redshift_emit_finding "$id" "$arn" \
        "Redshift cluster $cid ($arn) is configured with PubliclyAccessible=true, so it is reachable from outside its VPC over the internet if its security group and network ACLs permit the connection. Set the cluster to not publicly accessible and reach it through a VPN, Direct Connect, or a bastion/proxy inside the VPC instead."
    fi
  fi

  id=CLOUD-REDSHIFT-NO_ENCRYPTION_AT_REST-01
  if _rs_selected "$id"; then
    _rs_note_evaluated "$id"
    if [[ $enc != true ]]; then
      redshift_emit_finding "$id" "$arn" \
        "Redshift cluster $cid ($arn) has Encrypted=false, so its data blocks, backups and snapshots are held unencrypted on the underlying storage. Encryption at rest can only be enabled by creating a new, encrypted cluster from a snapshot and switching over to it - there is no in-place toggle."
    fi
  fi

  id=CLOUD-REDSHIFT-NO_ENCRYPTION_IN_TRANSIT-01
  if _rs_selected "$id"; then
    if [[ -z $pg ]]; then
      _rs_note_lost "$id" no_parameter_group
      run_record coverage_reduction "module=cloud reason=no_parameter_group service=redshift operation=describe-cluster-parameters cluster=$cid check=$id - the cluster's own describe-clusters response named no parameter group, so require_ssl could not be read at all."
    else
      local rc=0
      aws_ro redshift describe-cluster-parameters --parameter-group-name "$pg" >"$work/$safe.params.json" || rc=$?
      if (( rc != 0 )); then
        local reason=''
        aws_ro_reduction_reason_set reason
        _rs_note_lost "$id" "$reason"
        run_record coverage_reduction "module=cloud reason=$reason service=redshift operation=describe-cluster-parameters cluster=$cid parameter_group=$pg - the cluster's require_ssl setting could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}})."
      else
        _rs_note_evaluated "$id"
        redshift_doc_load "$work/$safe.params.json" || true
        if ! redshift_require_ssl_enabled; then
          redshift_emit_finding "$id" "$arn" \
            "Redshift cluster $cid ($arn)'s parameter group $pg does not set require_ssl to true, so a client can connect without TLS and the query traffic - including query text and result rows - crosses the network in the clear. Set require_ssl to true in the cluster's parameter group and apply it (a reboot may be required depending on the parameter's apply type)."
        fi
      fi
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_rs_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_RS_CHECK_IDS[@]+"${_RS_CHECK_IDS[@]}"}"; do
    _rs_selected "$id" || continue
    if (( ${_RS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_RS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_RS_LOST_REASON[$id]} service=redshift check=$id account=$account region=$region clusters_answered=${_RS_EVALUATED[$id]} clusters_unanswered=${_RS_LOST[$id]} of ${_RS_CLUSTERS_TOTAL} - this check ran, but ${_RS_LOST[$id]} cluster(s) did not answer, so it is covered for some of this region's clusters and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_RS_LOST_REASON[$id]:-no_cluster_examined} service=redshift check=$id account=$account region=$region clusters_total=${_RS_CLUSTERS_TOTAL} clusters_examined=${_RS_CLUSTERS_EXAMINED} - this check answered for NO cluster in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every cluster is configured correctly."
    fi
  done

  if (( _RS_CLUSTERS_TOTAL == 0 )); then
    run_record notes "module=cloud service=redshift account=$account region=$region clusters=0 - the cluster list was read successfully and contains no cluster, so every CLOUD-REDSHIFT-* check is covered vacuously."
  fi

  if (( ran == 0 && _RS_CLUSTERS_TOTAL > 0 )); then
    run_record coverage_gap "cloud redshift: account $account region $region has $_RS_CLUSTERS_TOTAL cluster(s) and NOT ONE of the ${#_RS_CHECK_IDS[@]} CLOUD-REDSHIFT-* checks answered for any of them, so no cluster's public accessibility, encryption at rest or encryption in transit was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_rs_run_service
