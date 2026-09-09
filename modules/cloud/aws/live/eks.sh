#!/usr/bin/env bash
# modules/cloud/aws/live/eks.sh - the §8.1 EKS read-only service pass
# (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-27).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` and carrying NO
# sourced-once guard - see s3.sh's own header for why one would silently
# turn every region after the first into a no-op.  `eks` is `regional`, so
# this runs once per enabled region with the ambient `aws_ro` region already
# pointed at it; no call here ever passes its own `--region`.
#
# `CLOUD-EKS-PUBLIC_ENDPOINT-01` NEEDS ONLY `describe-cluster` - AWS returns
# `endpointPublicAccess` and `publicAccessCidrs` directly on the cluster
# object, no per-resource follow-up call.  `CLOUD-EKS-
# POD_ROLE_OVERPERMISSIVE-01` needs two more levels: `list-nodegroups` then
# per-nodegroup `describe-nodegroup` to read `nodeRole`, then the shared
# `iam_policy_engine.sh` driver over that role's inline policies.  See
# eks_engine.sh's own header for what "pod role" means here and why it is a
# stated substitution rather than a literal per-ServiceAccount IRSA audit.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/eks_engine.sh
source "${BASH_SOURCE[0]%/*}/eks_engine.sh"
# shellcheck source=modules/cloud/aws/live/iam_policy_engine.sh
source "${BASH_SOURCE[0]%/*}/iam_policy_engine.sh"

declare -g _EKS_CLUSTERS_TOTAL=0
declare -g _EKS_CLUSTERS_EXAMINED=0
declare -g _EKS_NODEGROUPS_TOTAL=0
declare -g _EKS_CLUSTERS_TRUNCATED=0
declare -g _EKS_NODEGROUPS_TRUNCATED=0
declare -gA _EKS_EVALUATED=()
declare -gA _EKS_LOST=()
declare -gA _EKS_LOST_REASON=()

declare -ga _EKS_CHECK_IDS=(
  CLOUD-EKS-PUBLIC_ENDPOINT-01
  CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01
)

_eks_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_eks_note_evaluated() {
  _EKS_EVALUATED[$1]=$(( ${_EKS_EVALUATED[$1]:-0} + 1 ))
}

_eks_note_lost() {
  _EKS_LOST[$1]=$(( ${_EKS_LOST[$1]:-0} + 1 ))
  [[ -n ${_EKS_LOST_REASON[$1]:-} ]] || _EKS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_eks_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-eks.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_EKS_CHECK_IDS[@]+"${_EKS_CHECK_IDS[@]}"}"; do
    _eks_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_eks_checks_deselected service=eks account=$account region=$region - every CLOUD-EKS-* check id was removed by this run's check-selection filters, so no EKS API call was made and no cluster was examined."
    return 0
  fi

  local listf=$work/list-clusters.json rc=0
  aws_ro eks list-clusters >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=eks operation=list-clusters account=$account region=$region - the cluster list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO cluster, node group or role was examined and none of the ${#_EKS_CHECK_IDS[@]} CLOUD-EKS-* checks ran."
    run_record coverage_gap "cloud eks: the cluster list for account $account in $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no cluster's endpoint exposure or node-group role was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds eks:ListClusters."
    return 0
  fi
  [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && _EKS_CLUSTERS_TRUNCATED=1

  eks_doc_load "$listf" || true
  local -a clusters=()
  eks_array_collect clusters clusters
  local n=${clusters_n:-0}
  _EKS_CLUSTERS_TOTAL=$n

  local c
  for (( c = 0; c < n; c++ )); do
    _eks_examine_cluster "${clusters[$c]}" "$work"
  done

  _eks_record_coverage "$account" "$region"
  return 0
}

# `_eks_examine_cluster NAME WORKDIR` - describe-cluster (the endpoint
# check), then the node-group walk (the role check).  Never returns
# non-zero: a cluster that cannot be examined is an accounted-for
# reduction, not a reason to abandon the ones after it.
_eks_examine_cluster() {
  local name=$1 work=$2
  local safe=${name//[^A-Za-z0-9._-]/_}
  local descf=$work/describe-cluster-$safe.json rc=0
  aws_ro eks describe-cluster --name "$name" >"$descf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _eks_note_lost CLOUD-EKS-PUBLIC_ENDPOINT-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=eks operation=describe-cluster cluster=$name - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this cluster's endpoint exposure was NOT tested. Its node groups were not examined either, since the cluster's own ARN could not be resolved to cite in a finding."
    return 0
  fi
  _EKS_CLUSTERS_EXAMINED=$(( _EKS_CLUSTERS_EXAMINED + 1 ))

  eks_doc_load "$descf" || true
  local arn=''
  eks_cluster_arn_set arn
  [[ -n $arn ]] || arn="eks-cluster/$name"

  if _eks_selected CLOUD-EKS-PUBLIC_ENDPOINT-01; then
    _eks_note_evaluated CLOUD-EKS-PUBLIC_ENDPOINT-01
    if eks_cluster_endpoint_public; then
      local cidrs=''
      eks_cluster_public_cidrs_set cidrs
      eks_emit_finding CLOUD-EKS-PUBLIC_ENDPOINT-01 "$arn" '' \
        "Cluster $name ($arn) has its Kubernetes API endpoint reachable from outside the VPC (resourcesVpcConfig.endpointPublicAccess is true), admitting: $cidrs. The API server is the single most powerful control point in the cluster - anyone who can reach it and present valid credentials can create or modify any workload. Disable public access (endpointPublicAccess: false) and reach the endpoint over the VPC via endpointPrivateAccess, or at minimum restrict publicAccessCidrs to the specific ranges that legitimately need it rather than 0.0.0.0/0."
    fi
  fi

  _eks_walk_nodegroups "$name" "$arn" "$work"
  return 0
}

_eks_walk_nodegroups() {
  local cluster=$1 cluster_arn=$2 work=$3
  local id=CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01
  _eks_selected "$id" || return 0

  local safe=${cluster//[^A-Za-z0-9._-]/_}
  local ngf=$work/list-nodegroups-$safe.json rc=0
  aws_ro eks list-nodegroups --cluster-name "$cluster" >"$ngf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _eks_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=eks operation=list-nodegroups cluster=$cluster - the node group list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no node group's role in this cluster was examined."
    return 0
  fi
  [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && _EKS_NODEGROUPS_TRUNCATED=1

  eks_doc_load "$ngf" || true
  local -a groups=()
  eks_array_collect groups nodegroups
  local n=${groups_n:-0}
  _EKS_NODEGROUPS_TOTAL=$(( _EKS_NODEGROUPS_TOTAL + n ))

  if (( n == 0 )); then
    # A real, checked answer: this cluster has no node group at all
    # (Fargate-only, say), so there is no node role to over-assume.
    _eks_note_evaluated "$id"
    return 0
  fi

  local g
  for (( g = 0; g < n; g++ )); do
    _eks_check_nodegroup_role "$cluster" "${groups[$g]}" "$work"
  done
  return 0
}

_eks_check_nodegroup_role() {
  local cluster=$1 ng=$2 work=$3
  local id=CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01
  local safe="${cluster//[^A-Za-z0-9._-]/_}-${ng//[^A-Za-z0-9._-]/_}"
  local ngf=$work/describe-nodegroup-$safe.json rc=0
  aws_ro eks describe-nodegroup --cluster-name "$cluster" --nodegroup-name "$ng" >"$ngf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _eks_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=eks operation=describe-nodegroup cluster=$cluster nodegroup=$ng - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this node group's role was NOT tested."
    return 0
  fi

  eks_doc_load "$ngf" || true
  local rolearn=''
  eks_nodegroup_role_arn_set rolearn
  if [[ -z $rolearn ]]; then
    _eks_note_evaluated "$id"
    return 0
  fi

  local rolename result='' reason=''
  rolename=$(eks_iam_role_name_of "$rolearn")
  local rc2=0
  iam_role_overpermissive "$rolename" "$work" "${rolename//[^A-Za-z0-9._-]/_}" result reason || rc2=$?
  case $rc2 in
    0)
      _eks_note_evaluated "$id"
      eks_emit_finding "$id" "$rolearn" "$result" \
        "The node group $ng's IAM role $rolearn (cluster $cluster) has an inline policy granting Effect Allow with Action \"*\" on Resource \"*\" ($result). Every pod scheduled onto a node in this group that has NOT adopted a dedicated IAM Roles for Service Accounts (IRSA) binding inherits this role's full permission set via the EC2 instance metadata service. Replace the wildcard statement with the specific actions and resource ARNs the node's own workloads use, and require IRSA for any pod that needs AWS API access beyond that, so a compromised pod cannot reach the node role at all."
      ;;
    1)
      _eks_note_evaluated "$id"
      ;;
    *)
      _eks_note_lost "$id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=eks operation=iam:get-role-policy role=$rolename cluster=$cluster nodegroup=$ng - the node role's inline policies could not be fully read (${reason}), so its permissiveness was NOT tested. Its absence from the findings is not evidence that the role is scoped correctly."
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_eks_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_EKS_CHECK_IDS[@]+"${_EKS_CHECK_IDS[@]}"}"; do
    _eks_selected "$id" || continue
    if (( ${_EKS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_EKS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_EKS_LOST_REASON[$id]} service=eks check=$id account=$account region=$region clusters_answered=${_EKS_EVALUATED[$id]} clusters_unanswered=${_EKS_LOST[$id]} of ${_EKS_CLUSTERS_TOTAL} - this check ran, but ${_EKS_LOST[$id]} cluster(s)/node-group(s) did not answer, so it is covered for some of the region's clusters and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_EKS_LOST_REASON[$id]:-no_cluster_examined} service=eks check=$id account=$account region=$region clusters_total=${_EKS_CLUSTERS_TOTAL} clusters_examined=${_EKS_CLUSTERS_EXAMINED} - this check answered for NO cluster in $region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every cluster is configured correctly."
    fi
  done

  if (( _EKS_CLUSTERS_TOTAL == 0 )); then
    run_record notes "module=cloud service=eks account=$account region=$region clusters=0 - the cluster list was read successfully and contains no cluster, so every CLOUD-EKS-* check is covered vacuously."
  fi

  if (( _EKS_CLUSTERS_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=eks operation=list-clusters account=$account region=$region - the cluster list came back INCOMPLETE, so an unknown number of this region's clusters were never enumerated."
    run_record coverage_gap "cloud eks: the cluster list for account $account in $region was truncated, so an unknown number of clusters were never examined. A clean result for those clusters is the absence of a test, not the absence of a problem."
  fi
  if (( _EKS_NODEGROUPS_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=eks operation=list-nodegroups account=$account region=$region - a cluster's node-group list came back INCOMPLETE, so an unknown number of node groups were never enumerated."
    run_record coverage_gap "cloud eks: at least one cluster's node-group list for account $account in $region was truncated, so an unknown number of node-group roles were never examined."
  fi

  if (( ran == 0 && _EKS_CLUSTERS_TOTAL > 0 )); then
    run_record coverage_gap "cloud eks: account $account region $region has $_EKS_CLUSTERS_TOTAL cluster(s) and NOT ONE of the ${#_EKS_CHECK_IDS[@]} CLOUD-EKS-* checks answered for any of them, so no cluster's endpoint exposure or node role was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_eks_run_service
