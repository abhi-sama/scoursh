#!/usr/bin/env bash
# modules/cloud/aws/live/eks_engine.sh - the pure half of the §8.1 EKS
# read-only service (docs/STEP6-CLOUD-PLAN.md CLOUD-27).
#
# The run.sh/engine.sh split every other live/ script uses: no side effect
# at source time, no `aws_ro` call anywhere in this file, and the standard
# sourced-once guard.  modules/cloud/aws/live/eks.sh is the file that DOES
# something when `cloud_run_service` sources it.
#
# "POD ROLE OVER-PERMISSIVE" IS EVALUATED AS THE NODE GROUP'S OWN IAM ROLE,
# AND THAT SUBSTITUTION IS A STATED, DELIBERATE GAP RATHER THAN A GUESS.
# The literal per-pod role a Kubernetes workload assumes under IAM Roles for
# Service Accounts (IRSA) is a binding recorded on a Kubernetes
# ServiceAccount object inside the CLUSTER's own API server - not an AWS
# resource, and not observable through any `aws eks *` read-only call.
# scoursh has no Kubernetes credential and no cluster network path (the same
# boundary docs/DESIGN.md §7.5 and DAST-04's own SPA gap already draw for a
# client-rendered application scoursh cannot execute), so a literal
# per-ServiceAccount IRSA audit is out of reach here.  What IS reachable,
# and is a real, well-known finding in its own right: every pod scheduled
# onto a worker node that has NOT adopted IRSA for it inherits that NODE's
# own IAM role via the EC2 instance metadata service, so an over-permissive
# NODE GROUP role is exactly as reachable from arbitrary pod-controlled code
# as an over-permissive per-pod role would be, on any node running a
# workload without its own IRSA binding.  `eks_engine.sh` therefore
# evaluates `nodeRole`, the one IAM role the EKS API surfaces per node
# group, and CLOUD-EKS-POD_ROLE_OVERPERMISSIVE-01's own evidence and
# remediation text say precisely this rather than claiming a literal
# per-pod audit that was never performed.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_EKS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_EKS_ENGINE_SOURCED=1

if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _EKS_DOC=()
declare -gA _EKS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
eks_doc_load() {
  local file=$1
  _EKS_DOC=()
  _EKS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _EKS_DOC[$path]=$val
    _EKS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

eks_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

eks_doc_has() {
  [[ -n ${_EKS_DOCT[$1]+set} ]]
}

eks_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_EKS_DOC[$__path]:-}"
  [[ -n ${_EKS_DOCT[$__path]+set} ]]
}

# `eks_array_collect VARNAME ARRAYPATH` - as ecs_engine.sh's own
# `ecs_array_collect`.  `list-clusters`'s `clusters` and
# `list-nodegroups`'s `nodegroups` are both bare arrays of NAMES (not ARNs -
# unlike ECS's `clusterArns`/`serviceArns`, EKS's list operations name
# resources by their short name only, and every later call in this file
# takes that name, never an ARN).
eks_array_collect() {
  local __var=$1 __prefix=$2 __i=0 __p __v
  local -a __out=()
  while :; do
    __p=$(eks_path "$__prefix" "$__i")
    eks_doc_has "$__p" || break
    __v=${_EKS_DOC[$__p]:-}
    [[ -n $__v ]] && __out+=("$__v")
    __i=$(( __i + 1 ))
  done
  local __j
  for __j in "${!__out[@]}"; do
    printf -v "${__var}[$__j]" '%s' "${__out[$__j]}"
  done
  printf -v "${__var}_n" '%s' "${#__out[@]}"
  return 0
}

# ---------------------------------------------------------------------------
# 2. Classifiers, over a loaded describe-cluster document
# ---------------------------------------------------------------------------
eks_cluster_arn_set() {
  eks_doc_get "$1" "$(eks_path cluster arn)"
}

# `eks_cluster_endpoint_public` - true when
# `cluster.resourcesVpcConfig.endpointPublicAccess` is the boolean `true`.
eks_cluster_endpoint_public() {
  [[ ${_EKS_DOC[$(eks_path cluster resourcesVpcConfig endpointPublicAccess)]:-} == true ]]
}

# `eks_cluster_public_cidrs_set VARNAME` - the space-joined
# `publicAccessCidrs` list, or the literal `0.0.0.0/0` when the document
# carries none at all - AWS's own default the moment public access is
# enabled and no CIDR restriction is configured, so an ABSENT list is the
# widest case rather than a narrower one (the identical "an absent key is
# the open case, not the safe one" rule s3_engine.sh's `s3_bpa_gaps_set`
# states for Block Public Access).
eks_cluster_public_cidrs_set() {
  local __var=$1 __i=0 __p __v __out=''
  while :; do
    __p=$(eks_path cluster resourcesVpcConfig publicAccessCidrs "$__i")
    eks_doc_has "$__p" || break
    __v=${_EKS_DOC[$__p]:-}
    [[ -n $__v ]] && __out+="${__out:+ }$__v"
    __i=$(( __i + 1 ))
  done
  [[ -n $__out ]] || __out='0.0.0.0/0'
  printf -v "$__var" '%s' "$__out"
  return 0
}

eks_nodegroup_role_arn_set() {
  eks_doc_get "$1" "$(eks_path nodegroup nodeRole)"
}

eks_iam_role_name_of() {
  local arn=$1
  printf '%s' "${arn##*/}"
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
eks_registry_locate_set() {
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

# `eks_emit_finding CHECK_ID RESOURCE_ARN SUB_KEY EVIDENCE` - as
# s3_emit_finding/ecr_emit_finding/ecs_emit_finding.  `eks` is `regional`,
# so `loc_region` and the pass's own `cell` region component are the SAME
# value.
eks_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  eks_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/eks emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-EKS-PUBLIC_ENDPOINT-01)
      finding_set exposure external
      finding_set auth none
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
