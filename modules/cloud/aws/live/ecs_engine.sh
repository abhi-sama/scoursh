#!/usr/bin/env bash
# modules/cloud/aws/live/ecs_engine.sh - the pure half of the §8.1 ECS
# read-only service (docs/STEP6-CLOUD-PLAN.md CLOUD-26).
#
# The run.sh/engine.sh split every other live/ script uses: no side effect
# at source time, no `aws_ro` call anywhere in this file, and the standard
# sourced-once guard.  modules/cloud/aws/live/ecs.sh is the file that DOES
# something when `cloud_run_service` sources it.
#
# ONE READER, FOUR RESPONSE SHAPES.  `list-clusters`, `list-services`,
# `describe-services` and `describe-task-definition` are four different AWS
# operations with four different top-level shapes, but each is read exactly
# once per call and never re-read, so one shared `_ECS_DOC`/`_ECS_DOCT` pair
# (loaded fresh per response, s3_engine.sh's own `s3_doc_load` shape) is
# enough - there is no s3-style "read this document eight different ways"
# pressure here that would justify four separate maps.
#
# "TASK ROLE OVER-PERMISSIVE" IS ANSWERED BY `iam_policy_engine.sh`'s SHARED
# DRIVER, NOT HERE.  See that file's own header for why the question - and
# the AWS call chain that answers it - is identical for ECS's task role and
# EKS's node-group role, and is kept in one place rather than forked.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_ECS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_ECS_ENGINE_SOURCED=1

if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _ECS_DOC=()
declare -gA _ECS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
ecs_doc_load() {
  local file=$1
  _ECS_DOC=()
  _ECS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _ECS_DOC[$path]=$val
    _ECS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

ecs_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

ecs_doc_has() {
  [[ -n ${_ECS_DOCT[$1]+set} ]]
}

ecs_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_ECS_DOC[$__path]:-}"
  [[ -n ${_ECS_DOCT[$__path]+set} ]]
}

# `ecs_array_collect VARNAME ARRAYPATH` - every scalar element of the array
# at ARRAYPATH into the nameless bash array VARNAME (a real array, filled by
# `eval`-free repeated `printf -v "${VARNAME}[i]"` writes, the same
# convention lib/core.sh's own indexed-array setters use elsewhere in this
# codebase). Used for `list-clusters`'s `clusterArns` and `list-services`'s
# `serviceArns` - both bare arrays of strings at a fixed top-level key.
ecs_array_collect() {
  local __var=$1 __prefix=$2 __i=0 __p __v
  local -a __out=()
  while :; do
    __p=$(ecs_path "$__prefix" "$__i")
    ecs_doc_has "$__p" || break
    __v=${_ECS_DOC[$__p]:-}
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
# 2. Classifiers
# ---------------------------------------------------------------------------
# `ecs_service_assigns_public_ip` - true when the loaded `describe-services`
# document's FIRST service has `networkConfiguration.awsvpcConfiguration.
# assignPublicIp` set to `ENABLED`.  This is a signal about IP ASSIGNMENT,
# not a confirmed internet-reachability verdict: whether the ENI is actually
# reachable also depends on the subnet's route table and the security
# group, neither of which this check reads (a stated scope limit, carried
# into the check's own `confidence: medium` and its remediation text, the
# same discipline s3_engine.sh's ACL-vs-policy-evaluation note applies to
# its own heuristic-versus-AWS-verdict split).
ecs_service_assigns_public_ip() {
  [[ ${_ECS_DOC[$(ecs_path services 0 networkConfiguration awsvpcConfiguration assignPublicIp)]:-} == ENABLED ]]
}

ecs_service_arn_set() {
  ecs_doc_get "$1" "$(ecs_path services 0 serviceArn)"
}

ecs_service_task_definition_set() {
  ecs_doc_get "$1" "$(ecs_path services 0 taskDefinition)"
}

# `ecs_task_role_arn_set VARNAME` - the loaded `describe-task-definition`
# document's `taskDefinition.taskRoleArn`, or empty when the task
# definition names no task role at all (a task that only ever needed the
# EXECUTION role, which this check does not evaluate - see ecs.sh's own
# header for why only the task role is in scope).
ecs_task_role_arn_set() {
  ecs_doc_get "$1" "$(ecs_path taskDefinition taskRoleArn)"
}

# `ecs_iam_role_name_of ARN` - the RoleName IAM's own API needs, the last
# path segment of a role ARN.  A role ARN may carry a path
# (`role/service-role/X`), and the role's NAME is only ever the final
# segment regardless of how many path components precede it.
ecs_iam_role_name_of() {
  local arn=$1
  printf '%s' "${arn##*/}"
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
ecs_registry_locate_set() {
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

# `ecs_emit_finding CHECK_ID RESOURCE_ARN SUB_KEY EVIDENCE` - as
# s3_emit_finding/ecr_emit_finding.  `ecs` is `regional`, so `loc_region`
# and the pass's own `cell` region component are the SAME value.
ecs_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  ecs_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/ecs emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-ECS-PUBLIC_SERVICE-01)
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
