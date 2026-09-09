#!/usr/bin/env bash
# modules/cloud/aws/live/ecs.sh - the §8.1 ECS read-only service pass
# (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-26).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` and carrying NO
# sourced-once guard - see s3.sh's own header for why one would silently
# turn every region after the first into a no-op.  `ecs` is `regional`, so
# this runs once per enabled region with the ambient `aws_ro` region already
# pointed at it; no call here ever passes its own `--region`.
#
# THE CALL CHAIN IS FOUR OPERATIONS DEEP, AND EACH LEVEL NARROWS THE NEXT:
# `list-clusters` -> per-cluster `list-services` -> per-service
# `describe-services` (which carries the public-IP-assignment signal
# directly) -> per-service `describe-task-definition` (which names the task
# role, if any) -> the shared `iam_policy_engine.sh` driver, which lists and
# reads that role's own inline policies.  A failure at any level is a
# coverage loss for exactly what it blocks - the cluster's services when
# `list-services` fails, one service's two checks when `describe-services`
# fails, one service's task-role check alone when `describe-task-definition`
# or the IAM calls fail - never a reason to abandon the rest of the walk.
#
# ONLY THE INLINE TASK ROLE IS EVALUATED, NEVER THE EXECUTION ROLE.  The
# execution role (`executionRoleArn`) is what the ECS AGENT uses to pull the
# image and write logs; the TASK role (`taskRoleArn`) is what the
# APPLICATION inside the container assumes at runtime, which is the
# ticket's own "task role" language and the one whose over-permissiveness
# actually reaches application-controlled code.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/ecs_engine.sh
source "${BASH_SOURCE[0]%/*}/ecs_engine.sh"
# shellcheck source=modules/cloud/aws/live/iam_policy_engine.sh
source "${BASH_SOURCE[0]%/*}/iam_policy_engine.sh"

declare -g _ECS_SERVICES_TOTAL=0
declare -g _ECS_SERVICES_EXAMINED=0
declare -g _ECS_CLUSTERS_TRUNCATED=0
declare -g _ECS_SERVICES_TRUNCATED=0
declare -gA _ECS_EVALUATED=()
declare -gA _ECS_LOST=()
declare -gA _ECS_LOST_REASON=()

declare -ga _ECS_CHECK_IDS=(
  CLOUD-ECS-PUBLIC_SERVICE-01
  CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01
)

_ecs_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_ecs_note_evaluated() {
  _ECS_EVALUATED[$1]=$(( ${_ECS_EVALUATED[$1]:-0} + 1 ))
}

_ecs_note_lost() {
  _ECS_LOST[$1]=$(( ${_ECS_LOST[$1]:-0} + 1 ))
  [[ -n ${_ECS_LOST_REASON[$1]:-} ]] || _ECS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_ecs_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-ecs.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_ECS_CHECK_IDS[@]+"${_ECS_CHECK_IDS[@]}"}"; do
    _ecs_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_ecs_checks_deselected service=ecs account=$account region=$region - every CLOUD-ECS-* check id was removed by this run's check-selection filters, so no ECS API call was made and no service was examined."
    return 0
  fi

  local clustersf=$work/list-clusters.json rc=0
  aws_ro ecs list-clusters >"$clustersf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=ecs operation=list-clusters account=$account region=$region - the cluster list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO cluster, service or task role was examined and none of the ${#_ECS_CHECK_IDS[@]} CLOUD-ECS-* checks ran."
    run_record coverage_gap "cloud ecs: the cluster list for account $account in $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no service's network exposure or task role was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds ecs:ListClusters."
    return 0
  fi
  [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && _ECS_CLUSTERS_TRUNCATED=1

  ecs_doc_load "$clustersf" || true
  local -a clusters=()
  ecs_array_collect clusters clusterArns
  local nclusters=${clusters_n:-0}

  local c
  for (( c = 0; c < nclusters; c++ )); do
    _ecs_walk_cluster "${clusters[$c]}" "$work"
  done

  _ecs_record_coverage "$account" "$region"
  return 0
}

# `_ecs_walk_cluster CLUSTER_ARN WORKDIR` - list-services, then per-service
# examination.  Never returns non-zero.
_ecs_walk_cluster() {
  local cluster=$1 work=$2
  local safe=${cluster//[^A-Za-z0-9._-]/_}
  local svcf=$work/list-services-$safe.json rc=0
  aws_ro ecs list-services --cluster "$cluster" >"$svcf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    local cid
    for cid in "${_ECS_CHECK_IDS[@]+"${_ECS_CHECK_IDS[@]}"}"; do
      _ecs_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=ecs operation=list-services cluster=$cluster - this cluster's service list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no service in it was examined."
    return 0
  fi
  [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]] && _ECS_SERVICES_TRUNCATED=1

  ecs_doc_load "$svcf" || true
  local -a services=()
  ecs_array_collect services serviceArns
  local n=${services_n:-0}

  local s
  for (( s = 0; s < n; s++ )); do
    _ECS_SERVICES_TOTAL=$(( _ECS_SERVICES_TOTAL + 1 ))
    _ecs_examine_service "$cluster" "${services[$s]}" "$work"
  done
  return 0
}

# `_ecs_examine_service CLUSTER SERVICE_ARN WORKDIR` - the public-IP check
# straight off describe-services, and the task-role check one level deeper.
_ecs_examine_service() {
  local cluster=$1 service=$2 work=$3
  local safe=${service//[^A-Za-z0-9._-]/_}
  local descf=$work/describe-services-$safe.json rc=0
  aws_ro ecs describe-services --cluster "$cluster" --services "$service" >"$descf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _ecs_note_lost CLOUD-ECS-PUBLIC_SERVICE-01 "$reason"
    _ecs_note_lost CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=ecs operation=describe-services service=$service cluster=$cluster - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so neither of this service's checks was tested."
    return 0
  fi
  _ECS_SERVICES_EXAMINED=$(( _ECS_SERVICES_EXAMINED + 1 ))

  ecs_doc_load "$descf" || true
  local arn='' taskdef=''
  ecs_service_arn_set arn
  [[ -n $arn ]] || arn=$service
  ecs_service_task_definition_set taskdef

  if _ecs_selected CLOUD-ECS-PUBLIC_SERVICE-01; then
    _ecs_note_evaluated CLOUD-ECS-PUBLIC_SERVICE-01
    if ecs_service_assigns_public_ip; then
      ecs_emit_finding CLOUD-ECS-PUBLIC_SERVICE-01 "$arn" '' \
        "Service $arn (cluster $cluster) assigns a public IP to its tasks (networkConfiguration.awsvpcConfiguration.assignPublicIp is ENABLED). This is a signal that the task's network interface CAN receive a public IPv4 address, not a confirmed internet-reachability verdict - actual reachability also depends on the subnet's route table and the attached security group, neither of which this check reads. Set assignPublicIp to DISABLED and route outbound traffic through a NAT gateway if the tasks do not need to be directly reachable from the internet, and confirm the security group does not itself admit 0.0.0.0/0."
    fi
  fi

  [[ -n $taskdef ]] || return 0
  _ecs_check_task_role "$taskdef" "$arn" "$work"
  return 0
}

_ecs_check_task_role() {
  local taskdef=$1 service_arn=$2 work=$3
  local id=CLOUD-ECS-TASK_ROLE_OVERPERMISSIVE-01
  _ecs_selected "$id" || return 0

  local safe=${taskdef//[^A-Za-z0-9._-]/_}
  local tdf=$work/describe-task-definition-$safe.json rc=0
  aws_ro ecs describe-task-definition --task-definition "$taskdef" >"$tdf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _ecs_note_lost "$id" "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=ecs operation=describe-task-definition task_definition=$taskdef service=$service_arn - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this service's task role was NOT tested."
    return 0
  fi

  ecs_doc_load "$tdf" || true
  local rolearn=''
  ecs_task_role_arn_set rolearn
  if [[ -z $rolearn ]]; then
    # A real, checked answer: this task definition names no task role at
    # all, so there is nothing for the application to over-assume.
    _ecs_note_evaluated "$id"
    return 0
  fi

  local rolename result='' reason=''
  rolename=$(ecs_iam_role_name_of "$rolearn")
  local rc2=0
  iam_role_overpermissive "$rolename" "$work" "${rolename//[^A-Za-z0-9._-]/_}" result reason || rc2=$?
  case $rc2 in
    0)
      _ecs_note_evaluated "$id"
      ecs_emit_finding "$id" "$rolearn" "$result" \
        "The task role $rolearn (task definition $taskdef, service $service_arn) has an inline policy granting Effect Allow with Action \"*\" on Resource \"*\" ($result) - every action on every resource this account can reach, whatever the application actually needs. Any code that runs inside a container using this task definition inherits this role's full permission set. Replace the wildcard statement with the specific actions and resource ARNs the application uses, and confirm with CloudTrail which API calls it has actually made."
      ;;
    1)
      _ecs_note_evaluated "$id"
      ;;
    *)
      _ecs_note_lost "$id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=ecs operation=iam:get-role-policy role=$rolename task_definition=$taskdef service=$service_arn - the task role's inline policies could not be fully read (${reason}), so its permissiveness was NOT tested. Its absence from the findings is not evidence that the role is scoped correctly."
      ;;
  esac
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_ecs_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_ECS_CHECK_IDS[@]+"${_ECS_CHECK_IDS[@]}"}"; do
    _ecs_selected "$id" || continue
    if (( ${_ECS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_ECS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_ECS_LOST_REASON[$id]} service=ecs check=$id account=$account region=$region services_answered=${_ECS_EVALUATED[$id]} services_unanswered=${_ECS_LOST[$id]} of ${_ECS_SERVICES_TOTAL} - this check ran, but ${_ECS_LOST[$id]} service(s) did not answer, so it is covered for some of the region's services and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_ECS_LOST_REASON[$id]:-no_service_examined} service=ecs check=$id account=$account region=$region services_total=${_ECS_SERVICES_TOTAL} services_examined=${_ECS_SERVICES_EXAMINED} - this check answered for NO service in $region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every service is configured correctly."
    fi
  done

  if (( _ECS_SERVICES_TOTAL == 0 )); then
    run_record notes "module=cloud service=ecs account=$account region=$region services=0 - the cluster and service lists were read successfully and contain no service, so every CLOUD-ECS-* check is covered vacuously."
  fi

  if (( _ECS_CLUSTERS_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=ecs operation=list-clusters account=$account region=$region - the cluster list came back INCOMPLETE, so an unknown number of this region's clusters were never enumerated."
    run_record coverage_gap "cloud ecs: the cluster list for account $account in $region was truncated, so an unknown number of clusters were never examined. A clean result for those clusters is the absence of a test, not the absence of a problem."
  fi
  if (( _ECS_SERVICES_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=ecs operation=list-services account=$account region=$region - a cluster's service list came back INCOMPLETE, so an unknown number of services were never enumerated."
    run_record coverage_gap "cloud ecs: at least one cluster's service list for account $account in $region was truncated, so an unknown number of services were never examined."
  fi

  if (( ran == 0 && _ECS_SERVICES_TOTAL > 0 )); then
    run_record coverage_gap "cloud ecs: account $account region $region has $_ECS_SERVICES_TOTAL service(s) and NOT ONE of the ${#_ECS_CHECK_IDS[@]} CLOUD-ECS-* checks answered for any of them, so no service's network exposure or task role was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_ecs_run_service
