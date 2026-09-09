#!/usr/bin/env bash
# modules/cloud/aws/live/sqs.sh - the §8.1 SQS read-only service pass
# (docs/DESIGN.md §8.1's `sqs` row; docs/STEP6-CLOUD-PLAN.md CLOUD-29).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with NO
# sourced-once guard - `sqs` is `regional`, reached once per enabled region -
# exactly as sns.sh's own header records; its pure half is
# modules/cloud/aws/live/sqs_engine.sh.
#
# `list-queues` names every queue in this region BY URL ONLY - no ARN, no
# attributes - so `get-queue-attributes --attribute-names All` is the one
# per-queue call this pass makes, and it is what supplies the queue's ARN as
# well as its Policy and encryption attributes.
#
# EVERY AWS CALL GOES THROUGH `aws_ro`, spelled literally with a literal
# service and operation at each call site (tests/lint-aws-readonly.sh parses
# the source line; a wrapper would be invisible to it - s3.sh's own header).
#
# THE HONESTY ACCOUNTING follows s3.sh's/sns.sh's three rules verbatim.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/sqs_engine.sh
source "${BASH_SOURCE[0]%/*}/sqs_engine.sh"

declare -g _SQS_QUEUES_TOTAL=0
declare -g _SQS_QUEUES_EXAMINED=0
declare -gA _SQS_EVALUATED=()
declare -gA _SQS_LOST=()
declare -gA _SQS_LOST_REASON=()

declare -ga _SQS_CHECK_IDS=(
  CLOUD-SQS-PUBLIC_POLICY-01
  CLOUD-SQS-NO_ENCRYPTION-01
)

_sqs_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_sqs_note_evaluated() {
  _SQS_EVALUATED[$1]=$(( ${_SQS_EVALUATED[$1]:-0} + 1 ))
}

_sqs_note_lost() {
  _SQS_LOST[$1]=$(( ${_SQS_LOST[$1]:-0} + 1 ))
  [[ -n ${_SQS_LOST_REASON[$1]:-} ]] || _SQS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_sqs_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-sqs.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_SQS_CHECK_IDS[@]+"${_SQS_CHECK_IDS[@]}"}"; do
    _sqs_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_sqs_checks_deselected service=sqs account=$account region=$region - every CLOUD-SQS-* check id was removed by this run's check-selection filters, so no SQS API call was made and no queue was examined."
    return 0
  fi

  local listf=$work/list-queues.json rc=0
  aws_ro sqs list-queues >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=sqs operation=list-queues account=$account cell=${SCOURSH_CLOUD_CELL:-} region=$region - the region's queue list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO SQS queue was examined and none of the ${#_SQS_CHECK_IDS[@]} CLOUD-SQS-* checks ran."
    run_record coverage_gap "cloud sqs: the queue list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no queue's policy or encryption was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds sqs:ListQueues."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=sqs operation=list-queues account=$account region=$region - the queue list came back INCOMPLETE, so an unknown number of this region's queues were never enumerated."
    run_record coverage_gap "cloud sqs: the queue list for account $account region $region was truncated, so an unknown number of queues were never examined. A clean result for those queues is the absence of a test, not the absence of a problem."
  fi

  local -a urls=()
  local i=0 url=''
  sqs_doc_load "$listf" || true
  while :; do
    sqs_doc_get url "$(sqs_path QueueUrls "$i")" || break
    [[ -n $url ]] && urls+=("$url")
    i=$(( i + 1 ))
  done
  _SQS_QUEUES_TOTAL=${#urls[@]}

  local u
  for u in "${urls[@]+"${urls[@]}"}"; do
    _sqs_examine_queue "$u" "$work"
  done

  _sqs_record_coverage "$account" "$region"
  return 0
}

# `_sqs_examine_queue URL WORKDIR` - the one per-queue call and the two checks
# over it.  Never returns non-zero.
_sqs_examine_queue() {
  local url=$1 work=$2
  local safe=${url//[^A-Za-z0-9._-]/_}
  local rc=0 f=$work/$safe.attrs.json

  local need_policy=0 need_enc=0
  _sqs_selected CLOUD-SQS-PUBLIC_POLICY-01 && need_policy=1
  _sqs_selected CLOUD-SQS-NO_ENCRYPTION-01 && need_enc=1
  (( need_policy || need_enc )) || return 0

  aws_ro sqs get-queue-attributes --queue-url "$url" --attribute-names All >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason='' cid
    aws_ro_reduction_reason_set reason
    for cid in "${_SQS_CHECK_IDS[@]+"${_SQS_CHECK_IDS[@]}"}"; do
      _sqs_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=sqs operation=get-queue-attributes queue=$url - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this queue's policy and encryption were NOT tested. Its absence from the findings is not evidence that it is configured correctly."
    return 0
  fi
  sqs_doc_load "$f" || true

  local arn=''
  if ! sqs_queue_arn_set arn; then
    # No QueueArn in the response is a malformed answer, not a clean one - the
    # queue is counted examined (the call DID answer) but neither check can
    # cite a resource, so both are recorded lost for THIS queue alone rather
    # than emitted against an empty ARN.
    local cid
    for cid in "${_SQS_CHECK_IDS[@]+"${_SQS_CHECK_IDS[@]}"}"; do
      _sqs_note_lost "$cid" error
    done
    run_record coverage_reduction "module=cloud reason=error service=sqs operation=get-queue-attributes queue=$url - the response carried no QueueArn attribute, so no finding could cite a resource for this queue."
    return 0
  fi
  _SQS_QUEUES_EXAMINED=$(( _SQS_QUEUES_EXAMINED + 1 ))

  if (( need_policy )); then
    _sqs_note_evaluated CLOUD-SQS-PUBLIC_POLICY-01
    local pol=''
    if sqs_queue_policy_string_set pol; then
      sqs_policy_string_load "$pol"
      if sqs_policy_is_public; then
        sqs_emit_finding CLOUD-SQS-PUBLIC_POLICY-01 "$arn" \
          "The resource policy on SQS queue $arn grants at least one Effect Allow statement to a wildcard Principal (\"*\", or {\"AWS\":\"*\"}) with no Condition narrowing it. Any AWS principal can send to or receive from this queue. Observed via sqs get-queue-attributes."
      fi
    fi
  fi

  if (( need_enc )); then
    _sqs_note_evaluated CLOUD-SQS-NO_ENCRYPTION-01
    if ! sqs_queue_encrypted; then
      sqs_emit_finding CLOUD-SQS-NO_ENCRYPTION-01 "$arn" \
        "SQS queue $arn has neither a customer-managed KMS key (KmsMasterKeyId) nor SQS-managed default encryption (SqsManagedSseEnabled) turned on, so messages in this queue are not encrypted at rest. Enable SQS-managed SSE as the zero-cost baseline, or a customer-managed KMS key where a separate, auditable key policy is required."
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_sqs_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_SQS_CHECK_IDS[@]+"${_SQS_CHECK_IDS[@]}"}"; do
    _sqs_selected "$id" || continue
    if (( ${_SQS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_SQS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_SQS_LOST_REASON[$id]} service=sqs check=$id account=$account region=$region queues_answered=${_SQS_EVALUATED[$id]} queues_unanswered=${_SQS_LOST[$id]} of ${_SQS_QUEUES_TOTAL} - this check ran, but ${_SQS_LOST[$id]} queue(s) did not answer, so it is covered for some of the region's queues and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_SQS_LOST_REASON[$id]:-no_queue_examined} service=sqs check=$id account=$account region=$region queues_total=${_SQS_QUEUES_TOTAL} queues_examined=${_SQS_QUEUES_EXAMINED} - this check answered for NO queue in the region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every queue is configured correctly."
    fi
  done

  if (( _SQS_QUEUES_TOTAL == 0 )); then
    run_record notes "module=cloud service=sqs account=$account region=$region queues=0 - the region's queue list was read successfully and contains no queue, so every CLOUD-SQS-* check is covered vacuously."
  fi

  if (( ran == 0 && _SQS_QUEUES_TOTAL > 0 )); then
    run_record coverage_gap "cloud sqs: account $account region $region has $_SQS_QUEUES_TOTAL queue(s) and NOT ONE of the ${#_SQS_CHECK_IDS[@]} CLOUD-SQS-* checks answered for any of them, so no queue's policy or encryption posture was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_sqs_run_service
