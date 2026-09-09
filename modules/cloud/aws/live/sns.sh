#!/usr/bin/env bash
# modules/cloud/aws/live/sns.sh - the §8.1 SNS read-only service pass
# (docs/DESIGN.md §8.1's `sns` row; docs/STEP6-CLOUD-PLAN.md CLOUD-28).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard - `sns` is `regional`
# (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES`), so this file is
# legitimately reached once per enabled region, and a guard would silently
# make every region after the first a no-op.  Its pure half is
# modules/cloud/aws/live/sns_engine.sh, which does carry one.
#
# TWO CALLS PER TOPIC: `list-topics` names every topic in this region, and
# `get-topic-attributes` is the one call that answers both checks below - the
# `Policy` document and `KmsMasterKeyId` are both attributes of the same
# response, so one call serves two checks rather than two.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23), spelled
# literally at each call site with a literal service and operation - never
# through a local wrapper, for the reason s3.sh's own header states at length:
# tests/lint-aws-readonly.sh parses the operation out of the source line, and
# a wrapper would make every call here invisible to it.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, following s3.sh's own three rules
# verbatim: `checks_run` names what SUCCEEDED; an AccessDenied/throttle/opt-in
# region is a `coverage_reduction`, never silence; and there is no SNS
# equivalent of a `NoSuch*`-shaped "this IS the answer" error to special-case -
# every non-zero `get-topic-attributes` here is a real coverage loss.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/sns_engine.sh
source "${BASH_SOURCE[0]%/*}/sns_engine.sh"

# `declare -g`, for the reason s3.sh's own note records at length: this file
# executes inside `cloud_run_service`'s own function scope, so a bare
# `declare` would make every one of these local and it would die with the
# pass.  Reset here (not only declared) so a second pass in one process does
# not inherit the first pass's counters.
declare -g _SNS_TOPICS_TOTAL=0
declare -g _SNS_TOPICS_EXAMINED=0
declare -gA _SNS_EVALUATED=()
declare -gA _SNS_LOST=()
declare -gA _SNS_LOST_REASON=()

declare -ga _SNS_CHECK_IDS=(
  CLOUD-SNS-PUBLIC_POLICY-01
  CLOUD-SNS-NO_ENCRYPTION-01
)

# `_sns_selected ID` - tension 15's per-check filter.  The `declare -F` guard
# is PERMISSIVE when absent, for the identical reason s3.sh's own
# `_s3_selected` records: a direct-engine test suite sources this file with no
# module engine in the process, and a fail-closed default would make the whole
# pass inert while every "stays quiet" assertion in that suite still passed.
_sns_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_sns_note_evaluated() {
  _SNS_EVALUATED[$1]=$(( ${_SNS_EVALUATED[$1]:-0} + 1 ))
}

_sns_note_lost() {
  _SNS_LOST[$1]=$(( ${_SNS_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, s3.sh's own reasoning: the permission problem is the
  # actionable one and explains the rest.
  [[ -n ${_SNS_LOST_REASON[$1]:-} ]] || _SNS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_sns_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  # `mktemp -d`, never a name built from `$$`/`$BASHPID` - s3.sh's own CWE-377
  # via CWE-59 note applies identically here.
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-sns.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_SNS_CHECK_IDS[@]+"${_SNS_CHECK_IDS[@]}"}"; do
    _sns_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_sns_checks_deselected service=sns account=$account region=$region - every CLOUD-SNS-* check id was removed by this run's check-selection filters, so no SNS API call was made and no topic was examined."
    return 0
  fi

  local listf=$work/list-topics.json rc=0
  aws_ro sns list-topics >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=sns operation=list-topics account=$account cell=${SCOURSH_CLOUD_CELL:-} region=$region - the region's topic list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO SNS topic was examined and none of the ${#_SNS_CHECK_IDS[@]} CLOUD-SNS-* checks ran."
    run_record coverage_gap "cloud sns: the topic list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no topic's policy or encryption was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds sns:ListTopics."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=sns operation=list-topics account=$account region=$region - the topic list came back INCOMPLETE, so an unknown number of this region's topics were never enumerated."
    run_record coverage_gap "cloud sns: the topic list for account $account region $region was truncated, so an unknown number of topics were never examined. A clean result for those topics is the absence of a test, not the absence of a problem."
  fi

  local -a arns=()
  local i=0 arn=''
  sns_doc_load "$listf" || true
  while :; do
    sns_doc_get arn "$(sns_path Topics "$i" TopicArn)" || break
    [[ -n $arn ]] && arns+=("$arn")
    i=$(( i + 1 ))
  done
  _SNS_TOPICS_TOTAL=${#arns[@]}

  local t
  for t in "${arns[@]+"${arns[@]}"}"; do
    _sns_examine_topic "$t" "$work"
  done

  _sns_record_coverage "$account" "$region"
  return 0
}

# `_sns_examine_topic ARN WORKDIR` - the one per-topic call and the two checks
# over it.  Never returns non-zero: a topic that cannot be examined is an
# accounted-for reduction, not a reason to abandon the ones after it.
_sns_examine_topic() {
  local arn=$1 work=$2
  local safe=${arn//[^A-Za-z0-9._-]/_}
  local rc=0 f=$work/$safe.attrs.json

  local need_policy=0 need_enc=0
  _sns_selected CLOUD-SNS-PUBLIC_POLICY-01 && need_policy=1
  _sns_selected CLOUD-SNS-NO_ENCRYPTION-01 && need_enc=1
  (( need_policy || need_enc )) || return 0

  aws_ro sns get-topic-attributes --topic-arn "$arn" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason='' cid
    aws_ro_reduction_reason_set reason
    for cid in "${_SNS_CHECK_IDS[@]+"${_SNS_CHECK_IDS[@]}"}"; do
      _sns_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=sns operation=get-topic-attributes topic=$arn - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this topic's policy and encryption were NOT tested. Its absence from the findings is not evidence that it is configured correctly."
    return 0
  fi
  _SNS_TOPICS_EXAMINED=$(( _SNS_TOPICS_EXAMINED + 1 ))
  sns_doc_load "$f" || true

  if (( need_policy )); then
    _sns_note_evaluated CLOUD-SNS-PUBLIC_POLICY-01
    local pol=''
    if sns_topic_policy_string_set pol; then
      sns_policy_string_load "$pol"
      if sns_policy_is_public; then
        sns_emit_finding CLOUD-SNS-PUBLIC_POLICY-01 "$arn" \
          "The resource policy on SNS topic $arn grants at least one Effect Allow statement to a wildcard Principal (\"*\", or {\"AWS\":\"*\"}) with no Condition narrowing it. Any AWS principal, or an unauthenticated caller if the action does not require SigV4, can publish to or subscribe from this topic. Observed via sns get-topic-attributes."
      fi
    fi
  fi

  if (( need_enc )); then
    _sns_note_evaluated CLOUD-SNS-NO_ENCRYPTION-01
    # SC2034: `kms` is written by `sns_topic_kms_key_set` through `printf -v`,
    # so the linter cannot see the assignment; it is read only by that call's
    # own return status (s3_engine.sh's identical `algo`/`target` note).
    # shellcheck disable=SC2034
    local kms=''
    if ! sns_topic_kms_key_set kms; then
      sns_emit_finding CLOUD-SNS-NO_ENCRYPTION-01 "$arn" \
        "SNS topic $arn has no KmsMasterKeyId configured, so messages published to it are not encrypted at rest. Unlike S3 and SQS, SNS applies no default managed encryption to a new topic - this is the topic's real, current state rather than an inherited default. Set a KMS key (a customer-managed key or the AWS managed alias/aws/sns) as the topic's server-side encryption key."
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_sns_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_SNS_CHECK_IDS[@]+"${_SNS_CHECK_IDS[@]}"}"; do
    _sns_selected "$id" || continue
    if (( ${_SNS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_SNS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_SNS_LOST_REASON[$id]} service=sns check=$id account=$account region=$region topics_answered=${_SNS_EVALUATED[$id]} topics_unanswered=${_SNS_LOST[$id]} of ${_SNS_TOPICS_TOTAL} - this check ran, but ${_SNS_LOST[$id]} topic(s) did not answer, so it is covered for some of the region's topics and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_SNS_LOST_REASON[$id]:-no_topic_examined} service=sns check=$id account=$account region=$region topics_total=${_SNS_TOPICS_TOTAL} topics_examined=${_SNS_TOPICS_EXAMINED} - this check answered for NO topic in the region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every topic is configured correctly."
    fi
  done

  if (( _SNS_TOPICS_TOTAL == 0 )); then
    run_record notes "module=cloud service=sns account=$account region=$region topics=0 - the region's topic list was read successfully and contains no topic, so every CLOUD-SNS-* check is covered vacuously."
  fi

  if (( ran == 0 && _SNS_TOPICS_TOTAL > 0 )); then
    run_record coverage_gap "cloud sns: account $account region $region has $_SNS_TOPICS_TOTAL topic(s) and NOT ONE of the ${#_SNS_CHECK_IDS[@]} CLOUD-SNS-* checks answered for any of them, so no topic's policy or encryption posture was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_sns_run_service
