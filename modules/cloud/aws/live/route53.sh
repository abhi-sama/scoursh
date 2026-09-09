#!/usr/bin/env bash
# modules/cloud/aws/live/route53.sh - the §8.1 Route53 read-only service pass
# (docs/DESIGN.md §8.1's `route53` row; docs/STEP6-CLOUD-PLAN.md CLOUD-11).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with NO
# sourced-once guard - `route53` is `global`
# (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES`), reached ONCE per account,
# exactly as s3.sh.  Its pure half is
# modules/cloud/aws/live/route53_engine.sh, which states the check's scope
# decision (S3-website dangling records only) at length; read it first.
#
# FOUR CALLS: `route53 list-hosted-zones` (once), `s3api list-buckets` (once,
# self-contained - this file does not depend on live/s3.sh's own file
# existing, matching the "peers, any order" contract
# modules/cloud/aws/run.sh's own header states for the whole service table),
# and `route53 list-resource-record-sets` once per hosted zone.
#
# EVERY AWS CALL GOES THROUGH `aws_ro`, spelled literally with a literal
# service and operation (tests/lint-aws-readonly.sh; s3.sh's own header).
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/route53_engine.sh
source "${BASH_SOURCE[0]%/*}/route53_engine.sh"

declare -g _R53_ZONES_TOTAL=0
declare -g _R53_ZONES_EXAMINED=0
declare -g _R53_RECORDS_EXAMINED=0
declare -g _R53_BUCKETS_KNOWN=0
declare -gA _R53_EVALUATED=()
declare -gA _R53_LOST=()
declare -gA _R53_LOST_REASON=()
# The lowercased known-bucket-name set, read by `_route53_examine_zone`.  A
# plain `declare -gA` global rather than a nameref passed as an argument:
# `local -n` needs bash 4.3, and lib/core.sh's own frozen minimum is 4.2
# (AGENTS.md, "Things measured on this codebase" - the identical constraint
# that keeps `${var//pattern/&}`'s bash-5.2 meaning off this codebase's own
# code). Reset here (not only declared) for the same reason every other
# per-pass accumulator in this file is.
declare -gA _R53_KNOWN_BUCKETS=()

declare -ga _R53_CHECK_IDS=(
  CLOUD-ROUTE53-DANGLING_RECORD-01
)

_route53_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_route53_note_evaluated() {
  _R53_EVALUATED[$1]=$(( ${_R53_EVALUATED[$1]:-0} + 1 ))
}

_route53_note_lost() {
  _R53_LOST[$1]=$(( ${_R53_LOST[$1]:-0} + 1 ))
  [[ -n ${_R53_LOST_REASON[$1]:-} ]] || _R53_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_route53_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-route53.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  _route53_selected CLOUD-ROUTE53-DANGLING_RECORD-01 || {
    run_record coverage_reduction "module=cloud reason=all_route53_checks_deselected service=route53 account=$account - CLOUD-ROUTE53-DANGLING_RECORD-01 was removed by this run's check-selection filters, so no Route53 API call was made and no record was examined."
    return 0
  }

  # The bucket-name universe this check cross-references against.  A denied
  # or truncated bucket list is a reduction over the WHOLE check, since a
  # short bucket list can only make a genuinely-dangling record look owned -
  # never the other way - which is the direction that reads as a clean scan.
  local bucketsf=$work/list-buckets.json rc=0
  aws_ro s3api list-buckets >"$bucketsf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _route53_note_lost CLOUD-ROUTE53-DANGLING_RECORD-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=route53 operation=list-buckets account=$account cell=${SCOURSH_CLOUD_CELL:-} - the account's bucket list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no DNS record could be checked against it and CLOUD-ROUTE53-DANGLING_RECORD-01 did not run. A short or missing bucket list can only make a dangling record look owned, never the reverse, so this check refuses to guess rather than report a false clean."
    run_record coverage_gap "cloud route53: the bucket list for account $account could not be read (${SCOURSH_AWS_RO_OUTCOME}), so the S3-website dangling-record check did not run at all. A clean result here is the absence of a test, not the absence of a problem."
    _route53_record_coverage "$account"
    return 0
  fi
  local i=0 bname=''
  route53_doc_load "$bucketsf" || true
  while :; do
    route53_doc_get bname "$(route53_path Buckets "$i" Name)" || break
    [[ -n $bname ]] && _R53_KNOWN_BUCKETS[${bname,,}]=1
    i=$(( i + 1 ))
  done
  _R53_BUCKETS_KNOWN=${#_R53_KNOWN_BUCKETS[@]}

  local listf=$work/list-hosted-zones.json
  rc=0
  aws_ro route53 list-hosted-zones >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _route53_note_lost CLOUD-ROUTE53-DANGLING_RECORD-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=route53 operation=list-hosted-zones account=$account cell=${SCOURSH_CLOUD_CELL:-} - the account's hosted-zone list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO hosted zone was examined and CLOUD-ROUTE53-DANGLING_RECORD-01 did not run."
    run_record coverage_gap "cloud route53: the hosted-zone list for account $account could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no DNS record was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds route53:ListHostedZones."
    _route53_record_coverage "$account"
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=route53 operation=list-hosted-zones account=$account - the hosted-zone list came back INCOMPLETE, so an unknown number of this account's zones were never enumerated."
    run_record coverage_gap "cloud route53: the hosted-zone list for account $account was truncated, so an unknown number of zones were never examined. A clean result for those zones is the absence of a test, not the absence of a problem."
  fi

  local -a zone_ids=()
  route53_doc_load "$listf" || true
  i=0
  local zid=''
  while :; do
    route53_doc_get zid "$(route53_path HostedZones "$i" Id)" || break
    [[ -n $zid ]] && zone_ids+=("$zid")
    i=$(( i + 1 ))
  done
  _R53_ZONES_TOTAL=${#zone_ids[@]}

  local partition
  partition=$(route53_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  local z
  for z in "${zone_ids[@]+"${zone_ids[@]}"}"; do
    _route53_examine_zone "$z" "$partition" "$work"
  done

  _route53_record_coverage "$account"
  return 0
}

# `_route53_examine_zone ZONE_ID PARTITION WORKDIR` - the one per-zone call
# and the check over its records, reading the lowercased known-bucket-name set
# off the module-global `_R53_KNOWN_BUCKETS` this file declares above (never a
# nameref: bash namerefs need 4.3, and lib/core.sh's own frozen minimum is
# 4.2). Never returns non-zero.
_route53_examine_zone() {
  local zone_id=$1 partition=$2 work=$3
  local bare
  bare=$(route53_zone_id_bare "$zone_id")
  local safe=${bare//[^A-Za-z0-9._-]/_}
  local rc=0 f=$work/$safe.records.json

  aws_ro route53 list-resource-record-sets --hosted-zone-id "$bare" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _route53_note_lost CLOUD-ROUTE53-DANGLING_RECORD-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=route53 operation=list-resource-record-sets zone=$zone_id - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this zone's records were NOT tested."
    return 0
  fi
  _R53_ZONES_EXAMINED=$(( _R53_ZONES_EXAMINED + 1 ))
  _route53_note_evaluated CLOUD-ROUTE53-DANGLING_RECORD-01
  route53_doc_load "$f" || true

  local zone_arn
  zone_arn=$(route53_zone_arn "$partition" "$zone_id")

  local i=0 name='' type=''
  while :; do
    route53_doc_get name "$(route53_path ResourceRecordSets "$i" Name)" || break
    route53_doc_get type "$(route53_path ResourceRecordSets "$i" Type)" || true
    _R53_RECORDS_EXAMINED=$(( _R53_RECORDS_EXAMINED + 1 ))

    if ! route53_record_is_wildcard "$name"; then
      local target='' is_candidate=0
      case $type in
        CNAME)
          route53_doc_get target "$(route53_path ResourceRecordSets "$i" ResourceRecords 0 Value)" || true
          [[ -n $target ]] && route53_target_is_s3_website "$target" && is_candidate=1
          ;;
        A | AAAA)
          route53_doc_get target "$(route53_path ResourceRecordSets "$i" AliasTarget DNSName)" || true
          [[ -n $target ]] && route53_target_is_s3_website "$target" && is_candidate=1
          ;;
      esac
      if (( is_candidate )); then
        local bucket
        bucket=$(route53_record_bucket_candidate "$name")
        if [[ -z ${_R53_KNOWN_BUCKETS[$bucket]:-} ]]; then
          route53_emit_finding CLOUD-ROUTE53-DANGLING_RECORD-01 "$zone_arn" "$name:$type" \
            "DNS record $name ($type) in hosted zone $zone_id points to an S3 static-website endpoint ($target), which requires the serving bucket to be named exactly $bucket - and no bucket by that name currently exists in this account (s3api list-buckets). Any AWS account can create a bucket named $bucket and configure it as a static website, silently taking over everything served at $name. Remove this DNS record if the site is retired, or recreate the bucket $bucket if it is not."
        fi
      fi
    fi
    i=$(( i + 1 ))
  done
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_route53_record_coverage() {
  local account=$1 id
  local ran=0
  for id in "${_R53_CHECK_IDS[@]+"${_R53_CHECK_IDS[@]}"}"; do
    _route53_selected "$id" || continue
    if (( ${_R53_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_R53_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_R53_LOST_REASON[$id]} service=route53 check=$id account=$account zones_answered=${_R53_EVALUATED[$id]} zones_unanswered=${_R53_LOST[$id]} of ${_R53_ZONES_TOTAL} - this check ran, but ${_R53_LOST[$id]} zone(s)/prerequisite call(s) did not answer, so it is covered for some of the account's zones and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_R53_LOST_REASON[$id]:-no_zone_examined} service=route53 check=$id account=$account zones_total=${_R53_ZONES_TOTAL} zones_examined=${_R53_ZONES_EXAMINED} - this check answered for NO hosted zone in the account and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every DNS record is fine."
    fi
  done

  if (( _R53_ZONES_TOTAL == 0 && ${_R53_LOST[CLOUD-ROUTE53-DANGLING_RECORD-01]:-0} == 0 )); then
    run_record notes "module=cloud service=route53 account=$account zones=0 - the account's hosted-zone list was read successfully and contains no zone, so CLOUD-ROUTE53-DANGLING_RECORD-01 is covered vacuously."
  fi

  if (( ran == 0 && _R53_ZONES_TOTAL > 0 )); then
    run_record coverage_gap "cloud route53: account $account has $_R53_ZONES_TOTAL hosted zone(s) and CLOUD-ROUTE53-DANGLING_RECORD-01 answered for none of them, so no DNS record was tested. This is a run that did not look, not an account with nothing wrong - the coverage_reduction above names the failure class."
  fi
  return 0
}

_route53_run_service
