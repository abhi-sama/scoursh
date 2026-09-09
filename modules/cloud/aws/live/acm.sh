#!/usr/bin/env bash
# modules/cloud/aws/live/acm.sh - the §8.1 ACM read-only service pass
# (docs/DESIGN.md §8.1's `acm` row; docs/STEP6-CLOUD-PLAN.md CLOUD-10).
#
# THIS IS A SERVICE SCRIPT, sourced by `cloud_run_service` with NO
# sourced-once guard - `acm` is `regional`, reached once per enabled region.
# Its pure half is modules/cloud/aws/live/acm_engine.sh.
#
# TWO CALLS: `list-certificates` names every certificate ARN in this region;
# `describe-certificate` per ARN is the one call that answers the check,
# since `list-certificates`'s own summary shape is not relied on here (it
# varies across CLI/API versions in which fields it includes) - describe is
# the one call this file's contract depends on for `NotAfter`/`Status`.
#
# `NOW` IS RESOLVED ONCE, HERE, NOT INSIDE THE ENGINE - acm_engine.sh's own
# header states why expiry must never read the system clock inline inside a
# classifier.  `SCOURSH_CLOUD_ACM_NOW`, the same swappable-hook idiom
# lib/http.sh's SCOURSH_HTTP_RESOLVE/SCOURSH_HTTP_TRANSPORT and
# lib/paranoid.sh's SCOURSH_PARANOID_FORCE_BACKEND already use, overrides
# `date +%s` for a deterministic test; unset in any real run.
#
# EVERY AWS CALL GOES THROUGH `aws_ro`, spelled literally with a literal
# service and operation (tests/lint-aws-readonly.sh; s3.sh's own header).
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/acm_engine.sh
source "${BASH_SOURCE[0]%/*}/acm_engine.sh"

declare -g _ACM_CERTS_TOTAL=0
declare -g _ACM_CERTS_EXAMINED=0
declare -gA _ACM_EVALUATED=()
declare -gA _ACM_LOST=()
declare -gA _ACM_LOST_REASON=()

declare -ga _ACM_CHECK_IDS=(
  CLOUD-ACM-EXPIRING-01
)

_acm_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_acm_note_evaluated() {
  _ACM_EVALUATED[$1]=$(( ${_ACM_EVALUATED[$1]:-0} + 1 ))
}

_acm_note_lost() {
  _ACM_LOST[$1]=$(( ${_ACM_LOST[$1]:-0} + 1 ))
  [[ -n ${_ACM_LOST_REASON[$1]:-} ]] || _ACM_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------
_acm_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-acm.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_ACM_CHECK_IDS[@]+"${_ACM_CHECK_IDS[@]}"}"; do
    _acm_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_acm_checks_deselected service=acm account=$account region=$region - every CLOUD-ACM-* check id was removed by this run's check-selection filters, so no ACM API call was made and no certificate was examined."
    return 0
  fi

  local listf=$work/list-certificates.json rc=0
  aws_ro acm list-certificates >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=acm operation=list-certificates account=$account cell=${SCOURSH_CLOUD_CELL:-} region=$region - the region's certificate list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO certificate was examined and CLOUD-ACM-EXPIRING-01 did not run."
    run_record coverage_gap "cloud acm: the certificate list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no certificate's expiry was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds acm:ListCertificates."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=acm operation=list-certificates account=$account region=$region - the certificate list came back INCOMPLETE, so an unknown number of this region's certificates were never enumerated."
    run_record coverage_gap "cloud acm: the certificate list for account $account region $region was truncated, so an unknown number of certificates were never examined. A clean result for those certificates is the absence of a test, not the absence of a problem."
  fi

  local -a arns=()
  local i=0 arn=''
  acm_doc_load "$listf" || true
  while :; do
    acm_doc_get arn "$(acm_path CertificateSummaryList "$i" CertificateArn)" || break
    [[ -n $arn ]] && arns+=("$arn")
    i=$(( i + 1 ))
  done
  _ACM_CERTS_TOTAL=${#arns[@]}

  local now=${SCOURSH_CLOUD_ACM_NOW:-}
  [[ -n $now ]] || now=$(date +%s)

  local c
  for c in "${arns[@]+"${arns[@]}"}"; do
    _acm_examine_cert "$c" "$work" "$now"
  done

  _acm_record_coverage "$account" "$region"
  return 0
}

# `_acm_examine_cert ARN WORKDIR NOW` - the one per-certificate call and the
# one check over it.  Never returns non-zero.
_acm_examine_cert() {
  local arn=$1 work=$2 now=$3
  local safe=${arn//[^A-Za-z0-9._-]/_}
  local rc=0 f=$work/$safe.describe.json

  _acm_selected CLOUD-ACM-EXPIRING-01 || return 0

  aws_ro acm describe-certificate --certificate-arn "$arn" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    _acm_note_lost CLOUD-ACM-EXPIRING-01 "$reason"
    run_record coverage_reduction "module=cloud reason=$reason service=acm operation=describe-certificate certificate=$arn - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this certificate's expiry was NOT tested. Its absence from the findings is not evidence that it is fine."
    return 0
  fi
  _ACM_CERTS_EXAMINED=$(( _ACM_CERTS_EXAMINED + 1 ))
  acm_doc_load "$f" || true
  _acm_note_evaluated CLOUD-ACM-EXPIRING-01

  local status=''
  acm_cert_status_set status || true
  # PENDING_VALIDATION, INACTIVE, VALIDATION_TIMED_OUT, REVOKED and FAILED
  # certificates carry no meaningful "time remaining" story this check is
  # about - a pending certificate has never been issued, and the others are
  # already out of service for a different reason.  ISSUED and EXPIRED are the
  # two states a real NotAfter is actionable for; EXPIRED is the same
  # underlying fact at its most urgent value, not a second condition.
  case $status in
    ISSUED | EXPIRED) : ;;
    *) return 0 ;;
  esac

  local not_after=''
  acm_cert_not_after_set not_after || return 0

  acm_cert_is_expiring "$not_after" "$now" || return 0

  local domain='' days
  acm_cert_domain_set domain || true
  days=$(acm_days_until_expiry "$not_after" "$now")
  local when
  if (( days < 0 )); then
    when="expired $(( -days )) day(s) ago"
  else
    when="expires in $days day(s)"
  fi
  acm_emit_finding CLOUD-ACM-EXPIRING-01 "$arn" \
    "ACM certificate $arn${domain:+ ($domain)} $when (status $status), inside this check's $ACM_EXPIRY_WARNING_DAYS-day warning window. A certificate that is not renewed before NotAfter breaks TLS for every client of the service it terminates. If this certificate is ACM-managed with DNS or email validation and still attached to a listener, confirm renewal is not blocked by a missing/changed validation record; if it is imported (not ACM-issued), ACM cannot auto-renew it and it must be replaced manually."
  return 0
}

# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------
_acm_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_ACM_CHECK_IDS[@]+"${_ACM_CHECK_IDS[@]}"}"; do
    _acm_selected "$id" || continue
    if (( ${_ACM_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_ACM_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_ACM_LOST_REASON[$id]} service=acm check=$id account=$account region=$region certs_answered=${_ACM_EVALUATED[$id]} certs_unanswered=${_ACM_LOST[$id]} of ${_ACM_CERTS_TOTAL} - this check ran, but ${_ACM_LOST[$id]} certificate(s) did not answer, so it is covered for some of the region's certificates and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_ACM_LOST_REASON[$id]:-no_certificate_examined} service=acm check=$id account=$account region=$region certs_total=${_ACM_CERTS_TOTAL} certs_examined=${_ACM_CERTS_EXAMINED} - this check answered for NO certificate in the region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every certificate is fine."
    fi
  done

  if (( _ACM_CERTS_TOTAL == 0 )); then
    run_record notes "module=cloud service=acm account=$account region=$region certificates=0 - the region's certificate list was read successfully and contains no certificate, so CLOUD-ACM-EXPIRING-01 is covered vacuously."
  fi

  if (( ran == 0 && _ACM_CERTS_TOTAL > 0 )); then
    run_record coverage_gap "cloud acm: account $account region $region has $_ACM_CERTS_TOTAL certificate(s) and CLOUD-ACM-EXPIRING-01 answered for none of them, so no certificate's expiry was tested. This is a run that did not look, not a region with nothing wrong - the coverage_reduction above names the failure class."
  fi
  return 0
}

_acm_run_service
