#!/usr/bin/env bash
# modules/cloud/aws/live/cloudfront.sh - the §8.1 CloudFront read-only service
# pass (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-24).
#
# THIS IS A SERVICE SCRIPT, sourced by modules/cloud/aws/engine.sh's
# `cloud_run_service` - see s3.sh's own header for the full contract this
# carries verbatim (no sourced-once guard; a `global` row is reached once per
# account, with SCOURSH_CLOUD_REGION cleared to the literal `global`).  Its
# pure half is modules/cloud/aws/live/cloudfront_engine.sh.
#
# ONE LIST CALL, THEN ONE `get-distribution` PER DISTRIBUTION.  Unlike s3's
# seven-call-per-bucket shape, every one of this file's four checks reads
# from the SAME per-distribution document: `list-distributions` names every
# `DistributionSummary` in the account, but a summary carries no `Logging`
# block at all (CloudFront's own API shape - only the full `DistributionConfig`
# a `get-distribution` call returns has one), so this file always fetches the
# full config rather than trying to squeeze three of its four checks out of
# the summary and one out of a second call.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23), and
# the response is redirected to a file rather than captured with `$(...)` -
# see s3.sh's own header for why a command substitution would silently
# discard the honesty-outcome globals `aws_ro` sets.
#
# THE HONESTY ACCOUNTING RULES ARE s3.sh's, UNCHANGED: `checks_run` names
# what SUCCEEDED; a denied/throttled/truncated call is a `coverage_reduction`,
# never silence.  There is no `not_found`-shaped "answer that is a real
# result" here (unlike s3's three absence checks): every field this file
# reads is always present in a successful `get-distribution` response
# (`Logging`, `WebACLId`, `ViewerCertificate`, `DefaultCacheBehavior` and
# every `Origins.Items[]` entry are all REQUIRED members of `DistributionConfig`,
# never omitted the way an unset S3 sub-resource is), so every call failure
# here is a genuine coverage loss with no "the absent key is the answer" case
# to distinguish it from.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/cloudfront_engine.sh
source "${BASH_SOURCE[0]%/*}/cloudfront_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _CFD_DIST_TOTAL=0
declare -g _CFD_DIST_EXAMINED=0
declare -g _CFD_LIST_TRUNCATED=0
declare -gA _CFD_EVALUATED=()
declare -gA _CFD_LOST=()
declare -gA _CFD_LOST_REASON=()

declare -ga _CFD_CHECK_IDS=(
  CLOUD-CLOUDFRONT-VIEWER_HTTP_ALLOWED-01
  CLOUD-CLOUDFRONT-WEAK_MIN_TLS-01
  CLOUD-CLOUDFRONT-NO_WAF-01
  CLOUD-CLOUDFRONT-ORIGIN_EXPOSED-01
  CLOUD-CLOUDFRONT-NO_LOGGING-01
)

# `_cfd_selected ID` - byte-for-byte s3.sh's `_s3_selected`; see that file's
# own header for why the `declare -F` guard is permissive rather than
# fail-closed.
_cfd_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_cfd_note_evaluated() {
  _CFD_EVALUATED[$1]=$(( ${_CFD_EVALUATED[$1]:-0} + 1 ))
}

_cfd_note_lost() {
  _CFD_LOST[$1]=$(( ${_CFD_LOST[$1]:-0} + 1 ))
  [[ -n ${_CFD_LOST_REASON[$1]:-} ]] || _CFD_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_cfd_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-cfd.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_CFD_CHECK_IDS[@]+"${_CFD_CHECK_IDS[@]}"}"; do
    _cfd_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_cloudfront_checks_deselected service=cloudfront account=$account - every CLOUD-CLOUDFRONT-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no CloudFront API call was made and no distribution was examined."
    return 0
  fi

  local listf=$work/list-distributions.json rc=0
  aws_ro cloudfront list-distributions >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=cloudfront operation=list-distributions account=$account cell=${SCOURSH_CLOUD_CELL:-} - the account's distribution list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO distribution was examined and none of the ${#_CFD_CHECK_IDS[@]} CLOUD-CLOUDFRONT-* checks ran."
    run_record coverage_gap "cloud cloudfront: the distribution list for account $account could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no distribution's viewer TLS policy, WAF association, origin access control or logging was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds cloudfront:ListDistributions."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _CFD_LIST_TRUNCATED=1
  fi

  local -a ids=()
  local i=0 id_val=''
  cfd_doc_load "$listf" || true
  while :; do
    cfd_doc_has "$(cfd_path DistributionList Items "$i" Id)" || break
    cfd_doc_get id_val "$(cfd_path DistributionList Items "$i" Id)"
    [[ -n $id_val ]] && ids+=("$id_val")
    i=$(( i + 1 ))
  done
  _CFD_DIST_TOTAL=${#ids[@]}

  local d
  for d in "${ids[@]+"${ids[@]}"}"; do
    _cfd_examine_distribution "$d" "$work"
  done

  _cfd_record_coverage "$account"
  return 0
}

# `_cfd_examine_distribution ID WORKDIR` - one `get-distribution` call and the
# five checks over it.  Never returns non-zero: a distribution that cannot be
# examined is an accounted-for reduction, not a reason to abandon the ones
# after it.
_cfd_examine_distribution() {
  local id=$1 work=$2
  local safe=${id//[^A-Za-z0-9._-]/_}
  local f=$work/$safe.get-distribution.json rc=0

  local viewer_id=CLOUD-CLOUDFRONT-VIEWER_HTTP_ALLOWED-01
  local tls_id=CLOUD-CLOUDFRONT-WEAK_MIN_TLS-01
  local waf_id=CLOUD-CLOUDFRONT-NO_WAF-01
  local origin_id=CLOUD-CLOUDFRONT-ORIGIN_EXPOSED-01
  local log_id=CLOUD-CLOUDFRONT-NO_LOGGING-01

  aws_ro cloudfront get-distribution --id "$id" >"$f" || rc=$?
  if (( rc != 0 )); then
    local reason='' cid
    aws_ro_reduction_reason_set reason
    for cid in "${_CFD_CHECK_IDS[@]+"${_CFD_CHECK_IDS[@]}"}"; do
      _cfd_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=cloudfront operation=get-distribution distribution=$id - the distribution's configuration could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so none of its five properties was examined at all."
    return 0
  fi
  _CFD_DIST_EXAMINED=$(( _CFD_DIST_EXAMINED + 1 ))

  cfd_doc_load "$f" || true
  local arn=''
  cfd_doc_get arn "$(cfd_path Distribution ARN)" || true
  [[ -n $arn ]] || arn="arn:aws:cloudfront::${SCOURSH_CLOUD_ACCOUNT_ID:-}:distribution/$id"

  # ---- viewer protocol policy -------------------------------------------
  if _cfd_selected "$viewer_id"; then
    _cfd_note_evaluated "$viewer_id"
    local vpp=''
    cfd_doc_get vpp "$(cfd_path Distribution DistributionConfig DefaultCacheBehavior ViewerProtocolPolicy)" || true
    if cfd_viewer_policy_allows_http "$vpp"; then
      cfd_emit_finding "$viewer_id" "$arn" '' \
        "Distribution $id's default cache behavior has ViewerProtocolPolicy set to allow-all, so a viewer may reach it over plain HTTP as well as HTTPS - no TLS is enforced between the viewer and CloudFront at all. Set the viewer protocol policy to redirect-to-https or https-only."
    fi
  fi

  # ---- minimum TLS protocol ----------------------------------------------
  if _cfd_selected "$tls_id"; then
    _cfd_note_evaluated "$tls_id"
    local minproto=''
    cfd_doc_get minproto "$(cfd_path Distribution DistributionConfig ViewerCertificate MinimumProtocolVersion)" || true
    if cfd_min_protocol_is_weak "$minproto"; then
      cfd_emit_finding "$tls_id" "$arn" '' \
        "Distribution $id's viewer certificate configures MinimumProtocolVersion '${minproto:-<absent>}', which does not guarantee TLS 1.2. A distribution serving the CloudFront default certificate cannot set a custom minimum at all and is reported here for the same reason; attach a certificate through ACM and set a TLSv1.2_2021 (or later) minimum protocol version."
    fi
  fi

  # ---- WAF association -----------------------------------------------------
  if _cfd_selected "$waf_id"; then
    _cfd_note_evaluated "$waf_id"
    local webacl=''
    cfd_doc_get webacl "$(cfd_path Distribution DistributionConfig WebACLId)" || true
    if [[ -z $webacl ]]; then
      cfd_emit_finding "$waf_id" "$arn" '' \
        "Distribution $id has no AWS WAF web ACL associated (WebACLId is empty), so none of its requests are evaluated against a managed or custom rule set before reaching an origin. Associate a web ACL, at minimum the AWS Managed Core rule group, to filter common web exploits at the edge."
    fi
  fi

  # ---- origin exposure (S3 origin with no OAC/OAI) -----------------------
  if _cfd_selected "$origin_id"; then
    _cfd_note_evaluated "$origin_id"
    local n=0
    while :; do
      local base
      base=$(cfd_path Distribution DistributionConfig Origins Items "$n")
      cfd_doc_has "$(cfd_path "$base" Id)" || break
      # An origin is an S3 origin only when it carries an `S3OriginConfig`
      # block at all - a `CustomOriginConfig` (an ALB, an on-prem server, any
      # non-S3 HTTP(S) backend) is out of this check's scope: OAC/OAI is
      # exclusively an S3-origin access-control mechanism, and flagging a
      # custom origin for lacking one would be a defect this check has no
      # standing to raise.
      if cfd_doc_has "$(cfd_path "$base" S3OriginConfig OriginAccessIdentity)"; then
        local oai='' oac='' origin_id_field=''
        cfd_doc_get oai "$(cfd_path "$base" S3OriginConfig OriginAccessIdentity)"
        cfd_doc_get oac "$(cfd_path "$base" OriginAccessControlId)" || true
        cfd_doc_get origin_id_field "$(cfd_path "$base" Id)"
        if [[ -z $oai && -z $oac ]]; then
          cfd_emit_finding "$origin_id" "$arn" "$origin_id_field" \
            "Distribution $id's origin '$origin_id_field' is an S3 origin with neither an Origin Access Control nor a (legacy) Origin Access Identity configured, so the bucket must be readable by more than just this distribution - typically the whole bucket is public, or it trusts a wider principal than CloudFront alone. Configure an Origin Access Control and restrict the bucket policy to it, so the S3 origin is reachable only through this distribution."
        fi
      fi
      n=$(( n + 1 ))
    done
  fi

  # ---- logging -------------------------------------------------------------
  if _cfd_selected "$log_id"; then
    _cfd_note_evaluated "$log_id"
    local logging_enabled=''
    cfd_doc_get logging_enabled "$(cfd_path Distribution DistributionConfig Logging Enabled)" || true
    if [[ $logging_enabled != true ]]; then
      cfd_emit_finding "$log_id" "$arn" '' \
        "Distribution $id does not have standard access logging enabled, so there is no per-request record of what CloudFront served at the edge. A later investigation into a suspected abuse or content exposure has nothing to work from."
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_cfd_record_coverage() {
  local account=$1 id
  local ran=0
  for id in "${_CFD_CHECK_IDS[@]+"${_CFD_CHECK_IDS[@]}"}"; do
    _cfd_selected "$id" || continue
    if (( ${_CFD_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_CFD_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_CFD_LOST_REASON[$id]} service=cloudfront check=$id account=$account distributions_answered=${_CFD_EVALUATED[$id]} distributions_unanswered=${_CFD_LOST[$id]} of ${_CFD_DIST_TOTAL} - this check ran, but ${_CFD_LOST[$id]} distribution(s) did not answer, so it is covered for some of the account's distributions and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_CFD_LOST_REASON[$id]:-no_distribution_examined} service=cloudfront check=$id account=$account distributions_total=${_CFD_DIST_TOTAL} distributions_examined=${_CFD_DIST_EXAMINED} - this check answered for NO distribution in the account and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every distribution is configured correctly."
    fi
  done

  if (( _CFD_DIST_TOTAL == 0 )); then
    # A genuinely empty account: the list call succeeded (this function is
    # only reached after it did), so the run DID look and there was nothing
    # to look at - s3.sh's identical reasoning for its own empty-account case.
    run_record notes "module=cloud service=cloudfront account=$account distributions=0 - the account's distribution list was read successfully and contains no distribution, so every CLOUD-CLOUDFRONT-* check is covered vacuously."
  fi

  if (( _CFD_LIST_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=cloudfront operation=list-distributions account=$account distributions_seen=$_CFD_DIST_TOTAL - the distribution list came back INCOMPLETE (a continuation marker was present, or the page ceiling was reached), so an unknown number of this account's distributions were never enumerated and were not examined by any CLOUD-CLOUDFRONT-* check."
    run_record coverage_gap "cloud cloudfront: the distribution list for account $account was truncated at $_CFD_DIST_TOTAL distribution(s), so an unknown number of distributions were never examined. A clean result for those distributions is the absence of a test, not the absence of a problem."
  fi

  if (( ran == 0 && _CFD_DIST_TOTAL > 0 )); then
    run_record coverage_gap "cloud cloudfront: account $account has $_CFD_DIST_TOTAL distribution(s) and NOT ONE of the ${#_CFD_CHECK_IDS[@]} CLOUD-CLOUDFRONT-* checks answered for any of them, so no distribution's viewer TLS, WAF association, origin access control or logging posture was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_cfd_run_service
