#!/usr/bin/env bash
# modules/cloud/aws/live/macie.sh - the §8.1 Macie2 read-only pass
# (docs/DESIGN.md §8.1's `macie` row; docs/STEP6-CLOUD-PLAN.md CLOUD-34).
#
# A SERVICE SCRIPT, sourced once per enabled region (`macie` is `regional` in
# modules/cloud/aws/engine.sh's `_CLOUD_SERVICES` table - a Macie session is
# genuinely a per-(account, region) object).  No sourced-once guard, for the
# identical reason cloudtrail.sh's own header gives.  Its pure half is
# modules/cloud/aws/live/governance_engine.sh.
#
# NO `cis:` VALUE IS AUTHORED ON THIS CHECK'S RECORD, for the identical
# reason guardduty.sh's own header states: CIS Amazon Web Services
# Foundations Benchmark v3.0.0 has no Macie control, and
# modules/cloud/aws/live/checks.rules's header forbids inventing one.
#
# THE ONE GENUINE HAZARD IN THIS FILE: `get-macie-session` REPORTS "Macie is
# not enabled" AS AN AccessDeniedException, THE SAME AWS ERROR CODE A REAL
# PERMISSION GAP RETURNS.  Every other check in this bundle gets an honest,
# distinguishable signal for "the service is off" - an empty list (GuardDuty,
# Config, CloudTrail) or a status field with a real value (Inspector2).
# Macie is the exception: a disabled Macie account makes `get-macie-session`
# FAIL, and lib/awscli.sh's `_awscli_classify` has no way to tell that
# failure apart from an operator's scanning role genuinely lacking
# `macie2:GetMacieSession` - both classify as `access_denied`, because AWS
# gives both the identical error CODE.
#
# This file treats an `access_denied` outcome on THIS SPECIFIC CALL as the
# ANSWER "Macie is not enabled" rather than as a coverage loss, matching how
# real-world AWS security tooling (Prowler and ScoutSuite both do this)
# reads the identical signal.  The cost of being wrong is real and is worth
# naming rather than hiding: an account whose scanning role is missing
# EXACTLY `macie2:GetMacieSession` and nothing else would be reported as
# "Macie disabled" when the true state is unknown.  That is why this is the
# one check in the bundle whose registry record carries `confidence: medium`
# rather than `high` - the observation method itself has a known, stated
# ambiguity, and the confidence field is where that belongs (rather than a
# silent guess dressed as certainty).  A genuinely UNRELATED failure -
# `throttled`, `no_credentials`, `endpoint_unreachable` - is still a real
# coverage loss and is recorded as one, never folded into the "disabled"
# reading.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/governance_engine.sh
source "${BASH_SOURCE[0]%/*}/governance_engine.sh"

declare -g _MC_ID=CLOUD-MACIE-DISABLED-01

_mc_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local id=$_MC_ID

  if ! gov_selected "$id"; then
    run_record coverage_reduction "module=cloud reason=all_macie_checks_deselected service=macie2 account=$account region=$region - $id was removed by this run's check-selection filters, so no Macie2 API call was made."
    return 0
  fi

  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-mc.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local partition
  partition=$(gov_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  local f=$work/get-macie-session.json rc=0
  aws_ro macie2 get-macie-session >"$f" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == access_denied ]]; then
      # The documented ambiguity above: read as "Macie is not enabled here",
      # not as a coverage loss.
      run_record checks_run "$id"
      gov_emit_finding "$id" "$(gov_account_root_arn "$partition" "$account")" '' \
        "Amazon Macie is not enabled in region $region of account $account (get-macie-session was refused, which is how Macie itself reports a disabled account in this region - see this file's own header for why that reading is a stated ambiguity rather than a certainty), so no automated discovery of sensitive data (PII, credentials, financial records) in this region's S3 buckets is running. Enable Macie in this region."
      return 0
    fi
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=macie2 operation=get-macie-session account=$account region=$region - the Macie session status could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so $id was not tested in this region."
    return 0
  fi

  gov_doc_load "$f" || true
  run_record checks_run "$id"
  local status=''
  gov_doc_get status status
  [[ $status == ENABLED ]] && return 0
  gov_emit_finding "$id" "$(gov_account_root_arn "$partition" "$account")" '' \
    "Amazon Macie in region $region of account $account has a session but it is not active (get-macie-session reports status $status, expected ENABLED), so no automated discovery of sensitive data in this region's S3 buckets is running while it stays in this state. Resume the Macie session (EnableMacie / a status update to ENABLED)."
  return 0
}

_mc_run_service
