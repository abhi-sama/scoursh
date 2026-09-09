#!/usr/bin/env bash
# modules/cloud/aws/live/config.sh - the §8.1 AWS Config read-only pass
# (docs/DESIGN.md §8.1's `config` row; docs/STEP6-CLOUD-PLAN.md CLOUD-31).
#
# A SERVICE SCRIPT, reached by `cloud_run_service`'s plain `source` once per
# enabled region (`config` is `regional` in modules/cloud/aws/engine.sh's
# `_CLOUD_SERVICES` table - correctly, since a Config configuration recorder
# is genuinely a per-region singleton, unlike CloudTrail's account-wide,
# shadowed trail).  No sourced-once guard, for the identical reason
# cloudtrail.sh's own header gives.  Its pure half is
# modules/cloud/aws/live/governance_engine.sh.
#
# THE AWS CLI SERVICE NAME IS `configservice`, NOT `config` - `aws config
# ...` is a distinct, unrelated CLI top-level command (AWS AppConfig's
# predecessor namespace collision), and `docs/STEP6-CLOUD-PLAN.md`'s own
# CLOUD-31 row states this explicitly.  Every call below is spelled
# `configservice`, literally, for the same reason every call in this bundle
# is spelled literally: tests/lint-aws-readonly.sh parses the operation text
# out of the source line, not out of a variable.
#
# THE ARN THIS CHECK CITES IS A SCOURSH-CONSTRUCTED PSEUDO-ARN, NOT AN
# AWS-PUBLISHED ONE.  A Config configuration recorder has no ARN in AWS's own
# API or documentation - it is addressed by NAME alone, within one
# (account, region) pair - unlike a Config RULE, which does have a published
# `arn:aws:config:region:account:config-rule/config-rule-xxx` form.
# `arn:<partition>:config:<region>:<account>:configuration-recorder/<name>`
# is this file's own construction, chosen to stay legible and consistent
# with every other AWS ARN this codebase cites rather than because AWS
# documents it - the account root ARN (`gov_account_root_arn`) is used
# instead wherever there is no recorder object at all to name.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/governance_engine.sh
source "${BASH_SOURCE[0]%/*}/governance_engine.sh"

declare -g _CFG_ID=CLOUD-CONFIG-RECORDER_OFF-01

_cfg_recorder_arn() {
  printf 'arn:%s:config:%s:%s:configuration-recorder/%s' "$1" "$2" "$3" "$4"
}

_cfg_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local id=$_CFG_ID

  if ! gov_selected "$id"; then
    run_record coverage_reduction "module=cloud reason=all_config_checks_deselected service=configservice account=$account region=$region - $id was removed by this run's check-selection filters, so no AWS Config API call was made."
    return 0
  fi

  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-cfg.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local recf=$work/describe-configuration-recorders.json rc=0
  aws_ro configservice describe-configuration-recorders >"$recf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=configservice operation=describe-configuration-recorders account=$account region=$region - the recorder list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so $id was not tested in this region."
    return 0
  fi

  gov_doc_load "$recf" || true
  local partition
  partition=$(gov_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  if ! gov_doc_has "$(gov_path ConfigurationRecorders 0 name)"; then
    # No recorder exists in this region at all.  A real answer - AWS Config
    # is genuinely off here - not a coverage loss.
    run_record checks_run "$id"
    gov_emit_finding "$id" "$(gov_account_root_arn "$partition" "$account")" '' \
      "AWS Config has no configuration recorder in region $region of account $account (describe-configuration-recorders returned an empty list), so no resource configuration changes are being tracked here at all. CIS 3.3 requires AWS Config enabled with a recorder in every region."
    return 0
  fi

  local statf=$work/describe-configuration-recorder-status.json rc2=0
  aws_ro configservice describe-configuration-recorder-status >"$statf" || rc2=$?
  if (( rc2 != 0 )); then
    local reason2=''
    aws_ro_reduction_reason_set reason2
    run_record coverage_reduction "module=cloud reason=$reason2 service=configservice operation=describe-configuration-recorder-status account=$account region=$region - a configuration recorder exists in region $region but its recording status could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so $id was not tested for it. Its absence from the findings is not evidence that recording is on."
    return 0
  fi
  gov_doc_load "$statf" || true

  local i=0 name='' recording=''
  local any=0
  while :; do
    gov_doc_has "$(gov_path ConfigurationRecordersStatus "$i" name)" || break
    gov_doc_get name "$(gov_path ConfigurationRecordersStatus "$i" name)"
    gov_doc_get recording "$(gov_path ConfigurationRecordersStatus "$i" recording)"
    i=$(( i + 1 ))
    any=1
    [[ $recording == true ]] && continue
    gov_emit_finding "$id" "$(_cfg_recorder_arn "$partition" "$region" "$account" "$name")" '' \
      "AWS Config configuration recorder '$name' in region $region of account $account exists but is not recording (describe-configuration-recorder-status reports recording false), so resource configuration changes are not being tracked while it stays in this state. Start the recorder (StartConfigurationRecorder)."
  done

  if (( any )); then
    run_record checks_run "$id"
  else
    # A recorder object exists but the status call named none of them - a
    # document-shape mismatch this pass did not expect, so it is honestly
    # reported as not tested rather than silently credited.
    run_record coverage_reduction "module=cloud reason=no_recorder_status_matched service=configservice check=$id account=$account region=$region - a configuration recorder exists in this region, but describe-configuration-recorder-status named none of them, so $id was not tested."
  fi
  return 0
}

_cfg_run_service
