#!/usr/bin/env bash
# modules/cloud/aws/live/opensearch.sh - the §8.1 OpenSearch read-only service
# pass (docs/DESIGN.md §8.1's `opensearch` row; docs/STEP6-CLOUD-PLAN.md
# CLOUD-17).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard - `opensearch` is `regional`, so
# this pass legitimately runs once per enabled region, and a guard would
# silently make every region after the first a no-op.  Its pure half is
# modules/cloud/aws/live/opensearch_engine.sh, which does have a guard.
#
# TWO CALLS PER DOMAIN, NOT SEVEN: `list-domain-names` names every domain in
# the ambient region, and `describe-domain` alone answers every one of the
# three checks below (ARN, VPC placement, access policy, both encryption
# flags) - unlike S3, there is no separate per-property call to make.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, exactly as s3.sh's own header
# states it: `checks_run` names what actually answered, an `AccessDenied` (or
# any other `aws_ro_outcome_is_coverage_loss` outcome) on `describe-domain` is
# a `coverage_reduction` for every check that domain would have answered,
# never silence.  Unlike S3, no `NotFound`-shaped error here is itself an
# ANSWER: `describe-domain` either returns the whole document or it does not,
# so every failure here is a loss, never a "there is no policy" reading.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/opensearch_engine.sh
source "${BASH_SOURCE[0]%/*}/opensearch_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
declare -g _OS_DOMAINS_TOTAL=0
declare -g _OS_DOMAINS_EXAMINED=0
declare -gA _OS_EVALUATED=()
declare -gA _OS_LOST=()
declare -gA _OS_LOST_REASON=()

declare -ga _OS_CHECK_IDS=(
  CLOUD-OPENSEARCH-PUBLIC_ACCESS-01
  CLOUD-OPENSEARCH-NO_ENCRYPTION_AT_REST-01
  CLOUD-OPENSEARCH-NO_ENCRYPTION_IN_TRANSIT-01
)

# `_os_selected ID` - tension 15's per-check filter.  Permissive when
# `cloud_check_selected` is not loaded, for the identical reason s3.sh's own
# `_s3_selected` gives: a direct-engine test suite sources this script with no
# module engine in the process.
_os_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_os_note_evaluated() {
  _OS_EVALUATED[$1]=$(( ${_OS_EVALUATED[$1]:-0} + 1 ))
}

_os_note_lost() {
  _OS_LOST[$1]=$(( ${_OS_LOST[$1]:-0} + 1 ))
  [[ -n ${_OS_LOST_REASON[$1]:-} ]] || _OS_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_os_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-opensearch.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_OS_CHECK_IDS[@]+"${_OS_CHECK_IDS[@]}"}"; do
    _os_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_opensearch_checks_deselected service=opensearch account=$account region=$region - every CLOUD-OPENSEARCH-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no OpenSearch API call was made and no domain was examined."
    return 0
  fi

  local listf=$work/list-domain-names.json rc=0
  aws_ro opensearch list-domain-names >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=opensearch operation=list-domain-names account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the domain list for this region could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO OpenSearch domain was examined and none of the ${#_OS_CHECK_IDS[@]} CLOUD-OPENSEARCH-* checks ran."
    run_record coverage_gap "cloud opensearch: the domain list for account $account region $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no domain's public accessibility, encryption at rest or encryption in transit was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds es:ListDomainNames."
    return 0
  fi

  local -a domains=()
  local i=0 name=''
  opensearch_doc_load "$listf" || true
  while :; do
    [[ -n ${_OS_DOCT[DomainNames$'\x1f'$i$'\x1f'DomainName]+set} ]] || break
    name=${_OS_DOC[DomainNames$'\x1f'$i$'\x1f'DomainName]:-}
    [[ -n $name ]] && domains+=("$name")
    i=$(( i + 1 ))
  done
  _OS_DOMAINS_TOTAL=${#domains[@]}

  local d
  for d in "${domains[@]+"${domains[@]}"}"; do
    _os_examine_domain "$d" "$work"
  done

  _os_record_coverage "$account" "$region"
  return 0
}

# `_os_examine_domain DOMAIN WORKDIR` - one `describe-domain` call, then the
# three checks over its single response document.  Never returns non-zero: a
# domain that cannot be examined is an accounted-for reduction.
_os_examine_domain() {
  local d=$1 work=$2
  local safe=${d//[^A-Za-z0-9._-]/_}
  local rc=0 reason=''

  aws_ro opensearch describe-domain --domain-name "$d" >"$work/$safe.describe.json" || rc=$?
  if (( rc != 0 )); then
    aws_ro_reduction_reason_set reason
    local cid
    for cid in "${_OS_CHECK_IDS[@]+"${_OS_CHECK_IDS[@]}"}"; do
      _os_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=opensearch operation=describe-domain domain=$d - the domain's configuration could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so it was not examined at all."
    return 0
  fi
  _OS_DOMAINS_EXAMINED=$(( _OS_DOMAINS_EXAMINED + 1 ))
  opensearch_doc_load "$work/$safe.describe.json" || true

  local arn=''
  opensearch_arn_set arn || true
  [[ -n $arn ]] || arn="arn:aws:es:${SCOURSH_CLOUD_REGION:-}:${SCOURSH_CLOUD_ACCOUNT_ID:-}:domain/$d"

  local id=CLOUD-OPENSEARCH-PUBLIC_ACCESS-01
  if _os_selected "$id"; then
    _os_note_evaluated "$id"
    if opensearch_is_publicly_open; then
      opensearch_emit_finding "$id" "$arn" \
        "OpenSearch domain $d ($arn) is reachable on its public AWS-owned endpoint (no VPCOptions) and its access policy grants an Allow statement to the wildcard Principal \"*\", so any host on the internet that can reach the endpoint can call it. This is a heuristic reading of the raw AccessPolicies document, not AWS's own policy evaluation - review the full policy for any Condition that narrows it before treating this as certain."
    fi
  fi

  id=CLOUD-OPENSEARCH-NO_ENCRYPTION_AT_REST-01
  if _os_selected "$id"; then
    _os_note_evaluated "$id"
    if ! opensearch_encrypted_at_rest; then
      opensearch_emit_finding "$id" "$arn" \
        "OpenSearch domain $d ($arn) has no encryption at rest enabled (EncryptionAtRestOptions.Enabled is not true), so the indices, snapshots and slow/error logs this domain stores are held in plaintext on the underlying storage. Enable encryption at rest with an AWS-owned or customer-managed KMS key; this setting can only be changed by creating a new domain and reindexing into it, so plan the migration rather than expecting an in-place toggle."
    fi
  fi

  id=CLOUD-OPENSEARCH-NO_ENCRYPTION_IN_TRANSIT-01
  if _os_selected "$id"; then
    _os_note_evaluated "$id"
    if ! opensearch_encrypted_in_transit; then
      opensearch_emit_finding "$id" "$arn" \
        "OpenSearch domain $d ($arn) has node-to-node transport encryption disabled (NodeToNodeEncryptionOptions.Enabled is not true), so traffic between the domain's own data nodes crosses the network in the clear. Enable node-to-node encryption so inter-node traffic is encrypted; this is a distinct setting from HTTPS-to-client, which this check does not evaluate."
    fi
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
_os_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_OS_CHECK_IDS[@]+"${_OS_CHECK_IDS[@]}"}"; do
    _os_selected "$id" || continue
    if (( ${_OS_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_OS_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_OS_LOST_REASON[$id]} service=opensearch check=$id account=$account region=$region domains_answered=${_OS_EVALUATED[$id]} domains_unanswered=${_OS_LOST[$id]} of ${_OS_DOMAINS_TOTAL} - this check ran, but ${_OS_LOST[$id]} domain(s) did not answer, so it is covered for some of this region's domains and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_OS_LOST_REASON[$id]:-no_domain_examined} service=opensearch check=$id account=$account region=$region domains_total=${_OS_DOMAINS_TOTAL} domains_examined=${_OS_DOMAINS_EXAMINED} - this check answered for NO domain in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every domain is configured correctly."
    fi
  done

  if (( _OS_DOMAINS_TOTAL == 0 )); then
    run_record notes "module=cloud service=opensearch account=$account region=$region domains=0 - the domain list was read successfully and contains no domain, so every CLOUD-OPENSEARCH-* check is covered vacuously."
  fi

  if (( ran == 0 && _OS_DOMAINS_TOTAL > 0 )); then
    run_record coverage_gap "cloud opensearch: account $account region $region has $_OS_DOMAINS_TOTAL domain(s) and NOT ONE of the ${#_OS_CHECK_IDS[@]} CLOUD-OPENSEARCH-* checks answered for any of them, so no domain's public accessibility, encryption at rest or encryption in transit was tested. This is a run that did not look, not a region with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_os_run_service
