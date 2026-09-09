#!/usr/bin/env bash
# modules/cloud/aws/live/acm_engine.sh - the pure half of the §8.1 ACM
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-10).
#
# `acm` IS `regional`: `list-certificates`/`describe-certificate` both answer
# for the region the call was addressed to, so `loc_region` is the pass's own
# ambient region, exactly as sns_engine.sh/sqs_engine.sh record for their own
# services.
#
# EXPIRY TAKES "NOW" AS AN ARGUMENT, NEVER `date +%s` CALLED INLINE INSIDE A
# CLASSIFIER.  AGENTS.md's own DAST-07 TLS lesson applies verbatim one layer
# up: hardcoding the system clock makes a fixture's expiry outcome (`ok`,
# `expiring`, `expired`) depend on the day the suite happens to run, which is
# exactly the kind of test that goes red on its own a year later with no code
# change.  `acm_days_until_expiry NOT_AFTER NOW` is a pure function of two
# epoch-second integers, so a committed fixture certificate reaches every
# outcome deterministically regardless of when the suite runs.
#
# `NotAfter` ARRIVES AS A JSON NUMBER, OFTEN WITH A TRAILING `.0` - AWS's ACM
# API returns it as an epoch-seconds float, and bash arithmetic has no float
# type, so the fractional part is truncated (never rounded) before use.  A
# 30-DAY THRESHOLD IS FIXED ON THE CHECK, NOT A NEW CLI FLAG: exposing one
# would be scope this ticket does not need, and the number is stated plainly
# in the finding's own evidence so an operator who disagrees can see exactly
# what was applied.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_ACM_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_ACM_ENGINE_SOURCED=1

# -x back-edge cut: see sns_engine.sh's identical note.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _ACM_DOC=()
declare -gA _ACM_DOCT=()

# The threshold, in days, at which a certificate is reported as "nearing
# expiry".  A certificate already past NotAfter is reported too - it is the
# same underlying fact (insufficient time remaining) at its most urgent value,
# not a second condition - see this file's checks.rules record for why that is
# ONE check id rather than two.
declare -gi ACM_EXPIRY_WARNING_DAYS=30

# ---------------------------------------------------------------------------
# 1. Reading a response document
# ---------------------------------------------------------------------------
acm_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

acm_doc_load() {
  local file=$1
  _ACM_DOC=()
  _ACM_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _ACM_DOC[$path]=$val
    _ACM_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

acm_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_ACM_DOC[$__path]:-}"
  [[ -n ${_ACM_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Classifiers
# ---------------------------------------------------------------------------
# `acm_cert_status_set VARNAME` - `Certificate.Status`, over the loaded
# `describe-certificate` document.
acm_cert_status_set() {
  local __var=$1
  printf -v "$__var" '%s' "${_ACM_DOC[$(acm_path Certificate Status)]:-}"
  [[ -n ${_ACM_DOC[$(acm_path Certificate Status)]:-} ]]
}

# `acm_cert_domain_set VARNAME` - `Certificate.DomainName`, for the evidence
# text; a certificate always carries one.
acm_cert_domain_set() {
  local __var=$1
  printf -v "$__var" '%s' "${_ACM_DOC[$(acm_path Certificate DomainName)]:-}"
  [[ -n ${_ACM_DOC[$(acm_path Certificate DomainName)]:-} ]]
}

# `acm_cert_not_after_set VARNAME` - `Certificate.NotAfter` as a plain integer
# epoch-seconds value, the fractional part (if any) truncated.  Returns 1 with
# VARNAME empty when the certificate carries none at all - a PENDING_VALIDATION
# certificate has never been issued and has no expiry to report on.
acm_cert_not_after_set() {
  local __var=$1 __raw
  __raw=${_ACM_DOC[$(acm_path Certificate NotAfter)]:-}
  [[ -n $__raw ]] || { printf -v "$__var" '%s' ''; return 1; }
  printf -v "$__var" '%s' "${__raw%%.*}"
  return 0
}

# `acm_days_until_expiry NOT_AFTER NOW` - whole days from NOW to NOT_AFTER,
# both epoch seconds.  Negative when the certificate has already expired.
# Bash integer division truncates toward zero rather than flooring, which
# would round a just-expired certificate's negative remainder up toward 0 -
# dividing the (always non-positive-safe) SECONDS difference directly, rather
# than computing on already-divided days, is what keeps the comparison in
# `acm_cert_is_expiring` exact regardless of truncation direction.
acm_days_until_expiry() {
  local not_after=$1 now=$2
  printf '%s' "$(( (not_after - now) / 86400 ))"
}

# `acm_cert_is_expiring NOT_AFTER NOW` - true when fewer than
# `ACM_EXPIRY_WARNING_DAYS` days remain, INCLUSIVE of an already-past
# NOT_AFTER (a negative remainder is always `<=` a positive threshold).
# Compared in SECONDS, never on the day-truncated output of
# `acm_days_until_expiry`, so a certificate expiring in 29 days and 23 hours
# is not rounded down into "30 days" and missed.
acm_cert_is_expiring() {
  local not_after=$1 now=$2
  (( not_after - now <= ACM_EXPIRY_WARNING_DAYS * 86400 ))
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
acm_registry_locate_set() {
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

acm_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  acm_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/acm emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  finding_set exposure internal
  finding_set auth user
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
