#!/usr/bin/env bash
# modules/cloud/aws/live/governance_engine.sh - the pure half shared by the
# five §8.1 governance/detection read-only passes (docs/DESIGN.md §8.1's
# `cloudtrail` / `config` / `guardduty` / `inspector` / `macie` rows;
# docs/STEP6-CLOUD-PLAN.md CLOUD-30..34).
#
# WHY ONE SHARED ENGINE RATHER THAN FIVE, UNLIKE `s3_engine.sh`'s OWN
# PRECEDENT.  `s3_engine.sh`'s header states the rule step 6 should otherwise
# copy: one `live/<service>_engine.sh` per service.  This bundle departs from
# it deliberately, for a reason specific to these five services and not a
# general reconsideration: each of the five checks here is a single
# "is-it-enabled" observation over a tiny, mostly-flat response document, and
# the classifier logic every one of them needs - a JSON doc loader, a
# partition-aware pseudo-ARN builder for a resource AWS gives no ARN to (an
# empty detector/recorder list, a disabled Macie session), and the emitter -
# is IDENTICAL across all five, not merely similar the way, say, an ACL
# classifier and a policy classifier are similar.  Five near-duplicate files
# each carrying the same ~80 lines of doc-load/emit boilerplate for a check
# that itself is 30-60 lines is the premature-fragmentation failure this
# project's own CLAUDE.md warns against ("don't design for hypothetical
# future requirements"); one shared file for one cohesive PR-sized bundle
# (`docs/STEP6-CLOUD-PLAN.md`'s own "Tier 8 - governance & detection
# services (peers)" grouping) is the proportionate shape.  A later, larger
# service that genuinely needs its own classifiers (an ACL walk, a policy
# evaluator) still gets its own `<service>_engine.sh`, exactly as s3 did;
# this is not a reversal of that rule, only its scope read correctly for five
# checks this small.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_GOVERNANCE_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_GOVERNANCE_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten` / `cloud_json_unescape`
# / `cloud_check_selected` and is ALREADY SOURCED in every real run - regions.sh
# sources it before the service walk begins - so this guard is reached only by
# a direct-engine test.
#
# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is
# reached, and `shellcheck -x` re-expands EVERY source edge it follows rather
# than memoising - see tests/lint-source-graph.sh and docs/CI-RUNBOOK.md's
# "the memory model".  A direct-engine test suite sources engine.sh itself.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, NEVER a bare `declare`, for the reason modules/cloud/aws/engine.sh's
# own service table documents at length: a governance script is sourced from
# INSIDE `cloud_run_service`, so a bare `declare -A` here would create a LOCAL
# that dies with the pass rather than a global that survives it.
declare -gA _GOV_DOC=()
declare -gA _GOV_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document (byte-identical shape to s3_engine.sh's
#    s3_doc_load/s3_path/s3_doc_has/s3_doc_get, under a `gov_` prefix so the
#    two engines never collide when a test suite sources both).
# ---------------------------------------------------------------------------
gov_doc_load() {
  local file=$1
  _GOV_DOC=()
  _GOV_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe: a piped `while` runs its body in a
  # subshell and every key it stored would be discarded when that subshell
  # exits, leaving an empty map and a check that reports every resource
  # clean (lib/core.sh's `worker_id_set` lesson, in its loop form).
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _GOV_DOC[$path]=$val
    _GOV_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

gov_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

gov_doc_has() {
  [[ -n ${_GOV_DOCT[$1]+set} ]]
}

gov_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_GOV_DOC[$__path]:-}"
  [[ -n ${_GOV_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The partition and the account-level pseudo-resource
# ---------------------------------------------------------------------------
# `gov_partition_of CALLER_ARN` - byte-identical logic to s3_engine.sh's own
# `s3_partition_of`, duplicated rather than called: the two engines are
# intentionally NOT coupled to each other (s3_engine.sh's own header states
# an S3 classifier belongs to S3 and nothing else, and the symmetric argument
# applies here - a future edit to one must not have to reason about whether
# it also changes the other's behaviour).
gov_partition_of() {
  local arn=${1:-} rest part
  case $arn in
    arn:*)
      rest=${arn#arn:}
      part=${rest%%:*}
      [[ -n $part ]] && { printf '%s' "$part"; return 0; }
      ;;
  esac
  printf '%s' aws
}

# `gov_account_root_arn PARTITION ACCOUNT` - the pseudo-resource cited when a
# finding is about the ABSENCE of a service-level object (no CloudTrail trail
# anywhere in the account, no Config recorder, no GuardDuty detector) rather
# than about a specific misconfigured one.  `arn:<partition>:iam::<account>:root`
# is a REAL, resolvable ARN - the account's own root principal - chosen over
# an invented, non-standard ARN shape precisely because ARN correctness
# matters here the same way it does in s3_engine.sh's own partition
# reasoning: an operator pasting a fabricated ARN into a console or a policy
# gets silence rather than an error, while this one resolves to something
# real, unambiguous, and legitimately "the account" for a finding that is a
# fact about the whole account rather than about one resource.
gov_account_root_arn() {
  printf 'arn:%s:iam::%s:root' "$1" "$2"
}

# ---------------------------------------------------------------------------
# 3. Per-check selection (docs/FOUNDATION.md tension 15) - byte-identical to
#    s3.sh's own `_s3_selected`, duplicated here rather than in s3_engine.sh
#    for the identical reason gov_partition_of gives.
# ---------------------------------------------------------------------------
gov_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

# ---------------------------------------------------------------------------
# 4. Emission
# ---------------------------------------------------------------------------
# `gov_registry_locate_set SETVAR IDXVAR CHECK_ID` - find CHECK_ID in the
# check registry this run loaded.  Returns 1 when no loaded set carries it.
gov_registry_locate_set() {
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

# `gov_emit_finding CHECK_ID RESOURCE_ARN SUB_KEY EVIDENCE`
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD, exactly as
# s3_emit_finding's own header states at length - title, severity,
# confidence, cwe, owasp, remediation, references and `cis` all come from
# `finding_from_record` and are never restated here.
#
# THE REGION IS THE PASS'S OWN REGION, AND THAT IS NOT AN S3-STYLE SPLIT.
# Every one of these five services is declared `regional` in
# modules/cloud/aws/engine.sh's `_CLOUD_SERVICES` table (CloudTrail trails,
# Config recorders, GuardDuty detectors, Inspector2 and Macie2 account status
# are all genuinely per-region AWS objects, unlike S3's single account-wide
# `list-buckets`), so `SCOURSH_CLOUD_REGION` already IS the region the
# resource sits in and `SCOURSH_CLOUD_CELL` already IS `<account>/<that
# region>` - there is no bucket-region-versus-cell divergence to model here.
# A CloudTrail trail is the one exception worth naming: `cloudtrail.sh` only
# ever calls this with a trail whose OWN `HomeRegion` equals the current
# pass's region (see that file's own header), so the invariant holds there
# too.
gov_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  gov_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/governance emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # None of these five checks observes a public-internet exposure directly -
  # each is a fact about whether an account-level detection or audit control
  # is switched on, not about a resource being reachable - so every one of
  # them is `internal`/`user`, the same non-public branch S3's own
  # NO_VERSIONING/NO_LOGGING/NO_DEFAULT_ENCRYPTION checks use.
  finding_set exposure internal
  finding_set auth user
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
