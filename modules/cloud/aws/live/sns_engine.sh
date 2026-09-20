#!/usr/bin/env bash
# modules/cloud/aws/live/sns_engine.sh - the pure half of the §8.1 SNS
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-28).
#
# The run.sh/engine.sh split modules/sast/ established, reused by
# modules/cloud/aws/live/s3_engine.sh one level down: this file is a pure
# function library with the standard sourced-once guard and no side effect at
# source time; modules/cloud/aws/live/sns.sh is the file that DOES something
# when `cloud_run_service` sources it.
#
# `sns` IS `regional`, UNLIKE `s3`.  `list-topics`/`get-topic-attributes` both
# answer for the region the call was addressed to, so every topic this pass
# examines already belongs to `SCOURSH_CLOUD_REGION` - there is no per-topic
# region to resolve the way S3's per-bucket `get-bucket-location` call exists
# for.  `loc_region` is therefore the pass's own ambient region, read straight
# off `SCOURSH_CLOUD_REGION`.
#
# THE POLICY CHECK HAS NO AWS-SIDE EVALUATOR TO DEFER TO.  S3 has
# `get-bucket-policy-status`, which asks AWS to evaluate publicness with the
# same engine that serves real requests; SNS (and SQS) have no equivalent
# operation, so this file parses the resource policy DOCUMENT itself.  The
# rule is intentionally conservative and is a real, stated scope limitation
# rather than an oversight: a statement is treated as public when it grants
# Effect Allow to a Principal that is (or contains) the literal wildcard `*`
# AND carries NO `Condition` block at all.  A `Condition` - however narrow or
# broad - suppresses the finding, because evaluating whether a given Condition
# key genuinely narrows the grant (`aws:SourceArn` does; `aws:SourceIp` on an
# SNS API call does not, since SNS has no concept of the caller's IP) is a
# second IAM-policy-evaluation engine this scanner does not carry and must not
# quietly approximate. This is the same shape `_s3_check_bpa`'s "an absent key
# is a gap, not a pass" note takes from the other direction: better to under-
# report (miss a narrowed-but-still-risky grant) than to invent a verdict AWS
# itself was never asked for.  A `Statement` that is a bare object rather than
# an array (valid IAM grammar for a single-statement policy) is NOT walked -
# every AWS-console- and CLI-authored policy on record emits the array form,
# and this is recorded here as a stated gap rather than silently assumed
# covered.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_SNS_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_SNS_ENGINE_SOURCED=1

# See s3_engine.sh's identical note: this file is reached from INSIDE
# `cloud_run_service` in every real run, where modules/cloud/aws/engine.sh (and
# everything it drags in) is already sourced - this guard is what lets a
# direct-engine test suite source this file standalone.
# -x back-edge cut: see s3_engine.sh's identical note - every file on this edge
# is already inlined via modules/cloud/aws/run.sh -> regions.sh -> engine.sh in
# the source graph that matters, and shellcheck -x re-expands every edge it
# follows rather than memoising (tests/lint-source-graph.sh).
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, never a bare `declare`: this file executes inside
# `cloud_run_service`'s own function scope in a real run (see s3_engine.sh's
# identical note for the full reasoning), so an unqualified `declare -A` would
# create a local that dies with the first service pass.
declare -gA _SNS_DOC=()
declare -gA _SNS_DOCT=()
declare -gA _SNS_POLICY_DOC=()
declare -gA _SNS_POLICY_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading a response document
# ---------------------------------------------------------------------------
sns_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

# `sns_doc_load FILE` - flatten a `get-topic-attributes` response into
# `_SNS_DOC`/`_SNS_DOCT`, exactly as s3_doc_load does for an S3 response.
sns_doc_load() {
  local file=$1
  _SNS_DOC=()
  _SNS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)`, never a pipe: a piped `while` runs in a subshell and every
  # assignment made in it is discarded when the subshell exits, leaving an
  # empty map (lib/core.sh's standing subshell lesson, in its loop form).
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _SNS_DOC[$path]=$val
    _SNS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

sns_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_SNS_DOC[$__path]:-}"
  [[ -n ${_SNS_DOCT[$__path]+set} ]]
}

# `sns_policy_string_load POLICY` - flatten an already-UNESCAPED policy
# document (the value `sns_doc_get` returns for `Attributes<US>Policy` is
# already plain JSON text, per `sns_doc_load`'s own unescape-on-load rule)
# into `_SNS_POLICY_DOC`/`_SNS_POLICY_DOCT`.  A SEPARATE map from the
# attributes document, so a policy walk can never accidentally read an
# attributes-level leaf that happens to share a path.
sns_policy_string_load() {
  local text=$1
  _SNS_POLICY_DOC=()
  _SNS_POLICY_DOCT=()
  [[ -n $text ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _SNS_POLICY_DOC[$path]=$val
    _SNS_POLICY_DOCT[$path]=$type
  done < <(cloud_json_flatten <<<"$text" 2>/dev/null)
  return 0
}

sns_policy_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_SNS_POLICY_DOC[$__path]:-}"
  [[ -n ${_SNS_POLICY_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Classifiers
# ---------------------------------------------------------------------------
# `_sns_statement_condition_present INDEX` - true when `Statement[INDEX]`
# carries a `Condition` block at all, over the LOADED policy document.
# A prefix scan rather than a single-key lookup: `Condition` is itself a
# nested object (`{"StringEquals": {...}}`), so any leaf beneath it is enough
# to prove the block exists.
_sns_statement_condition_present() {
  local prefix
  prefix=$(sns_path Statement "$1" Condition)
  local k
  for k in "${!_SNS_POLICY_DOCT[@]}"; do
    [[ $k == "$prefix"* ]] && return 0
  done
  return 1
}

# `_sns_statement_principal_is_wildcard INDEX` - true when `Statement[INDEX]`'s
# Principal is the bare string `*`, `{"AWS": "*"}`, or `{"AWS": [..., "*"]}`.
# Compared as a WHOLE VALUE, never a substring: an account id that merely ends
# in the digit sequence is not a wildcard, and this codebase's standing rule
# (s3_engine.sh's own ACL-grantee note) is to test grantee/principal values
# exactly for that reason.
_sns_statement_principal_is_wildcard() {
  local i=$1 v=''
  sns_policy_doc_get v "$(sns_path Statement "$i" Principal)"
  [[ $v == '*' ]] && return 0
  sns_policy_doc_get v "$(sns_path Statement "$i" Principal AWS)"
  [[ $v == '*' ]] && return 0
  local j=0
  while sns_policy_doc_get v "$(sns_path Statement "$i" Principal AWS "$j")"; do
    [[ $v == '*' ]] && return 0
    j=$(( j + 1 ))
  done
  return 1
}

# `sns_policy_is_public` - true when the LOADED policy document (via
# `sns_policy_string_load`) grants Effect Allow to a wildcard Principal with no
# Condition, on any statement.  `Effect` is a REQUIRED field on every IAM
# policy statement, so testing its presence is a reliable array-length probe
# without needing a Sid or Action fallback the way s3's ACL walk does.
sns_policy_is_public() {
  local i=0 effect=''
  while sns_policy_doc_get effect "$(sns_path Statement "$i" Effect)"; do
    if [[ $effect == Allow ]] \
      && _sns_statement_principal_is_wildcard "$i" \
      && ! _sns_statement_condition_present "$i"; then
      return 0
    fi
    i=$(( i + 1 ))
  done
  return 1
}

# `sns_topic_kms_key_set VARNAME` - the topic's `KmsMasterKeyId`, over the
# loaded attributes document.  Empty/absent means server-side encryption is
# not configured.  UNLIKE S3 and SQS, SNS applies no managed default
# encryption to a new topic - there is no SSE-S3-style "already safe by
# default" exemption to make here, so an absent key is unconditionally the
# finding.
sns_topic_kms_key_set() {
  local __var=$1 __p
  __p=$(sns_path Attributes KmsMasterKeyId)
  printf -v "$__var" '%s' "${_SNS_DOC[$__p]:-}"
  [[ -n ${_SNS_DOC[$__p]:-} ]]
}

# `sns_topic_policy_string_set VARNAME` - the topic's raw (already-unescaped)
# `Policy` document text, over the loaded attributes document.  Empty when the
# attribute is absent - which does not happen for SNS in practice (every topic
# carries a default policy naming its own owner), but a caller must not assume
# it.
sns_topic_policy_string_set() {
  local __var=$1 __p
  __p=$(sns_path Attributes Policy)
  printf -v "$__var" '%s' "${_SNS_DOC[$__p]:-}"
  [[ -n ${_SNS_DOC[$__p]:-} ]]
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
# `sns_registry_locate_set SETVAR IDXVAR CHECK_ID` - identical contract to
# s3_engine.sh's `s3_registry_locate_set`.
sns_registry_locate_set() {
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

# `sns_emit_finding CHECK_ID TOPIC_ARN EVIDENCE` - the static half of the
# finding comes from the check record via `finding_from_record`, exactly as
# s3_emit_finding's own header states at length; not restated here.
#
# `loc_region` IS `SCOURSH_CLOUD_REGION`, NOT A RESOLVED PER-RESOURCE VALUE.
# Unlike a bucket, an SNS topic has no region distinct from the one the API
# call that found it was addressed to - the ARN's own region component agrees
# by construction.  The CELL is the pass's own `<account>/<region>`, which for
# a `regional` service (unlike `global` S3) is the SAME as loc_region; there
# is no S3-style divergence to guard here.
sns_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  sns_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/sns emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-SNS-PUBLIC_POLICY-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
