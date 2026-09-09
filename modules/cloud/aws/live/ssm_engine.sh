#!/usr/bin/env bash
# modules/cloud/aws/live/ssm_engine.sh - the pure half of the §8.1 SSM
# (Systems Manager Parameter Store) read-only service (docs/DESIGN.md §8.1;
# docs/STEP6-CLOUD-PLAN.md CLOUD-09).
#
# Same run.sh/engine.sh split as kms_engine.sh/kms.sh; see that file's own
# header for why the split exists. Regional, for the same reason KMS and
# Secrets Manager are - see kms_engine.sh's header for the fuller argument.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_SSM_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_SSM_ENGINE_SOURCED=1

if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _SSM_DOC=()
declare -gA _SSM_DOCT=()

ssm_doc_load() {
  local file=$1
  _SSM_DOC=()
  _SSM_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _SSM_DOC[$path]=$val
    _SSM_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

ssm_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

ssm_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_SSM_DOC[$__path]:-}"
  [[ -n ${_SSM_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# The ARN
# ---------------------------------------------------------------------------
# `ssm_partition_of CALLER_ARN` - the byte-identical shape of `s3_partition_of`
# (s3_engine.sh), duplicated here rather than shared: `s3_engine.sh` is not
# unconditionally sourced by this module (a direct-engine SSM test suite has
# no reason to pull in the whole S3 classifier set), and a six-line, READ-
# NEVER-HARDCODED ARN-partition reader is cheaper to keep in step by
# duplication than by adding a cross-service source edge for one function.
ssm_partition_of() {
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

# `ssm_parameter_arn PARTITION REGION ACCOUNT NAME` - `describe-parameters`'s
# `ParameterMetadata` carries no ARN field at all (unlike `describe-key`'s
# `KeyMetadata.Arn` or `list-secrets`'s `SecretList[].ARN`), so it is BUILT
# here rather than trusted from a response - the identical choice `s3_bucket_
# arn` makes one file over, for the identical reason: this project has no
# other source for it that does not cost a second, unwanted call
# (`get-parameter`, which additionally retrieves the parameter's VALUE - a
# cost this scanner has no reason to pay merely to learn an ARN it can compute
# for free).
#
# A leading `/` in NAME is stripped before concatenation: AWS's own published
# format is `arn:PARTITION:ssm:REGION:ACCOUNT:parameter/NAME`, and a
# hierarchical name like `/prod/db/password` already supplies its own leading
# slash - keeping both would double it (`parameter//prod/db/password`), which
# names a resource that does not exist.  A flat name with no leading slash
# (`mySimpleParameter`) needs nothing stripped.
ssm_parameter_arn() {
  local partition=$1 region=$2 account=$3 name=$4
  name=${name#/}
  printf 'arn:%s:ssm:%s:%s:parameter/%s' "$partition" "$region" "$account" "$name"
}

# ---------------------------------------------------------------------------
# The classifiers
# ---------------------------------------------------------------------------
# `ssm_param_entry_field_set VARNAME INDEX FIELD` - a scalar field of the
# loaded `describe-parameters` response's `Parameters[INDEX]`.
ssm_param_entry_field_set() {
  local __var=$1 __idx=$2 __field=$3
  ssm_doc_get "$__var" "$(ssm_path Parameters "$__idx" "$__field")"
}

# `ssm_name_looks_sensitive NAME` - a NAME-based heuristic for "this parameter
# probably holds a secret", matched on lowercase substrings.
#
# THIS IS A DECLARED, NAME-ONLY HEURISTIC, NOT A CONTENT SCAN, and the
# distinction is the whole reason `CLOUD-SSM-STRING_TYPE_SENSITIVE-01`'s own
# check record carries `confidence: medium` rather than `high`.
# `aws_ro`'s read-only chokepoint and this module's own AWS credential are
# never used to fetch a parameter's VALUE (a String parameter's value is
# unencrypted at rest regardless, but reading it is still a real API call
# this check has no need to make, and a SecureString's value additionally
# requires KMS decrypt permission the scanning role should not need to hold).
# So the ONLY signal available is the parameter's own path/name, which is
# necessarily approximate in both directions: a parameter literally named
# `/app/feature-flags/enable-token-auth` matches on `token` and is not a
# secret, and a parameter named `/app/db-creds` that this list does not
# happen to match is a secret this check will miss.  Both are accepted,
# stated limitations of a name-only signal - the alternative, fetching every
# String value to inspect its shape, is a cost and a privilege this ticket
# does not take on.
ssm_name_looks_sensitive() {
  local n=${1,,}
  case $n in
    *password* | *passwd* | *secret* | *apikey* | *api-key* | *api_key* | \
      *credential* | *creds* | *privatekey* | *private-key* | *private_key* | \
      *accesskey* | *access-key* | *access_key* | *clientsecret* | \
      *client-secret* | *client_secret* | *authtoken* | *auth-token* | \
      *auth_token* | *token*)
      return 0
      ;;
    *) return 1 ;;
  esac
}

# `ssm_policy_entry_field_set VARNAME INDEX FIELD` - a scalar field of the
# loaded `get-resource-policies` response's `Policies[INDEX]`.
ssm_policy_entry_field_set() {
  local __var=$1 __idx=$2 __field=$3
  ssm_doc_get "$__var" "$(ssm_path Policies "$__idx" "$__field")"
}

# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------
ssm_registry_locate_set() {
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

ssm_emit_finding() {
  local check_id=$1 arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  ssm_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/ssm emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-SSM-PUBLIC_POLICY-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      finding_set sensitive_data true
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-}"
  finding_set loc_account_id "${SCOURSH_CLOUD_ACCOUNT_ID:-}"
  finding_set loc_region "${SCOURSH_CLOUD_REGION:-}"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
