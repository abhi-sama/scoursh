#!/usr/bin/env bash
# modules/cloud/aws/live/opensearch_engine.sh - the pure half of the §8.1
# OpenSearch read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md
# CLOUD-17).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3.sh + s3_engine.sh
# established, copied verbatim: this file is a pure function library with the
# standard sourced-once guard and no side effect at source time, and
# modules/cloud/aws/live/opensearch.sh is the file that DOES something when
# `cloud_run_service` sources it.
#
# OPENSEARCH IS `regional` (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES`),
# UNLIKE S3.  `list-domain-names` is scoped to the ambient region
# `cloud_run_service` already set before sourcing this pass, so - unlike S3's
# bucket-list-then-resolve-each-bucket's-own-region shape - every domain this
# pass sees is genuinely IN the region this pass is examining.  `loc_region`
# and the coverage `cell` are therefore the SAME region for every finding here,
# with no per-resource region-resolution call needed at all.
#
# THE ARN COMES DIRECTLY FROM `describe-domain`'S OWN RESPONSE
# (`DomainStatus.ARN`), never constructed.  Unlike an S3 bucket, whose
# `list-buckets` response carries no ARN at all, OpenSearch hands one back on
# the very call that also answers every other question this file asks - so
# there is nothing here to get wrong the way a hand-built ARN could.
#
# THE PUBLIC-ACCESS CHECK IS A HEURISTIC, AND IT SAYS SO IN ITS OWN
# `confidence: medium`.  OpenSearch has no `get-bucket-policy-status`
# equivalent - no read-only call that answers "is this domain's access policy
# public" the way AWS's own S3 evaluator does - so this file reads the raw
# `AccessPolicies` document and applies `modules/cloud/aws/engine.sh`'s
# `cloud_policy_is_wide_open` to it.  See that function's own header for what
# it does and does not evaluate (a wildcard Principal on an Allow statement,
# with any `Condition` deliberately ignored).
#
# A DOMAIN INSIDE A VPC IS NOT REPORTED PUBLIC EVEN WITH A WIDE-OPEN POLICY.
# `VPCOptions` presence means the domain's endpoint is a private VPC address,
# unreachable from the internet regardless of what the access policy allows -
# so "public" here is genuinely two facts, both required: no VPC placement
# AND a policy that would admit anyone.  Reporting on the policy alone would
# flag a domain no internet host can even route to, which is the overstated
# finding the false-positive-flood lesson (s3_engine.sh's own encryption
# classifier header) warns against on the S3 side of this module.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_OPENSEARCH_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_OPENSEARCH_ENGINE_SOURCED=1

# -x back-edge cut: modules/cloud/aws/engine.sh's own hub chain is already
# inlined by the time this file is reached in every real run (regions.sh
# sources it before the service walk begins) - see tests/lint-source-graph.sh
# and docs/CI-RUNBOOK.md's "the memory model".  A direct-engine test suite
# sources engine.sh itself.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, never a bare `declare` - s3_engine.sh's own header states why
# at length: nothing sources this file at top level in a real run, so a bare
# `declare -A` inside the sourced-then-executed script body would be a LOCAL
# that dies with the pass.
declare -gA _OS_DOC=()
declare -gA _OS_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one `describe-domain` response
# ---------------------------------------------------------------------------
# `opensearch_doc_load FILE` - the identical shape to s3_engine.sh's
# `s3_doc_load`: flatten FILE once into `_OS_DOC`/`_OS_DOCT`, both keyed by
# `cloud_json_flatten`'s US-joined path.  See that function's own header for
# why a whole-document flatten beats a per-leaf re-read here too.
opensearch_doc_load() {
  local file=$1
  _OS_DOC=()
  _OS_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _OS_DOC[$path]=$val
    _OS_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

opensearch_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_OS_DOC[$__path]:-}"
  [[ -n ${_OS_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The classifiers - one per check, each over an already-loaded document
# ---------------------------------------------------------------------------
# `opensearch_arn_set VARNAME` - `DomainStatus.ARN`, read verbatim.
opensearch_arn_set() {
  local __var=$1
  printf -v "$__var" '%s' "${_OS_DOC[DomainStatus$'\x1f'ARN]:-}"
  [[ -n ${_OS_DOC[DomainStatus$'\x1f'ARN]:-} ]]
}

# `opensearch_is_vpc_attached` - true when the loaded document carries a
# `VPCOptions.VPCId`, meaning the domain's endpoint is a private VPC address
# rather than the public AWS-owned one.
opensearch_is_vpc_attached() {
  [[ -n ${_OS_DOC[DomainStatus$'\x1f'VPCOptions$'\x1f'VPCId]:-} ]]
}

# `opensearch_is_publicly_open` - true only when the domain is NOT VPC-attached
# AND its access policy is wide open, per this file's own header.
opensearch_is_publicly_open() {
  opensearch_is_vpc_attached && return 1
  local policy=''
  policy=${_OS_DOC[DomainStatus$'\x1f'AccessPolicies]:-}
  [[ -n $policy ]] || return 1
  cloud_policy_load "$policy" || return 1
  cloud_policy_is_wide_open
}

# `opensearch_encrypted_at_rest` - `DomainStatus.EncryptionAtRestOptions.Enabled`.
opensearch_encrypted_at_rest() {
  [[ ${_OS_DOC[DomainStatus$'\x1f'EncryptionAtRestOptions$'\x1f'Enabled]:-} == true ]]
}

# `opensearch_encrypted_in_transit` - `DomainStatus.NodeToNodeEncryptionOptions.Enabled`,
# the node-to-node transport encryption setting - the "in transit" property a
# search cluster actually has, as distinct from HTTPS-to-client (which
# `DomainEndpointOptions.EnforceHTTPS` covers and this file does not check;
# see this file's own scope note if a future ticket wants that as a second
# id).
opensearch_encrypted_in_transit() {
  [[ ${_OS_DOC[DomainStatus$'\x1f'NodeToNodeEncryptionOptions$'\x1f'Enabled]:-} == true ]]
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
# `opensearch_registry_locate_set SETVAR IDXVAR CHECK_ID` - s3_engine.sh's own
# `s3_registry_locate_set`, copied rather than shared: a per-service copy costs
# nothing (`checks_registry_load` is already loaded once for the whole run) and
# keeps each service's emitter free of a cross-service function dependency.
opensearch_registry_locate_set() {
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

# `opensearch_emit_finding CHECK_ID ARN EVIDENCE`
#
# THE STATIC HALF COMES FROM THE CHECK RECORD, exactly as
# `s3_emit_finding`'s own header explains: title, severity, confidence, cwe,
# owasp, remediation, references, and `cis` are all fields of the registry
# record and are never restated here.
#
# THE CELL AND THE REGION ARE THE SAME VALUE HERE, unlike S3's global pass:
# this is a `regional` service (modules/cloud/aws/engine.sh's service table),
# so `SCOURSH_CLOUD_REGION` IS the region every domain this pass examined
# actually sits in - there is no bucket-style "resource's own region differs
# from the pass's cell" split to make.
opensearch_emit_finding() {
  local check_id=$1 arn=$2 evidence=$3
  local set='' idx=''
  opensearch_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/opensearch emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-OPENSEARCH-PUBLIC_ACCESS-01)
      finding_set exposure external
      finding_set auth none
      finding_set sensitive_data true
      ;;
    *)
      finding_set exposure internal
      finding_set auth user
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-}"
  finding_set loc_account_id "${SCOURSH_CLOUD_ACCOUNT_ID:-}"
  finding_set loc_region "${SCOURSH_CLOUD_REGION:-}"
  finding_set loc_resource_key "$arn"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
