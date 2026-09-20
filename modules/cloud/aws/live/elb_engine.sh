#!/usr/bin/env bash
# modules/cloud/aws/live/elb_engine.sh - the pure half of the §8.1 ELB
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-14).
#
# The run.sh/engine.sh split modules/cloud/aws/live/s3_engine.sh established:
# this file is a pure function library with the standard sourced-once guard
# and no side effect at source time; modules/cloud/aws/live/elb.sh is the file
# that DOES something when `cloud_run_service` sources it.
#
# TWO AWS SERVICES, ONE SCRIPT, THREE CHECK IDS.  `elb` (Classic Load
# Balancer) and `elbv2` (ALB/NLB) are one AWS product across two API
# generations - docs/STEP6-CLOUD-PLAN.md's own counting note says so, and
# _CLOUD_SERVICES has one row, `live/elb.sh:regional`, for both.  Each check
# id below is therefore evaluated against BOTH namespaces; `elb_classic_arn`
# and the classic ELB's ARN vs elbv2's own `LoadBalancerArn` field are the
# only place the two API generations diverge in shape.
#
# ELB IS `regional`, AND THAT IS SIMPLER THAN S3'S `global` ROW.  Both
# `describe-load-balancers` calls are addressed to whatever region
# `cloud_run_service` set as ambient before sourcing this file, and every
# load balancer that call returns genuinely lives in that region - unlike an
# S3 bucket, a load balancer has no independent "real region" a second call
# has to resolve.  So `loc_region` here is simply `$SCOURSH_CLOUD_REGION`,
# and the coverage cell modules/cloud/aws/run.sh already publishes
# (`<account>/<region>`) is the correct home for the finding by construction,
# with none of s3_engine.sh's cell-vs-bucket-region split.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_ELB_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_ELB_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten` / `cloud_json_unescape`
# and is already sourced in every real run (regions.sh sources it before the
# service walk begins), so this is reached only by a direct-engine test.
# -x back-edge cut: see s3_engine.sh's own identical note - every file in this
# edge's chain is already inlined by the time this file is reached in the
# source graph that matters (modules/cloud/aws/run.sh -> regions.sh ->
# engine.sh -> modules/sast/engine.sh -> the lib/ hub chain).
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, never a bare `declare`, for the reason modules/cloud/aws/engine.sh's
# service table documents at length: this file executes inside
# `cloud_run_service`'s own function scope, where a bare `declare -A` would be
# a local that dies with the pass.
declare -gA _ELB_DOC=()
declare -gA _ELB_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document (byte-for-byte the s3_engine.sh pattern)
# ---------------------------------------------------------------------------
elb_doc_load() {
  local file=$1
  _ELB_DOC=()
  _ELB_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)`, never a pipe: a piped `while` runs in a subshell and every
  # assignment it made is discarded on exit (lib/core.sh's `worker_id_set`
  # lesson, in its loop form - s3_doc_load's own note records the same fact).
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _ELB_DOC[$path]=$val
    _ELB_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

elb_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

elb_doc_has() {
  [[ -n ${_ELB_DOCT[$1]+set} ]]
}

elb_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_ELB_DOC[$__path]:-}"
  [[ -n ${_ELB_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The ARN
# ---------------------------------------------------------------------------
# `elb_partition_of CALLER_ARN` - byte-for-byte s3_engine.sh's `s3_partition_of`,
# duplicated rather than shared: it is ten lines, and a shared copy would put a
# module-wide helper in modules/cloud/aws/engine.sh for one caller today and a
# second tomorrow, the same "confine it to the service that needs it" argument
# s3_engine.sh's own header makes about its ACL/policy classifiers.
elb_partition_of() {
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

# `elb_classic_arn PARTITION REGION ACCOUNT NAME` - Classic ELB's
# `describe-load-balancers` response carries NO ARN field at all (the API
# predates ARN-based tagging for this service), so it is CONSTRUCTED from the
# documented `elasticloadbalancing:loadbalancer/<name>` resource shape, the
# identical convention AWS's own IAM policy documentation and console use for
# a Classic ELB.  ALB/NLB need no equivalent: `elbv2 describe-load-balancers`
# already returns a real `LoadBalancerArn` field, read directly rather than
# reconstructed - one fact, one source, never re-derived where the API already
# names it.
elb_classic_arn() {
  printf 'arn:%s:elasticloadbalancing:%s:%s:loadbalancer/%s' "$1" "$2" "$3" "$4"
}

# ---------------------------------------------------------------------------
# 3. The classifiers
# ---------------------------------------------------------------------------
# `elb_policy_is_weak POLICY_NAME` - true when POLICY_NAME does not itself
# prove a TLS 1.2-or-later floor.
#
# THE TEST IS "PROVES STRONG", NOT "NAMES A KNOWN-WEAK POLICY", AND THAT
# ASYMMETRY IS DELIBERATE.  AWS's own predefined-policy names embed their
# guaranteed minimum protocol version since the 2017 naming convention
# (`ELBSecurityPolicy-TLS-1-2-2017-01`, `...-FS-1-2-...`, the 2021
# `...-TLS13-1-2-...` family), so a name containing `TLS-1-2` or `TLS13`
# is real, checkable evidence of a TLS 1.2+ floor.  Every OLDER predefined
# name (`ELBSecurityPolicy-2016-08`, the four dated 2011-2015 policies, the
# two explicit `TLS-1-0`/`TLS-1-1` names) permits TLS 1.0 or 1.1, and a
# CUSTOM policy an operator named without embedding a protocol floor in its
# name is, from this string alone, indistinguishable from one that does not
# enforce one - so it is reported too.  Reading it the other way (flag only a
# hardcoded weak-name list) would report every custom policy name clean by
# construction, which is the overstated-coverage failure docs/DESIGN.md §15
# forbids on the exact case a fixed list can never anticipate.
elb_policy_is_weak() {
  case $1 in
    *TLS-1-2* | *TLS13*) return 1 ;;
    *) return 0 ;;
  esac
}

# `elb_classic_policy_doc_is_weak` - true when the LOADED
# `describe-load-balancer-policies` document (one `PolicyDescriptions[0]`,
# per elb.sh's own one-policy-per-call shape) describes a Classic ELB TLS
# policy that does not enforce a TLS 1.2 floor.
#
# WHY THIS EXISTS BESIDE `elb_policy_is_weak`, AND WHY elb.sh CALLS THIS ONE
# FOR CLASSIC ELB RATHER THAN THE LISTENER'S OWN POLICY NAME.  A Classic ELB
# listener's `PolicyNames` entry is whatever the operator NAMED the policy
# when they created it - commonly a Terraform-generated name like
# `my-lb-ssl-policy` that carries no protocol information in its own bytes at
# all, even when the policy it names is a plain reference to a modern
# predefined one.  Classifying on that name alone (the way ALB/NLB's
# `SslPolicy` field safely can, because THAT field genuinely IS the
# predefined policy's own name with no indirection) would report the common
# "custom name, predefined reference" shape as weak on every account that
# uses it - a false positive on exactly the ordinary case.
# `describe-load-balancer-policies` resolves the indirection: a policy
# created by REFERENCING a predefined one carries a
# `Reference-Security-Policy` attribute naming which, and that value is
# tested with the identical `elb_policy_is_weak` rule; a policy with no such
# attribute is a genuinely custom one, and is classified from its own
# `Protocol-SSLv3` / `Protocol-TLSv1` / `Protocol-TLSv1.1` attributes, each
# `"true"` when that legacy protocol is enabled - matching AWS's own
# Trusted Advisor check for this exact posture.
elb_classic_policy_doc_is_weak() {
  local __i=0 __name='' __val='' __has_ref=0 __ssl3='' __tls10='' __tls11=''
  while :; do
    elb_doc_has "$(elb_path PolicyDescriptions 0 PolicyAttributeDescriptions "$__i" AttributeName)" || break
    elb_doc_get __name "$(elb_path PolicyDescriptions 0 PolicyAttributeDescriptions "$__i" AttributeName)" || true
    elb_doc_get __val "$(elb_path PolicyDescriptions 0 PolicyAttributeDescriptions "$__i" AttributeValue)" || true
    case $__name in
      Reference-Security-Policy)
        __has_ref=1
        elb_policy_is_weak "$__val" && return 0 || return 1
        ;;
      Protocol-SSLv3) __ssl3=$__val ;;
      Protocol-TLSv1) __tls10=$__val ;;
      Protocol-TLSv1.1) __tls11=$__val ;;
    esac
    __i=$(( __i + 1 ))
  done
  (( __has_ref )) && return 1
  [[ $__ssl3 == true || $__tls10 == true || $__tls11 == true ]]
}

# `elb_default_actions_redirect_https VARNAME` - true when the loaded ELBv2
# `describe-listeners` document's `DefaultActions` array (already indexed to
# ONE listener by the caller's own path prefix - see elb.sh) contains a
# `redirect` action whose `RedirectConfig.Protocol` is the LITERAL string
# `HTTPS`.
#
# `#{protocol}` (AWS's "keep the original protocol" placeholder) is
# DELIBERATELY NOT treated as a redirect to HTTPS.  On an HTTP listener that
# value leaves the connection on HTTP - it is the syntax for a path- or
# host-based redirect that does not change scheme - so accepting it as proof
# of a TLS upgrade would report a listener that never leaves cleartext as
# fixed.
elb_default_actions_redirect_https() {
  local prefix=$1 __i=0 __type='' __proto=''
  while :; do
    __type=${_ELB_DOC[$(elb_path "$prefix" DefaultActions "$__i" Type)]:-}
    if ! elb_doc_has "$(elb_path "$prefix" DefaultActions "$__i" Type)"; then
      break
    fi
    if [[ $__type == redirect ]]; then
      __proto=${_ELB_DOC[$(elb_path "$prefix" DefaultActions "$__i" RedirectConfig Protocol)]:-}
      [[ $__proto == HTTPS ]] && return 0
    fi
    __i=$(( __i + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 4. Emission
# ---------------------------------------------------------------------------
# `elb_registry_locate_set SETVAR IDXVAR CHECK_ID` - s3_engine.sh's
# `s3_registry_locate_set`, byte-identical, duplicated for the same
# per-service ownership reason as `elb_partition_of` above.
elb_registry_locate_set() {
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

# `elb_emit_finding CHECK_ID ARN REGION SUB_KEY EVIDENCE`
#
# THE STATIC HALF OF THE FINDING COMES FROM THE CHECK RECORD - see
# s3_engine.sh's `s3_emit_finding` for the full argument; the same reasoning
# applies verbatim.
#
# `loc_region` IS `$SCOURSH_CLOUD_REGION`, AND THE CELL IS `$SCOURSH_CLOUD_CELL`
# - AND THEY AGREE, unlike s3's split.  `elb.sh` is a `regional` row, so the
# pass that examined this load balancer ran IN the region the load balancer
# actually lives in; there is no second, independently-resolved "real region"
# for a finding to cite the way an S3 bucket's is.
#
# EXPOSURE IS `internet`, NOT `external` - deliberately different from
# s3_engine.sh's own spelling.  data/severity-rubric.conf's frozen `exposure`
# fact has exactly three values, `internet` / `internal` / `unknown`
# (rules/RULE-FORMAT.md §9.6.5); `external` matches none of them and silently
# takes the rubric's `_rubric_mod` no-match default of `+0`, which is the SAME
# outcome as `unknown` - so an internet-facing finding gets no severity boost
# at all under that spelling.  That mismatch is pre-existing in
# modules/cloud/aws/live/s3_engine.sh and is out of this ticket's scope to
# correct there; it is not repeated here.
elb_emit_finding() {
  local check_id=$1 arn=$2 region=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  elb_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/elb emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  case $check_id in
    CLOUD-ELB-NO_ACCESS_LOGS-01)
      finding_set exposure internal
      finding_set auth user
      ;;
    *)
      finding_set exposure internet
      finding_set auth none
      ;;
  esac
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/$region}"
  finding_set loc_account_id "$account"
  finding_set loc_region "$region"
  finding_set loc_resource_key "$arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
