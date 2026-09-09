#!/usr/bin/env bash
# modules/cloud/aws/live/route53_engine.sh - the pure half of the §8.1 Route53
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-11).
#
# `route53` IS `global` (modules/cloud/aws/engine.sh's `_CLOUD_SERVICES`), and
# UNLIKE `s3` its resources have no per-resource region to resolve at all - a
# hosted zone is a global DNS namespace, not a regional API object - so
# `loc_region` here is the literal string `global`, matching
# docs/STEP6-CLOUD-PLAN.md's own CLOUD-11 wording ("Global service;
# region: global") rather than the pass's cell-vs-region split S3 needs.
#
# THE CHECK IS SCOPED TO ONE WELL-KNOWN SUBDOMAIN-TAKEOVER VECTOR, DELIBERATELY
# NARROWER THAN "every dangling DNS record": an S3 static-website ALIAS or
# CNAME record whose target names an S3 website endpoint, where the record's
# own DNS NAME (which AWS's S3-website-hosting feature requires to equal the
# bucket name) does not correspond to any bucket the account currently owns.
# Three reasons this is the v1 scope rather than a placeholder:
#
#   1. IT NEEDS NO NETWORK CALL scoursh's egress model does not already
#      authorise.  A real subdomain-takeover check for an externally-hosted
#      target (a CNAME to `*.herokuapp.com`, `*.github.io`, ...) requires
#      resolving that hostname to see whether it answers - a DNS lookup is
#      NEITHER of the two categories docs/FOUNDATION.md's no-egress rule
#      permits (a curl to a config/scope.conf host, or a read-only AWS API
#      call), so this scanner must not add one. The S3 case needs no DNS
#      resolution at all: whether the referenced BUCKET exists is answerable
#      entirely from `s3api list-buckets`, a read-only AWS API call like any
#      other.
#   2. IT IS THE CLASSIC, MOST-CITED AWS TAKEOVER VECTOR: AWS's S3
#      static-website hosting feature requires the serving bucket's name to
#      equal the DNS name being served, so a deleted bucket behind a
#      still-published CNAME/ALIAS is claimable by ANY AWS account that
#      creates a bucket with that exact name - the account that owned the DNS
#      record has no say in who gets it back.
#   3. THE OTHER SHAPES (ELB, CloudFront) NAME A TARGET RESOURCE THIS TICKET'S
#      SERVICE SCRIPTS DO NOT YET EXIST TO CROSS-REFERENCE AGAINST, and adding
#      direct `elbv2`/`cloudfront` calls here to compensate would grow this
#      one check into three, each carrying its own false-positive shape, for a
#      "small remainder" bundle. Recorded as a stated, deliberate gap rather
#      than silently assumed covered.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_ROUTE53_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_ROUTE53_ENGINE_SOURCED=1

# -x back-edge cut: see sns_engine.sh's identical note.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

declare -gA _R53_DOC=()
declare -gA _R53_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading a response document
# ---------------------------------------------------------------------------
route53_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

route53_doc_load() {
  local file=$1
  _R53_DOC=()
  _R53_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _R53_DOC[$path]=$val
    _R53_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

route53_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_R53_DOC[$__path]:-}"
  [[ -n ${_R53_DOCT[$__path]+set} ]]
}

route53_doc_has() {
  [[ -n ${_R53_DOCT[$1]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. Classifiers
# ---------------------------------------------------------------------------
# `route53_zone_id_bare ZONE_ID` - `list-hosted-zones`'s own `Id` field is
# `/hostedzone/Z1234567890ABC`; strip the prefix, since `--hosted-zone-id`
# takes the bare id and the ARN this file builds names it bare too.
route53_zone_id_bare() {
  printf '%s' "${1#/hostedzone/}"
}

# `route53_partition_of CALLER_ARN` - byte-for-byte s3_engine.sh's
# `s3_partition_of`, duplicated rather than shared for the reason
# sqs_engine.sh's own header states for its policy classifier: a real THIRD
# occurrence is the signal to lift a helper into the module engine, not the
# second.
route53_partition_of() {
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

# `route53_zone_arn PARTITION ZONE_ID` - `arn:<partition>:route53:::hostedzone/<id>`.
route53_zone_arn() {
  printf 'arn:%s:route53:::hostedzone/%s' "$1" "$(route53_zone_id_bare "$2")"
}

# `route53_record_is_wildcard NAME` - true for a Route53 wildcard record name,
# which the API renders with the literal escape `\052` for the `*` label
# (`\052.example.com.`). Such a name can never be a literal bucket name, so it
# is never a takeover candidate and must not be treated as one.
route53_record_is_wildcard() {
  [[ $1 == '\052.'* ]]
}

# `route53_record_bucket_candidate NAME` - the candidate S3 bucket name for a
# record, which AWS's own static-website-hosting requirement makes the
# record's own DNS name with the trailing root dot stripped and folded to
# lowercase (S3 bucket names are always lowercase; a mixed-case DNS label
# would never have matched a real bucket in the first place, so folding here
# only widens which records are CONSIDERED, never which are flagged).
route53_record_bucket_candidate() {
  local name=${1%.}
  printf '%s' "${name,,}"
}

# `route53_target_is_s3_website VALUE` - true when VALUE (a CNAME's
# ResourceRecords[0].Value, or an ALIAS's AliasTarget.DNSName) names an S3
# static-website hosting endpoint, either the older per-region hyphenated form
# (`s3-website-us-east-1.amazonaws.com`) or the newer dotted form
# (`s3-website.us-east-1.amazonaws.com`).  Matched on the whole lowercased
# value, never a bare substring test against the RECORD NAME - the substring
# `s3-website` only ever needs to appear in the TARGET, since that is AWS's
# own fixed hostname vocabulary and not attacker- or operator-controlled text.
route53_target_is_s3_website() {
  local v=${1,,}
  [[ $v == *s3-website* && $v == *.amazonaws.com* ]]
}

# ---------------------------------------------------------------------------
# 3. Emission
# ---------------------------------------------------------------------------
route53_registry_locate_set() {
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

# `route53_emit_finding CHECK_ID ZONE_ARN SUB_KEY EVIDENCE` - `loc_region` is
# the literal string `global`, per this file's own header; the cell is the
# pass's `<account>/global`, so unlike S3 the two agree.
route53_emit_finding() {
  local check_id=$1 zone_arn=$2 sub_key=$3 evidence=$4
  local set='' idx=''
  route53_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/route53 emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  finding_set exposure external
  finding_set auth none
  finding_set cell "${SCOURSH_CLOUD_CELL:-$account/global}"
  finding_set loc_account_id "$account"
  finding_set loc_region global
  finding_set loc_resource_key "$zone_arn"
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
