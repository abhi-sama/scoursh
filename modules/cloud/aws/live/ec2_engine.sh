#!/usr/bin/env bash
# modules/cloud/aws/live/ec2_engine.sh - the pure half of the §8.1 EC2/VPC
# read-only service (docs/DESIGN.md §8.1; docs/STEP6-CLOUD-PLAN.md CLOUD-13).
#
# The run.sh/engine.sh split modules/sast/ established, and modules/cloud/aws/
# already applies one level down for s3 (live/s3.sh + live/s3_engine.sh): this
# file is a pure function library with the standard sourced-once guard and no
# side effect at source time, and modules/cloud/aws/live/ec2.sh is the file
# that DOES something when `cloud_run_service` sources it.  Nothing here calls
# `aws_ro`, reads the run context or emits anything by itself; every function
# takes an already-loaded response document (or a string) and answers one
# question about it, which is what lets tests/suites/cloud-ec2.sh exercise the
# classifiers against committed fixtures with no scan, no stub and no run
# directory.
#
# EC2/VPC IS `ec2.sh`'S _CLOUD_SERVICES ROW, ALREADY MARKED `regional`
# (modules/cloud/aws/engine.sh).  Unlike s3 (a `global` pass over one
# account-wide bucket list), every EC2 API used here IS scoped by region, so
# this pass runs once per enabled region and both the finding's `cell` and its
# `loc_region` are that SAME region - there is no s3-shaped split between the
# two here, because nothing in this file resolves a resource whose region
# differs from the pass's own.
#
# shellcheck shell=bash

if [[ -n ${SCOURSH_CLOUD_EC2_ENGINE_SOURCED:-} ]]; then
  return 0
fi
SCOURSH_CLOUD_EC2_ENGINE_SOURCED=1

# modules/cloud/aws/engine.sh supplies `cloud_json_flatten`/`cloud_json_unescape`
# and is ALREADY SOURCED in every real run - regions.sh sources it before the
# service walk begins - so this is reached only by a direct-engine test.
#
# -x back-edge cut: in the source graph that matters (modules/cloud/aws/run.sh
# -> regions.sh -> engine.sh -> modules/sast/engine.sh -> the lib/ hub chain)
# every one of those files is already inlined by the time this file is reached,
# and `shellcheck -x` re-expands EVERY source edge it follows rather than
# memoising - see tests/lint-source-graph.sh and docs/CI-RUNBOOK.md's "the
# memory model".  A direct-engine test suite sources engine.sh itself.
if [[ -z ${SCOURSH_CLOUD_ENGINE_SOURCED:-} ]]; then
  # shellcheck source=/dev/null
  source "${BASH_SOURCE[0]%/*}/../engine.sh"
fi

# `declare -g`, NEVER a bare `declare`, on every global this file introduces -
# modules/cloud/aws/live/s3_engine.sh's own header records why at length: in a
# real run NOTHING sources this file at top level, `cloud_run_service` reaches
# it by running `source` from inside its own function scope, and a bare
# `declare -A` there would create a LOCAL that dies with the first service
# pass.
declare -gA _EC2_DOC=()
declare -gA _EC2_DOCT=()

# ---------------------------------------------------------------------------
# 1. Reading one response document
# ---------------------------------------------------------------------------
# `ec2_doc_load FILE` / `ec2_path P...` / `ec2_doc_has PATH` / `ec2_doc_get
# VARNAME PATH` - byte-for-byte the same shape as s3_engine.sh's own
# `s3_doc_load`/`s3_path`/`s3_doc_has`/`s3_doc_get`, and for the identical
# reason given there: every check below walks an ARRAY (SecurityGroups,
# IpPermissions, IpRanges, Reservations, Instances, ...) whose length is not
# known in advance, so the whole flattened map is needed rather than a single
# named leaf.
ec2_doc_load() {
  local file=$1
  _EC2_DOC=()
  _EC2_DOCT=()
  [[ -r $file ]] || return 1
  local path type val
  # `< <(...)` rather than a pipe, so the assignments land in THIS shell - the
  # standing subshell lesson (`lib/core.sh`'s `worker_id_set`), in its loop
  # form; a `cloud_json_flatten <"$f" | while ...` would discard every entry
  # the instant the subshell exited.
  while IFS=$'\t' read -r path type val; do
    [[ -n $path ]] || continue
    [[ $type == s ]] && val=$(cloud_json_unescape "$val")
    _EC2_DOC[$path]=$val
    _EC2_DOCT[$path]=$type
  done < <(cloud_json_flatten <"$file" 2>/dev/null)
  return 0
}

ec2_path() {
  local out=$1
  shift
  local seg
  for seg in "$@"; do out+=$'\x1f'$seg; done
  printf '%s' "$out"
}

ec2_doc_has() {
  [[ -n ${_EC2_DOCT[$1]+set} ]]
}

ec2_doc_get() {
  local __var=$1 __path=$2
  printf -v "$__var" '%s' "${_EC2_DOC[$__path]:-}"
  [[ -n ${_EC2_DOCT[$__path]+set} ]]
}

# ---------------------------------------------------------------------------
# 2. The ARN
# ---------------------------------------------------------------------------
# `ec2_partition_of CALLER_ARN` - a byte-for-byte copy of
# `s3_engine.sh`'s `s3_partition_of`, duplicated rather than shared for the
# reason that file's own header gives at length for `cloud_json_flatten`
# itself: a THIRD copy is one small, intentional duplication; a shared home for
# it would either live in the module engine (which every one of thirty
# services would then source, growing it into a file that answers a question
# only two of them ask) or in `lib/` (a new hub `tests/lint-source-graph.sh`
# exists to keep from happening).
ec2_partition_of() {
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

# `ec2_arn PARTITION REGION ACCOUNT RESOURCE_TYPE RESOURCE_ID` -
# `arn:<partition>:ec2:<region>:<account>:<resource_type>/<resource_id>`.
#
# UNLIKE `s3_bucket_arn`, EVERY EC2 ARN CARRIES A REGION AND AN ACCOUNT: EC2
# resources are region-scoped and account-owned, so both are real components of
# the ARN itself, not merely of the finding's location profile.  This is the
# ordinary EC2 ARN shape (`arn:aws:ec2:us-east-1:123456789012:volume/vol-...`),
# not a case worth a second look the way S3's account/region-free bucket ARN
# was.
ec2_arn() {
  printf 'arn:%s:ec2:%s:%s:%s/%s' "$1" "$2" "$3" "$4" "$5"
}

# ---------------------------------------------------------------------------
# 3. Security groups - ingress rules open to the internet
# ---------------------------------------------------------------------------
# The ports docs/STEP6-CLOUD-PLAN.md's CLOUD-13 row names explicitly (22, 3389
# - SSH and RDP, CIS 5.2's own "remote server administration ports") versus the
# common database ports CIS has no control for at all.  Two lists, because
# citing CIS 5.2 against a Redis or MySQL exposure would misattribute a control
# that does not cover it (docs/CIS-MAPPINGS.md §1's own rule) - the reason
# CLOUD-EC2-SG_OPEN_ADMIN_PORT-01 and CLOUD-EC2-SG_OPEN_DB_PORT-01 are two
# check ids rather than one.
declare -g EC2_ADMIN_PORTS='22 3389'
declare -g EC2_DB_PORTS='1433 1434 3306 5432 1521 27017 6379 5984 9200 11211 5439'

# `ec2_port_in_range FROM TO PORT` - true when PORT falls in [FROM, TO].  FROM
# and TO empty (as AWS returns for an IpPermission naming protocol `-1`, "all
# traffic", which carries no FromPort/ToPort at all) mean the WHOLE port range,
# never "no ports": a `-1` rule is the most permissive shape a security group
# can express, and reading its absent bounds as zero-width would report the
# single most dangerous rule shape as covering nothing.
ec2_port_in_range() {
  local from=${1:-} to=${2:-} port=$3
  [[ -n $from ]] || from=0
  [[ -n $to ]] || to=65535
  (( from <= port && port <= to ))
}

# `ec2_protocol_is_relevant PROTOCOL` - true for `tcp` and for `-1` (all
# protocols).  UDP and ICMP entries are skipped: none of the ports this file
# checks (SSH, RDP, and the database ports above) are ordinarily served over
# UDP, and an ICMP IpPermission's FromPort/ToPort carry a type/code pair with
# no relationship to a TCP port number, so testing them against a port list
# would be a category error rather than a narrowing.
ec2_protocol_is_relevant() {
  case $1 in
    tcp | -1) return 0 ;;
    *) return 1 ;;
  esac
}

# `ec2_sg_public_ingress_set VARNAME IDX` - over the loaded describe-security-
# groups document, one `PROTOCOL FROM TO` line per IpPermission of security
# group index IDX that grants ingress from `0.0.0.0/0` (IPv4 only - IPv6's
# `::/0` is CIS 5.3, a distinct control this ticket's brief does not name, and
# folding it into this line would misreport an IPv6-only exposure under a
# `0.0.0.0/0`-shaped finding).  Empty output means this security group's
# IpPermissions grant nothing to the whole internet.
ec2_sg_public_ingress_set() {
  local __var=$1 __idx=$2
  local __out='' __j=0 __proto='' __from='' __to='' __k=0 __cidr=''
  while :; do
    ec2_doc_has "$(ec2_path SecurityGroups "$__idx" IpPermissions "$__j" IpProtocol)" || break
    ec2_doc_get __proto "$(ec2_path SecurityGroups "$__idx" IpPermissions "$__j" IpProtocol)"
    __from=''
    __to=''
    ec2_doc_get __from "$(ec2_path SecurityGroups "$__idx" IpPermissions "$__j" FromPort)" || true
    ec2_doc_get __to "$(ec2_path SecurityGroups "$__idx" IpPermissions "$__j" ToPort)" || true
    __k=0
    while :; do
      ec2_doc_has "$(ec2_path SecurityGroups "$__idx" IpPermissions "$__j" IpRanges "$__k" CidrIp)" || break
      ec2_doc_get __cidr "$(ec2_path SecurityGroups "$__idx" IpPermissions "$__j" IpRanges "$__k" CidrIp)"
      if [[ $__cidr == 0.0.0.0/0 ]] && ec2_protocol_is_relevant "$__proto"; then
        __out+="${__out:+$'\n'}$__proto $__from $__to"
      fi
      __k=$(( __k + 1 ))
    done
    __j=$(( __j + 1 ))
  done
  printf -v "$__var" '%s' "$__out"
}

# `ec2_ports_open_in_rules RULES PORTLIST` - true when any `PROTOCOL FROM TO`
# line of RULES (ec2_sg_public_ingress_set's own output) covers ANY port named
# in the space-separated PORTLIST.
ec2_ports_open_in_rules() {
  local rules=$1 ports=$2
  local line from to port
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    from=$(printf '%s' "$line" | awk '{print $2}')
    to=$(printf '%s' "$line" | awk '{print $3}')
    for port in $ports; do
      ec2_port_in_range "$from" "$to" "$port" && return 0
    done
  done <<<"$rules"
  return 1
}

# ---------------------------------------------------------------------------
# 4. AMIs and EBS snapshots - the public-sharing predicates
# ---------------------------------------------------------------------------
# `ec2_launch_permission_is_public` - true when the loaded
# `describe-image-attribute --attribute launchPermission` document grants
# launch permission to the `all` group (the AMI-sharing analogue of an S3
# bucket ACL's `AllUsers` grantee - a public AMI can be launched, and its
# contents inspected, by any AWS account in the partition).
ec2_launch_permission_is_public() {
  local i=0 group=''
  while :; do
    ec2_doc_has "$(ec2_path LaunchPermissions "$i" Group)" || break
    ec2_doc_get group "$(ec2_path LaunchPermissions "$i" Group)"
    [[ $group == all ]] && return 0
    i=$(( i + 1 ))
  done
  return 1
}

# `ec2_create_volume_permission_is_public` - the identical shape over a loaded
# `describe-snapshot-attribute --attribute createVolumePermission` document.
ec2_create_volume_permission_is_public() {
  local i=0 group=''
  while :; do
    ec2_doc_has "$(ec2_path CreateVolumePermissions "$i" Group)" || break
    ec2_doc_get group "$(ec2_path CreateVolumePermissions "$i" Group)"
    [[ $group == all ]] && return 0
    i=$(( i + 1 ))
  done
  return 1
}

# ---------------------------------------------------------------------------
# 5. Volumes, instances, VPCs - single-document per-resource predicates
# ---------------------------------------------------------------------------
# `ec2_volume_id_at IDX` / `ec2_volume_encrypted_at IDX` - over a loaded
# describe-volumes document.  `describe-volumes` reports `Encrypted` directly
# on every returned volume, so unlike AMIs and snapshots this needs no second,
# per-resource call - the property this check tests is already inline in the
# list response.
ec2_volume_id_at() {
  local __var=$1 __idx=$2
  ec2_doc_get "$__var" "$(ec2_path Volumes "$__idx" VolumeId)"
}

ec2_volume_is_encrypted_at() {
  local __idx=$1 __v=''
  ec2_doc_get __v "$(ec2_path Volumes "$__idx" Encrypted)" || return 1
  [[ $__v == true ]]
}

# `ec2_instance_at IDX VAR_ID VAR_STATE VAR_HTTPTOKENS` - over a loaded
# describe-instances document.  `describe-instances` nests every instance
# under `Reservations[n].Instances[m]`, so the walk needs BOTH indices; this
# function is called with `n m` already resolved by the caller's own nested
# loop rather than re-deriving them, since a flattened path map has no notion
# of "the next instance" across a reservation boundary on its own.
ec2_instance_at() {
  local __r=$1 __i=$2 __idvar=$3 __statevar=$4 __httvar=$5
  ec2_doc_get "$__idvar" "$(ec2_path Reservations "$__r" Instances "$__i" InstanceId)" || return 1
  ec2_doc_get "$__statevar" "$(ec2_path Reservations "$__r" Instances "$__i" State Name)"
  # `HttpTokens` absent means the instance was never asked about IMDSv2 at all
  # - an instance stopped since before AWS introduced the setting, in
  # practice - which is NOT the same fact as an explicit `optional`, but is
  # reported identically: either way IMDSv1 is available, which is the whole
  # exposure this check exists to close.
  ec2_doc_get "$__httvar" "$(ec2_path Reservations "$__r" Instances "$__i" MetadataOptions HttpTokens)" || true
  return 0
}

# `ec2_imdsv2_not_enforced HTTPTOKENS` - true when HTTPTOKENS is anything
# other than `required` (`optional`, or absent/empty).
ec2_imdsv2_not_enforced() {
  [[ ${1:-} != required ]]
}

# `ec2_vpc_id_at IDX` - over a loaded describe-vpcs document.
ec2_vpc_id_at() {
  local __var=$1 __idx=$2
  ec2_doc_get "$__var" "$(ec2_path Vpcs "$__idx" VpcId)"
}

# ---------------------------------------------------------------------------
# 6. Emission
# ---------------------------------------------------------------------------
# `ec2_registry_locate_set SETVAR IDXVAR CHECK_ID` - a byte-for-byte copy of
# `s3_engine.sh`'s own `s3_registry_locate_set`; see that function's header for
# why this is not shared through the module engine.
ec2_registry_locate_set() {
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

# `ec2_emit_finding CHECK_ID RESOURCE_TYPE RESOURCE_ID SUB_KEY EVIDENCE` -
# EC2/VPC's own `s3_emit_finding`.  Every static field (title, severity,
# confidence, cwe, owasp, remediation, references, and - where one exists -
# `cis`) comes from the check record via `finding_from_record`, never
# restated here, for `s3_emit_finding`'s own stated reason: a script that set
# them by hand is a second copy of every one of them to keep in step with the
# registry's.
#
# THE CELL AND THE REGION ARE THE SAME VALUE HERE, unlike s3's `global` pass:
# `SCOURSH_CLOUD_CELL` is `<account>/<region>` for a `regional` service
# (`modules/cloud/aws/engine.sh`'s `cloud_run_service`), and every EC2/VPC
# resource this file examines genuinely lives in the region this pass is
# currently scanning - there is no second, "resource's own region" to resolve
# and no s3-shaped divergence between the two to guard against.
ec2_emit_finding() {
  local check_id=$1 rtype=$2 rid=$3 sub_key=$4 evidence=$5
  local set='' idx=''
  ec2_registry_locate_set set idx "$check_id" \
    || die "$SCOURSH_EXIT_INCOMPLETE" \
      "internal: cloud/ec2 emitted '$check_id', which is in no loaded check registry (modules/cloud/aws/live/checks.rules)"

  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  local arn
  arn=$(ec2_arn "$(ec2_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")" "$region" "$account" "$rtype" "$rid")

  finding_new
  finding_from_record "$set" "$idx"
  finding_set module cloud
  # `exposure`/`auth`/`sensitive_data` feed data/severity-rubric.conf's
  # adjustment of the record's base severity, exactly as s3_emit_finding's own
  # case does: a network-reachable-from-anywhere or publicly-shared resource is
  # `external`/`none`, an internal misconfiguration is not.
  case $check_id in
    CLOUD-EC2-SG_OPEN_ADMIN_PORT-01 | CLOUD-EC2-SG_OPEN_DB_PORT-01)
      finding_set exposure external
      finding_set auth none
      ;;
    CLOUD-EC2-PUBLIC_AMI-01 | CLOUD-EC2-PUBLIC_EBS_SNAPSHOT-01)
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
  finding_set loc_sub_key "$sub_key"
  finding_set_evidence "$evidence"
  finding_emit
  return 0
}
