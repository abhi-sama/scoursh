#!/usr/bin/env bash
# modules/cloud/aws/live/ec2.sh - the §8.1 EC2/VPC read-only service pass
# (docs/DESIGN.md §8.1's `ec2` row; docs/STEP6-CLOUD-PLAN.md CLOUD-13).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard: `ec2` is a `regional` row in
# `_CLOUD_SERVICES`, so one run legitimately reaches this file once per enabled
# region, and a guard would silently make every region after the first a
# no-op - the failure that reads as a complete multi-region audit.  Its pure
# half - every classifier, the ARN builder and the emitter - is
# modules/cloud/aws/live/ec2_engine.sh, which does have a guard.
#
# EVERY FIELD THIS FILE OBSERVES IS ALREADY REGION-SCOPED, unlike s3.sh's
# `global` pass.  `ec2`, unlike `s3api`, has no account-wide list call at all:
# `describe-security-groups`, `describe-network-interfaces`,
# `describe-images`, `describe-snapshots`, `describe-volumes`,
# `describe-instances`, `describe-vpcs` and `describe-flow-logs` are all
# answered by the region the ambient `--region` names, so there is no
# s3-shaped divergence between the finding's `cell` (the pass's own) and its
# `loc_region` (the resource's own) to resolve - here the two are the same
# value, set once from `SCOURSH_CLOUD_REGION`.
#
# SEVEN PROPERTIES, EIGHT CHECK IDS.  `docs/STEP6-CLOUD-PLAN.md`'s own CLOUD-13
# row names: security groups open `0.0.0.0/0` on 22/3389/db ports, default SG
# in use, public AMIs, public EBS snapshots, unencrypted EBS, IMDSv2 not
# enforced, VPC flow logs off.  The admin-port and database-port cases split
# into CLOUD-EC2-SG_OPEN_ADMIN_PORT-01 and CLOUD-EC2-SG_OPEN_DB_PORT-01
# because CIS AWS Foundations Benchmark v3.0.0 control 5.2 covers "remote
# server administration ports" specifically (22, 3389) and has no database-port
# equivalent - citing 5.2 against a Redis or MySQL exposure would misattribute
# a control that does not cover it (docs/CIS-MAPPINGS.md §1), which is the same
# reasoning modules/cloud/aws/live/checks.rules already records for S3's own
# PUBLIC_ACL_READ/WRITE split (there, on severity; here, on which CIS control -
# if any - genuinely applies).
#
# EIGHT INDEPENDENT AWS API FAMILIES, NOT ONE LIST FEEDING SEVEN CHECKS.
# Unlike S3 (one `list-buckets` call that every other check depends on),
# EC2/VPC's seven properties are answered by SIX INDEPENDENT list families -
# security groups (+ network interfaces, for the "in use" half of the default-
# SG check), images (+ per-image `describe-image-attribute`), snapshots (+
# per-snapshot `describe-snapshot-attribute`), volumes, instances, and VPCs (+
# flow logs) - so a single family's `AccessDenied` must not stop the others
# from being examined.  Each family below is independent: a role denied
# `ec2:DescribeImages` but permitted everything else still gets six of eight
# checks answered, and the two AMI/snapshot checks alone are recorded as
# uncovered.
#
# THE MULTI-CALL SHAPE THE MODULE'S OWN CONTRACT ASKS FOR ("list/describe then
# per-resource get") IS REAL HERE FOR TWO OF THE SIX FAMILIES, NOT INVENTED FOR
# UNIFORMITY.  AMIs and snapshots are the only two of EC2's describe-* families
# whose public-sharing STATE is a SEPARATE, per-resource call
# (`describe-image-attribute`/`describe-snapshot-attribute` with
# `--attribute`) rather than a field already present on the list response - a
# security group's rules, a volume's `Encrypted` flag, an instance's
# `MetadataOptions`, and a VPC's own id are all inline in their own `describe-*`
# list call, which is a real, documented difference between what these EC2
# APIs return inline and what S3's own `get-bucket-*` calls each answer with a
# single field.  Forcing a second call for every family here would spend API
# budget that these six do not need, purely to look uniform with S3's own
# per-property-call shape.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23), spelled
# literally at each call site with a literal service and operation, and the
# response is redirected to a file rather than captured with `$(...)` - both
# for `modules/cloud/aws/live/s3.sh`'s own stated reasons (tests/lint-aws-
# readonly.sh's static parse, and the subshell hazard that would otherwise
# silently discard every `SCOURSH_AWS_RO_*` outcome global a nested command
# substitution sets).
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE.  1. `checks_run` names only a
# check that ACTUALLY ANSWERED for at least one resource in THIS region - a
# family whose list call was denied entirely never touches its check ids'
# `_EC2_EVALUATED` counters, so they are simply absent from `checks_run` for
# this region's cell, exactly as `modules/cloud/aws/live/s3.sh`'s own rule 1
# states it.  2. An `AccessDenied`, a throttle, or a region this account has
# not enabled is a `coverage_reduction`, never silence -
# `aws_ro_outcome_is_coverage_loss` is the one predicate that decides that,
# and this file never re-derives the judgement.  3. A `not_found`-shaped
# answer that carries a real fact ("this instance's MetadataOptions were never
# set", say) is treated as an answer, not a loss - though unlike S3's three
# `NoSuch*`-as-answer cases, every EC2 list call used here is a bulk `describe-*`
# with no per-resource `NotFound` branch to reach in the first place.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/ec2_engine.sh
source "${BASH_SOURCE[0]%/*}/ec2_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, reset here rather than only declared, for `s3.sh`'s own stated
# reason - and MORE load-bearing here than there: this file is sourced ONCE PER
# REGION in an ordinary run (s3.sh sources only once, since `s3` is `global`),
# so without an explicit reset every region after the first would silently
# inherit the previous region's counters.
declare -gA _EC2_EVALUATED=()
declare -gA _EC2_LOST=()
declare -gA _EC2_LOST_REASON=()

declare -ga _EC2_CHECK_IDS=(
  CLOUD-EC2-SG_OPEN_ADMIN_PORT-01
  CLOUD-EC2-SG_OPEN_DB_PORT-01
  CLOUD-EC2-DEFAULT_SG_IN_USE-01
  CLOUD-EC2-PUBLIC_AMI-01
  CLOUD-EC2-PUBLIC_EBS_SNAPSHOT-01
  CLOUD-EC2-UNENCRYPTED_VOLUME-01
  CLOUD-EC2-IMDSV2_NOT_ENFORCED-01
  CLOUD-EC2-FLOW_LOGS_OFF-01
)

# `_ec2_selected ID` - byte-for-byte `s3.sh`'s own `_s3_selected`; see that
# function's header for why the `declare -F` guard is permissive rather than
# fail-closed.
_ec2_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

_ec2_note_evaluated() {
  _EC2_EVALUATED[$1]=$(( ${_EC2_EVALUATED[$1]:-0} + 1 ))
}

_ec2_note_lost() {
  _EC2_LOST[$1]=$(( ${_EC2_LOST[$1]:-0} + 1 ))
  # FIRST reason wins, `s3.sh`'s own reasoning: the earliest failure is the
  # actionable one and the one that plausibly explains any that follow it.
  [[ -n ${_EC2_LOST_REASON[$1]:-} ]] || _EC2_LOST_REASON[$1]=$2
}

# `_ec2_family_lost REASON ID...` - a whole API family's LIST call failed
# entirely (never a per-resource failure): no resource of that family was
# examined at all this region, so nothing is added to `_EC2_EVALUATED` for the
# affected ids - they are simply absent from `checks_run` - but the REASON is
# recorded so the final roll-up's "answered for NO resource" line names the
# real cause (AccessDenied, throttled, ...) instead of a generic fallback.
_ec2_family_lost() {
  local reason=$1
  shift
  local id
  for id in "$@"; do
    [[ -n ${_EC2_LOST_REASON[$id]:-} ]] || _EC2_LOST_REASON[$id]=$reason
  done
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_ec2_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-}
  # `mktemp -d`, never a name built from `$$` or a fixed string - `s3.sh`'s own
  # reasoning against a symlink-planting local-user attack (CWE-377 via
  # CWE-59).  No `-p` (tension 24: GNU-only).
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-ec2.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_EC2_CHECK_IDS[@]+"${_EC2_CHECK_IDS[@]}"}"; do
    _ec2_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_ec2_checks_deselected service=ec2 account=$account region=$region - every CLOUD-EC2-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no EC2 API call was made and no resource was examined in this region."
    return 0
  fi

  _ec2_pass_security_groups "$account" "$region" "$work"
  _ec2_pass_amis "$account" "$region" "$work"
  _ec2_pass_snapshots "$account" "$region" "$work"
  _ec2_pass_volumes "$account" "$region" "$work"
  _ec2_pass_instances "$account" "$region" "$work"
  _ec2_pass_vpc_flow_logs "$account" "$region" "$work"

  _ec2_record_coverage "$account" "$region"
  return 0
}

# `_ec2_call REASONVAR SERVICE OPERATION OUTFILE [ARGS...]` - one `aws_ro`
# call, writing the reason (lib/awscli.sh's own vocabulary) into REASONVAR on
# failure.  A thin shared tail so a call site never has to remember to call
# `aws_ro_reduction_reason_set` itself.
_ec2_call() {
  local __reasonvar=$1 __svc=$2 __op=$3 __out=$4
  shift 4
  local __rc=0
  aws_ro "$__svc" "$__op" "$@" >"$__out" || __rc=$?
  if (( __rc != 0 )); then
    aws_ro_reduction_reason_set "$__reasonvar"
    return 1
  fi
  printf -v "$__reasonvar" '%s' ''
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=ec2 operation=$__op account=${SCOURSH_CLOUD_ACCOUNT_ID:-} region=${SCOURSH_CLOUD_REGION:-} - the response came back INCOMPLETE (a continuation token was present, or the page ceiling was reached), so an unknown number of this region's resources from this call were never enumerated."
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 3. Security groups: open admin/database ports, and the default SG
# ---------------------------------------------------------------------------
_ec2_pass_security_groups() {
  local account=$1 region=$2 work=$3
  local admin=CLOUD-EC2-SG_OPEN_ADMIN_PORT-01 db=CLOUD-EC2-SG_OPEN_DB_PORT-01 defsg=CLOUD-EC2-DEFAULT_SG_IN_USE-01
  _ec2_selected "$admin" || _ec2_selected "$db" || _ec2_selected "$defsg" || return 0

  local reason='' rc=0
  local sgf=$work/describe-security-groups.json
  _ec2_call reason ec2 describe-security-groups "$sgf" || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$admin" "$db" "$defsg"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-security-groups account=$account region=$region - the security group list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no security group in this region was examined for an open admin/database port or for default-SG usage."
    return 0
  fi
  ec2_doc_load "$sgf" || true

  local -a default_sg_ids=()
  local i=0 gid='' gname='' rules=''
  while :; do
    ec2_doc_has "$(ec2_path SecurityGroups "$i" GroupId)" || break
    ec2_doc_get gid "$(ec2_path SecurityGroups "$i" GroupId)"
    gname=''
    ec2_doc_get gname "$(ec2_path SecurityGroups "$i" GroupName)" || true

    if [[ $gname == default ]]; then
      default_sg_ids+=("$gid")
    fi

    ec2_sg_public_ingress_set rules "$i"
    if [[ -n $rules ]]; then
      if _ec2_selected "$admin"; then
        _ec2_note_evaluated "$admin"
        if ec2_ports_open_in_rules "$rules" "$EC2_ADMIN_PORTS"; then
          ec2_emit_finding "$admin" security-group "$gid" '' \
            "Security group $gid ($gname, $region) allows ingress from 0.0.0.0/0 (every IPv4 address on the internet) to at least one remote administration port (22/SSH or 3389/RDP). Any host on the internet can attempt to authenticate against this port. Remove the 0.0.0.0/0 rule and restrict it to a known jump host, a VPN/Direct Connect CIDR, or use AWS Systems Manager Session Manager instead of a directly reachable admin port."
        fi
      fi
      if _ec2_selected "$db"; then
        _ec2_note_evaluated "$db"
        if ec2_ports_open_in_rules "$rules" "$EC2_DB_PORTS"; then
          ec2_emit_finding "$db" security-group "$gid" '' \
            "Security group $gid ($gname, $region) allows ingress from 0.0.0.0/0 to at least one common database port (MySQL/MariaDB 3306, PostgreSQL 5432, MSSQL 1433/1434, Oracle 1521, MongoDB 27017, Redis 6379, CouchDB 5984, Elasticsearch 9200, Memcached 11211, or Redshift 5439). A database reachable from the whole internet is exposed to credential-stuffing and unpatched-CVE scanning the moment it is provisioned. Restrict ingress to the application tier's own security group and remove the 0.0.0.0/0 rule."
        fi
      fi
    elif _ec2_selected "$admin" || _ec2_selected "$db"; then
      # A security group with no rule open to 0.0.0.0/0 at all is still an
      # examined resource - both checks are credited for it even though
      # neither fires, exactly as `s3.sh`'s own per-bucket checks credit a
      # hardened bucket.
      _ec2_selected "$admin" && _ec2_note_evaluated "$admin"
      _ec2_selected "$db" && _ec2_note_evaluated "$db"
    fi
    i=$(( i + 1 ))
  done

  if (( ${#default_sg_ids[@]} == 0 )) || ! _ec2_selected "$defsg"; then
    return 0
  fi

  # The default SG's "in use" state needs a SECOND, independent call:
  # describe-security-groups names WHICH group is the default, but not
  # whether anything actually references it - only a network interface's own
  # `Groups[]` says that.
  local enif=$work/describe-network-interfaces.json
  _ec2_call reason ec2 describe-network-interfaces "$enif" || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$defsg"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-network-interfaces account=$account region=$region - the network interface list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so whether this region's default security group(s) are actually attached to anything could not be determined."
    return 0
  fi
  ec2_doc_load "$enif" || true
  local -A used_groups=()
  local ni=0 nj=0 used_gid=''
  while :; do
    ec2_doc_has "$(ec2_path NetworkInterfaces "$ni" NetworkInterfaceId)" || break
    nj=0
    while :; do
      ec2_doc_has "$(ec2_path NetworkInterfaces "$ni" Groups "$nj" GroupId)" || break
      ec2_doc_get used_gid "$(ec2_path NetworkInterfaces "$ni" Groups "$nj" GroupId)"
      used_groups[$used_gid]=1
      nj=$(( nj + 1 ))
    done
    ni=$(( ni + 1 ))
  done

  local dgid=''
  for dgid in "${default_sg_ids[@]}"; do
    _ec2_note_evaluated "$defsg"
    if [[ -n ${used_groups[$dgid]:-} ]]; then
      ec2_emit_finding "$defsg" security-group "$dgid" '' \
        "The default security group $dgid in region $region is attached to at least one network interface. CIS AWS Foundations Benchmark 5.4 calls for the default security group of every VPC to restrict all traffic and, in practice, for nothing to rely on it - a resource left in the default SG inherits whatever broad rule set it carries and is easy to overlook in a review that only inspects custom groups. Move every attached resource to a purpose-specific security group and remove the default SG's own rules."
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# 4. AMIs owned by this account, shared with the `all` group
# ---------------------------------------------------------------------------
_ec2_pass_amis() {
  local account=$1 region=$2 work=$3
  local id=CLOUD-EC2-PUBLIC_AMI-01
  _ec2_selected "$id" || return 0

  local reason='' rc=0
  local listf=$work/describe-images.json
  _ec2_call reason ec2 describe-images "$listf" --owners self || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$id"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-images account=$account region=$region - this account's owned AMI list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no AMI in this region was examined for public launch permission."
    return 0
  fi
  ec2_doc_load "$listf" || true

  local -a image_ids=()
  local i=0 iid=''
  while :; do
    ec2_doc_has "$(ec2_path Images "$i" ImageId)" || break
    ec2_doc_get iid "$(ec2_path Images "$i" ImageId)"
    [[ -n $iid ]] && image_ids+=("$iid")
    i=$(( i + 1 ))
  done

  local img attrf safe
  for img in "${image_ids[@]+"${image_ids[@]}"}"; do
    safe=${img//[^A-Za-z0-9._-]/_}
    attrf=$work/image-attr-$safe.json
    rc=0
    _ec2_call reason ec2 describe-image-attribute "$attrf" --image-id "$img" --attribute launchPermission || rc=$?
    if (( rc != 0 )); then
      _ec2_note_lost "$id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-image-attribute image=$img account=$account region=$region - the launch permission for this AMI could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so it was not tested."
      continue
    fi
    ec2_doc_load "$attrf" || true
    _ec2_note_evaluated "$id"
    if ec2_launch_permission_is_public; then
      ec2_emit_finding "$id" image "$img" '' \
        "AMI $img in region $region grants launch permission to the AllUsers/\"all\" group (describe-image-attribute's launchPermission), so any AWS account in this partition can launch an instance from it and inspect its full disk contents - which routinely includes application code, configuration, and any credential baked into the image. Remove the public launch permission and share the AMI only with named account ids or an AWS Organization, or use AWS Resource Access Manager if it needs to be shared broadly within an organisation."
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# 5. EBS snapshots owned by this account, shared with the `all` group
# ---------------------------------------------------------------------------
_ec2_pass_snapshots() {
  local account=$1 region=$2 work=$3
  local id=CLOUD-EC2-PUBLIC_EBS_SNAPSHOT-01
  _ec2_selected "$id" || return 0

  local reason='' rc=0
  local listf=$work/describe-snapshots.json
  _ec2_call reason ec2 describe-snapshots "$listf" --owner-ids self || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$id"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-snapshots account=$account region=$region - this account's owned EBS snapshot list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no snapshot in this region was examined for public create-volume permission."
    return 0
  fi
  ec2_doc_load "$listf" || true

  local -a snap_ids=()
  local i=0 sid=''
  while :; do
    ec2_doc_has "$(ec2_path Snapshots "$i" SnapshotId)" || break
    ec2_doc_get sid "$(ec2_path Snapshots "$i" SnapshotId)"
    [[ -n $sid ]] && snap_ids+=("$sid")
    i=$(( i + 1 ))
  done

  local snap attrf safe
  for snap in "${snap_ids[@]+"${snap_ids[@]}"}"; do
    safe=${snap//[^A-Za-z0-9._-]/_}
    attrf=$work/snapshot-attr-$safe.json
    rc=0
    _ec2_call reason ec2 describe-snapshot-attribute "$attrf" --snapshot-id "$snap" --attribute createVolumePermission || rc=$?
    if (( rc != 0 )); then
      _ec2_note_lost "$id" "$reason"
      run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-snapshot-attribute snapshot=$snap account=$account region=$region - the create-volume permission for this snapshot could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so it was not tested."
      continue
    fi
    ec2_doc_load "$attrf" || true
    _ec2_note_evaluated "$id"
    if ec2_create_volume_permission_is_public; then
      ec2_emit_finding "$id" snapshot "$snap" '' \
        "EBS snapshot $snap in region $region grants create-volume permission to the AllUsers/\"all\" group (describe-snapshot-attribute's createVolumePermission), so any AWS account in this partition can create a volume from it, attach it, and read every byte it contains - a direct data-exposure path that bypasses every access control on the running instance. Remove the public permission and share the snapshot only with named account ids."
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# 6. EBS volumes - encryption at rest
# ---------------------------------------------------------------------------
_ec2_pass_volumes() {
  local account=$1 region=$2 work=$3
  local id=CLOUD-EC2-UNENCRYPTED_VOLUME-01
  _ec2_selected "$id" || return 0

  local reason='' rc=0
  local f=$work/describe-volumes.json
  _ec2_call reason ec2 describe-volumes "$f" || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$id"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-volumes account=$account region=$region - the EBS volume list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no volume in this region was examined for encryption at rest."
    return 0
  fi
  ec2_doc_load "$f" || true

  local i=0 vid=''
  while :; do
    ec2_doc_has "$(ec2_path Volumes "$i" VolumeId)" || break
    ec2_volume_id_at vid "$i"
    _ec2_note_evaluated "$id"
    if ! ec2_volume_is_encrypted_at "$i"; then
      ec2_emit_finding "$id" volume "$vid" '' \
        "EBS volume $vid in region $region is not encrypted at rest (describe-volumes reports Encrypted: false). Data written to it - and any snapshot later taken of it - is stored in plaintext, and a compromised storage-layer credential or a mis-shared snapshot exposes it directly. Enable EBS encryption by default for the region (which volumes created from this point on inherit) and re-create this volume from an encrypted copy, since existing volumes cannot be encrypted in place."
    fi
    i=$(( i + 1 ))
  done
  return 0
}

# ---------------------------------------------------------------------------
# 7. Instances - IMDSv2 enforcement
# ---------------------------------------------------------------------------
_ec2_pass_instances() {
  local account=$1 region=$2 work=$3
  local id=CLOUD-EC2-IMDSV2_NOT_ENFORCED-01
  _ec2_selected "$id" || return 0

  local reason='' rc=0
  local f=$work/describe-instances.json
  _ec2_call reason ec2 describe-instances "$f" || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$id"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-instances account=$account region=$region - the instance list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so no instance in this region was examined for IMDSv2 enforcement."
    return 0
  fi
  ec2_doc_load "$f" || true

  local r=0 i=0 iid='' state='' httptokens=''
  while :; do
    ec2_doc_has "$(ec2_path Reservations "$r" ReservationId)" || break
    i=0
    while :; do
      ec2_doc_has "$(ec2_path Reservations "$r" Instances "$i" InstanceId)" || break
      ec2_instance_at "$r" "$i" iid state httptokens
      # A terminated instance's MetadataOptions are a fact about its last-run
      # configuration, not about anything an operator can act on today - and
      # continuing to report it would make a finding that never goes away no
      # matter what is done, which is the "fixed" predicate's own worst case
      # (tension 12).
      if [[ $state != terminated ]]; then
        _ec2_note_evaluated "$id"
        if ec2_imdsv2_not_enforced "$httptokens"; then
          ec2_emit_finding "$id" instance "$iid" '' \
            "Instance $iid in region $region does not enforce IMDSv2 (MetadataOptions.HttpTokens is ${httptokens:-<absent>}, not required). The original instance metadata service (IMDSv1) answers a plain, unauthenticated HTTP GET, so any request the instance is tricked into making on its own behalf - the textbook Server-Side Request Forgery shape - can retrieve the instance's IAM role credentials. Set HttpTokens to required (IMDSv2 only) on the instance's metadata options."
        fi
      fi
      i=$(( i + 1 ))
    done
    r=$(( r + 1 ))
  done
  return 0
}

# ---------------------------------------------------------------------------
# 8. VPCs - flow logging
# ---------------------------------------------------------------------------
_ec2_pass_vpc_flow_logs() {
  local account=$1 region=$2 work=$3
  local id=CLOUD-EC2-FLOW_LOGS_OFF-01
  _ec2_selected "$id" || return 0

  local reason='' rc=0
  local vpcf=$work/describe-vpcs.json
  _ec2_call reason ec2 describe-vpcs "$vpcf" || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$id"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-vpcs account=$account region=$region - the VPC list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so whether any VPC in this region has flow logging enabled could not be determined."
    return 0
  fi
  ec2_doc_load "$vpcf" || true

  local -a vpc_ids=()
  local i=0 vid=''
  while :; do
    ec2_doc_has "$(ec2_path Vpcs "$i" VpcId)" || break
    ec2_vpc_id_at vid "$i"
    [[ -n $vid ]] && vpc_ids+=("$vid")
    i=$(( i + 1 ))
  done
  if (( ${#vpc_ids[@]} == 0 )); then
    return 0
  fi

  local flf=$work/describe-flow-logs.json
  _ec2_call reason ec2 describe-flow-logs "$flf" || rc=$?
  if (( rc != 0 )); then
    _ec2_family_lost "$reason" "$id"
    run_record coverage_reduction "module=cloud reason=$reason service=ec2 operation=describe-flow-logs account=$account region=$region - the flow log list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this region's ${#vpc_ids[@]} VPC(s) could not be checked for active flow logging."
    return 0
  fi
  ec2_doc_load "$flf" || true

  local -A active_resource=()
  local fi=0 fresource='' fstatus=''
  while :; do
    ec2_doc_has "$(ec2_path FlowLogs "$fi" FlowLogId)" || break
    fresource=''
    fstatus=''
    ec2_doc_get fresource "$(ec2_path FlowLogs "$fi" ResourceId)" || true
    ec2_doc_get fstatus "$(ec2_path FlowLogs "$fi" FlowLogStatus)" || true
    [[ $fstatus == ACTIVE ]] && active_resource[$fresource]=1
    fi=$(( fi + 1 ))
  done

  local v
  for v in "${vpc_ids[@]}"; do
    _ec2_note_evaluated "$id"
    if [[ -z ${active_resource[$v]:-} ]]; then
      ec2_emit_finding "$id" vpc "$v" '' \
        "VPC $v in region $region has no ACTIVE flow log (describe-flow-logs names none for this VPC). CIS AWS Foundations Benchmark 3.7 calls for flow logging in every VPC: without it there is no record of accepted or rejected network traffic in or out of the VPC, so a later investigation into a suspected compromise or a data-exfiltration path has no network-layer evidence to work from. Enable VPC flow logs to CloudWatch Logs or S3 with a retention period matched to the estate's incident-response window."
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# 9. The roll-up
# ---------------------------------------------------------------------------
# One `checks_run` line per check that ACTUALLY ANSWERED for at least one
# resource in THIS region, and one `coverage_reduction` per check that did
# not - `s3.sh`'s own rule 1, applied per-region rather than per-account
# because this is where `_cloud_record_coverage` (modules/cloud/aws/run.sh)
# credits the `<account>/<region>` cell for an `ec2` pass.
_ec2_record_coverage() {
  local account=$1 region=$2 id
  local ran=0
  for id in "${_EC2_CHECK_IDS[@]+"${_EC2_CHECK_IDS[@]}"}"; do
    _ec2_selected "$id" || continue
    if (( ${_EC2_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      if (( ${_EC2_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_EC2_LOST_REASON[$id]} service=ec2 check=$id account=$account region=$region resources_answered=${_EC2_EVALUATED[$id]} resources_unanswered=${_EC2_LOST[$id]} - this check ran, but ${_EC2_LOST[$id]} resource(s) did not answer, so it is covered for some of this region's resources and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_EC2_LOST_REASON[$id]:-no_resource_examined} service=ec2 check=$id account=$account region=$region - this check answered for NO resource in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every resource in this region is configured correctly."
    fi
  done

  if (( ran == 0 )); then
    run_record coverage_gap "cloud ec2 ($region): NOT ONE of the ${#_EC2_CHECK_IDS[@]} CLOUD-EC2-* checks answered for any resource in this region, so no security group, AMI, snapshot, volume, instance or VPC in $region was tested. This is a run that did not look, not a region with nothing in it - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_ec2_run_service
