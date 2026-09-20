#!/usr/bin/env bash
# modules/cloud/aws/live/s3.sh - the §8.1 S3 read-only service pass
# (docs/DESIGN.md §8.1's `s3` row; docs/STEP6-CLOUD-PLAN.md CLOUD-05).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard - a regional service is legitimately
# reached once per region and a guard would silently make every region after the
# first a no-op, which is the failure that reads as a complete multi-region
# audit.  (`s3` is a `global` row, so it is reached once per run; the rule is
# the table's, not this row's, and copying the exception here would be one more
# thing for the next service to copy wrongly.)  Its pure half - every
# classifier, the ARN builder and the emitter - is
# modules/cloud/aws/live/s3_engine.sh, which does have a guard.
#
# WHY S3 IS A `global` ROW AND WHAT THAT COSTS.  `list-buckets` is one
# account-wide call whose response names every bucket in the account, and each
# per-bucket call is addressed by bucket NAME rather than by region, so
# iterating regions would issue N identical `list-buckets` calls and mint N
# copies of every finding, one per cell.  modules/cloud/aws/engine.sh's service
# table records that argument in full.  The consequence this file owns is that
# the bucket's own region has to be RESOLVED rather than inherited: a finding
# must cite where the bucket actually is, and `get-bucket-location` is the only
# thing that knows.  That is the seventh operation in the per-bucket sequence
# and the reason it exists.
#
# CELL VERSUS REGION, THE ONE THING MOST LIKELY TO BE GOT WRONG HERE.  The
# finding's `cell` is `<account>/global`, the cell of the PASS - what
# `cloud_run_service` published and what `_cloud_record_coverage` credits.  The
# finding's `loc_region` is the bucket's real region.  They differ on purpose:
# the cell answers "what did this run visit" (tension 12) and the run visited
# the account's global S3 namespace, while the region answers "where is this
# resource".  Putting the bucket's region in the cell would file every finding
# under a cell no pass ever covers, so no remediated bucket could ever be
# classified `fixed` and every one would sit at `unknown` forever.
#
# EVERY AWS CALL GOES THROUGH `aws_ro` (docs/FOUNDATION.md tension 23), spelled
# literally at each call site with a literal service and operation - never
# through a local wrapper taking the operation in a variable.  That is not
# style: `tests/lint-aws-readonly.sh` parses the operation out of the source
# line, and a wrapper would make every call in this file invisible to the lint
# that certifies the read-only guarantee.  The response is redirected to a file
# rather than captured with `$(...)`, for the reason `aws_ro_into`'s own header
# gives - a command substitution runs in a subshell, so every
# `SCOURSH_AWS_RO_*` outcome global is set in a process that then exits and the
# caller reads pre-call values, which turns an `AccessDenied` into an
# indistinguishable "empty response" and re-opens the exact honesty gap
# lib/awscli.sh's outcome vocabulary exists to close.
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, not a decoration on it.  Three
# rules, each of which a naive implementation gets wrong in the direction that
# reads as a clean account:
#   1. `checks_run` NAMES WHAT SUCCEEDED.  A check id is recorded only if its
#      own API call actually answered for at least one bucket.  Recording the
#      ids the pass INTENDED to run would credit coverage - and so let tension
#      12 report a prior finding `fixed` - for a check every bucket denied.
#   2. AN `AccessDenied` IS A `coverage_reduction`, NEVER SILENCE.  So is a
#      throttle, an unreachable endpoint and a truncated bucket list.
#      `aws_ro_outcome_is_coverage_loss` is the single predicate that separates
#      "we looked" from "we did not"; this file never re-derives that judgement.
#   3. `not_found` IS AN ANSWER, NOT A LOSS, AND IT IS THE COMMONEST ONE HERE.
#      `NoSuchBucketPolicy`, `NoSuchPublicAccessBlockConfiguration` and
#      `ServerSideEncryptionConfigurationNotFoundError` are how S3 says "there
#      is no policy / no Block Public Access / no default encryption" - which is
#      precisely what three of these checks asked.  Treating them as failures
#      would suppress the finding on every bucket that has the problem, leaving
#      the check firing only where the setting exists but is wrong.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/s3_engine.sh
source "${BASH_SOURCE[0]%/*}/s3_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, for the reason s3_engine.sh's own note records: this file is
# sourced from INSIDE `cloud_run_service`, so a bare `declare` would make every
# one of these a local that dies with the pass.  They are reset here rather
# than only declared, because a second pass in one process (two `scan_main`
# calls in one test process) must not inherit the first pass's counters.
declare -g _S3_BUCKETS_TOTAL=0
declare -g _S3_BUCKETS_EXAMINED=0
declare -g _S3_BUCKETS_NO_REGION=0
declare -g _S3_LIST_TRUNCATED=0
declare -gA _S3_EVALUATED=()
declare -gA _S3_LOST=()
declare -gA _S3_LOST_REASON=()

# Every check id this pass can emit, in registry order.  Spelled once, here,
# and read by the selection gate, the `checks_run` roll-up and the
# not-evaluated accounting alike - three places that must agree about what
# "every S3 check" means, and did not have to be kept in step by hand.
declare -ga _S3_CHECK_IDS=(
  CLOUD-S3-PUBLIC_ACL_READ-01
  CLOUD-S3-PUBLIC_ACL_WRITE-01
  CLOUD-S3-PUBLIC_POLICY-01
  CLOUD-S3-BLOCK_PUBLIC_ACCESS_OFF-01
  CLOUD-S3-NO_DEFAULT_ENCRYPTION-01
  CLOUD-S3-NO_VERSIONING-01
  CLOUD-S3-NO_LOGGING-01
)

# `_s3_selected ID` - tension 15's per-check filter, through the module
# engine's own `cloud_check_selected`.
#
# THE `declare -F` GUARD IS PERMISSIVE WHEN THE FUNCTION IS ABSENT, and
# inverting that is the trap modules/dast/engine.sh's own
# `dast_check_selected` header records at length: a direct-engine test suite
# sources a service script with no module engine in the process, so a
# fail-CLOSED default - or an unguarded call, which is exit 127 and therefore
# "deselected" - would make the whole pass inert while every "stays quiet"
# assertion in that suite still passed green.  Nothing is unsafe about the
# permissive reading: with no engine loaded there is no `aws_ro` to call
# either.
_s3_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

# `_s3_note_evaluated ID` / `_s3_note_lost ID REASON` - the two halves of rule 1
# above.  Kept as functions so a call site can never record one without the
# other being available beside it.
_s3_note_evaluated() {
  _S3_EVALUATED[$1]=$(( ${_S3_EVALUATED[$1]:-0} + 1 ))
}

_s3_note_lost() {
  _S3_LOST[$1]=$(( ${_S3_LOST[$1]:-0} + 1 ))
  # FIRST reason wins rather than last: a run whose first ten buckets were
  # denied and whose eleventh was throttled should report the permission
  # problem, which is the actionable one and the one that explains the other
  # ten.  Last-wins would report whichever failure happened to come last.
  [[ -n ${_S3_LOST_REASON[$1]:-} ]] || _S3_LOST_REASON[$1]=$2
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_s3_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  # `mktemp -d`, never a name built from `$$` or a fixed string.  Every path
  # under $SCOURSH_SCRATCH is reached by standalone-engine callers through the
  # `${TMPDIR:-/tmp}` fallback, so a predictable name is one a local user can
  # pre-create as a symlink that this process then writes THROUGH - depositing
  # an account's API responses wherever someone else chose (CWE-377 via
  # CWE-59).  DAST-08 shipped the pid-derived spelling and had to correct it in
  # the same ticket; `lib/awscli.sh`'s own `_awscli_transport` already uses the
  # right idiom.  A TEMPLATE with no `-p` (tension 24: `-p` is a GNU spelling).
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-s3.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_S3_CHECK_IDS[@]+"${_S3_CHECK_IDS[@]}"}"; do
    _s3_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_s3_checks_deselected service=s3 account=$account - every CLOUD-S3-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no S3 API call was made and no bucket was examined."
    return 0
  fi

  # -------------------------------------------------------------------------
  # The one global call.
  # -------------------------------------------------------------------------
  local listf=$work/list-buckets.json rc=0
  aws_ro s3api list-buckets >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    run_record coverage_reduction "module=cloud reason=$reason service=s3 operation=list-buckets account=$account cell=${SCOURSH_CLOUD_CELL:-} - the account's bucket list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO S3 bucket was examined and none of the ${#_S3_CHECK_IDS[@]} CLOUD-S3-* checks ran."
    run_record coverage_gap "cloud s3: the bucket list for account $account could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no bucket's ACL, policy, encryption, public-access block, versioning or logging was tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds s3:ListAllMyBuckets."
    return 0
  fi
  # A truncated list is a SHORT list that is indistinguishable from a complete
  # one, which is exactly the §4.3 gap lib/awscli.sh's truncation detection
  # exists for.  The pass still examines the buckets it did get - reporting
  # nothing would throw away real findings - but the bound is declared.
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _S3_LIST_TRUNCATED=1
  fi

  # -------------------------------------------------------------------------
  # The buckets.
  # -------------------------------------------------------------------------
  local -a buckets=()
  local i=0 name=''
  s3_doc_load "$listf" || true
  while :; do
    s3_doc_has "$(s3_path Buckets "$i" Name)" || break
    s3_doc_get name "$(s3_path Buckets "$i" Name)"
    [[ -n $name ]] && buckets+=("$name")
    i=$(( i + 1 ))
  done
  _S3_BUCKETS_TOTAL=${#buckets[@]}

  local b
  for b in "${buckets[@]+"${buckets[@]}"}"; do
    _s3_examine_bucket "$b" "$work"
  done

  _s3_record_coverage "$account"
  return 0
}

# `_s3_examine_bucket BUCKET WORKDIR` - the seven per-bucket calls and the
# seven checks over them.  Never returns non-zero: a bucket that cannot be
# examined is an accounted-for reduction, not a reason to abandon the ones
# after it.
_s3_examine_bucket() {
  local b=$1 work=$2
  local safe=${b//[^A-Za-z0-9._-]/_}
  local rc=0 region='' reason=''

  # 1. The region, FIRST, because every later call is addressed to it and every
  #    finding cites it.  This one call carries no `--region` of its own: the
  #    pass is `global`, so `cloud_run_service` cleared the ambient region and
  #    the CLI resolves its own endpoint from the operator's environment.  A
  #    bucket whose region cannot be established is SKIPPED rather than
  #    reported against a guessed region: `loc_region` is a fingerprint
  #    component (tension 5), so a guess that a later fix corrects would make
  #    every one of that bucket's findings a new finding and leave the old ones
  #    permanently unresolvable.
  rc=0
  aws_ro s3api get-bucket-location --bucket "$b" >"$work/$safe.location.json" || rc=$?
  if (( rc != 0 )); then
    aws_ro_reduction_reason_set reason
    _S3_BUCKETS_NO_REGION=$(( _S3_BUCKETS_NO_REGION + 1 ))
    local cid
    for cid in "${_S3_CHECK_IDS[@]+"${_S3_CHECK_IDS[@]}"}"; do
      _s3_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=s3 operation=get-bucket-location bucket=$b - the bucket's region could not be established (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so it was not examined at all. A finding must cite the region the resource is really in, and a guessed region would change the finding's identity the moment it was corrected."
    return 0
  fi
  s3_doc_load "$work/$safe.location.json" || true
  s3_location_region_set region
  _S3_BUCKETS_EXAMINED=$(( _S3_BUCKETS_EXAMINED + 1 ))

  # Every remaining call is addressed to the bucket's OWN region.  S3 will
  # redirect a request sent to the wrong regional endpoint, but an opt-in
  # region does not answer at all from outside itself, so addressing the bucket
  # correctly is the difference between a real answer and an
  # `endpoint_unreachable` on precisely the buckets an estate is least likely
  # to be watching.
  _s3_check_acl "$b" "$region" "$work/$safe.acl.json"
  _s3_check_policy "$b" "$region" "$work/$safe.policy-status.json"
  _s3_check_bpa "$b" "$region" "$work/$safe.bpa.json"
  _s3_check_encryption "$b" "$region" "$work/$safe.encryption.json"
  _s3_check_versioning "$b" "$region" "$work/$safe.versioning.json"
  _s3_check_logging "$b" "$region" "$work/$safe.logging.json"
  return 0
}

# `_s3_call_lost BUCKET OPERATION IDS...` - shared tail for a per-bucket call that failed in a
# way that is a coverage loss rather than an answer.
_s3_call_lost() {
  local b=$1 op=$2
  shift 2
  local reason='' cid
  aws_ro_reduction_reason_set reason
  for cid in "$@"; do
    _s3_note_lost "$cid" "$reason"
  done
  run_record coverage_reduction "module=cloud reason=$reason service=s3 operation=$op bucket=$b checks=[$*] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this property of this bucket was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
  return 0
}

_s3_check_acl() {
  local b=$1 region=$2 f=$3
  local read_id=CLOUD-S3-PUBLIC_ACL_READ-01 write_id=CLOUD-S3-PUBLIC_ACL_WRITE-01
  _s3_selected "$read_id" || _s3_selected "$write_id" || return 0
  local rc=0
  aws_ro s3api get-bucket-acl --bucket "$b" --region "$region" >"$f" || rc=$?
  if (( rc != 0 )); then
    # `AccessControlListNotSupported` (a BucketOwnerEnforced bucket, where ACLs
    # are inert by design) classifies as `access_denied` and is reported as a
    # reduction like any other.  That is deliberately not special-cased into a
    # pass: it IS the safe configuration, but this pass did not observe the
    # ACL, and inventing "therefore no public ACL" from an error code is the
    # kind of confident inference this module's honesty rules forbid - the
    # Block Public Access check covers the same ground with a real observation.
    _s3_call_lost "$b" get-bucket-acl "$read_id" "$write_id"
    return 0
  fi
  s3_doc_load "$f" || true
  local grants=''
  s3_acl_public_grants_set grants

  local line class perm
  local reads='' writes=''
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    class=${line%% *}
    perm=${line#* }
    if s3_permission_is_write "$perm"; then
      writes+="${writes:+$'\n'}$class $perm"
    else
      reads+="${reads:+$'\n'}$class $perm"
    fi
  done <<<"$grants"

  # One finding per (bucket, grantee class) rather than per grant: a class
  # granted both READ and READ_ACP is one exposure an operator removes once,
  # and `loc_sub_key` carries the class, so two classes remain two
  # fingerprints while two permissions of one class do not.
  if _s3_selected "$read_id"; then
    _s3_note_evaluated "$read_id"
    _s3_emit_acl_class "$read_id" "$b" "$region" "$reads" 'read'
  fi
  if _s3_selected "$write_id"; then
    _s3_note_evaluated "$write_id"
    _s3_emit_acl_class "$write_id" "$b" "$region" "$writes" 'write or full-control'
  fi
  return 0
}

_s3_emit_acl_class() {
  local check_id=$1 b=$2 region=$3 lines=$4 what=$5
  [[ -n $lines ]] || return 0
  local class perms line
  local seen=''
  while IFS= read -r line; do
    [[ -n $line ]] || continue
    class=${line%% *}
    [[ $'\n'"$seen"$'\n' == *$'\n'"$class"$'\n'* ]] && continue
    seen+="${seen:+$'\n'}$class"
    perms=''
    local l2
    while IFS= read -r l2; do
      [[ $l2 == "$class "* ]] || continue
      perms+="${perms:+, }${l2#* }"
    done <<<"$lines"
    # Evidence is hard-capped at SCOURSH_EVIDENCE_MAX_BYTES (512) and the TAIL
    # is what gets cut, so the grantee class, the permissions and the bucket -
    # the three facts an operator acts on - lead, and the explanation follows.
    _s3_emit "$check_id" "$b" "$region" "$class" \
      "ACL grants $perms to $class on bucket $b ($region). The $class group is a public grantee: AllUsers is every principal on the internet including anonymous ones, and AuthenticatedUsers is every holder of any AWS credential in the partition, not only this account. Observed $what access via s3api get-bucket-acl."
  done <<<"$lines"
  return 0
}

_s3_check_policy() {
  local b=$1 region=$2 f=$3
  local id=CLOUD-S3-PUBLIC_POLICY-01
  _s3_selected "$id" || return 0
  local rc=0
  aws_ro s3api get-bucket-policy-status --bucket "$b" --region "$region" >"$f" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # `NoSuchBucketPolicy`: the bucket has no policy at all, so its policy is
      # not public.  A real answer, and the commonest one.
      _s3_note_evaluated "$id"
      return 0
    fi
    _s3_call_lost "$b" get-bucket-policy-status "$id"
    return 0
  fi
  s3_doc_load "$f" || true
  _s3_note_evaluated "$id"
  s3_policy_is_public || return 0
  _s3_emit "$id" "$b" "$region" '' \
    "AWS evaluates the bucket policy on $b ($region) as PUBLIC (get-bucket-policy-status reported IsPublic true). At least one statement grants a bucket or object action to a principal that is not constrained to this account or organisation. This is AWS's own policy evaluation, made with the evaluator that serves real requests, not a pattern match over the policy document."
  return 0
}

_s3_check_bpa() {
  local b=$1 region=$2 f=$3
  local id=CLOUD-S3-BLOCK_PUBLIC_ACCESS_OFF-01
  _s3_selected "$id" || return 0
  local rc=0 gaps=''
  aws_ro s3api get-public-access-block --bucket "$b" --region "$region" >"$f" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # `NoSuchPublicAccessBlockConfiguration`: no Block Public Access
      # configuration exists on this bucket, which is the finding rather than a
      # failure to look.  Reporting all four as absent is exactly right - none
      # of them is set.
      _s3_note_evaluated "$id"
      _s3_emit "$id" "$b" "$region" '' \
        "Bucket $b ($region) has NO Block Public Access configuration at all (get-public-access-block returned NoSuchPublicAccessBlockConfiguration), so none of BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy or RestrictPublicBuckets is in force at the bucket level. One future ACL or policy edit is then enough to expose it, and nothing will refuse the edit. An account-level Block Public Access setting, if one exists, still applies and is not visible to this check."
      return 0
    fi
    _s3_call_lost "$b" get-public-access-block "$id"
    return 0
  fi
  s3_doc_load "$f" || true
  _s3_note_evaluated "$id"
  s3_bpa_gaps_set gaps
  [[ -n $gaps ]] || return 0
  _s3_emit "$id" "$b" "$region" '' \
    "Block Public Access on bucket $b ($region) is incomplete: $gaps not enabled. The four settings are not interchangeable - BlockPublicAcls and IgnorePublicAcls neutralise public ACLs while BlockPublicPolicy rejects a new public bucket policy and RestrictPublicBuckets suppresses an existing one - so any one of them left off leaves a route open."
  return 0
}

_s3_check_encryption() {
  local b=$1 region=$2 f=$3
  local id=CLOUD-S3-NO_DEFAULT_ENCRYPTION-01
  _s3_selected "$id" || return 0
  # SC2034: `algo` is written by `s3_encryption_algorithm_set` through `printf -v`, so
  # the linter cannot see the assignment; it is read by that call's own return
  # status and by the evidence below.  (This comment deliberately does not
  # BEGIN with the linter's own name: a comment line starting with that word is
  # parsed as a DIRECTIVE, which AGENTS.md records as a standing trap and which
  # this block tripped on its first draft.)  The disable carries the reason
  # rather than leaving a future reader to re-derive it.
  # shellcheck disable=SC2034
  local rc=0 algo=''
  aws_ro s3api get-bucket-encryption --bucket "$b" --region "$region" >"$f" || rc=$?
  if (( rc != 0 )); then
    if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == not_found ]]; then
      # `ServerSideEncryptionConfigurationNotFoundError`: no default encryption
      # configuration.  The finding, not a failure to look.
      _s3_note_evaluated "$id"
      _s3_emit "$id" "$b" "$region" '' \
        "Bucket $b ($region) has no default server-side encryption configuration (get-bucket-encryption returned ServerSideEncryptionConfigurationNotFoundError), so an object is encrypted at rest only if the uploading client asked for it. Set a default of SSE-S3 (AES256) as the zero-cost baseline, or SSE-KMS where a separate, auditable key policy and CloudTrail key-usage events are required."
      return 0
    fi
    _s3_call_lost "$b" get-bucket-encryption "$id"
    return 0
  fi
  s3_doc_load "$f" || true
  _s3_note_evaluated "$id"
  s3_encryption_algorithm_set algo && return 0
  _s3_emit "$id" "$b" "$region" '' \
    "Bucket $b ($region) returned a server-side encryption configuration that names no algorithm, so no default encryption is actually in force. An object written here is encrypted at rest only if the uploading client asked for it."
  return 0
}

_s3_check_versioning() {
  local b=$1 region=$2 f=$3
  local id=CLOUD-S3-NO_VERSIONING-01
  _s3_selected "$id" || return 0
  local rc=0 status=''
  aws_ro s3api get-bucket-versioning --bucket "$b" --region "$region" >"$f" || rc=$?
  if (( rc != 0 )); then
    _s3_call_lost "$b" get-bucket-versioning "$id"
    return 0
  fi
  s3_doc_load "$f" || true
  _s3_note_evaluated "$id"
  s3_versioning_status_set status && return 0
  _s3_emit "$id" "$b" "$region" '' \
    "Versioning on bucket $b ($region) is $status. An overwrite or a delete is therefore unrecoverable, which makes accidental deletion, a compromised credential and ransomware-style encryption of the bucket's contents terminal rather than merely disruptive. Suspended is reported alongside never-enabled because objects written after suspension are as unrecoverable as they were before versioning existed."
  return 0
}

_s3_check_logging() {
  local b=$1 region=$2 f=$3
  local id=CLOUD-S3-NO_LOGGING-01
  _s3_selected "$id" || return 0
  # SC2034: `target` is written by `s3_logging_target_set` through `printf -v`, so
  # the linter cannot see the assignment; it is read by that call's own return
  # status and by the evidence below.  (This comment deliberately does not
  # BEGIN with the linter's own name: a comment line starting with that word is
  # parsed as a DIRECTIVE, which AGENTS.md records as a standing trap and which
  # this block tripped on its first draft.)  The disable carries the reason
  # rather than leaving a future reader to re-derive it.
  # shellcheck disable=SC2034
  local rc=0 target=''
  aws_ro s3api get-bucket-logging --bucket "$b" --region "$region" >"$f" || rc=$?
  if (( rc != 0 )); then
    _s3_call_lost "$b" get-bucket-logging "$id"
    return 0
  fi
  s3_doc_load "$f" || true
  _s3_note_evaluated "$id"
  s3_logging_target_set target && return 0
  _s3_emit "$id" "$b" "$region" '' \
    "Server access logging is not enabled on bucket $b ($region), so there is no record of who read or wrote which object. A later investigation into a suspected exposure has nothing to work from and cannot establish whether anything was accessed. Enable server access logging to a separate, restricted log bucket, or CloudTrail S3 data events where the record must be reliable and queryable."
  return 0
}

# `_s3_emit CHECK_ID BUCKET REGION SUB_KEY EVIDENCE` - thin wrapper over the
# engine's emitter, kept so a call site never has to remember the argument
# order twice over.
_s3_emit() {
  s3_emit_finding "$1" "$2" "$3" "$4" "$5"
}

# ---------------------------------------------------------------------------
# 3. The roll-up
# ---------------------------------------------------------------------------
# One `checks_run` line per check that ACTUALLY ANSWERED for at least one
# bucket, and one `coverage_reduction` per check that did not.  This is the
# accounting rule this file's header states as rule 1, and it is what
# `_cloud_record_coverage` reads to write the `<account>/global` coverage cell -
# so a check credited here that never ran would let tension 12 report a prior
# finding `fixed` on the strength of a call that was denied.
_s3_record_coverage() {
  local account=$1 id
  local ran=0 lost=0
  for id in "${_S3_CHECK_IDS[@]+"${_S3_CHECK_IDS[@]}"}"; do
    _s3_selected "$id" || continue
    if (( ${_S3_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      # A check that answered for SOME buckets and was denied for others is
      # covered AND incomplete.  Both facts are recorded: the `checks_run` line
      # above and this reduction, because reporting only the first overstates
      # the coverage and reporting only the second would suppress a cell the
      # run genuinely did visit.
      if (( ${_S3_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_S3_LOST_REASON[$id]} service=s3 check=$id account=$account buckets_answered=${_S3_EVALUATED[$id]} buckets_unanswered=${_S3_LOST[$id]} of ${_S3_BUCKETS_TOTAL} - this check ran, but ${_S3_LOST[$id]} bucket(s) did not answer, so it is covered for some of the account's buckets and not for others."
      fi
    else
      lost=$(( lost + 1 ))
      run_record coverage_reduction "module=cloud reason=${_S3_LOST_REASON[$id]:-no_bucket_examined} service=s3 check=$id account=$account buckets_total=${_S3_BUCKETS_TOTAL} buckets_examined=${_S3_BUCKETS_EXAMINED} - this check answered for NO bucket in the account and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every bucket is configured correctly."
    fi
  done

  if (( _S3_BUCKETS_TOTAL == 0 )); then
    # A genuinely empty account.  The checks above are still credited: the
    # bucket list was read successfully, so the run DID look and there was
    # nothing to look at - which is what lets a prior finding for a bucket that
    # has since been deleted be classified `fixed` rather than sitting at
    # `unknown` forever.  This is the one place "no findings" legitimately
    # means "nothing wrong", and it is recorded so a reader can tell it from
    # the many places it does not.
    run_record notes "module=cloud service=s3 account=$account buckets=0 - the account's bucket list was read successfully and contains no bucket, so every CLOUD-S3-* check is covered vacuously."
  fi

  if (( _S3_LIST_TRUNCATED )); then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=s3 operation=list-buckets account=$account buckets_seen=$_S3_BUCKETS_TOTAL - the bucket list came back INCOMPLETE (a continuation token was present, or the page ceiling was reached), so an unknown number of this account's buckets were never enumerated and were not examined by any CLOUD-S3-* check."
    run_record coverage_gap "cloud s3: the bucket list for account $account was truncated at $_S3_BUCKETS_TOTAL bucket(s), so an unknown number of buckets were never examined. A clean result for those buckets is the absence of a test, not the absence of a problem."
  fi

  if (( _S3_BUCKETS_NO_REGION > 0 )); then
    run_record coverage_gap "cloud s3: $_S3_BUCKETS_NO_REGION of $_S3_BUCKETS_TOTAL bucket(s) in account $account could not have their region established, so none of the seven checks was applied to them at all. A finding must cite the region a resource is really in; guessing one would change the finding's identity the moment the guess was corrected."
  fi

  if (( ran == 0 && _S3_BUCKETS_TOTAL > 0 )); then
    run_record coverage_gap "cloud s3: account $account has $_S3_BUCKETS_TOTAL bucket(s) and NOT ONE of the ${#_S3_CHECK_IDS[@]} CLOUD-S3-* checks answered for any of them, so no bucket's public access, encryption, versioning or logging posture was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_s3_run_service
