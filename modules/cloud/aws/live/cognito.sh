#!/usr/bin/env bash
# modules/cloud/aws/live/cognito.sh - the §8.3 Cognito read-only service pass
# (docs/DESIGN.md §8.3; docs/STEP6-CLOUD-PLAN.md CLOUD-20).
#
# THIS IS A SERVICE SCRIPT: modules/cloud/aws/engine.sh's `cloud_run_service`
# reaches it with a plain `source`, so it inherits the whole run context and
# anything it emits lands in this process's shard.  Per that function's own
# contract it carries NO sourced-once guard - `cognito` is a `regional` row in
# `_CLOUD_SERVICES`, so it is legitimately reached once per enabled region and
# a guard would silently make every region after the first a no-op, which is
# the failure that reads as a complete multi-region audit.  Its pure half -
# every classifier, the ARN builders and the emitter - is
# modules/cloud/aws/live/cognito_engine.sh, which does have a guard.
#
# WHY COGNITO IS A `regional` ROW, AND WHAT THAT MAKES SIMPLER THAN S3.  Both
# API namespaces are regional: a user pool created in eu-west-2 does not appear
# in `cognito-idp list-user-pools` in us-east-1, and the same holds for
# `cognito-identity list-identity-pools`.  So the pass runs once per enabled
# region, every resource it sees is in the region it is enumerating, and the
# finding's `loc_region` and its `cell` are the same value.  s3.sh's long note
# about the two deliberately differing does not apply here and its shape must
# not be copied: resolving a per-resource region would mean inventing a fact
# the API already settled.
#
# THREE API NAMESPACES, ONE SCRIPT, AND THE THIRD IS THE ONE WORTH FLAGGING.
# `cognito-idp` and `cognito-identity` are §8.3's own pairing.  `iam` is
# reached for exactly one purpose: reading the policies attached to an identity
# pool's UNAUTHENTICATED role, because §8.3's identity-pool bullet requires
# that role be inspected "for over-permissiveness" and that the result be "its
# own high-severity finding, not a note".  Those `iam` calls are made ONLY when
# a pool both allows unauthenticated identities and has such a role attached -
# there is nothing to inspect otherwise, and spending the calls anyway would
# multiply an estate's IAM API cost by its region count for no finding.
#
# NOTHING HERE PROBES.  §8.3's closing paragraph is explicit - "Prefer
# config-derived detection of user-enumeration and self-signup over live
# endpoint probing ... active probing creates real users and fires
# verification email/SMS" - and this pass calls no `SignUp`, no
# `ForgotPassword`, no `InitiateAuth` and no `GetCredentialsForIdentity`.
# Every answer is read out of a `describe-*`/`list-*`/`get-*` response.  The
# live user-enumeration probe is §7.4's, under `--allow-intrusive`, and is a
# different check id rather than a widening of one of these.
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
# indistinguishable "empty response".
#
# THE HONESTY ACCOUNTING IS THE DELIVERABLE, and this pass inherits s3.sh's
# three rules verbatim because they are the module's, not that service's:
#   1. `checks_run` NAMES WHAT SUCCEEDED.  A check id is recorded only if its
#      own API call actually answered for at least one resource.
#   2. AN `AccessDenied` IS A `coverage_reduction`, NEVER SILENCE.  So is a
#      throttle, an unreachable endpoint and a truncated list.
#      `aws_ro_outcome_is_coverage_loss` is the single predicate that separates
#      "we looked" from "we did not"; this file never re-derives it.
#   3. `not_found` IS AN ANSWER.  It matters less here than it did for S3 -
#      Cognito has no "absent configuration" error of its own - but an `iam`
#      role that has been deleted out from under an identity pool answers
#      `NoSuchEntity`, and that is a real fact about the pool (its
#      unauthenticated role does not exist, so nothing can assume it) rather
#      than a failure to look.
#
# ONE FURTHER RULE THIS SERVICE ADDS, BECAUSE ITS CALL COUNT IS THE FIRST IN
# STEP 6 THAT CAN RUN AWAY.  A user pool costs one describe plus one list plus
# one describe PER APP CLIENT, an identity pool costs two calls plus up to
# several IAM calls, and every one of those is multiplied by the region count.
# So every walk is BOUNDED, and reaching a bound is never silent: each cap has
# its own `coverage_reduction` naming what was not examined.  A silent cap is
# the same defect as a silent AccessDenied wearing a performance justification.
#
# shellcheck shell=bash
# shellcheck source=modules/cloud/aws/live/cognito_engine.sh
source "${BASH_SOURCE[0]%/*}/cognito_engine.sh"

# ---------------------------------------------------------------------------
# 1. Per-pass state
# ---------------------------------------------------------------------------
# `declare -g`, for the reason cognito_engine.sh's own note records: this file
# is sourced from INSIDE `cloud_run_service`, so a bare `declare` would make
# every one of these a local that dies with the pass.  They are RESET here
# rather than only declared, and that is load-bearing for a `regional` service
# in a way it was not for `s3`: this file is sourced once per region in ONE
# process, so a counter that was only declared would accumulate across regions
# and every roll-up after the first would describe the union of the regions
# visited so far while claiming to describe one.
declare -g _CG_POOLS_TOTAL=0
declare -g _CG_POOLS_EXAMINED=0
declare -g _CG_CLIENTS_TOTAL=0
declare -g _CG_CLIENTS_EXAMINED=0
declare -g _CG_IDPOOLS_TOTAL=0
declare -g _CG_IDPOOLS_EXAMINED=0
declare -g _CG_LIST_TRUNCATED=''
declare -g _CG_CAPPED=''
declare -gA _CG_EVALUATED=()
declare -gA _CG_LOST=()
declare -gA _CG_LOST_REASON=()

# The bounds.  Overridable from the environment for a test that wants to reach
# one cheaply, in the same documented-seam shape
# `SCOURSH_DAST_RECOMMENDED_HEADERS_FILE` uses - not a `config/scanner.conf`
# key, because §9.6.1's key set is frozen and a per-service cap is not a knob
# an operator has any reason to turn.
: "${SCOURSH_COGNITO_MAX_USER_POOLS:=200}"
: "${SCOURSH_COGNITO_MAX_CLIENTS_PER_POOL:=100}"
: "${SCOURSH_COGNITO_MAX_IDENTITY_POOLS:=200}"
: "${SCOURSH_COGNITO_MAX_ROLE_POLICIES:=25}"

# `list-user-pools` and `list-identity-pools` both REQUIRE `--max-results`, and
# both cap it at 60.  This is not a scoursh choice: the CLI refuses the call
# without it (`cli_usage`), so the page size is the API's own maximum and the
# `NextToken` on the response is what says the account has more.
declare -g _CG_PAGE_SIZE=60

# Every check id this pass can emit, in registry order.  Spelled once, here,
# and read by the selection gate, the `checks_run` roll-up and the
# not-evaluated accounting alike - three places that must agree about what
# "every Cognito check" means, and did not have to be kept in step by hand.
declare -ga _CG_CHECK_IDS=(
  CLOUD-COGNITO-WEAK_PASSWORD_POLICY-01
  CLOUD-COGNITO-TEMP_PASSWORD_VALIDITY-01
  CLOUD-COGNITO-MFA_OFF-01
  CLOUD-COGNITO-MFA_OPTIONAL-01
  CLOUD-COGNITO-ADVANCED_SECURITY_OFF-01
  CLOUD-COGNITO-SELF_REGISTRATION_OPEN-01
  CLOUD-COGNITO-RECOVERY_SMS_ONLY-01
  CLOUD-COGNITO-DELETION_PROTECTION_OFF-01
  CLOUD-COGNITO-SELF_SERVICE_SURFACE-01
  CLOUD-COGNITO-CLIENT_PLAINTEXT_AUTH-01
  CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01
  CLOUD-COGNITO-CLIENT_INSECURE_CALLBACK-01
  CLOUD-COGNITO-CLIENT_WILDCARD_CALLBACK-01
  CLOUD-COGNITO-CLIENT_TOKEN_LIFETIME-01
  CLOUD-COGNITO-CLIENT_TOKEN_REVOCATION_OFF-01
  CLOUD-COGNITO-CLIENT_WRITABLE_ATTRIBUTE-01
  CLOUD-COGNITO-CLIENT_USER_EXISTENCE_ERRORS-01
  CLOUD-COGNITO-CLIENT_PUBLIC_CONFIDENTIAL_FLOW-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01
  CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01
  CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01
)

# The subsets each list call gates.  A denied `list-user-pools` loses every
# user-pool and app-client check and NOT the identity-pool ones, which are
# reached through a separate list call in a separate API namespace - reporting
# all twenty-four lost would overstate the damage and, worse, would hide the
# fact that the identity-pool half of the pass ran fine.
declare -ga _CG_POOL_CHECK_IDS=(
  CLOUD-COGNITO-WEAK_PASSWORD_POLICY-01
  CLOUD-COGNITO-TEMP_PASSWORD_VALIDITY-01
  CLOUD-COGNITO-MFA_OFF-01
  CLOUD-COGNITO-MFA_OPTIONAL-01
  CLOUD-COGNITO-ADVANCED_SECURITY_OFF-01
  CLOUD-COGNITO-SELF_REGISTRATION_OPEN-01
  CLOUD-COGNITO-RECOVERY_SMS_ONLY-01
  CLOUD-COGNITO-DELETION_PROTECTION_OFF-01
  CLOUD-COGNITO-SELF_SERVICE_SURFACE-01
)

declare -ga _CG_CLIENT_CHECK_IDS=(
  CLOUD-COGNITO-CLIENT_PLAINTEXT_AUTH-01
  CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01
  CLOUD-COGNITO-CLIENT_INSECURE_CALLBACK-01
  CLOUD-COGNITO-CLIENT_WILDCARD_CALLBACK-01
  CLOUD-COGNITO-CLIENT_TOKEN_LIFETIME-01
  CLOUD-COGNITO-CLIENT_TOKEN_REVOCATION_OFF-01
  CLOUD-COGNITO-CLIENT_WRITABLE_ATTRIBUTE-01
  CLOUD-COGNITO-CLIENT_USER_EXISTENCE_ERRORS-01
  CLOUD-COGNITO-CLIENT_PUBLIC_CONFIDENTIAL_FLOW-01
)

declare -ga _CG_IDPOOL_CHECK_IDS=(
  CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01
  CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01
  CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01
  CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01
)

# `_cg_selected ID` - tension 15's per-check filter, through the module
# engine's own `cloud_check_selected`.
#
# THE `declare -F` GUARD IS PERMISSIVE WHEN THE FUNCTION IS ABSENT, and
# inverting that is the trap modules/dast/engine.sh's own `dast_check_selected`
# header records at length and s3.sh's own `_s3_selected` repeats: a
# direct-engine test suite sources a service script with no module engine in
# the process, so a fail-CLOSED default - or an unguarded call, which is exit
# 127 and therefore "deselected" - would make the whole pass inert while every
# "stays quiet" assertion in that suite still passed green.  Nothing is unsafe
# about the permissive reading: with no engine loaded there is no `aws_ro` to
# call either.
_cg_selected() {
  declare -F cloud_check_selected >/dev/null 2>&1 || return 0
  cloud_check_selected "$1"
}

# `_cg_any_selected IDS...` - true when at least one of IDS survived the filter.
_cg_any_selected() {
  local id
  for id in "$@"; do
    _cg_selected "$id" && return 0
  done
  return 1
}

# `_cg_note_evaluated ID` / `_cg_note_lost ID REASON` - the two halves of rule
# 1 above.  Kept as functions so a call site can never record one without the
# other being available beside it.
_cg_note_evaluated() {
  _CG_EVALUATED[$1]=$(( ${_CG_EVALUATED[$1]:-0} + 1 ))
}

_cg_note_lost() {
  _CG_LOST[$1]=$(( ${_CG_LOST[$1]:-0} + 1 ))
  # FIRST reason wins rather than last, for s3.sh's own reason: a run whose
  # first ten pools were denied and whose eleventh was throttled should report
  # the permission problem, which is the actionable one and the one that
  # explains the other ten.
  [[ -n ${_CG_LOST_REASON[$1]:-} ]] || _CG_LOST_REASON[$1]=$2
}

# `_cg_call_lost OPERATION RESOURCE IDS...` - shared tail for a call that
# failed in a way that is a coverage loss rather than an answer.
_cg_call_lost() {
  local op=$1 res=$2
  shift 2
  local reason='' cid
  aws_ro_reduction_reason_set reason
  for cid in "$@"; do
    _cg_note_lost "$cid" "$reason"
  done
  run_record coverage_reduction "module=cloud reason=$reason service=cognito operation=$op resource=$res region=${SCOURSH_CLOUD_REGION:-} checks=[$*] - the call did not answer (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so this property of this resource was NOT tested. Its absence from the findings is not evidence that it is configured correctly."
  return 0
}

# `_cg_emit CHECK_ID ARN SUB_KEY EVIDENCE` - thin wrapper over the engine's
# emitter, kept so a call site never has to remember the argument order twice
# over.  It also applies the SELECTION gate one last time, so a check id can
# never be emitted by a code path that forgot to ask.
_cg_emit() {
  _cg_selected "$1" || return 0
  cognito_emit_finding "$1" "$2" "$3" "$4"
}

# ---------------------------------------------------------------------------
# 2. The pass
# ---------------------------------------------------------------------------
_cg_run_service() {
  local account=${SCOURSH_CLOUD_ACCOUNT_ID:-}
  local region=${SCOURSH_CLOUD_REGION:-}
  local partition
  partition=$(cognito_partition_of "${SCOURSH_AWS_CALLER_ARN:-}")

  # `mktemp -d`, never a name built from `$$` or a fixed string.  Every path
  # under $SCOURSH_SCRATCH is reached by standalone-engine callers through the
  # `${TMPDIR:-/tmp}` fallback, so a predictable name is one a local user can
  # pre-create as a symlink that this process then writes THROUGH - depositing
  # an account's API responses wherever someone else chose (CWE-377 via
  # CWE-59).  A TEMPLATE with no `-p` (tension 24: `-p` is a GNU spelling).
  local work
  work=$(mktemp -d "${SCOURSH_SCRATCH:-${TMPDIR:-/tmp}}/cloud-cognito.XXXXXX")
  chmod 700 "$work" 2>/dev/null || true

  local id selected=0
  for id in "${_CG_CHECK_IDS[@]+"${_CG_CHECK_IDS[@]}"}"; do
    _cg_selected "$id" && selected=$(( selected + 1 ))
  done
  if (( selected == 0 )); then
    run_record coverage_reduction "module=cloud reason=all_cognito_checks_deselected service=cognito account=$account region=$region - every CLOUD-COGNITO-* check id was removed by this run's check-selection filters (--profile-scan / --intensity / --allow-intrusive), so no Cognito API call was made and no user pool, app client or identity pool was examined."
    return 0
  fi

  _cg_walk_user_pools "$account" "$region" "$partition" "$work"
  _cg_walk_identity_pools "$account" "$region" "$partition" "$work"
  _cg_record_coverage "$account" "$region"
  return 0
}

# ---------------------------------------------------------------------------
# 3. User pools and their app clients
# ---------------------------------------------------------------------------
_cg_walk_user_pools() {
  local account=$1 region=$2 partition=$3 work=$4
  _cg_any_selected "${_CG_POOL_CHECK_IDS[@]}" "${_CG_CLIENT_CHECK_IDS[@]}" || return 0

  local listf=$work/list-user-pools.json rc=0
  aws_ro cognito-idp list-user-pools --max-results "$_CG_PAGE_SIZE" >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    local cid
    for cid in "${_CG_POOL_CHECK_IDS[@]}" "${_CG_CLIENT_CHECK_IDS[@]}"; do
      _cg_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=cognito operation=list-user-pools account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's user-pool list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO user pool and NO app client in $region was examined. The identity-pool half of this pass is unaffected and is reported separately."
    run_record coverage_gap "cloud cognito: the user-pool list for account $account in $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so no pool's password policy, MFA, advanced security, self-registration or recovery configuration was tested, and no app client's authentication flows, OAuth settings, callback URLs, token lifetimes or writable attributes were tested. A clean result here is the absence of a test, not the absence of a problem - confirm the scanning role holds cognito-idp:ListUserPools and cognito-idp:DescribeUserPool."
    return 0
  fi
  # A truncated list is a SHORT list that is indistinguishable from a complete
  # one.  The pass still examines the pools it did get - reporting nothing
  # would throw away real findings - but the bound is declared.
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _CG_LIST_TRUNCATED+="${_CG_LIST_TRUNCATED:+ }list-user-pools"
  fi

  local -a pools=() names=()
  local i=0 pid='' pname=''
  cognito_doc_load "$listf" || true
  while :; do
    cognito_doc_has "$(cognito_path UserPools "$i" Id)" || break
    cognito_doc_get pid "$(cognito_path UserPools "$i" Id)"
    # `|| pname=''` because the name is OPTIONAL and `cognito_doc_get`
    # returns 1 for an absent path.  Under the `set -Eeuo pipefail` a service
    # script inherits, an unguarded call that returns 1 as a plain statement
    # aborts the whole run on the first resource that happens to have no
    # name - a crash on ordinary data.  The id above is pre-guarded by
    # `cognito_doc_has` and needs no such tail.
    cognito_doc_get pname "$(cognito_path UserPools "$i" Name)" || pname=''
    [[ -n $pid ]] && { pools+=("$pid"); names+=("$pname"); }
    i=$(( i + 1 ))
  done
  _CG_POOLS_TOTAL=${#pools[@]}

  local n=0
  for (( n = 0; n < ${#pools[@]}; n++ )); do
    if (( n >= SCOURSH_COGNITO_MAX_USER_POOLS )); then
      _CG_CAPPED+="${_CG_CAPPED:+ }user_pools"
      run_record coverage_reduction "module=cloud reason=cognito_user_pool_cap service=cognito account=$account region=$region examined=$n total=$_CG_POOLS_TOTAL cap=$SCOURSH_COGNITO_MAX_USER_POOLS - the per-region user-pool ceiling was reached, so $(( _CG_POOLS_TOTAL - n )) pool(s) in this region were NOT examined by any CLOUD-COGNITO-* check. A clean result for those pools is the absence of a test."
      break
    fi
    _cg_examine_user_pool "${pools[n]}" "${names[n]}" "$account" "$region" "$partition" "$work"
  done
  return 0
}

# `_cg_examine_user_pool POOL_ID POOL_NAME ACCOUNT REGION PARTITION WORKDIR` -
# the nine user-pool checks plus the walk over the pool's app clients.  Never
# returns non-zero: a pool that cannot be examined is an accounted-for
# reduction, not a reason to abandon the ones after it.
_cg_examine_user_pool() {
  local pid=$1 pname=$2 account=$3 region=$4 partition=$5 work=$6
  local safe=${pid//[^A-Za-z0-9._-]/_}
  local f=$work/pool.$safe.json rc=0 arn=''

  _cg_any_selected "${_CG_POOL_CHECK_IDS[@]}" "${_CG_CLIENT_CHECK_IDS[@]}" || return 0

  rc=0
  aws_ro cognito-idp describe-user-pool --user-pool-id "$pid" >"$f" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost describe-user-pool "$pid" "${_CG_POOL_CHECK_IDS[@]}"
    # The app clients are reached through a DIFFERENT call and are still
    # examined: a describe that was denied says nothing about whether
    # `list-user-pool-clients` will be, and abandoning the clients here would
    # turn one permission gap into nine more.  The client walk builds its own
    # ARN from the pool id, which this pass already has.
    _cg_walk_clients "$pid" "$pname" "$account" "$region" "$partition" "$work" \
      "$(cognito_user_pool_arn "$partition" "$region" "$account" "$pid")"
    return 0
  fi
  cognito_doc_load "$f" || true
  _CG_POOLS_EXAMINED=$(( _CG_POOLS_EXAMINED + 1 ))

  # THE API'S OWN ARN WINS OVER THE CONSTRUCTED ONE.  `loc_resource_key` is a
  # fingerprint component (tension 5), so a constructed ARN that ever disagreed
  # with the real one by a byte would give the same pool two identities across
  # the day the disagreement was noticed and fixed - and every finding filed
  # under the old spelling would then be permanently unresolvable.
  cognito_doc_get arn "$(cognito_path "$COGNITO_POOL_ROOT" Arn)" || arn=''
  [[ -n $arn ]] || arn=$(cognito_user_pool_arn "$partition" "$region" "$account" "$pid")

  local label="user pool $pid${pname:+ ($pname)}"

  _cg_check_password_policy "$arn" "$label"
  _cg_check_temp_password "$arn" "$label"
  _cg_check_mfa "$arn" "$label"
  _cg_check_advanced_security "$arn" "$label"
  _cg_check_self_registration "$arn" "$label"
  _cg_check_recovery "$arn" "$label"
  _cg_check_deletion_protection "$arn" "$label"
  _cg_check_self_service_surface "$arn" "$label"

  _cg_walk_clients "$pid" "$pname" "$account" "$region" "$partition" "$work" "$arn"
  return 0
}

_cg_check_password_policy() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-WEAK_PASSWORD_POLICY-01
  _cg_selected "$id" || return 0
  local weak=''
  if ! cognito_pool_password_weaknesses_set weak; then
    # No `Policies.PasswordPolicy` object at all.  Cognito applies its own
    # default (8 characters, all four classes) to such a pool, so this is a
    # real answer meaning "at the default" rather than a failure to look - the
    # check is covered and stays quiet.  Listing five weaknesses for it would
    # be five false positives on the safest possible configuration.
    _cg_note_evaluated "$id"
    return 0
  fi
  _cg_note_evaluated "$id"
  [[ -n $weak ]] || return 0
  # Evidence is hard-capped at SCOURSH_EVIDENCE_MAX_BYTES (512) and the TAIL is
  # what gets cut, so the weaknesses and the pool - the facts an operator acts
  # on - lead, and the explanation follows.
  _cg_emit "$id" "$arn" '' \
    "Password policy on $label is weak: $weak. Cognito's own default for a pool that configures no policy is an 8-character minimum with uppercase, lowercase, numbers and symbols all required, so a pool reported here has been explicitly loosened below that default rather than merely left unconfigured. Read from Policies.PasswordPolicy in the describe-user-pool response."
  return 0
}

_cg_check_temp_password() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-TEMP_PASSWORD_VALIDITY-01
  _cg_selected "$id" || return 0
  local days=''
  _cg_note_evaluated "$id"
  cognito_pool_temp_password_days_set days || return 0
  _cg_emit "$id" "$arn" '' \
    "Temporary passwords on $label stay valid for $days days, against Cognito's own default of 7. An administratively-created password is delivered over email or SMS, so for the whole of that window a working credential for the account is sitting in a mailbox or a message log - neither of which is encrypted end to end nor under the operator's control. Read from Policies.PasswordPolicy.TemporaryPasswordValidityDays."
  return 0
}

_cg_check_mfa() {
  local arn=$1 label=$2
  local off_id=CLOUD-COGNITO-MFA_OFF-01 opt_id=CLOUD-COGNITO-MFA_OPTIONAL-01
  _cg_any_selected "$off_id" "$opt_id" || return 0
  local mode=''
  cognito_pool_mfa_set mode && {
    # `ON`: both checks looked and both are satisfied.  Crediting BOTH is what
    # is right here - a run that saw an MFA-required pool has genuinely covered
    # the OPTIONAL question too, since the answer to "is it optional" is no.
    _cg_selected "$off_id" && _cg_note_evaluated "$off_id"
    _cg_selected "$opt_id" && _cg_note_evaluated "$opt_id"
    return 0
  }
  _cg_selected "$off_id" && _cg_note_evaluated "$off_id"
  _cg_selected "$opt_id" && _cg_note_evaluated "$opt_id"
  if [[ $mode == OPTIONAL ]]; then
    _cg_emit "$opt_id" "$arn" '' \
      "MFA on $label is OPTIONAL, so whether any given account has a second factor is that user's decision. An attacker holding a valid password does not need to defeat the second factor - they need only find an account that never enrolled one, and on an OPTIONAL pool most accounts have not. Reported separately from, and more mildly than, MFA being off entirely, because the mechanism is configured and some users are protected by it. Read from MfaConfiguration."
    return 0
  fi
  _cg_emit "$off_id" "$arn" '' \
    "MFA on $label is OFF, so a password is the only thing standing between an attacker and any account in this pool. Credential stuffing against a pool with no second factor succeeds for every reused password in any breach corpus. Read from MfaConfiguration in the describe-user-pool response; note that MfaConfiguration is absent rather than OFF on some responses, and this check reads an absent value as OFF because a pool that has never had MFA configured does not have it."
  return 0
}

_cg_check_advanced_security() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-ADVANCED_SECURITY_OFF-01
  _cg_selected "$id" || return 0
  local mode=''
  _cg_note_evaluated "$id"
  cognito_pool_advanced_security_set mode && return 0
  local detail
  if [[ $mode == AUDIT ]]; then
    detail="is AUDIT, not ENFORCED. In AUDIT mode Cognito computes a risk score for every sign-in and publishes it, and then takes no action on it - so a sign-in presenting a password from a known-compromised credential list succeeds exactly as it would with the feature off"
  else
    detail="is OFF. Neither compromised-credential detection nor adaptive authentication is running, so Cognito accepts a password it knows to be in a breach corpus and does not challenge a sign-in from an unfamiliar device or location"
  fi
  _cg_emit "$id" "$arn" '' \
    "Advanced security mode on $label $detail. Read from UserPoolAddOns.AdvancedSecurityMode."
  return 0
}

_cg_check_self_registration() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-SELF_REGISTRATION_OPEN-01
  _cg_selected "$id" || return 0
  _cg_note_evaluated "$id"
  cognito_pool_self_registration_open || return 0
  _cg_emit "$id" "$arn" '' \
    "Self-registration is open on $label: AdminCreateUserConfig.AllowAdminCreateUserOnly is not true, so anyone holding an app client id - a public value that ships in the application's own JavaScript or mobile binary - can create an account. Reported for review rather than as a defect: for a consumer-facing application this is the point of the pool, and for an internal or B2B pool it means every downstream decision that treats a signed-in user as a known user is wrong. Derived from the pool's configuration; no SignUp call was made."
  return 0
}

_cg_check_recovery() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-RECOVERY_SMS_ONLY-01
  _cg_selected "$id" || return 0
  local mechs=''
  _cg_note_evaluated "$id"
  cognito_pool_recovery_set mechs || return 0
  _cg_emit "$id" "$arn" '' \
    "Account recovery on $label prefers a phone/SMS channel: $mechs. Recovery is an authentication bypass by design - it hands whoever controls the channel a way into the account without the password - and a phone number is not under the account holder's sole control, since a SIM swap against the carrier, a ported number or an SS7 interception all deliver the code to an attacker without touching the user's device. Reported on the HIGHEST-PRIORITY mechanism, so a pool offering email first and phone as a fallback is not flagged."
  return 0
}

_cg_check_deletion_protection() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-DELETION_PROTECTION_OFF-01
  _cg_selected "$id" || return 0
  _cg_note_evaluated "$id"
  cognito_pool_deletion_protection_off || return 0
  _cg_emit "$id" "$arn" '' \
    "Deletion protection on $label is not ACTIVE, so one DeleteUserPool call destroys every account, password and attribute in the pool. Cognito offers no backup or export of a user pool's directory, so the loss is unrecoverable rather than merely disruptive - unlike almost every other AWS resource, there is nothing to restore from. Read from DeletionProtection, where an absent value is INACTIVE."
  return 0
}

_cg_check_self_service_surface() {
  local arn=$1 label=$2
  local id=CLOUD-COGNITO-SELF_SERVICE_SURFACE-01
  _cg_selected "$id" || return 0
  local surface=''
  _cg_note_evaluated "$id"
  cognito_pool_self_service_surface_set surface || return 0
  _cg_emit "$id" "$arn" '' \
    "Unauthenticated self-service operations exposed by $label: $surface. Each is reachable by anyone holding an app client id, which is a public value shipped in the application's own code, so each is an internet-facing endpoint. This is an inventory rather than a defect - every operation named is a legitimate feature a great many applications intend to expose - and it is DERIVED from the pool's own configuration: scoursh sends no SignUp and no ForgotPassword, because doing so creates real accounts and fires real verification email and SMS."
  return 0
}

# ---------------------------------------------------------------------------
# 4. App clients
# ---------------------------------------------------------------------------
_cg_walk_clients() {
  local pid=$1 pname=$2 account=$3 region=$4 partition=$5 work=$6 pool_arn=$7
  _cg_any_selected "${_CG_CLIENT_CHECK_IDS[@]}" || return 0

  local safe=${pid//[^A-Za-z0-9._-]/_}
  local listf=$work/clients.$safe.json rc=0
  aws_ro cognito-idp list-user-pool-clients --user-pool-id "$pid" --max-results "$_CG_PAGE_SIZE" >"$listf" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost list-user-pool-clients "$pid" "${_CG_CLIENT_CHECK_IDS[@]}"
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _CG_LIST_TRUNCATED+="${_CG_LIST_TRUNCATED:+ }list-user-pool-clients"
  fi

  local -a clients=() cnames=()
  local i=0 cid='' cname=''
  cognito_doc_load "$listf" || true
  while :; do
    cognito_doc_has "$(cognito_path UserPoolClients "$i" ClientId)" || break
    cognito_doc_get cid "$(cognito_path UserPoolClients "$i" ClientId)"
    cognito_doc_get cname "$(cognito_path UserPoolClients "$i" ClientName)" || cname=''
    [[ -n $cid ]] && { clients+=("$cid"); cnames+=("$cname"); }
    i=$(( i + 1 ))
  done
  _CG_CLIENTS_TOTAL=$(( _CG_CLIENTS_TOTAL + ${#clients[@]} ))

  local n=0
  for (( n = 0; n < ${#clients[@]}; n++ )); do
    if (( n >= SCOURSH_COGNITO_MAX_CLIENTS_PER_POOL )); then
      _CG_CAPPED+="${_CG_CAPPED:+ }app_clients"
      run_record coverage_reduction "module=cloud reason=cognito_app_client_cap service=cognito user_pool=$pid region=$region examined=$n total=${#clients[@]} cap=$SCOURSH_COGNITO_MAX_CLIENTS_PER_POOL - the per-pool app-client ceiling was reached, so $(( ${#clients[@]} - n )) client(s) of this pool were NOT examined by any CLOUD-COGNITO-CLIENT_* check."
      break
    fi
    _cg_examine_client "$pid" "$pname" "${clients[n]}" "${cnames[n]}" "$pool_arn" "$work"
  done
  return 0
}

# `_cg_examine_client POOL_ID POOL_NAME CLIENT_ID CLIENT_NAME POOL_ARN WORKDIR`
#
# THE FINDING'S RESOURCE IS THE USER POOL'S ARN AND THE CLIENT ID RIDES IN
# `loc_sub_key`, AND THAT IS NOT A SHORTCUT.  AWS defines no ARN for a Cognito
# app client - the resource is addressed by `(user pool id, client id)`
# everywhere in the API and in every IAM policy - so there is no ARN to cite.
# Inventing one (`.../userpool/<pool>/client/<id>`, the shape it would
# plausibly take) would put a string in `loc_resource_key` that names nothing
# an operator can look up, paste into a policy, or search a console for; and
# `loc_resource_key` is a fingerprint component (tension 5), so the day someone
# noticed and removed the invention, every app-client finding in every stored
# baseline would change identity at once.  Citing the pool's real ARN with the
# client id in `sub_key` keeps every client a distinct fingerprint (which is
# what the profile's fourth component is for) while every string in the finding
# is one AWS actually publishes.
_cg_examine_client() {
  local pid=$1 pname=$2 cid=$3 cname=$4 pool_arn=$5 work=$6
  local safe=${pid//[^A-Za-z0-9._-]/_}.${cid//[^A-Za-z0-9._-]/_}
  local f=$work/client.$safe.json rc=0

  aws_ro cognito-idp describe-user-pool-client --user-pool-id "$pid" --client-id "$cid" >"$f" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost describe-user-pool-client "$pid/$cid" "${_CG_CLIENT_CHECK_IDS[@]}"
    return 0
  fi
  cognito_doc_load "$f" || true
  _CG_CLIENTS_EXAMINED=$(( _CG_CLIENTS_EXAMINED + 1 ))

  local label="app client $cid${cname:+ ($cname)} of user pool $pid${pname:+ ($pname)}"

  _cg_check_client_plaintext_auth "$pool_arn" "$cid" "$label"
  _cg_check_client_implicit_oauth "$pool_arn" "$cid" "$label"
  _cg_check_client_callbacks "$pool_arn" "$cid" "$label"
  _cg_check_client_token_lifetime "$pool_arn" "$cid" "$label"
  _cg_check_client_revocation "$pool_arn" "$cid" "$label"
  _cg_check_client_writable "$pool_arn" "$cid" "$label"
  _cg_check_client_existence_errors "$pool_arn" "$cid" "$label"
  _cg_check_client_public_confidential "$pool_arn" "$cid" "$label"
  return 0
}

_cg_check_client_plaintext_auth() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_PLAINTEXT_AUTH-01
  _cg_selected "$id" || return 0
  local flows=''
  _cg_note_evaluated "$id"
  cognito_client_plaintext_flows_set flows || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label permits non-SRP password flows: ${flows//$'\n'/, }. Under these the user's password is sent to Cognito as a request parameter rather than proved through the SRP exchange, so it is present in cleartext wherever the request is handled at the endpoints - an application log that records request bodies, an APM or error-reporting agent that captures parameters, a proxy or WAF doing TLS termination and logging. ALLOW_USER_SRP_AUTH removes the whole class."
  return 0
}

_cg_check_client_implicit_oauth() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_IMPLICIT_OAUTH-01
  _cg_selected "$id" || return 0
  _cg_note_evaluated "$id"
  cognito_client_implicit_oauth || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label permits the implicit OAuth grant. Cognito returns the access and ID tokens in the URL FRAGMENT of the redirect, so the tokens land in the browser address bar, in session history, in any referrer a later navigation sends, and in whatever the browser or an extension records - none of which a bearer token can be revoked from. The authorization code grant with PKCE returns a single-use code instead. Read from AllowedOAuthFlows, and only where AllowedOAuthFlowsUserPoolClient is true, so a stale flow on a client whose OAuth surface is switched off is not reported."
  return 0
}

# The two callback checks share one function because they read the SAME two
# URL lists and a client with both problems should pay for one describe call,
# not two.  They remain two check ids for the reason the registry records:
# severity varies with which shape was seen, and `severity` is a per-record
# registry field the suites assert the script and the registry agree on.
_cg_check_client_callbacks() {
  local arn=$1 cid=$2 label=$3
  local insecure_id=CLOUD-COGNITO-CLIENT_INSECURE_CALLBACK-01
  local wildcard_id=CLOUD-COGNITO-CLIENT_WILDCARD_CALLBACK-01
  local urls=''

  if _cg_selected "$insecure_id"; then
    _cg_note_evaluated "$insecure_id"
    if cognito_client_insecure_urls_set urls; then
      _cg_emit "$insecure_id" "$arn" "$cid" \
        "$label has plaintext http:// redirect destinations: ${urls//$'\n'/, }. The callback URL is where Cognito delivers an authorization code, or with the implicit grant the tokens themselves, so a plaintext destination means that delivery crosses the network unprotected. Loopback URLs (http://localhost, http://127.0.0.1) are deliberately NOT reported: RFC 8252 section 7.3 endorses them for native applications because the redirect never leaves the user's own machine."
    fi
  fi

  if _cg_selected "$wildcard_id"; then
    _cg_note_evaluated "$wildcard_id"
    urls=''
    if cognito_client_wildcard_urls_set urls; then
      _cg_emit "$wildcard_id" "$arn" "$cid" \
        "$label has wildcarded or hostless redirect destinations: ${urls//$'\n'/, }. The redirect URI allow-list is the only thing between an authorization flow and an attacker-chosen destination: a wildcard host admits every subdomain, including one obtained through a dangling DNS record, and a wildcard path admits any handler on the host. An attacker who can name the redirect can have a victim complete a flow and receive the code or token themselves - account takeover leaving no trace in the application."
    fi
  fi
  return 0
}

_cg_check_client_token_lifetime() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_TOKEN_LIFETIME-01
  _cg_selected "$id" || return 0
  local long=''
  _cg_note_evaluated "$id"
  cognito_client_long_tokens_set long || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label configures excessive token lifetimes (kind, configured seconds, threshold): ${long//$'\n'/; }. A Cognito access or ID token is a bearer JWT that Cognito cannot invalidate before it expires - there is no revocation list and no introspection endpoint - so the lifetime is a hard floor on how long a stolen token keeps working after the theft is found, the password is changed or the account is disabled. An unconfigured validity is NOT reported: Cognito's own defaults (1 hour, 1 hour, 30 days) are inside every threshold here."
  return 0
}

_cg_check_client_revocation() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_TOKEN_REVOCATION_OFF-01
  _cg_selected "$id" || return 0
  _cg_note_evaluated "$id"
  cognito_client_revocation_off || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label has token revocation disabled, so there is no way to end a session before its tokens expire: the RevokeToken API refuses to act for a client that has it off, and a refresh token taken from a device, a browser profile or a log keeps minting fresh access tokens for its whole validity window. Password change, account disable and user deletion do not stop it. Read from EnableTokenRevocation, where an absent value is off - which is the state of every client created before the feature shipped."
  return 0
}

_cg_check_client_writable() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_WRITABLE_ATTRIBUTE-01
  _cg_selected "$id" || return 0
  local attrs=''
  _cg_note_evaluated "$id"
  cognito_client_sensitive_writes_set attrs || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label may WRITE security-relevant user attributes: ${attrs//$'\n'/, }. An attribute the client may write is one the END USER may write, because the client is their own browser or mobile application, so a writable email_verified or phone_number_verified lets any account assert it has verified an address it does not own, and a writable privilege attribute lets it assert its own role or entitlement. Wherever a Lambda trigger, an API Gateway authorizer or a downstream service reads that claim, this is a direct privilege escalation. Read from WriteAttributes."
  return 0
}

_cg_check_client_existence_errors() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_USER_EXISTENCE_ERRORS-01
  _cg_selected "$id" || return 0
  _cg_note_evaluated "$id"
  cognito_client_user_existence_errors_off || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label does not have PreventUserExistenceErrors ENABLED, so Cognito answers UserNotFoundException for an unknown username and NotAuthorizedException for a known one with a wrong password. Anyone holding the app client id - a public value shipped in the application's own JavaScript or mobile binary - can tell the two apart one request at a time and enumerate the pool's whole membership, with no credential. This is derived from the client's configuration: scoursh sent no authentication request to establish it."
  return 0
}

_cg_check_client_public_confidential() {
  local arn=$1 cid=$2 label=$3
  local id=CLOUD-COGNITO-CLIENT_PUBLIC_CONFIDENTIAL_FLOW-01
  _cg_selected "$id" || return 0
  local flows=''
  _cg_note_evaluated "$id"
  cognito_client_confidential_only_flows_set flows || return 0
  _cg_emit "$id" "$arn" "$cid" \
    "$label has NO client secret and yet permits flows that assume one: ${flows//$'\n'/, }. A client with no secret is a public client - a single-page application or a mobile binary whose code an attacker holds - so anything it may do, anyone may do. client_credentials authenticates the CLIENT ITSELF with no user in the exchange at all, and the ADMIN_* flows are meant to be called server-to-server by a trusted backend. Derived from the ABSENCE of ClientSecret in the describe-user-pool-client response, which is how the API reports a public client."
  return 0
}

# ---------------------------------------------------------------------------
# 5. Identity pools
# ---------------------------------------------------------------------------
_cg_walk_identity_pools() {
  local account=$1 region=$2 partition=$3 work=$4
  _cg_any_selected "${_CG_IDPOOL_CHECK_IDS[@]}" || return 0

  local listf=$work/list-identity-pools.json rc=0
  aws_ro cognito-identity list-identity-pools --max-results "$_CG_PAGE_SIZE" >"$listf" || rc=$?
  if (( rc != 0 )); then
    local reason=''
    aws_ro_reduction_reason_set reason
    local cid
    for cid in "${_CG_IDPOOL_CHECK_IDS[@]}"; do
      _cg_note_lost "$cid" "$reason"
    done
    run_record coverage_reduction "module=cloud reason=$reason service=cognito operation=list-identity-pools account=$account region=$region cell=${SCOURSH_CLOUD_CELL:-} - the region's identity-pool list could not be read (${SCOURSH_AWS_RO_OUTCOME}${SCOURSH_AWS_RO_CODE:+, code ${SCOURSH_AWS_RO_CODE}}), so NO identity pool in $region was examined. The user-pool half of this pass is unaffected and is reported separately."
    run_record coverage_gap "cloud cognito: the identity-pool list for account $account in $region could not be read (${SCOURSH_AWS_RO_OUTCOME}), so nothing tested whether any identity pool allows unauthenticated identities, hands AWS credentials to anonymous callers, or attaches an over-permissive unauthenticated role. A clean result here is the absence of a test - confirm the scanning role holds cognito-identity:ListIdentityPools, cognito-identity:DescribeIdentityPool and cognito-identity:GetIdentityPoolRoles."
    return 0
  fi
  if [[ ${SCOURSH_AWS_RO_OUTCOME:-} == truncated ]]; then
    _CG_LIST_TRUNCATED+="${_CG_LIST_TRUNCATED:+ }list-identity-pools"
  fi

  local -a ipools=() inames=()
  local i=0 ipid='' ipname=''
  cognito_doc_load "$listf" || true
  while :; do
    cognito_doc_has "$(cognito_path IdentityPools "$i" IdentityPoolId)" || break
    cognito_doc_get ipid "$(cognito_path IdentityPools "$i" IdentityPoolId)"
    cognito_doc_get ipname "$(cognito_path IdentityPools "$i" IdentityPoolName)" || ipname=''
    [[ -n $ipid ]] && { ipools+=("$ipid"); inames+=("$ipname"); }
    i=$(( i + 1 ))
  done
  _CG_IDPOOLS_TOTAL=${#ipools[@]}

  local n=0
  for (( n = 0; n < ${#ipools[@]}; n++ )); do
    if (( n >= SCOURSH_COGNITO_MAX_IDENTITY_POOLS )); then
      _CG_CAPPED+="${_CG_CAPPED:+ }identity_pools"
      run_record coverage_reduction "module=cloud reason=cognito_identity_pool_cap service=cognito account=$account region=$region examined=$n total=$_CG_IDPOOLS_TOTAL cap=$SCOURSH_COGNITO_MAX_IDENTITY_POOLS - the per-region identity-pool ceiling was reached, so $(( _CG_IDPOOLS_TOTAL - n )) pool(s) in this region were NOT examined by any CLOUD-COGNITO-IDPOOL_* check."
      break
    fi
    _cg_examine_identity_pool "${ipools[n]}" "${inames[n]}" "$account" "$region" "$partition" "$work"
  done
  return 0
}

_cg_examine_identity_pool() {
  local ipid=$1 ipname=$2 account=$3 region=$4 partition=$5 work=$6
  local safe=${ipid//[^A-Za-z0-9._-]/_}
  local f=$work/idpool.$safe.json rolesf=$work/idpool-roles.$safe.json rc=0
  local arn
  arn=$(cognito_identity_pool_arn "$partition" "$region" "$account" "$ipid")
  local label="identity pool $ipid${ipname:+ ($ipname)}"

  aws_ro cognito-identity describe-identity-pool --identity-pool-id "$ipid" >"$f" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost describe-identity-pool "$ipid" "${_CG_IDPOOL_CHECK_IDS[@]}"
    return 0
  fi
  cognito_doc_load "$f" || true
  _CG_IDPOOLS_EXAMINED=$(( _CG_IDPOOLS_EXAMINED + 1 ))

  local allows_unauth=0
  cognito_idpool_allows_unauth && allows_unauth=1

  if _cg_selected CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01; then
    _cg_note_evaluated CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01
    if (( allows_unauth )); then
      _cg_emit CLOUD-COGNITO-IDPOOL_UNAUTH_IDENTITIES-01 "$arn" '' \
        "$label has AllowUnauthenticatedIdentities set to true, so any caller who knows the identity pool id - a public value shipped in the application's own JavaScript or mobile binary - can obtain an identity from it with no credential of any kind. On its own that is a configuration fact; what turns it into an exposure is an unauthenticated IAM role being attached, and what turns that into a serious one is the scope of that role. Check for CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01 and the IDPOOL_UNAUTH_ROLE_* findings on this same pool."
    fi
  fi

  if _cg_selected CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01; then
    _cg_note_evaluated CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01
    if cognito_idpool_classic_flow; then
      _cg_emit CLOUD-COGNITO-IDPOOL_CLASSIC_FLOW-01 "$arn" '' \
        "$label has AllowClassicFlow enabled, re-opening Cognito Identity's original two-step exchange (GetOpenIdToken then a direct sts assume-role-with-web-identity) alongside the modern single-step GetCredentialsForIdentity. The two-step form hands the caller an OpenID token they present to STS themselves, which takes role selection out of the pool's own role-mapping rules and lets the caller name the role: whoever obtains the token may attempt any role whose trust policy accepts this pool. Read from AllowClassicFlow."
    fi
  fi

  # `get-identity-pool-roles` is a SECOND call, and it is made only when at
  # least one check that reads it is selected.  It carries the role ARNs and
  # the role mappings; without it there is nothing to say about either.
  _cg_any_selected CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01 \
    CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01 \
    CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01 \
    CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01 || return 0

  rc=0
  aws_ro cognito-identity get-identity-pool-roles --identity-pool-id "$ipid" >"$rolesf" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost get-identity-pool-roles "$ipid" \
      CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01 \
      CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01 \
      CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01 \
      CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01
    return 0
  fi
  cognito_doc_load "$rolesf" || true

  local unauth_role=''
  local has_unauth_role=0
  cognito_idpool_role_set unauth_role unauthenticated && has_unauth_role=1

  if _cg_selected CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01; then
    local mappings=''
    _cg_note_evaluated CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01
    if cognito_idpool_ambiguous_mappings_set mappings; then
      _cg_emit CLOUD-COGNITO-IDPOOL_ROLE_MAPPING-01 "$arn" '' \
        "$label has role mappings whose AmbiguousRoleResolution is AuthenticatedRole (provider and mapping type): ${mappings//$'\n'/; }. A role mapping exists to give different classes of user different IAM roles from a claim in their token; AmbiguousRoleResolution decides what happens when a token matches several rules or none. AuthenticatedRole falls back to the pool's DEFAULT authenticated role, so a token carrying an unexpected or user-influenced claim silently receives whatever that role can do. Deny is the safe value, despite the names reading the other way round."
    fi
  fi

  if _cg_selected CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01; then
    _cg_note_evaluated CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01
    if (( allows_unauth && has_unauth_role )); then
      _cg_emit CLOUD-COGNITO-IDPOOL_UNAUTH_CREDENTIALS-01 "$arn" '' \
        "$label both allows unauthenticated identities and attaches the unauthenticated role $unauth_role, so GetCredentialsForIdentity returns real, signed AWS credentials for that role to any caller who knows the pool id - no sign-in, no token, no account. The pool id ships in the application's own JavaScript or mobile binary and is routinely visible in a browser network tab. Derived from the pool's own configuration; scoursh never called GetCredentialsForIdentity - the credentials are obtainable, and no scan obtained any."
    fi
  fi

  # §8.3: "AllowUnauthenticatedIdentities = true -> then INSPECT the
  # unauthenticated IAM role policy for over-permissiveness ... emit as its own
  # high-severity finding, not a note."  The inspection happens ONLY when both
  # halves hold, because a role attached to a pool that refuses anonymous
  # identities is not anonymously assumable through this path and the IAM calls
  # would buy nothing.
  if (( allows_unauth && has_unauth_role )); then
    _cg_inspect_unauth_role "$arn" "$label" "$unauth_role" "$work"
  elif _cg_any_selected CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01 CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01; then
    # The pool has no anonymous path, so the two role checks are ANSWERED - the
    # question "is this pool's anonymous role over-permissive" has the answer
    # "there is no anonymous role", which is a real answer and not a failure to
    # look.  Crediting them is what lets tension 12 classify a prior finding
    # `fixed` on the day an operator turns AllowUnauthenticatedIdentities off,
    # which is the correct remediation and must not leave the finding at
    # `unknown` forever.
    _cg_selected CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01 \
      && _cg_note_evaluated CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01
    _cg_selected CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01 \
      && _cg_note_evaluated CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 6. The unauthenticated role's policies
# ---------------------------------------------------------------------------
# `_cg_inspect_unauth_role POOL_ARN POOL_LABEL ROLE_ARN WORKDIR`
#
# The `iam` half of this pass, and the only place it reaches a third API
# namespace.  It reads every policy attached to the role - inline and managed
# alike - and asks `cognito_policy_grants_set` one narrow question of each: is
# there an unconditioned `Allow` of a wildcard action against a wildcard
# resource.  The engine's own section 6 records why the question is that narrow
# rather than "what does this role really permit", which is IAM policy
# evaluation and cannot be done correctly in shell.
#
# ONE FINDING PER ROLE, AT THE WORST GRADE SEEN.  A role holding both `*` and
# `s3:*` has one problem an operator fixes once; emitting both ids would report
# it twice under two severities and make the lower one look like a separate,
# still-open issue after the higher one was fixed.
_cg_inspect_unauth_role() {
  local pool_arn=$1 label=$2 role_arn=$3 work=$4
  local admin_id=CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_ADMIN-01
  local broad_id=CLOUD-COGNITO-IDPOOL_UNAUTH_ROLE_BROAD-01
  _cg_any_selected "$admin_id" "$broad_id" || return 0

  local role
  role=$(cognito_role_name_of "$role_arn")
  local safe=${role//[^A-Za-z0-9._-]/_}
  local rc=0 grants='' all_grants='' conditioned=0 examined=0 sources=''

  # -- inline policies -------------------------------------------------------
  local inlinef=$work/role-inline.$safe.json
  rc=0
  aws_ro iam list-role-policies --role-name "$role" >"$inlinef" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost list-role-policies "$role" "$admin_id" "$broad_id"
    return 0
  fi
  local -a inline=()
  local i=0 pn=''
  cognito_doc_load "$inlinef" || true
  while :; do
    cognito_doc_has "$(cognito_path PolicyNames "$i")" || break
    cognito_doc_get pn "$(cognito_path PolicyNames "$i")"
    [[ -n $pn ]] && inline+=("$pn")
    i=$(( i + 1 ))
  done

  # -- managed policies ------------------------------------------------------
  local attachedf=$work/role-attached.$safe.json
  rc=0
  aws_ro iam list-attached-role-policies --role-name "$role" >"$attachedf" || rc=$?
  if (( rc != 0 )); then
    _cg_call_lost list-attached-role-policies "$role" "$admin_id" "$broad_id"
    return 0
  fi
  local -a managed=()
  i=0
  local parn=''
  cognito_doc_load "$attachedf" || true
  while :; do
    cognito_doc_has "$(cognito_path AttachedPolicies "$i" PolicyArn)" || break
    cognito_doc_get parn "$(cognito_path AttachedPolicies "$i" PolicyArn)"
    [[ -n $parn ]] && managed+=("$parn")
    i=$(( i + 1 ))
  done

  # -- read each document ----------------------------------------------------
  local n=0 docf=''
  for (( n = 0; n < ${#inline[@]}; n++ )); do
    if (( examined >= SCOURSH_COGNITO_MAX_ROLE_POLICIES )); then break; fi
    docf=$work/role-inline-doc.$safe.$n.json
    rc=0
    aws_ro iam get-role-policy --role-name "$role" --policy-name "${inline[n]}" >"$docf" || rc=$?
    if (( rc != 0 )); then
      _cg_call_lost get-role-policy "$role/${inline[n]}" "$admin_id" "$broad_id"
      continue
    fi
    cognito_doc_load "$docf" || true
    _cg_accumulate_grants all_grants conditioned "inline ${inline[n]}" sources PolicyDocument
    examined=$(( examined + 1 ))
  done

  local verf='' ver=''
  for (( n = 0; n < ${#managed[@]}; n++ )); do
    if (( examined >= SCOURSH_COGNITO_MAX_ROLE_POLICIES )); then break; fi
    docf=$work/role-managed.$safe.$n.json
    rc=0
    aws_ro iam get-policy --policy-arn "${managed[n]}" >"$docf" || rc=$?
    if (( rc != 0 )); then
      _cg_call_lost get-policy "${managed[n]}" "$admin_id" "$broad_id"
      continue
    fi
    cognito_doc_load "$docf" || true
    # The DEFAULT version is the one in force.  Reading v1 - or the newest by
    # number - would judge a policy the role is not actually using, in either
    # direction: a policy hardened in v3 would still be reported on its v1
    # wildcard, and one loosened in v3 would be reported clean on v1.
    cognito_doc_get ver "$(cognito_path Policy DefaultVersionId)" || ver=''
    if [[ -z $ver ]]; then
      run_record coverage_reduction "module=cloud reason=cognito_policy_version_unresolved service=cognito operation=get-policy policy=${managed[n]} role=$role - the attached managed policy named no DefaultVersionId, so its document could not be fetched and its statements were NOT examined for over-permissiveness."
      continue
    fi
    verf=$work/role-managed-ver.$safe.$n.json
    rc=0
    aws_ro iam get-policy-version --policy-arn "${managed[n]}" --version-id "$ver" >"$verf" || rc=$?
    if (( rc != 0 )); then
      _cg_call_lost get-policy-version "${managed[n]}@$ver" "$admin_id" "$broad_id"
      continue
    fi
    cognito_doc_load "$verf" || true
    _cg_accumulate_grants all_grants conditioned "managed ${managed[n]}" sources PolicyVersion Document
    examined=$(( examined + 1 ))
  done

  local total=$(( ${#inline[@]} + ${#managed[@]} ))
  if (( total > SCOURSH_COGNITO_MAX_ROLE_POLICIES )); then
    _CG_CAPPED+="${_CG_CAPPED:+ }role_policies"
    run_record coverage_reduction "module=cloud reason=cognito_role_policy_cap service=cognito role=$role pool=$label examined=$examined total=$total cap=$SCOURSH_COGNITO_MAX_ROLE_POLICIES - the per-role policy ceiling was reached, so $(( total - examined )) policy document(s) on this unauthenticated role were NOT examined for over-permissiveness. A clean result for this role is therefore partial."
  fi

  # A role with no readable policy at all is NOT credited: the question "is
  # this anonymous role over-permissive" was not answered.  `_cg_call_lost`
  # above has already recorded the reason for each failure.
  if (( examined == 0 )); then
    if (( total == 0 )); then
      # A role that genuinely has no policy attached grants nothing, which IS
      # an answer - and a reassuring one.  It is credited.
      _cg_selected "$admin_id" && _cg_note_evaluated "$admin_id"
      _cg_selected "$broad_id" && _cg_note_evaluated "$broad_id"
    fi
    return 0
  fi

  _cg_selected "$admin_id" && _cg_note_evaluated "$admin_id"
  _cg_selected "$broad_id" && _cg_note_evaluated "$broad_id"

  if (( conditioned > 0 )); then
    run_record coverage_reduction "module=cloud reason=cognito_conditioned_statement_not_assessed service=cognito role=$role pool=$label statements=$conditioned - $conditioned wildcard statement(s) on this unauthenticated role carry a Condition block, which narrows what they grant in a way this scan does not evaluate. They were counted and set aside rather than judged: reporting them would flag every properly-narrowed policy, and evaluating them correctly means implementing IAM policy evaluation. Review them by hand - aws:SourceIp on 0.0.0.0/0 and aws:Referer narrow nothing."
  fi

  grants=$all_grants
  [[ -n $grants ]] || return 0
  local grade
  grade=$(cognito_policy_worst_grade "$grants")
  local id
  if [[ $grade == admin ]]; then id=$admin_id; else id=$broad_id; fi
  # `(( conditioned ))`, never `${conditioned:+...}`: the variable holds the
  # STRING `0` when no statement was set aside, and `:+` tests for a non-empty
  # value rather than a non-zero one - so the parameter-expansion spelling
  # appends "0 conditioned statement(s) were set aside" to every finding on a
  # policy that had none.
  local aside=''
  (( conditioned > 0 )) && aside="; $conditioned conditioned statement(s) were set aside and are listed as a coverage reduction"
  _cg_emit "$id" "$pool_arn" "" \
    "The unauthenticated role of $label is $role_arn, and its policies grant: ${grants//$'\n'/; } (from: ${sources//$'\n'/, }). This pool allows unauthenticated identities, so that role is assumable by anyone who knows the pool id - a public value shipped in the application's own code. Only statements with NO Condition are reported here$aside."
  return 0
}

# `_cg_accumulate_grants GRANTSVAR CONDVAR SOURCE_LABEL SOURCESVAR ROOT...` -
# run the policy classifier over the currently-loaded document and fold its
# result into the caller's accumulators.
#
# A SEPARATE FUNCTION SO THE TWO DOCUMENT SHAPES SHARE ONE CALL SITE.  An
# inline policy arrives under `PolicyDocument` and a managed policy version
# under `PolicyVersion`.`Document`, and those two paths are the ONLY difference
# between the two branches above - duplicating twelve lines to vary one
# argument is how the two drift.
_cg_accumulate_grants() {
  local __gvar=$1 __cvar=$2 __label=$3 __svar=$4
  shift 4
  local __g='' __have=${!__gvar} __sources=${!__svar}

  # THE DOCUMENT MUST BE A NESTED OBJECT, NOT A STRING.  The IAM API returns a
  # policy document URL-ENCODED and the CLI decodes it into real JSON, which is
  # what every path here assumes - but a CLI or a response that handed back the
  # encoded string would flatten to ONE string leaf, every `Statement` path
  # would be absent, and the classifier would report the most permissive policy
  # in the account as having no statements at all.  That is a silent false
  # negative on the highest-severity check in this pack, so it is detected and
  # declared rather than assumed away.
  if cognito_doc_has "$(cognito_path "$@")"; then
    run_record coverage_reduction "module=cloud reason=cognito_policy_document_not_decoded service=cognito policy=$__label - the policy document came back as an opaque string rather than as decoded JSON (the AWS CLI normally URL-decodes it), so its statements were NOT examined for over-permissiveness."
    return 0
  fi

  cognito_policy_grants_set __g "$@" || true
  if [[ -n $__g ]]; then
    printf -v "$__gvar" '%s' "${__have:+$__have$'\n'}$__g"
    printf -v "$__svar" '%s' "${__sources:+$__sources$'\n'}$__label"
  fi
  printf -v "$__cvar" '%s' "$(( ${!__cvar} + _COGNITO_POLICY_CONDITIONED ))"
  return 0
}

# ---------------------------------------------------------------------------
# 7. The roll-up
# ---------------------------------------------------------------------------
# One `checks_run` line per check that ACTUALLY ANSWERED for at least one
# resource, and one `coverage_reduction` per check that did not.  This is the
# accounting rule this file's header states as rule 1, and it is what
# `_cloud_record_coverage` reads to write the `<account>/<region>` coverage
# cell - so a check credited here that never ran would let tension 12 report a
# prior finding `fixed` on the strength of a call that was denied.
_cg_record_coverage() {
  local account=$1 region=$2 id
  local ran=0

  for id in "${_CG_CHECK_IDS[@]+"${_CG_CHECK_IDS[@]}"}"; do
    _cg_selected "$id" || continue
    if (( ${_CG_EVALUATED[$id]:-0} > 0 )); then
      run_record checks_run "$id"
      ran=$(( ran + 1 ))
      # A check that answered for SOME resources and was denied for others is
      # covered AND incomplete.  Both facts are recorded: reporting only the
      # first overstates the coverage, and reporting only the second would
      # suppress a cell the run genuinely did visit.
      if (( ${_CG_LOST[$id]:-0} > 0 )); then
        run_record coverage_reduction "module=cloud reason=${_CG_LOST_REASON[$id]} service=cognito check=$id account=$account region=$region resources_answered=${_CG_EVALUATED[$id]} resources_unanswered=${_CG_LOST[$id]} - this check ran, but ${_CG_LOST[$id]} resource(s) did not answer, so it is covered for some of this region's Cognito resources and not for others."
      fi
    else
      run_record coverage_reduction "module=cloud reason=${_CG_LOST_REASON[$id]:-no_cognito_resource_examined} service=cognito check=$id account=$account region=$region user_pools=$_CG_POOLS_TOTAL app_clients=$_CG_CLIENTS_TOTAL identity_pools=$_CG_IDPOOLS_TOTAL - this check answered for NO resource in this region and is therefore NOT recorded in checks_run. Its absence from the findings is not evidence that every Cognito resource here is configured correctly."
    fi
  done

  if (( _CG_POOLS_TOTAL == 0 && _CG_IDPOOLS_TOTAL == 0 )); then
    # A region with no Cognito resources at all.  The checks above are still
    # credited where their list call succeeded: the run DID look and there was
    # nothing to look at - which is what lets a prior finding for a pool that
    # has since been deleted be classified `fixed` rather than sitting at
    # `unknown` forever.  This is the one place "no findings" legitimately
    # means "nothing wrong", and it is recorded so a reader can tell it from
    # the many places it does not.
    run_record notes "module=cloud service=cognito account=$account region=$region user_pools=0 identity_pools=0 - both Cognito list calls succeeded and the region holds neither a user pool nor an identity pool, so every CLOUD-COGNITO-* check is covered vacuously here."
  fi

  # A CAP THAT WAS REACHED IS RESTATED AS A `coverage_gap`, not only as the
  # per-cap `coverage_reduction` the walk already wrote.  A reduction is a
  # machine-readable record in run.json; a gap is what lib/report.sh renders
  # into the limitations section of report.md and report.html - the surfaces a
  # consumer actually reads.  A bound that only ever appears in a machine
  # record is a bound the person reading the report never learns about, which
  # is the same defect as not recording it at all wearing a compliance sticker.
  if [[ -n $_CG_CAPPED ]]; then
    run_record coverage_gap "cloud cognito: a per-resource ceiling was reached in account $account, $region ([$_CG_CAPPED]), so some Cognito resources in this region were enumerated but never examined. A clean result for those resources is the absence of a test, not the absence of a problem. The ceilings are SCOURSH_COGNITO_MAX_USER_POOLS ($SCOURSH_COGNITO_MAX_USER_POOLS), SCOURSH_COGNITO_MAX_CLIENTS_PER_POOL ($SCOURSH_COGNITO_MAX_CLIENTS_PER_POOL), SCOURSH_COGNITO_MAX_IDENTITY_POOLS ($SCOURSH_COGNITO_MAX_IDENTITY_POOLS) and SCOURSH_COGNITO_MAX_ROLE_POLICIES ($SCOURSH_COGNITO_MAX_ROLE_POLICIES)."
  fi

  if [[ -n $_CG_LIST_TRUNCATED ]]; then
    run_record coverage_reduction "module=cloud reason=aws_api_truncated service=cognito account=$account region=$region operations=[$_CG_LIST_TRUNCATED] user_pools_seen=$_CG_POOLS_TOTAL identity_pools_seen=$_CG_IDPOOLS_TOTAL - at least one Cognito list came back INCOMPLETE (a continuation token was present), so an unknown number of this region's Cognito resources were never enumerated and were not examined by any CLOUD-COGNITO-* check."
    run_record coverage_gap "cloud cognito: a resource list for account $account in $region was truncated, so an unknown number of user pools, app clients or identity pools were never examined. A clean result for those resources is the absence of a test, not the absence of a problem."
  fi

  if (( ran == 0 )) && (( _CG_POOLS_TOTAL > 0 || _CG_IDPOOLS_TOTAL > 0 )); then
    run_record coverage_gap "cloud cognito: account $account in $region holds $_CG_POOLS_TOTAL user pool(s) and $_CG_IDPOOLS_TOTAL identity pool(s) and NOT ONE of the ${#_CG_CHECK_IDS[@]} CLOUD-COGNITO-* checks answered for any of them, so no pool's password policy, MFA, advanced security or recovery configuration was tested, no app client's flows, callback URLs or token settings were tested, and no identity pool's anonymous access was tested. This is a run that did not look, not an account with nothing wrong - each check's own coverage_reduction above names the failure class."
  fi
  return 0
}

_cg_run_service
